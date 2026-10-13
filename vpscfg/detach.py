"""Detached remote execution for mutation steps, and the evidence a reconcile reads.

A mutation step used to run as the foreground of one SSH session. When that
session dropped, the door could not tell whether the command had finished, so
it kept the host lock and printed "remote completion is unknown" even when the
command had completed seconds later (2026-10-12, apps: a `docker compose up -d`
came up healthy while the lock stayed held and every later step refused).

Now a step is LAUNCHED on the host, detached from the session, and the door
waits on files instead of on the session:

  /run/vpscfg-ops/<op>/          0700 root; <op> is the lock's operation id
      <i>.sh   the step's remote command, exactly as gated
      <i>.run  the fixed runner (below); started under systemd-run
               (KillMode=mixed) when the host has systemd, else setsid/nohup
      <i>.started  (dir) the runner's single-run guard
      <i>.pid  the runner   <i>.cpid  the step = its own process group id
      <i>.unit  <i>.out  <i>.err  <i>.rc   (rc written last, atomically)

The local side polls (one short SSH call per poll), streams the log, and reads
<i>.rc. A dropped poll is retried with backoff until the step's own timeout;
only if no poll succeeds for that whole time is completion "unknown".

Threats:
  - Protects against: a dropped SSH session costing a deploy (the step keeps
    running and its real rc is read on re-attach); a step launching without its
    lock (the launch re-reads /run/vpscfg.lock/token and refuses unless it is
    THIS operation's, so a late or replayed launch after a reconcile runs
    nothing); a step running twice (`mkdir <i>.started` is the runner's atomic
    single-run guard, and a launch refuses if <i>.sh already exists); other
    local users reading step output (op dir 0700, files under umask 077); a
    garbled or hostile poll reply steering the door (strict line grammar, ints
    and base64 only; anything else counts as a failed poll, never as an rc);
    stderr being lost (both streams are files, read back and masked by the
    caller before display or journal); a lost launch reply turning into a
    false "did not run" (the door claims <i>.started — the runner's own
    single-run guard — before saying so, so a launch still in flight can never
    start the step later); a runaway step filling /run (each log keeps its
    first LOG_CAP bytes, the rest is drained to /dev/null, the step is never
    killed for its output); output lost to a reader's stdio buffer while a
    process the step left holds the FIFO (the reader copies each read() to the
    log with `dd count=1`, unbuffered); a unit outliving its step's timeout
    indefinitely (RuntimeMaxSec = timeout + RUNTIME_GRACE, KillMode=mixed); a
    stop or timeout leaving the step's children running (the step runs in its
    OWN process group — setsid, else perl setpgrp, else it is never started,
    rc 125 — and a TERM goes to the whole group; the trap is installed before
    anything starts, so an early TERM means the step never starts, rc 143); a
    verdict of COMPLETED while a process of the step's group is still alive
    (poll reports it running); op dirs accumulating (removed with the lock, in
    the same remote command, once the outcome is known or reconcile journaled
    the evidence); a trailing newline smuggled into an op id (OP_RE is
    anchored with \\A...\\Z); a host without systemd running a step whose
    escapee nothing can stop (refused before anything is written unless the
    governor lists it in allow_unmanaged_steps); an exit code taken as "done"
    while the step's group still runs (the door waits LOG_GRACE, then keeps the
    lock as STILL RUNNING); a recycled group-leader pid being signalled or
    counted as the step (<i>.cstart: a live pid with another start time is
    REUSED — UNKNOWN, never signalled; a leaderless live group is signalled
    only when every member proves, from Linux /proc, the step's session, a
    start no earlier than the leader AND the step's VPSCFG_OP=<op>.<i> tag in
    its environment — never off Linux; session and start time alone let a
    reused group through); a log reader stopping early under a foreign locale
    or dd dialect (progress is the log's own size; LC_ALL=C), or blocking
    forever on a FIFO (the runner opens a read-write end BEFORE the readers
    start — an open that never blocks, so an early TERM cannot lose the rc —
    then opens the read ends itself and hands them to the readers already
    open, so no process ever waits in a FIFO open; it holds the write ends
    until the step started and closes them on every path; a SIGKILLed
    runner's ends close with it); a
    failing systemd-run on a host not opted in falling back to an unmanaged
    launch (it fences the step and says SYSTEMD_FAILED instead); a guard
    already taken by an earlier fence being reported as this launch
    (FENCED_BY_OTHER: outcome unknown, the lock stays).
  - Does NOT protect against: root on the host forging <i>.rc (the host is
    trusted, as everywhere in this door); a reboot wiping /run mid-step (the
    op dir is gone, so the outcome is reported unknown and needs reconcile); a
    command whose meaning depends on the interactive SSH session (a TTY, the
    ssh agent, SSH_* variables) — the step runs with the session's cwd, HOME
    and PATH, under bash when present, else sh; a process the step started
    in a session of its OWN (a daemon that calls setsid itself) on a non-
    systemd host — it leaves the step's process group, so neither the group
    check nor `reconcile --stop` reaches it (under systemd, KillMode=mixed
    does); the step's process-group id being reused by an unrelated process
    group after the step's group is gone, which could make the op look running
    or let --stop signal that group (a window that exists only while the op's
    lock is still held).
"""

import base64
import re
import shlex
import subprocess
import time

from . import lock

OPS_DIR = "/run/vpscfg-ops"
OP_RE = re.compile(r"\A[0-9a-f]{16,128}\Z")  # \Z: no trailing newline
CHUNK = 65536              # bytes per stream per poll
KEEP = 1 << 20             # bytes per stream kept locally
TAIL = 2048                # bytes of each log a reconcile shows
POLL_TIMEOUT = 30          # one poll's own SSH timeout
FINAL_REATTACH = 3         # attach attempts allowed after the step's deadline
BACKOFF_MAX = 15
LAUNCHED = "VPSCFG-LAUNCHED"
FENCED = "VPSCFG-FENCED"
LOG_CAP = 16 * 1024 * 1024  # bytes of each of .out / .err kept on the host
# A systemd unit outlives its step's door timeout by at most this long.
RUNTIME_GRACE = 60

# Module attributes so tests never really sleep.
_sleep = time.sleep
_clock = time.monotonic


class DetachUnknown(OSError):
    """Re-attachment failed for the whole timeout, or the step outlived it.
    An OSError so the caller's existing "unknown completion" path retains the
    lock. Carries whatever output was read before contact was lost."""

    def __init__(self, message, out=b"", err=b""):
        OSError.__init__(self, message)
        self.out, self.err = bytes(out), bytes(err)


class PollError(ValueError):
    pass


def op_dir(op):
    if not OP_RE.match(op or ""):
        raise ValueError("operation id %r is not lowercase hex" % (op,))
    return "%s/%s" % (OPS_DIR, op)


def unit_name(op, idx):
    return "vpscfg-%s-%d" % (op[:16], int(idx))


# The log reader: fd 0 is the FIFO, fd 3 the log file, $VPSCFG_LOG its path
# (environment, not argv: the reader's argv never names the op dir). Each
# `dd count=1` copies what one read() returns straight to the file — no stdio
# buffer, so nothing waits for EOF to be written (a background process the step
# left holding the FIFO open cannot keep output from the file). Progress is the
# log's own size, never dd's statistics text, so no locale or dd dialect can
# confuse it (and it runs under LC_ALL=C LANG=C anyway). A read that copies
# nothing is end of file. At LOG_CAP bytes it switches to draining into
# /dev/null, so the step is never killed for its output.
_READER = ("n=0; while :; do b=$((%(cap)d-n)); [ \"$b\" -le 0 ] && break;"
           " [ \"$b\" -gt 65536 ] && b=65536;"
           " dd bs=$b count=1 2>/dev/null >&3;"
           " m=$(wc -c < \"$VPSCFG_LOG\" 2>/dev/null); m=$((${m:-0}+0));"
           " [ \"$m\" -le \"$n\" ] && exit 0; n=$m; done;"
           " exec cat >/dev/null")
# The step's process-group leader's start time: /proc/<pid>/stat field 22
# (the comm field may hold spaces, so everything up to ") " is cut first) on
# Linux, else `ps -o lstart=`. Recorded at launch in <i>.cstart; a live pid
# whose start time differs is a REUSED pid, never the step.
_START_FN = ("st() { if test -r /proc/$1/stat; then sed 's/.*) //' /proc/$1/stat 2>/dev/null"
             " | cut -d' ' -f20; else ps -o lstart= -p \"$1\" 2>/dev/null | tr -s ' '; fi; }")
# The state of step <i>'s process group, from <i>.cpid / <i>.cstart, as $pg:
# none (no group recorded), alive (leader alive, same start time), reused
# (a live pid with that number started at another time: not the step),
# leaderless (leader gone, group still has members), gone. $g is the pgid.
_PG_FN = (_START_FN + "; pgstate() { pg=none; g=; test -s \"$1.cpid\" || return 0;"
          " g=$(tr -dc 0-9 < \"$1.cpid\"); test -n \"$g\" || return 0;"
          " if kill -s 0 \"$g\" 2>/dev/null && ! ps -o stat= -p \"$g\" 2>/dev/null"
          " | grep -q '^Z'; then now=$(st \"$g\"); was=$(cat \"$1.cstart\" 2>/dev/null);"
          " if test -n \"$was\" && test \"$now\" = \"$was\"; then pg=alive; else pg=reused; fi;"
          " elif kill -s 0 -- -\"$g\" 2>/dev/null; then pg=leaderless; else pg=gone; fi; }")
# After the step exits, its log readers get at most this long to reach EOF
# before the exit code is written. A reader still running then is held open
# by a process the step left behind (it is in the step's process group, so
# reconcile reports STILL RUNNING until it ends or `--stop` ends it); its
# output keeps reaching the log as it is written, up to LOG_CAP.
LOG_GRACE = 5
# Exit codes the runner itself writes: the FIFOs could not be made (74), or
# the host offers no way to put the step in its own process group (125) —
# then nothing could stop all of it, so it is never started.
RC_NO_FIFO, RC_NO_ISOLATION = 74, 125
# The environment variable that tags every process of step <i> of op <op> as
# `<op>.<i>` (see _PGVERIFY_FN).
STEP_TAG = "VPSCFG_OP"


def _runner(d, i):
    """Fixed text; only the validated op dir and step index are interpolated.

    The TERM trap is installed FIRST, so a TERM that arrives before the step
    starts is not lost. The step runs in its own process group (setsid, else
    perl's setpgrp; with neither it is never started: rc 125), recorded in
    <i>.cpid; TERM to the runner (RuntimeMaxSec, `reconcile --stop`) goes to
    that whole group, so no child of the step survives it. Each stream goes
    through a FIFO to _READER (LOG_CAP, unbuffered). After the step exits the
    readers get LOG_GRACE seconds, then the exit code is written regardless."""
    p = "%s/%d" % (d, i)
    q = shlex.quote
    return ("umask 077\n"
            "c=; t=\n"
            # The trap only records the TERM; the runner's own flow forwards it
            # to the step's group (right after launch, and on every poll). A
            # trap that ran `kill` itself made macOS bash 3.2 crash (SIGSEGV,
            # no exit code) under a storm of TERMs.
            "trap 't=1' TERM\n"
            "mkdir %(p)s.started 2>/dev/null || exit 75\n"
            "echo $$ > %(p)s.pid\n"
            "cd \"${VPSCFG_CWD:-/}\" 2>/dev/null || cd /\n"
            "%(startfn)s\n"
            "fin() { printf '%%s\\n' \"$1\" > %(p)s.rc.tmp && mv %(p)s.rc.tmp %(p)s.rc; }\n"
            "rm -f %(p)s.ofifo %(p)s.efifo\n"
            "mkfifo %(p)s.ofifo %(p)s.efifo || { fin %(nofifo)d; exit %(nofifo)d; }\n"
            # The runner holds a write end of each FIFO from BEFORE the readers
            # start until the step has started. Opened read-write, which never
            # blocks (no wait for a reader, so a TERM cannot interrupt the open
            # and `command` keeps a failed redirection from killing the
            # shell); the readers then never block opening theirs, and never
            # wait forever for a writer: if the runner dies (even SIGKILL) its
            # ends close with it, and every exit below closes them first.
            # The READ ends are opened here too (5, 6: never blocks, a writer
            # already exists) and handed to the readers already open: no
            # process ever blocks opening a FIFO. (A reader that opened its own
            # FIFO after the runner closed or lost its write ends — an early
            # TERM, a SIGKILL — blocked forever, and the runner's `wait` with
            # it.)
            "command exec 7<>%(p)s.ofifo 8<>%(p)s.efifo 5<%(p)s.ofifo 6<%(p)s.efifo 2>/dev/null ||"
            " { exec 5<&- 6<&- 7>&- 8>&-; rm -f %(p)s.ofifo %(p)s.efifo; fin %(nofifo)d;"
            " exit %(nofifo)d; }\n"
            "VPSCFG_LOG=%(p)s.out LC_ALL=C LANG=C sh -c %(reader)s vpscfg-log-reader"
            " <&5 3> %(p)s.out 5<&- 6<&- 7>&- 8>&- & o=$!\n"
            "VPSCFG_LOG=%(p)s.err LC_ALL=C LANG=C sh -c %(reader)s vpscfg-log-reader"
            " <&6 3> %(p)s.err 5<&- 6<&- 7>&- 8>&- & e=$!\n"
            "exec 5<&- 6<&-\n"
            "if command -v bash >/dev/null 2>&1; then x=bash; else x=sh; fi\n"
            # TERM already arrived (stop / RuntimeMaxSec before the launch):
            # the step is never started.
            "if test -n \"$t\"; then exec 7>&- 8>&-; wait;"
            " rm -f %(p)s.ofifo %(p)s.efifo; fin 143; exit 143; fi\n"
            # Every process of the step inherits its tag (VPSCFG_OP=<op>.<i>):
            # how `reconcile --stop` tells the step's members from a reused group.
            "if command -v setsid >/dev/null 2>&1; then\n"
            " %(tag)s setsid $x %(p)s.sh >%(p)s.ofifo 2>%(p)s.efifo </dev/null 7>&- 8>&- & c=$!\n"
            "elif command -v perl >/dev/null 2>&1; then\n"
            " %(tag)s perl -e 'setpgrp(0, 0) or exit %(noiso)d; exec @ARGV or exit %(noiso)d'"
            " $x %(p)s.sh >%(p)s.ofifo 2>%(p)s.efifo </dev/null 7>&- 8>&- & c=$!\n"
            "else\n"
            " echo 'vpscfg: this host has neither setsid nor perl: the step cannot run"
            " in its own process group, so nothing could stop all of it; not started' >&8;"
            " exec 7>&- 8>&-; wait; rm -f %(p)s.ofifo %(p)s.efifo;"
            " fin %(noiso)d; exit %(noiso)d\n"
            "fi\n"
            "echo $c > %(p)s.cpid\n"
            # setsid/setpgrp happen inside the child: wait (bounded) until its
            # process group is its own pid, else kill it before it does work.
            "k=0; while :; do g=$(ps -o pgid= -p \"$c\" 2>/dev/null | tr -dc 0-9);"
            " test -z \"$g\" && break; test \"$g\" = \"$c\" && break; k=$((k+1));"
            " if test $k -ge 100; then kill -KILL \"$c\" 2>/dev/null; echo 'vpscfg: step not"
            " isolated in its own process group; killed' > %(p)s.iso; break; fi;"
            " sleep 0.05; done\n"
            # The leader's start time: a later live pid with this number and
            # another start time is a reused pid, never signalled as the step.
            "printf '%%s\\n' \"$(st \"$c\")\" > %(p)s.cstart\n"
            "exec 7>&- 8>&-\n"
            "test -n \"$t\" && { t=; kill -s TERM -- -\"$c\" 2>/dev/null; }\n"
            # Poll instead of a blocking `wait`: dash runs a trap only after
            # `wait <pid>` returns, which would let the step outlive a TERM.
            # Each TERM that arrived since the last poll goes to the step's
            # whole group. A zombie (exited, unreaped) step counts as gone.
            "while s=$(ps -o stat= -p \"$c\" 2>/dev/null) && test -n \"$s\""
            " && case $s in Z*) false;; *) true;; esac; do"
            " test -n \"$t\" && { t=; kill -s TERM -- -\"$c\" 2>/dev/null; }; sleep 0.2; done\n"
            "wait \"$c\"; r=$?\n"
            "test -s %(p)s.iso && r=%(noiso)d\n"
            "n=0; while [ $n -lt %(grace10)d ] && { kill -0 $o 2>/dev/null || kill -0 $e 2>/dev/null; };"
            " do sleep 0.1; n=$((n+1)); done\n"
            "rm -f %(p)s.ofifo %(p)s.efifo\n"
            "fin \"$r\"\n"
            % {"p": p, "reader": q(_READER % {"cap": LOG_CAP}), "grace10": LOG_GRACE * 10,
               "nofifo": RC_NO_FIFO, "noiso": RC_NO_ISOLATION, "startfn": _START_FN,
               "tag": "%s=%s" % (STEP_TAG, q("%s.%d" % (d.rstrip("/").rsplit("/", 1)[-1], i)))})


UNMANAGED = "VPSCFG-UNMANAGED"
SYSTEMD_FAILED = "VPSCFG-SYSTEMD-FAILED"
FENCED_BY_OTHER = "VPSCFG-FENCED-BY-OTHER"


def launch_cmd(op, idx, remote, token, timeout=None, unmanaged_ok=False):
    """Write the step and start it detached. Prints LAUNCHED only after the
    runner has been started; every earlier failure stops the && chain. Under
    systemd the unit is bounded: RuntimeMaxSec = the step's timeout + grace.

    A host WITHOUT systemd (no systemd-run, or not booted with it) is refused
    before anything is written — prints UNMANAGED — unless the governor opted
    it in (`unmanaged_ok`, from `allow_unmanaged_steps`): there a process the
    step starts in a session of its own escapes every stop, and the operator
    accepted that risk explicitly. On a systemd host that is NOT opted in, a
    failing systemd-run never falls back to setsid/nohup: the door fences the
    step (claims <i>.started) and prints SYSTEMD_FAILED — nothing runs."""
    d = op_dir(op)
    q = shlex.quote
    p = "%s/%d" % (d, idx)
    unit = unit_name(op, idx)
    env = '--setenv=VPSCFG_CWD="$C" --setenv=HOME="$HOME" --setenv=PATH="$PATH"'
    if timeout:
        env += " --property=RuntimeMaxSec=%d" % (int(timeout) + RUNTIME_GRACE)
    gate = ("" if unmanaged_ok else
            "if ! { command -v systemd-run >/dev/null 2>&1 && test -d /run/systemd/system; };"
            " then echo %s; exit 0; fi; " % UNMANAGED)
    if unmanaged_ok:
        # Opted in: no systemd, or systemd-run failed — setsid, else nohup.
        # (If a failed systemd-run did start its unit after all, this runner
        # exits 75 at the single-run guard.)
        fallback = (
            " elif command -v setsid >/dev/null 2>&1; then"
            " VPSCFG_CWD=\"$C\" nohup setsid /bin/sh %(p)s.run >/dev/null 2>&1 </dev/null &"
            " echo %(mark)s setsid;"
            " else VPSCFG_CWD=\"$C\" nohup /bin/sh %(p)s.run >/dev/null 2>&1 </dev/null &"
            " echo %(mark)s nohup; fi")
    else:
        # Not opted in: a failed systemd-run NEVER falls back to an unmanaged
        # launch. Claim the runner's single-run guard: if this creates it, the
        # step can never start (a unit systemd-run reported as failed but
        # started anyway exits 75) — SYSTEMD_FAILED, nothing ran. If the guard
        # already exists AND a runner wrote its pid (waited for, bounded),
        # the unit DID start the runner: it is launched. A guard with no
        # runner pid was taken by something else (a fence from an earlier,
        # lost launch): FENCED_BY_OTHER — this launch ran nothing, and
        # whether anything ran is unknown.
        fallback = (
            " elif mkdir %(p)s.started 2>/dev/null; then echo %(failed)s;"
            " else k=0; while ! test -s %(p)s.pid && test $k -lt 30; do sleep 0.1;"
            " k=$((k+1)); done;"
            " if test -s %(p)s.pid; then printf '%%s\\n' %(unit)s > %(p)s.unit"
            " && echo %(mark)s systemd; else echo %(other)s; fi; fi")
    return gate + ((
        "umask 077 && C=$PWD && mkdir -p %(ops)s && chmod 700 %(ops)s && mkdir -p %(d)s"
        " && chmod 700 %(d)s"
        " && test \"$(cat %(lock)s/token 2>/dev/null)\" = %(token)s"
        " && test ! -e %(p)s.sh"
        " && printf '%%s' %(script)s > %(p)s.sh && printf '%%s' %(runner)s > %(p)s.run"
        " && if command -v systemd-run >/dev/null 2>&1 && test -d /run/systemd/system"
        " && systemd-run --quiet --collect --unit=%(unit)s --property=KillMode=mixed"
        " %(env)s /bin/sh %(p)s.run >/dev/null 2>&1;"
        " then printf '%%s\\n' %(unit)s > %(p)s.unit && echo %(mark)s systemd;"
        + fallback)
        % {"ops": q(OPS_DIR), "d": q(d), "p": q(p), "lock": q(lock.LOCK_DIR),
           "token": q(token), "script": q(remote), "runner": q(_runner(d, idx)),
           "unit": q(unit), "env": env, "mark": LAUNCHED, "failed": SYSTEMD_FAILED,
           "other": FENCED_BY_OTHER})


def fence_cmd(op, idx):
    """Atomically claim step `idx`'s single-run guard. FENCED only if this
    command created it (mkdir fails when the runner, or a fence, got there)."""
    d = op_dir(op)
    return ("umask 077 && mkdir -p %(ops)s && chmod 700 %(ops)s && mkdir -p %(d)s"
            " && chmod 700 %(d)s && mkdir %(p)s.started 2>/dev/null && echo %(mark)s"
            % {"ops": shlex.quote(OPS_DIR), "d": shlex.quote(d),
               "p": shlex.quote("%s/%d" % (d, idx)), "mark": FENCED})


def _fence(host, op, idx, ssh):
    """True: fenced, the step can never start. False: a runner had already
    claimed it. Unreachable: the outcome is unknown (DetachUnknown)."""
    try:
        rc, out, _ = ssh(host, fence_cmd(op, idx), timeout=POLL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DetachUnknown("could not fence step %d of op %s on %s (%s); whether it "
                            "launched is unknown" % (idx, op[:8], host, e))
    return FENCED in (out or "")


def poll_cmd(op, idx, out_off=None, err_off=None):
    """State plus the next chunk of each log (offset None: the last TAIL bytes)."""
    d = op_dir(op)
    q = shlex.quote
    p = "%d" % idx

    def chunk(name, off):
        if off is None:
            return "tail -c %d %s.%s 2>/dev/null | base64 | tr -d '\\n'" % (TAIL, p, name)
        return ("tail -c +%d %s.%s 2>/dev/null | head -c %d | base64 | tr -d '\\n'"
                % (int(off) + 1, p, name, CHUNK))

    return (
        "{ cd %(d)s 2>/dev/null && test -e %(p)s.sh; } || { echo 'VPSCFG-STATE missing'; exit 0; };"
        " %(pgfn)s;"
        " r=; test -e %(p)s.rc && r=$(head -c 16 %(p)s.rc | tr -dc 0-9);"
        " run=no;"
        " if test -s %(p)s.unit && command -v systemctl >/dev/null 2>&1"
        " && systemctl is-active --quiet \"$(cat %(p)s.unit)\"; then run=yes; fi;"
        " if test $run = no && test -s %(p)s.pid && kill -0 \"$(cat %(p)s.pid)\" 2>/dev/null"
        " && ps -p \"$(cat %(p)s.pid)\" -o args= 2>/dev/null | grep -qF %(run)s; then run=yes; fi;"
        # Any process left in the step's own process group (a child it
        # started, a daemon it left) means the step is not over. A REUSED
        # leader pid is not the step: it never makes the step "running".
        " pgstate %(p)s; case $pg in alive|leaderless) run=yes;; esac;"
        " st=pending; test -d %(p)s.started && st=started;"
        " how=nohup; test -s %(p)s.unit && how=systemd;"
        " o=$(wc -c < %(p)s.out 2>/dev/null || echo 0); e=$(wc -c < %(p)s.err 2>/dev/null || echo 0);"
        " echo \"VPSCFG-STATE $st running=$run rc=$r out=$(echo $o) err=$(echo $e) how=$how"
        " pg=$pg\";"
        " printf 'VPSCFG-OUT '; %(out)s; echo;"
        " printf 'VPSCFG-ERR '; %(err)s; echo"
        % {"d": q(d), "p": p, "run": q("%s/%s.run" % (d, p)), "pgfn": _PG_FN,
           "out": chunk("out", out_off), "err": chunk("err", err_off)})


_STATE_RE = re.compile(r"^VPSCFG-STATE (started|pending) running=(yes|no) rc=(\d{0,9}) "
                       r"out=(\d{1,15}) err=(\d{1,15}) how=(systemd|nohup)"
                       r" pg=(none|alive|gone|reused|leaderless)\Z")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=]*$")


def parse_poll(text):
    """Strict: a reply that does not parse is a failed poll, never an rc."""
    lines = [l.strip() for l in (text or "").splitlines() if l.strip()]
    if lines[:1] == ["VPSCFG-STATE missing"]:
        return {"state": "missing", "running": False, "rc": None, "out": b"", "err": b"",
                "out_size": 0, "err_size": 0, "how": None, "pg": "none"}
    if len(lines) != 3:
        raise PollError("poll reply has %d line(s), want 3" % len(lines))
    m = _STATE_RE.match(lines[0])
    if not m:
        raise PollError("unparseable poll state")
    chunks = {}
    for line, name in zip(lines[1:], ("OUT", "ERR")):
        head = "VPSCFG-%s" % name
        body = line[len(head):].strip() if line.startswith(head) else None
        if body is None or not _B64_RE.match(body):
            raise PollError("unparseable %s chunk" % name.lower())
        try:
            chunks[name] = base64.b64decode(body, validate=True)
        except (ValueError, TypeError):
            raise PollError("bad base64 in %s chunk" % name.lower())
    return {"state": m.group(1), "running": m.group(2) == "yes",
            "rc": int(m.group(3)) if m.group(3) else None,
            "out_size": int(m.group(4)), "err_size": int(m.group(5)), "how": m.group(6),
            "pg": m.group(7), "out": chunks["OUT"], "err": chunks["ERR"]}


def poll(host, op, idx, ssh, out_off=None, err_off=None, timeout=POLL_TIMEOUT):
    rc, out, err = ssh(host, poll_cmd(op, idx, out_off, err_off), timeout=timeout)
    if rc != 0:
        raise PollError("poll exited rc=%s: %s" % (rc, (err or "").strip()[:80]))
    return parse_poll(out)


class DetachStillRunning(DetachUnknown):
    """The step wrote its exit code, but processes of its group (or its unit,
    or its runner) are still alive after LOG_GRACE: it is not over, so the
    lock and the op dir stay. Carries the rc and the output read so far."""

    def __init__(self, message, rc, out=b"", err=b""):
        DetachUnknown.__init__(self, message, out, err)
        self.rc = rc


def run(host, op, idx, remote, token, ssh, timeout, progress=None, on_output=None,
        unmanaged_ok=False):
    """Launch step `idx` of operation `op` detached and wait for its rc.

    Returns (rc, stdout_bytes, stderr_bytes). Raises DetachUnknown (an OSError)
    when completion cannot be established within `timeout`, and gates.Refused
    when the step provably did not start (the caller may release the lock)."""
    from .gates import Refused
    say = progress or (lambda msg: None)
    out_buf, err_buf = bytearray(), bytearray()
    deadline = _clock() + timeout
    launch_known = False
    try:
        lrc, lout, lerr = ssh(host, launch_cmd(op, idx, remote, token, timeout,
                                               unmanaged_ok=unmanaged_ok),
                              timeout=POLL_TIMEOUT)
        if UNMANAGED in (lout or ""):
            raise Refused(
                "%s has no systemd; step NOT started (governor allow_unmanaged_steps: "
                "[\"%s\"] accepts that a process escaping its group cannot be stopped)"
                % (host, host))
        fenced_by_other = FENCED_BY_OTHER in (lout or "")
        if fenced_by_other:
            pass  # raised below, outside this OSError handler
        elif SYSTEMD_FAILED in (lout or ""):
            raise Refused(
                "systemd-run failed on %s; step NOT started (fenced: it can no longer "
                "start; no unmanaged fallback without allow_unmanaged_steps)" % host)
        elif LAUNCHED not in (lout or ""):
            raise Refused("detached launch refused on %s (rc=%s): %s — the step did not "
                          "start (lock not this operation's, or the op dir already holds "
                          "this step)" % (host, lrc, ((lerr or lout or "").strip()
                                                      .splitlines() or ["no output"])[0][:120]))
        launch_known = True
    except (OSError, subprocess.TimeoutExpired) as e:
        fenced_by_other = False
        say("SSH lost while launching step %d (%s); re-attaching to op %s"
            % (idx, e.__class__.__name__, op[:8]))
    if fenced_by_other:
        # Not "did not run": something else holds this step's single-run
        # guard (an earlier fence or launch) and no runner is recorded. This
        # launch started nothing; what the other one did is unknown — the
        # lock stays (an OSError: the caller's "unknown completion" path).
        raise DetachUnknown(
            "step %d of op %s on %s: its single-run guard was already taken by another "
            "launch or fence and no runner is recorded; this launch ran nothing, and "
            "whether the step ran is unknown — the lock stays" % (idx, op[:8], host))

    backoff, failures, late, missing = 1, 0, 0, 0
    interval = 1.0
    rc_seen = None
    while True:
        past = _clock() >= deadline
        try:
            st = poll(host, op, idx, ssh, len(out_buf), len(err_buf),
                      timeout=POLL_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired, PollError) as e:
            failures += 1
            if past:
                late += 1
                if late > FINAL_REATTACH:
                    raise DetachUnknown(
                        "SSH connection lost; re-attachment to op %s failed for the whole "
                        "%ds timeout (%d attempt(s)); remote completion is unknown"
                        % (op[:8], timeout, failures), out_buf, err_buf)
            say("SSH lost (%s); re-attach attempt %d to op %s in %ds"
                % (e.__class__.__name__, failures, op[:8], min(backoff, BACKOFF_MAX)))
            _sleep(min(backoff, BACKOFF_MAX))
            backoff *= 2
            continue
        if failures:
            say("re-attached to op %s after %d failed attempt(s)" % (op[:8], failures))
            failures, backoff = 0, 1
        if st["state"] == "missing":
            if launch_known:
                raise DetachUnknown("op dir for %s step %d vanished on %s (reboot?); "
                                    "remote completion is unknown" % (op[:8], idx, host),
                                    out_buf, err_buf)
            missing += 1
            if missing >= 2:
                # No step file yet. Before declaring "did not run", claim the
                # runner's own single-run guard (<i>.started): if WE create it,
                # a launch still in flight can never run the step (its runner
                # exits 75 at that mkdir). If it already exists, a runner
                # started after all: keep polling.
                if _fence(host, op, idx, ssh):
                    raise Refused("SSH dropped before step %d launched on %s; it did not "
                                  "run (fenced: it can no longer start)" % (idx, host))
                launch_known = True
                continue
            _sleep(1)
            continue
        launch_known = True
        if len(out_buf) < KEEP:
            out_buf += st["out"][:KEEP - len(out_buf)]
        if len(err_buf) < KEEP:
            err_buf += st["err"][:KEEP - len(err_buf)]
        if on_output and (st["out"] or st["err"]):
            on_output(bytes(out_buf), bytes(err_buf))
        more = ((st["out_size"] > len(out_buf) and len(out_buf) < KEEP and st["out"])
                or (st["err_size"] > len(err_buf) and len(err_buf) < KEEP and st["err"]))
        if st["rc"] is not None and not more:
            if not st["running"]:
                return st["rc"], bytes(out_buf), bytes(err_buf)
            # The exit code exists but the step's group (or unit/runner) is
            # still alive: a child it left behind. Wait up to LOG_GRACE for
            # it to end; past that it is STILL RUNNING and nothing is released.
            if rc_seen is None:
                rc_seen = _clock()
            if _clock() - rc_seen >= LOG_GRACE:
                raise DetachStillRunning(
                    "step %d of op %s exited rc=%d but a process it left in its group "
                    "(pg=%s) is still running on %s — STILL RUNNING; the lock stays. "
                    "Stop it with: vpsexec reconcile %s --stop"
                    % (idx, op[:8], st["rc"], st.get("pg"), host, host),
                    st["rc"], out_buf, err_buf)
            _sleep(0.5)
            continue
        if st["rc"] is not None:
            continue  # drain the rest of the logs before returning
        if past:
            raise DetachUnknown("step %d of op %s still %s at its %ds timeout; remote "
                                "completion is unknown" % (idx, op[:8], "running" if
                                                           st["running"] else "unfinished",
                                                           timeout), out_buf, err_buf)
        _sleep(interval)
        interval = min(interval + 0.5, 5.0)


# ---- reconcile evidence --------------------------------------------------

def list_steps_cmd(op):
    return "ls -1 %s 2>/dev/null" % shlex.quote(op_dir(op))


def parse_steps(text):
    return sorted(set(int(m.group(1)) for m in
                      (re.match(r"^(\d{1,4})\.sh$", l.strip()) for l in (text or "").splitlines())
                      if m))


def procs_cmd(op):
    """Processes whose argv names the op dir (the runner, under any launcher)."""
    # `[/]run/...` matches the runner's argv but not this command's own shell,
    # whose argv carries the bracketed spelling.
    return ("ps -eo pid=,args= 2>/dev/null | grep %s || true"
            % shlex.quote("[/]" + op_dir(op)[1:]))


STOPPED = "VPSCFG-STOPPED"
STOP_REFUSED = "VPSCFG-STOP-REFUSED"


# A LEADERLESS group (leader gone, members alive) is the step's only if every
# member proves it, from Linux /proc/<pid>/stat (after cutting through ") "):
# field 3 is the pgrp, 4 the session, 20 the start time in clock ticks — the
# same clock as <i>.cstart there. Every member of pgrp $1 must be in session $1
# (the step's setsid made pgid == sid) and must have started no earlier than
# the leader ($2); there must be at least one. No /proc (not Linux) or a
# non-numeric cstart: unproven (return 1).
#
# Session and start time alone cannot tell the step's group from a REUSED one
# (an unrelated setsid'd leader that got the same pid after the step's group
# ended, and has since exited too). So every member must also carry the step's
# tag: the runner starts the step with VPSCFG_OP=<op>.<i> in its environment,
# and each member's /proc/<pid>/environ must hold exactly that entry ($3, the
# whole `VPSCFG_OP=<op>.<i>` string). environ is NUL-separated: newlines inside
# values are first mapped to \001, so no value can forge a whole entry. A
# member without the tag (or whose environ cannot be read) refuses.
#
# The stat line is read whole (newlines in comm mapped to spaces) and cut at
# its LAST ") ", the one that closes comm, so no comm can shift the fields.
_PGVERIFY_FN = ("pgverify() { vg=$1; vc=$2; vm=$3; test -r %(proc)s/self/stat || return 1;"
                " case $vc in ''|*[!0-9]*) return 1;; esac; test -n \"$vm\" || return 1; vn=0;"
                " for vf in %(proc)s/[0-9]*/stat; do"
                " vs=$(tr '\\n' ' ' < \"$vf\" 2>/dev/null | sed 's/.*) //');"
                " test -n \"$vs\" || continue;"
                " test \"$(echo \"$vs\" | cut -d' ' -f3)\" = \"$vg\" || continue;"
                " test \"$(echo \"$vs\" | cut -d' ' -f4)\" = \"$vg\" || return 1;"
                " vt=$(echo \"$vs\" | cut -d' ' -f20);"
                " case $vt in ''|*[!0-9]*) return 1;; esac;"
                " test \"$vt\" -ge \"$vc\" || return 1;"
                " tr '\\n\\000' '\\001\\n' < \"${vf%%/stat}/environ\" 2>/dev/null"
                " | grep -qxF \"$vm\" || return 1;"
                " vn=$((vn+1)); done;"
                " test $vn -gt 0; }")


def stop_cmd(op, proc="/proc"):
    """Stop every step of `op`. First every step's process group is judged
    (pgstate): if any group's leader pid is alive but REUSED (another start
    time), or the leader is gone while the group lives on (LEADERLESS) and its
    members do not all prove they are the step's (pgverify: Linux /proc only,
    same session as the group, started no earlier than the leader), the
    group's identity cannot be proven and NOTHING is signalled — the reply is
    STOP_REFUSED <reason> <step> <pgid> and a human acts by hand. (pgverify
    also requires every member to carry the step's VPSCFG_OP=<op>.<i> tag.)
    Otherwise:
    every process of each step's systemd unit, each live step group (leader
    alive with its recorded start time, or leaderless and verified), and each
    runner whose argv still names the op dir (it forwards TERM to its step's
    group). TERM only. `proc` is the proc filesystem's root (tests)."""
    d = op_dir(op)
    return ("cd %(d)s 2>/dev/null || { echo %(mark)s none; exit 0; };"
            " %(pgfn)s; %(verify)s;"
            " for f in *.cpid; do test -s \"$f\" || continue; i=${f%%.cpid}; pgstate \"$i\";"
            " case $pg in reused) echo \"%(refused)s $pg $i $g\"; exit 0;;"
            " leaderless) pgverify \"$g\" \"$(cat \"$i.cstart\" 2>/dev/null)\" \"%(tag)s.$i\""
            " || { echo \"%(refused)s $pg $i $g\"; exit 0; };; esac;"
            " done;"
            " for u in *.unit; do test -s \"$u\" && command -v systemctl >/dev/null 2>&1"
            " && systemctl kill --kill-who=all --signal=TERM \"$(cat \"$u\")\" 2>/dev/null;"
            " done;"
            " for f in *.cpid; do test -s \"$f\" || continue; i=${f%%.cpid}; pgstate \"$i\";"
            " case $pg in alive) kill -s TERM -- -\"$g\" 2>/dev/null;;"
            " leaderless) pgverify \"$g\" \"$(cat \"$i.cstart\" 2>/dev/null)\" \"%(tag)s.$i\""
            " && kill -s TERM -- -\"$g\" 2>/dev/null;; esac; done;"
            " for f in *.pid; do test -s \"$f\" || continue; p=$(tr -dc 0-9 < \"$f\");"
            " test -n \"$p\" && ps -p \"$p\" -o args= 2>/dev/null | grep -qF %(d)s"
            " && kill -TERM \"$p\" 2>/dev/null; done; echo %(mark)s"
            % {"d": shlex.quote(d), "mark": STOPPED, "refused": STOP_REFUSED,
               "pgfn": _PG_FN, "verify": _PGVERIFY_FN % {"proc": shlex.quote(proc)},
               "tag": "%s=%s" % (STEP_TAG, op)})


def inspect(host, op, ssh, timeout=POLL_TIMEOUT):
    """{'steps': [{idx, state, running, rc, how, out_tail, err_tail}], 'procs': str}."""
    rc, out, err = ssh(host, list_steps_cmd(op), timeout=timeout)
    steps = []
    for idx in parse_steps(out):
        st = poll(host, op, idx, ssh, timeout=timeout)
        st["idx"] = idx
        steps.append(st)
    prc, pout, _ = ssh(host, procs_cmd(op), timeout=timeout)
    return {"steps": steps, "procs": (pout or "").strip()}


def verdict(evidence):
    """('STILL RUNNING' | 'COMPLETED' | 'UNKNOWN', rc or None)."""
    steps = evidence["steps"]
    if any(s["running"] for s in steps) or evidence["procs"]:
        return "STILL RUNNING", None
    if any(s.get("pg") == "reused" for s in steps):
        # The leader's pid now belongs to another process (other start time):
        # whether the step's own group still runs cannot be told from here.
        return "UNKNOWN", None
    if steps and steps[-1]["rc"] is not None:
        return "COMPLETED", steps[-1]["rc"]
    return "UNKNOWN", None
