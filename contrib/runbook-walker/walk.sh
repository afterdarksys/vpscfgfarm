#!/usr/bin/env bash
# walk.sh: run the steps of one reviewed runbook (a policies/*.yaml file) in
# order, each one through vpsexec. The commands are read from the runbook
# itself, so they are always exactly what it authorises.
#
# The walker holds no authority. Every step goes through the door with every
# gate intact; vpsexec still prints the plan and still asks for approval
# (or takes it from an approval contract, see deploy.sh).
#
# What it adds over typing the steps yourself:
#   - every `vpscfg-push <sha256> <name>` artifact is found by content hash and
#     checked BEFORE the first step runs, so a missing or rebuilt artifact
#     stops the walk before anything changes;
#   - completed steps are recorded per runbook, so an interrupted walk resumes
#     with --from N and a finished one is not re-run by accident;
#   - rollback steps (`rollback: true`, or a why containing "(rollback only")
#     are skipped; run one deliberately with --only N;
#   - a step whose why says "Stop if" pauses after it runs, so you read the
#     output before the next step;
#   - steps marked break_glass: true get --break-glass, and the approval
#     contract if one was given. Other steps get neither;
#   - a `where: container` step gets `--in <container>` from its `container:`
#     key (vpsexec authorises such a step only inside that container).
#
# Usage:
#   walk.sh --runbook NAME --list
#   walk.sh --runbook NAME --reason "why" [--grant FILE] [--from N | --only N]
#
# Options:
#   --runbook NAME|PATH  runbook file name in the policies dir (".yaml" optional),
#                        or a path to one. Required: there is no default.
#   --list               print the steps and exit. Never calls vpsexec.
#   --reason TEXT        journaled by vpsexec with every step. Required to run.
#   --grant FILE         approval contract from `vpsexec grant new` (deploy.sh
#                        mints one for you). Passed to break_glass steps only.
#   --from N             resume at step N.
#   --only N             run exactly step N (rollback steps included) and stop.
#                        Does not read or write the progress record.
#   --policies DIR       where runbooks are   [$VPSCFG_POLICIES, else <repo>/policies]
#   --vpsexec PATH       the door             [$VPSEXEC, else <repo>/vpsexec]
#   --artifacts DIR      where pushed files are, searched recursively by sha256
#                                             [$VPSCFG_ARTIFACTS, else current dir]
#   --state-dir DIR      progress records     [$VPSCFG_WALK_STATE, else
#                                              ${XDG_STATE_HOME:-~/.local/state}/vpscfg-walk]
#   PYTHON=...           interpreter with PyYAML [python3]
#
# A `where: container` step without a `container:` key does not say WHICH
# container, so the walker cannot build its --in flag. It refuses such a
# runbook before the first step: add `container: NAME` to the entry, or run the
# step by hand with vpsexec ... --in NAME.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
POLICIES="${VPSCFG_POLICIES:-$REPO/policies}"
VPSEXEC="${VPSEXEC:-$REPO/vpsexec}"
ARTIFACTS="${VPSCFG_ARTIFACTS:-$PWD}"
STATE_DIR="${VPSCFG_WALK_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/vpscfg-walk}"
PYTHON="${PYTHON:-python3}"

RUNBOOK=""
REASON=""
GRANT=""
FROM=""
ONLY=""
LIST=0

die() { echo "walk.sh: $*" >&2; exit 2; }
need() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --runbook)   need "$@"; RUNBOOK="$2"; shift 2 ;;
    --reason)    need "$@"; REASON="$2"; shift 2 ;;
    --grant)     need "$@"; GRANT="$2"; shift 2 ;;
    --from)      need "$@"; FROM="$2"; shift 2 ;;
    --only)      need "$@"; ONLY="$2"; shift 2 ;;
    --policies)  need "$@"; POLICIES="$2"; shift 2 ;;
    --vpsexec)   need "$@"; VPSEXEC="$2"; shift 2 ;;
    --artifacts) need "$@"; ARTIFACTS="$2"; shift 2 ;;
    --state-dir) need "$@"; STATE_DIR="$2"; shift 2 ;;
    --list)      LIST=1; shift ;;
    -h|--help)   sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)           die "unknown argument: $1 (see --help)" ;;
  esac
done

[ -n "$RUNBOOK" ] || die "--runbook is required (there is no default: pick the runbook on purpose)"
case "$RUNBOOK" in
  */*) RUNBOOK_FILE="$RUNBOOK" ;;
  *)   RUNBOOK_FILE="$POLICIES/${RUNBOOK%.yaml}.yaml" ;;
esac
[ -f "$RUNBOOK_FILE" ] || die "no such runbook: $RUNBOOK_FILE"
NAME="$(basename "$RUNBOOK_FILE" .yaml)"

"$PYTHON" -c 'import yaml' 2>/dev/null \
  || die "$PYTHON cannot import yaml; install PyYAML (pip install -r requirements.txt) or set PYTHON"

# The YAML is read by one small Python helper so bash never parses YAML.
#   steps FILE        -> idx, rollback, break_glass, where, container, hosts, cmd, why
#                        (tab-separated; container is "-" when absent)
#   sha FILE          -> sha256 of the file
#   artifacts FILE D  -> sha, path for every vpscfg-push in FILE, found under D
helper() {
  "$PYTHON" - "$@" <<'PY'
import hashlib, os, sys
import yaml

ROLLBACK_MARK = "(rollback only"

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

def fail(msg):
    sys.stderr.write("walk.sh: %s\n" % msg)
    sys.exit(1)

def entries(path):
    with open(path, "rb") as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict) or doc.get("version") != 1:
        fail("%s is not a version 1 policy file" % path)
    runbooks = doc.get("runbooks") or []
    if not isinstance(runbooks, list) or not runbooks:
        fail("%s has no runbooks to walk" % path)
    out = []
    for i, r in enumerate(runbooks, 1):
        if not isinstance(r, dict):
            fail("%s step %d is not a mapping" % (path, i))
        hosts = r.get("hosts", r.get("host"))
        if isinstance(hosts, str):
            hosts = [hosts]
        if not hosts or not all(isinstance(h, str) and h.strip() for h in hosts):
            fail("%s step %d has no hosts" % (path, i))
        cmd, why = str(r.get("cmd") or ""), " ".join(str(r.get("why") or "").split())
        if not cmd.strip() or not why:
            fail("%s step %d needs cmd and why" % (path, i))
        if "\t" in cmd or "\n" in cmd:
            fail("%s step %d: cmd contains a tab or newline" % (path, i))
        rollback = r.get("rollback") is True or ROLLBACK_MARK in why.lower()
        container = str(r.get("container") or "-")
        if not all(c.isalnum() or c in ".-" for c in container):
            fail("%s step %d: bad container name %r" % (path, i, container))
        out.append((i, rollback, r.get("break_glass") is True,
                    r.get("where", "host"), container, ",".join(hosts), cmd, why))
    return out

mode = sys.argv[1]
if mode == "steps":
    for i, rb, bg, where, container, hosts, cmd, why in entries(sys.argv[2]):
        print("\t".join([str(i), str(int(rb)), str(int(bg)), where, container,
                         hosts, cmd, why]))
elif mode == "sha":
    print(sha(sys.argv[2]))
elif mode == "artifacts":
    wanted = {}
    for _, _, _, _, _, _, cmd, _ in entries(sys.argv[2]):
        words = cmd.split()
        if words[0] == "vpscfg-push":
            if len(words) != 3:
                fail("malformed push step: %s" % cmd)
            wanted[words[1]] = words[2]
    found = {}
    if wanted:
        for root, dirs, files in os.walk(sys.argv[3]):
            dirs.sort()
            for name in sorted(files):
                path = os.path.join(root, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                if name in wanted.values() and path not in found.values():
                    digest = sha(path)
                    if wanted.get(digest) == name and digest not in found:
                        found[digest] = path
    missing = sorted(set(wanted) - set(found))
    for digest in missing:
        sys.stderr.write("MISSING ARTIFACT: %s (sha256 %s) under %s\n"
                         % (wanted[digest], digest, sys.argv[3]))
    if missing:
        sys.exit(1)
    for digest, path in sorted(found.items()):
        print("%s\t%s" % (digest, os.path.abspath(path)))
else:
    fail("helper: unknown mode %r" % mode)
PY
}

STEPS="$(helper steps "$RUNBOOK_FILE")"
TOTAL="$(printf '%s\n' "$STEPS" | wc -l | tr -d ' ')"
RUNBOOK_SHA="$(helper sha "$RUNBOOK_FILE")"

if [ "$LIST" = 1 ]; then
  echo "$NAME  ($RUNBOOK_FILE)"
  echo "sha256 $RUNBOOK_SHA, $TOTAL step(s)"
  echo
  while IFS=$'\t' read -r n rb bg where container hosts cmd why <&3; do
    marks=""
    [ "$bg" = 1 ] && marks="$marks break-glass"
    [ "$rb" = 1 ] && marks="$marks ROLLBACK(skipped)"
    if [ "$where" = container ]; then
      if [ "$container" = - ]; then marks="$marks container(unnamed)"; else marks="$marks in:$container"; fi
    fi
    case "$cmd" in vpscfg-push\ *) marks="$marks push" ;; esac
    case "$why" in *"Stop if"*) marks="$marks stop-if" ;; esac
    printf '%3s  %-16s %-30s %s\n' "$n" "$hosts" "${marks# }" "$why"
  done 3<<<"$STEPS"
  exit 0
fi

# ---- everything below runs steps; --list never gets here --------------------

[ -n "$REASON" ] || die '--reason "why" is required: vpsexec journals it with every step'
for v in "$FROM" "$ONLY"; do
  case "$v" in ''|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;; *) die "step numbers are 1-$TOTAL, got '$v'" ;; esac
done
[ -z "$FROM" ] || [ -z "$ONLY" ] || die "--from and --only do not mix"
[ -z "$FROM" ] || [ "$FROM" -le "$TOTAL" ] || die "--from $FROM: $NAME has $TOTAL step(s)"
[ -z "$ONLY" ] || [ "$ONLY" -le "$TOTAL" ] || die "--only $ONLY: $NAME has $TOTAL step(s)"
[ -x "$VPSEXEC" ] || die "vpsexec not found or not executable: $VPSEXEC (use --vpsexec or VPSEXEC=)"
[ -z "$GRANT" ] || [ -f "$GRANT" ] || die "no such approval contract: $GRANT"

# A container step that does not name its container; refuse before anything runs.
CONTAINER_STEPS="$(printf '%s\n' "$STEPS" | awk -F'\t' '$4 == "container" && $5 == "-" {printf "%s ", $1}')"
[ -z "$CONTAINER_STEPS" ] \
  || die "step(s) ${CONTAINER_STEPS}are where: container with no container: key; add container: NAME to the runbook entry, or run them by hand with vpsexec ... --in NAME"

# Preflight: every pushed artifact must exist and hash to what the runbook names.
echo "== preflight: artifacts under $ARTIFACTS"
INDEX="$(helper artifacts "$RUNBOOK_FILE" "$ARTIFACTS")" || {
  echo "Nothing has run. Put the artifacts under --artifacts DIR (or rebuild them to the hashes the runbook names)." >&2
  exit 1
}
if [ -n "$INDEX" ]; then
  printf '%s\n' "$INDEX" | awk -F'\t' '{print "  ok  " $2}'
else
  echo "  (no vpscfg-push steps)"
fi
artifact() { printf '%s\n' "$INDEX" | awk -F'\t' -v h="$1" '$1 == h {print $2; exit}'; }

# Progress: one line per completed step. Re-running finished steps (a backup
# overwritten with already-new content, say) needs an explicit --from.
PROGRESS="$STATE_DIR/$NAME.progress"
if [ -z "$ONLY" ]; then
  (umask 077 && mkdir -p "$STATE_DIR")
  DONE=0
  [ -f "$PROGRESS" ] && DONE="$(grep -c . "$PROGRESS" || true)"
  if [ -z "$FROM" ]; then
    if [ "$DONE" -gt 0 ]; then
      echo "$NAME already has $DONE completed step(s); last: $(tail -n 1 "$PROGRESS")" >&2
      echo "Resume with --from <next step>, or --from 1 to re-run from the start on purpose." >&2
      exit 2
    fi
    FROM=1
  fi
fi

# Throw away keystrokes typed before our own prompt appears (an extra Enter
# during a long build) so they cannot become its answer. vpsexec does the same
# before its prompts. Best effort.
flush_input() {
  if [ -t 0 ]; then
    "$PYTHON" -c 'import sys, termios; termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)' 2>/dev/null || true
  fi
}

echo "== walking $NAME (sha256 ${RUNBOOK_SHA:0:12}), $TOTAL step(s)"
while IFS=$'\t' read -r n rb bg where container hosts cmd why <&3; do
  if [ -n "$ONLY" ]; then
    [ "$n" = "$ONLY" ] || continue
  else
    [ "$n" -lt "$FROM" ] && continue
    if [ "$rb" = 1 ]; then
      echo
      echo "-- skip step $n (rollback): $why"
      continue
    fi
  fi

  flags=(--run --reason "$REASON")
  [ "$where" = container ] && flags+=(--in "$container")
  if [ "$bg" = 1 ]; then
    flags+=(--break-glass)
    [ -z "$GRANT" ] || flags+=("--approval-contract=$GRANT")
  fi

  echo
  echo "== step $n/$TOTAL on $hosts: $why"
  case "$cmd" in
    vpscfg-push\ *)
      read -r _ sha _ <<<"$cmd"
      set -- "$hosts" push "$(artifact "$sha")" --sha256 "$sha" ;;
    *)
      set -- "$hosts" "$cmd" ;;
  esac
  if ! "$VPSEXEC" "$@" "${flags[@]}"; then
    echo >&2
    if [ -n "$ONLY" ]; then
      echo "Step $n failed or was refused." >&2
    else
      echo "Step $n failed or was refused. Fix the cause, then resume with --from $n." >&2
    fi
    exit 1
  fi

  if [ -n "$ONLY" ]; then
    echo
    echo "Ran step $n only. The progress record was not changed."
    exit 0
  fi
  printf '%s\t%s\t%s\n' "$n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${why%%:*}" >> "$PROGRESS"

  case "$why" in *"Stop if"*)
    flush_input
    ok=""
    read -r -p ">> Step $n says 'Stop if'. Check the output above. Continue? [y/N] " ok || true
    if [ "$ok" != y ]; then
      echo "Stopped after step $n. Resume with --from $((n + 1))."
      exit 1
    fi ;;
  esac
done 3<<<"$STEPS"

echo
echo "Done: $NAME walked to the end."
echo "When the change is finished, retire the runbook in a reviewed commit:"
echo "  git mv policies/$NAME.yaml policies/examples/superseded/"
