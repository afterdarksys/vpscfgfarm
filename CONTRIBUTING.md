# Contributing to vpscfgfarm

Thank you for helping. This project is a door in front of production, so the
bar for a change is "does it keep every refusal", before "does it add the
feature". The rules below are how that bar is kept.

If you found a way past a door, do not open a pull request: report it
privately (see [SECURITY.md](SECURITY.md)).

## The thesis, which every change must keep

Don't run commands by hand in prod. Humans make mistakes, AI makes mistakes,
cats make mistakes, blind humans make mistakes — contract-based, verifiable
code protects all of them. **The checking lives in the door, not the
operator.**

## Working rules

1. **Refusal tests first.** A change that adds or touches a gate starts with
   the tests that prove what must be *refused*: the negative cases (tampered,
   expired, oversized, wrong key, wrong host, wrong container, one character
   off) before the happy path. Where you can, mutation-check them: remove the
   guard you added and show that a test fails.
2. **Never weaken the door for convenience.** If the door is in your way, the
   fix is a narrower, reviewed authorisation (a runbook, a read grammar, a
   posture change in the governor), never a bypass, a broader pattern, a new
   flag that skips a gate, or an environment variable. A change that makes a
   refusal go away must say, in its description, why that refusal was wrong.
3. **Fail closed.** Any doubt refuses: an unreadable file, an unparseable
   value, an unknown key, a probe that did not answer. "Unknown" is never
   "fine", and an unknown command is a mutation, not a read.
4. **Every verb shows its plan by default.** Execution is always an explicit
   `--run`. Reads need no approval; everything else does.
5. **Read-only against real hosts while you develop.** Tests are hermetic:
   transports are injected and no test dials a host. Try changes against
   `contrib/example-estate` or your own lab, never against systems you are not
   authorised to operate.
6. **No real infrastructure in the repository.** Examples and fixtures use
   fictional names and documentation-only addresses and domains: RFC 5737
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 2606
   (`example.com`, `example.net`, `.example`). Never commit a governor, an
   `estate.path`, a journal, credentials or real hostnames.

## Invariants with tests behind them

- **The deny-always floor exists in three copies**: `vpscfg-control.py`,
  `vpsexec` and `vpscfg/gates.py`. Each door validates independently, so each
  carries its own copy, and `FloorSyncTest` (in
  `tests/test_control_and_executor.py` and `tests/test_vpsexec.py`) fails the
  build if they ever differ. Change all three in the same commit. Entries may
  be added; removing one is not on the table.
- **A skipped test fails CI.** A suite that silently skips is worse than a red
  one: without PyYAML, for example, every policy test would skip and the build
  would go green. The only allowed skips are a fixed list of macOS-only tests
  on the Linux leg, and the macOS leg allows none. Do not add `skip`,
  `skipIf` or `.only`-style shortcuts to get a change through; make the test
  runnable instead.
- **Policies are tightening-only.** A policy file can name groups, add deny
  and risky patterns, list checks that must classify as reads, and authorise
  exact commands on exact hosts. It can never change a posture, widen the read
  allowlist or lift the floor. Unknown keys and duplicate keys refuse the whole
  load. Loosening lives in exactly two reviewed places: the governor and the
  Python read grammars. `.vpscfgfarm.map` files and `--override` files are
  untrusted input and never grant elevation.
- **Nothing reads the environment to locate the governor.** No environment
  variable, flag or search path may redirect the governor or the policies, and
  the doors run under a pinned interpreter with `-I`. Never change a door's
  shebang to `#!/usr/bin/env ...`; use `tools/pin-interpreter.sh`.
- **No operator string ever reaches the executor.** Contracted mutations take
  their commands from contract fields only; ad-hoc commands go through
  `vpsexec`, a separate door with its own gate stack.
- **Can't journal, can't mutate.** A change that adds a mutation also journals
  it, and refuses if the journal cannot be written.

## Changing what counts as a read

The read tier is a set of positive grammars in `vpscfg/readpolicy.py`: named
subcommands and flags only, never a head-word allow. Each new form needs a
positive test and the negative tests for its dangerous neighbours (the flag
that writes a file, the option that executes code, the bundled short flag).

**`ps` changes go through the procps oracle.** procps reparses the whole argv
as BSD syntax after a UNIX-style parse failure, so the only reliable way to
know whether a `ps` form prints process environments is to run it.
`tools/procps-oracle.sh` (opt-in, needs Docker, never touches a fleet host)
runs every form in `tests/data/procps_oracle/forms.txt` on two Debian images
with a canary in every process environment and records a verdict per form.
`tests/test_door_device_reads.py` pins those verdicts: every form that leaked
must be refused by the door, and every form the door reads must be clean on
both images. After changing the `ps` grammar, add your forms, re-run the
oracle and commit its outputs with the change.

## Security-relevant code

Code that touches authentication, secrets, tokens, TLS, SQL, randomness or the
gates carries a `Threats:` note in its module docstring (what it protects
against, and what it does not) and negative tests that show it rejects
tampered, expired, oversized or wrong-key input and fails closed. Follow the
existing modules for the shape.

## Running the tests

```sh
python3 -m pip install --require-hashes -r requirements.txt
python3 -m unittest discover -s tests
```

The suite needs `rsync` and `tar`. Some tests (interpreter isolation, ACLs)
exercise macOS-specific behaviour and run only there.

## Pull requests

- Keep a change to one concern, with its tests in the same commit.
- Say in the description which refusals the change touches and which tests
  prove they still hold.
- A change to a gate gets a reviewer who is not its author.

## License of contributions

vpscfgfarm is licensed under the Apache License, Version 2.0. Contributions
are accepted under the same license (inbound = outbound, as section 5 of the
license describes). There is **no CLA**. A `Signed-off-by` line
([Developer Certificate of Origin](https://developercertificate.org/)) is
welcome but optional.
