# Security policy

vpscfgfarm is a door in front of production. Its whole value is that it
refuses, so a way past a refusal is the most serious kind of bug it can have.
Please report it privately first.

## How to report

Use GitHub's **private vulnerability reporting** on this repository: the
**Security** tab, then **Report a vulnerability**. The report is visible only
to the maintainers until an advisory is published.

Please do not open a public issue or pull request for a bypass, and do not
post a working bypass anywhere public until a fix is released.

A useful report includes:

- the commit you tested;
- the exact command line (or files: governor, policy, contract, map file,
  override) that gets past the door, made minimal if you can;
- what the door should have done (refuse, require approval, mask) and what it
  did instead;
- ideally, a failing test in the style of `tests/` that demonstrates it.

Please test against `contrib/example-estate` or your own lab hosts only, never
against systems you are not authorised to operate.

## What counts as a bypass

Anything that lets a door do what its governor, its floor or a host's posture
says it must not. In particular:

- **A mutation without the governor**: any path that changes a host while the
  governor is missing, invalid, in `lockdown`, has `mutation_enabled: false`,
  or has not released the scope.
- **Reaching the deny-always floor**: any spelling, quoting, encoding,
  wrapper, container placement or file (policy, runbook, override, map,
  contract, play) that gets a floor command, or a policy's `deny_extra`
  pattern, executed.
- **Getting past a posture**: mutating a `frozen` or `lockdown` host without
  `--break-glass` and a committed runbook naming that exact command for that
  host; elevation granted by an ad-hoc `--override` file; a host alias that
  launders a posture.
- **Misclassification**: a command that changes state, or can run arbitrary
  code, being classified as a read (and so running without `--run`, a reason
  or approval).
- **Reads the door should refuse**: reading a secret it is meant to refuse,
  such as a credential path listed in `deny_extra`, a raw device, process
  memory or environment, or secret values that reach the terminal, the
  journal or telemetry unmasked.
- **Approval forgery or replay**: a plan hash, approval contract (grant),
  break-glass phrase or queued play that authorises something other than what
  was shown, or that can be used twice, after expiry, or without a terminal.
- **Choosing the governor**: any environment variable, flag, search path,
  interpreter trick or pointer-file trick that makes a door obey a governor or
  policy directory other than the configured one, or that forges the token
  between the outer and inner door.
- **Journal evasion**: a mutation that runs without being journaled, or a
  journal edit that `vpscfg journal verify` does not detect within its
  documented limits.

## What is not a bypass

- Running commands on a host with raw ssh, outside the doors. The doors
  cannot stop that; `vpscfg fleet changes` is there to notice it.
- Anything that requires already being able to edit the doors, the package,
  the governor or committed policy: that is a reviewed change, which is the
  point.
- Starting a door as `python3 vpsexec` (rather than by path) with a hostile
  interpreter startup hook. This form is documented as unprotectable; harnesses
  must deny it. A bypass of a door started by path is in scope.
- The limits each module documents in its `Threats:` note. A way around a
  documented limit that the note claims is covered is in scope.

## Supported versions

Only the latest commit on the default branch is supported. Fixes are made
there.
