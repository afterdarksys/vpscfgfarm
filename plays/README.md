# plays/ — queued multi-step mutations for a human to run with `vpsrun`

The agent writes `plays/<name>.yaml`; the human runs `vpsrun plays/<name>.yaml`
in a real terminal, reads every step's plan, and types one phrase
(`PLAY:<n>:<tag>`, or `PLAY:<n>:BREAK-GLASS:<m>:<tag>`, where the tag is 6 hex of the plans shown). The agent then reads the outcome
with `vpsexec last -n <n>`. Plays are gitignored: they are one-off intent, not
policy. Authority still comes only from `policies/` and `overrides/`.

```yaml
version: 1
reason: "edge1 CNI lease leak: stop the crashlooping deployment"
steps:
  - hosts: edge1
    cmd: "k3s kubectl scale deployment shop-worker -n shop --replicas=0"
    flags: ["--override=overrides/edge1-crashloop-scaledown.yml"]
    why: "shop-worker: stale image, crashlooping"
```

Allowed step flags: `--override=`, `--in=`, `--in-match=`, `--verify=`,
`--break-glass`, `--canary[=N]`, `--timeout=`, `--require-blackout`. A read
step is never planned (plan mode would run it before approval): it runs at its
own position after the phrase, as a plain read with no `--run`, approval or
contract, may carry only `--in=`, `--in-match=` and `--timeout=`, and halts the
play if the door does not report it as tier read.

## Prechecks

`precheck: [k3s, firewall]` at the top of a play runs `vpscfg fleet k3s` /
`vpscfg fleet firewall` against every host the play touches, before anything
is planned. Any CRITICAL or HIGH finding refuses the whole play. Plays that
touch netfilter-persistent, reboot a host, or stop/disable k3s or Docker must
declare `precheck: [k3s]` (enforced by tests/test_vpsrun.py).
