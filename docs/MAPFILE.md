# .vpscfgfarm.map — the per-directory baseline and leash

One YAML file, droppable into ANY directory (typically a project repo next
to its legacy `deploy.sh`). It does two jobs:

**Route.** With a `service:` line, the directory gains an identity:

    cd ~/src/shop
    vpscfg deploy            # host + service inferred; every gate unchanged
    vpscfg verify            # the contract's post-conditions
    vpscfg map               # show + validate what this directory resolves to

Routing is bound BOTH ways: the map names a contract, and that contract's
`repo:` must contain the map's directory. A map pasted into the wrong repo —
or a malicious one pointing your deploy at someone else's contract — refuses
instead of routing.

**Restrict.** `constraints:` tighten what the doors run when invoked from
this directory — vpsexec's whole gate stack (checks included, since checks
re-enter it) and vpscfg's deploy plans:

    version: 1
    service: shop-web
    deploy:
      entry: ./deploy.sh              # documentation of the legacy path
      host: web1.example.internal     # must match the contract, or refuse
    constraints:
      deny_extra: ["docker build"]    # absolute, like every deny
      risky_extra: ["systemctl restart"]
      max_tier: read                  # read | mutating; risky-as-cap refused
      hosts_allow: [edge1]            # whole run refuses if ANY host is outside
      forbid_flags: ["--force", "-f"] # bundled shorts (-sfo) are expanded
      require_blackout: true
      forbid_break_glass: true

## The one rule

A map is UNTRUSTED input — it lives in repos outside this one's review. It
may route and restrict, and can never grant:

- No key in the schema loosens anything.
- Unknown keys refuse the whole file (a typo'd constraint that silently
  does nothing is a hole, not a convenience).
- Grant-shaped keys (`break_glass`, `posture`, `scopes`, ...) anywhere at
  any nesting refuse the whole file.
- A map that exists but fails validation REFUSES the run — a broken leash
  never degrades to no leash.
- Discovery is nearest-wins walking up from CWD; maps do not merge.

## What it does not do

A map constrains a PLACE, not a person: `cd` elsewhere and the leash is
elsewhere's. Fleet-wide law lives in `policies/` and the compiled-in floor,
exactly as before — a map can only add to them. `vpsexec check` inherits
map constraints; the vpscfg-control.py door does not read maps (its
commands come from contracts alone).

The examples on this page are complete maps. Loader and tests:
`vpscfg/mapfile.py`, `tests/test_mapfile.py`.

## Operator-local and gitignored

The map is **operator-local config, not part of the app**, so it is **gitignored**,
never committed to the site repo. Ignore it once, fleet-wide, in the global
excludes file rather than per-repo:

    git config --global core.excludesfile ~/.gitignore_global
    echo '.vpscfgfarm.map' >> ~/.gitignore_global

A natural rollout is one map per deployable repository on the fleet (a git repo
with its own `deploy.sh`), starting constraints-only and gaining a `service:` line
when its contract is promoted.

### Service-less maps (the common rollout case)

`service:` is optional. A repo whose vpscfgfarm contract is not promoted yet drops
a **constraints-only** map — it routes nothing but still documents the deploy
`entry`/`host` and applies the leash:

    version: 1
    deploy:
      entry: ./deploy.sh          # the repository deploy script vpscfgfarm drives
      host: db1                    # informational until a contract binds it
    constraints:
      hosts_allow: [db1]           # a command from here touches ONLY this host
      forbid_flags: ["--force", "-f"]

Add the `service:` line when the contract is promoted; routing then binds both ways
(the contract's `repo:` must contain the map's directory) and `vpscfg deploy`/
`verify` work from the repo.

### Driving the repository deploy script

The map names the repo's own `deploy.sh` as `deploy.entry`. Where a repo had no
ansible, a uniform `ansible/deploy.yml` was added that runs that same `deploy.sh`,
so `vpscfg <host> ansible ansible/deploy.yml --run` drives the deploy through the
gated door. The playbook passes no arguments by default; confirm each repo's
`deploy.sh` argument convention (some take a subcommand like `all`, some a tag)
before relying on it — uniform automation over non-uniform deploy scripts is the
trap this whole system exists to prevent.
