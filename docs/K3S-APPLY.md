# K3S-APPLY — deploying a k3s workload through the door

Until now the executor could only rsync files and run a build command. That
left every k3s service outside the door. `apply: {mode: k3s}` closes that gap with one deliberately
narrow mutation: **change the image of one declared container in one
declared Deployment**, to an image built from the contract's sources.

## Contract

```yaml
service: demo-web
host: edge1
scope_kind: pod                 # REQUIRED for k3s — graduated separately from containers
repo: /home/ops/src/demo
apply:
  mode: k3s
  namespace: demo               # kube-*, cert-manager and default are refused
  deployment: demo-web
  container: web                # container name inside the pod spec
  image: registry.example.com/demo/web   # repository only; NO tag, NO digest
  dockerfile: Dockerfile        # relpath in repo
  context: .                    # optional, default "."
  platform: linux/amd64         # optional, default linux/amd64
  rollout_timeout: 120s         # optional, default 120s, max 15m
sync:
  include: [Dockerfile, app/]   # the build inputs, bound into the image tag and plan hash
  never: []                     # still required (the schema's load-bearing-divergence rule)
verify:
  - http: { url: "https://demo.example.com/health", expect: 200 }
blast_radius: { volumes: [] }
```

There is no `deploy_dir`, and no free-form `build:`. A contract that has
either is refused.

**Build repo requirements.** The `repo` must be a git checkout with a
**clean working tree**: no modified and no untracked files. The image tag
binds the HEAD commit, which covers the whole tracked context including the
Dockerfile. On top of that it binds the include manifest (modes and bytes)
and the build parameters. A dirty tree still shows a plan, but preflight is
NO-GO and `--run` refuses, because the tag would not name what gets built.

**Single-node clusters only.** The image is side-loaded onto the contract's
host. A pod scheduled on another node would attempt a registry pull, which
401s on this fleet. Preflight is NO-GO unless the cluster has exactly one
node.

## What `deploy --run` does (under the host lock, every step journaled)

1. **Record the live image**, along with the pull policy and ready count, via
   one fixed `kubectl get deployment -o jsonpath`. This recorded image is the
   rollback target.
   - If `imagePullPolicy` is `Always`, the deploy refuses. The image is
     side-loaded because containerd pulls 401 on this fleet, so it must never
     be re-pulled.
   - If the live image already equals this build, the deploy refuses because
     there is nothing to do.
2. **Build locally:** `docker build --platform … -f <dockerfile> -t <image>:vpscfg-<16 hex> -- <context>`.
   The tag is content-addressed from the commit, the include manifest and the
   build parameters. The same commit and sources always give the same tag,
   and any change gives a new one. After the build, the sources are re-read.
   If anything changed while docker was reading them, the image is not
   imported.
   - This replaces `:latest`, which with `IfNotPresent` lets a service run
     a months-old image without anyone noticing.
3. **Save and import:** `docker save` writes to a private local tmpdir, and
   the file is streamed into `k3s ctr -n k8s.io images import -` over ssh
   stdin. No tarball lands on the host, and the local one is always deleted.
4. **Set the image:** `k3s kubectl -n <ns> set image deployment/<d> <container>=<ref>`.
   This is the only cluster mutation. There is no `kubectl apply`, no
   manifest, and no delete.
5. **Wait for the rollout:** `rollout status --timeout=<rollout_timeout>`.
6. **Verify:** run the contract's verify block.
7. **Confirm:** re-read the Deployment. The live image must be the new ref,
   and every replica must be ready. A deploy that does not confirm is never
   reported as successful.

**If anything fails:**
- **Build or import fails:** the running workload was never touched, and the
  lock is released.
- **Rollout or verify fails:** the recorded previous image is set back, and
  its rollout and verify are re-run.
  - If that restore is healthy, the lock is released. Healthy means the
    Deployment is re-read and runs the recorded image, every replica is
    ready, and verify passes. Setting the image back is an exact revert,
    unlike the archive overlay used in file mode. The deploy is still
    reported as FAILED.
  - If the restore is unhealthy or fails, the lock is **retained**; see
    RECOVERY.md.
- **The confirm step fails**, for example because `set image` "succeeded"
  but the cluster still runs another image: the lock is retained and success
  is never reported.

`rollback --run` for a k3s contract sets back the `previous_image` of the
**last completed door deploy** of that scope, as recorded in the executor
journal. It does this only when that deploy's image is what is live now.
It then waits for the rollout, verifies and confirms.

It deliberately does **not** use `kubectl rollout undo`, for two reasons.
After a failed deploy's set-back, the "previous revision" is the failed
image, so undo would bring it back. And undo reverts the whole pod template,
not just the image.

If no door deploy is journaled, or the live image changed since the last
one, the rollback target is unknown and rollback refuses. The fix is to
deploy a known-good commit.

**Preflight** (`deploy --preflight`) is k3s-aware:
- `sync_plan` becomes a live-state check: the Dockerfile exists, the live
  image, pull policy and ready count are shown, `Always` means NO-GO, more
  than one node means NO-GO, and an already-live build is a warning. A dirty
  build tree makes the `plan` check fail, so the verdict is NO-GO.
- `drift` is skipped, because there are no host files.
- `backup` reports that the rollback target is the recorded image. Declared
  `migrations:` are NO-GO, because this mode snapshots no data.
- `capacity` checks `/` and `/var/lib/rancher` (containerd's store) instead
  of a deploy_dir.
- The plan hash covers the image ref.

The single-use, 30-minute GO gate applies unchanged.

## What this mode does NOT do

- **Manifest changes** (env, resources, probes, replicas, new Deployments)
  are not deployed. They need their own reviewed path.
- **No data backup.** Volumes and PVCs are not snapshotted, which is why a
  contract with migrations is refused.
- **Git-ignored files are not bound.** They can still enter the build
  context. That is what `.dockerignore` is for.
- **The tag binds the sources, not the build output.** A non-reproducible
  Dockerfile (`apt-get` without pins, `:latest` base images) can build
  different bytes under the same tag.
- **The build context is the repo's to police.** Anything it includes, such
  as a `.env`, is baked into the image. Keep a `.dockerignore`.

## Stage 3 — graduating the first pod scope (the ritual)

STABILITY.md Stage 3 is "pod scope (k3s), test host first — one namespace at a
time". This mode is the prerequisite. The unlock itself is a human's reviewed
commit, made only after a real deploy and rollback have passed. It is never
made ahead of the evidence.

1. **Pick the candidate**, read-only, through the door:
   `vpsexec edge1 'k3s kubectl get deploy -A -o wide'`.

   Choose the most disposable Deployment that meets all of these:
   - 1 replica, in its own namespace, not public-critical
   - no PVC
   - `imagePullPolicy: IfNotPresent` (or `Never`)
   - built from a repo and Dockerfile we control

   Rule out anything serving a public product and anything in
   `cert-manager`, `kube-*` or `default`.
2. **Write its contract** from the template above. Read every field off the
   live object; never guess. Then run `vpscfg lint` and
   `vpscfg edge1 deploy <svc> --preflight`, which must give GO or
   GO-WITH-WARNINGS.
3. **Unlock commit (A):** add `"pod:edge1/<svc>"` to `scopes.unlocked` in
   `vpscfg-control.json`. In the same commit, update any test in your estate
   that pins the governor's unlocked scopes.
   One scope per commit, with the reason in the message.
4. **Rehearse:**
   1. `deploy --preflight`
   2. `deploy --run --reason "stage 3 pin test"` — the verify block must pass
   3. `rollback --run --reason "stage 3 rollback proof"` — verify must pass again
   4. `deploy --preflight` once more, so the journal shows a clean state
5. **Evidence commit (B):** append two entries to `scopes.tested`
   (`proof: deploy` and `proof: rollback`, `result: pass`), each citing its
   journal timestamps, in the same shape as the Stage 2 records.
6. **On any failure:** revert commit A. The journal shows exactly what ran.
