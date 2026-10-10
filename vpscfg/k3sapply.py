"""k3s apply mode — pure helpers: schema, image identity, fixed commands.

A contract opts in with an `apply:` block:

    apply:
      mode: k3s
      namespace: storage              # k8s names only; kube-* / cert-manager refused
      deployment: storage-api
      container: api                  # the container in the pod spec whose image changes
      image: registry.example.com/storage/api   # repository, NO tag
      dockerfile: api/Dockerfile      # relpath in repo
      context: .                      # relpath in repo (default ".")
      platform: linux/amd64           # default; the fleet is amd64
      rollout_timeout: 120s           # default 120s, max 15m

The executor (the only module that mutates) runs, under the host lock:
record the live image -> docker build (local) -> docker save (local tmpdir)
-> stream into `k3s ctr -n k8s.io images import -` over ssh stdin ->
`k3s kubectl set image` on ONE declared deployment/container -> rollout
status -> verify -> confirm the live image. Verify failure sets the recorded
previous image back and waits for its rollout.

Threats:
  - Protects against: the stale-`:latest` failure mode — `:latest` with
    IfNotPresent silently running a stale image (tags here are content-
    addressed from the source manifest, so a new source is a new tag and an
    old tag is the old source); broad cluster mutation (no `kubectl apply`,
    no manifests, no delete: exactly one `set image` on one declared
    deployment/container, plus its inverse); scope laundering (a k3s
    contract must be scope_kind `pod`, so a container-scope unlock cannot
    release it); touching the cluster's own machinery (kube-*, cert-manager
    and default are refused at contract load, per STABILITY.md);
    a registry pull silently 401ing (imagePullPolicy Always is refused —
    the image is side-loaded, so it must never be re-pulled).
  - Does NOT protect against: manifest changes (env, resources, probes) —
    those are not deployed by this mode and need their own reviewed path;
    secrets baked into an image by a permissive build context (a
    .dockerignore is the repo's job); a Dockerfile that is not reproducible
    (the tag binds the sources, not the build output); a rollout that
    passes readiness but is semantically broken (that is verify's job).
"""
import hashlib
import json
import re
import shlex
import subprocess

from . import drift, secretmask
from .gates import Refused

K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
IMAGE_REPO_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)+$")
PLATFORMS = frozenset(["linux/amd64", "linux/arm64"])
FROZEN_NAMESPACES = frozenset(["kube-system", "kube-public", "kube-node-lease",
                               "cert-manager", "default"])
KEYS = frozenset(["mode", "namespace", "deployment", "container", "image",
                  "dockerfile", "context", "platform", "rollout_timeout"])
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 900
TAG_PREFIX = "vpscfg-"


def is_k3s(contract):
    return isinstance(contract.get("apply"), dict) and contract["apply"].get("mode") == "k3s"


def timeout_seconds(value):
    if value is None:
        return DEFAULT_TIMEOUT
    m = re.fullmatch(r"([0-9]+)(s|m)?", str(value))
    if not m:
        raise Refused("apply.rollout_timeout must look like 120s or 5m")
    seconds = int(m.group(1)) * (60 if m.group(2) == "m" else 1)
    if not 1 <= seconds <= MAX_TIMEOUT:
        raise Refused("apply.rollout_timeout must be between 1s and %ds" % MAX_TIMEOUT)
    return seconds


def validate(contract):
    """Contract-load validation. Refuses the whole contract on any doubt."""
    ap = contract.get("apply")
    if ap is None:
        return
    if not isinstance(ap, dict) or ap.get("mode") != "k3s":
        raise Refused("apply.mode must be 'k3s' (the only non-default apply mode)")
    unknown = sorted(set(ap) - KEYS)
    if unknown:
        raise Refused("apply has unknown keys %r" % unknown)
    for field in ("namespace", "deployment", "container"):
        if not isinstance(ap.get(field), str) or not K8S_NAME_RE.fullmatch(ap[field]):
            raise Refused("apply.%s must be a Kubernetes name" % field)
    if ap["namespace"] in FROZEN_NAMESPACES:
        raise Refused("namespace %r is frozen forever (STABILITY.md) — no apply mode "
                      "reaches it" % ap["namespace"])
    image = ap.get("image")
    if not isinstance(image, str) or not IMAGE_REPO_RE.fullmatch(image):
        raise Refused("apply.image must be a repository without tag or digest "
                      "(the tag is derived from the sources)")
    if not isinstance(ap.get("dockerfile"), str):
        raise Refused("apply.dockerfile must be a relpath in the repo")
    drift.validate_relpath(ap["dockerfile"])
    context = ap.get("context", ".")
    if not isinstance(context, str):
        raise Refused("apply.context must be a relpath in the repo")
    if context != ".":
        drift.validate_relpath(context)
    if ap.get("platform", "linux/amd64") not in PLATFORMS:
        raise Refused("apply.platform must be one of %s" % ", ".join(sorted(PLATFORMS)))
    timeout_seconds(ap.get("rollout_timeout"))
    if contract.get("scope_kind") != "pod":
        raise Refused("a k3s apply contract must declare scope_kind: pod — the "
                      "governor graduates pod scopes separately from containers")
    if not contract.get("repo"):
        raise Refused("a k3s apply contract needs repo (the build source)")
    if contract.get("build") is not None:
        raise Refused("k3s mode builds from apply.dockerfile — a free-form build "
                      "command is refused")


def git_state(repo, runner=None):
    """(HEAD commit, dirty paths) of the build repo. The whole context is
    bound through the commit, so the working tree must be clean: a modified
    or untracked file would be built but not named by the tag."""
    def default(argv):
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout, r.stderr
    run = runner or default
    rc, head, err = run(["git", "-C", repo, "rev-parse", "HEAD"])
    if rc != 0 or not re.fullmatch(r"[0-9a-f]{40,64}", head.strip()):
        raise Refused("k3s build repo %s is not a git checkout with a commit (%s)"
                      % (repo, (err or head).strip()[:120]))
    rc, status, err = run(["git", "-C", repo, "status", "--porcelain", "--untracked-files=all"])
    if rc != 0:
        raise Refused("cannot read git status of %s: %s" % (repo, err.strip()[:120]))
    return head.strip(), [l[3:] for l in status.splitlines() if l.strip()]


def source_digest(contract, manifest, commit):
    """sha256 over everything the build reads: the commit (the whole tracked
    context, Dockerfile included), the include manifest (modes + bytes), and
    the build parameters."""
    ap = contract["apply"]
    raw = json.dumps({"commit": commit, "manifest": manifest,
                      "build": [ap["dockerfile"], ap.get("context", "."),
                                ap.get("platform", "linux/amd64")]},
                     sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def image_ref(contract, manifest, git_runner=None, require_clean=True):
    """Content-addressed image reference: same commit + sources, same tag.
    Refuses a dirty tree (require_clean) — the plan would not name what
    gets built."""
    commit, dirty = git_state(contract["repo"], runner=git_runner)
    if dirty and require_clean:
        raise Refused("k3s build repo has uncommitted/untracked files (%s) — commit them; "
                      "the image tag binds the commit" % ", ".join(dirty[:5]))
    return "%s:%s%s" % (contract["apply"]["image"], TAG_PREFIX,
                        source_digest(contract, manifest, commit)[:16])


def _kubectl(ap, *args):
    return " ".join(["k3s", "kubectl", "-n", shlex.quote(ap["namespace"])] +
                    [shlex.quote(a) for a in args])


def read_state_cmd(contract):
    """Fixed read: the declared container's image and pull policy, plus the
    deployment's desired/ready replica counts, as one tab-separated line."""
    ap = contract["apply"]
    c = ap["container"]
    tpl = ('{range .spec.template.spec.containers[?(@.name=="%s")]}{.image}{"\\t"}'
           '{.imagePullPolicy}{end}{"\\t"}{.spec.replicas}{"\\t"}{.status.readyReplicas}' % c)
    return _kubectl(ap, "get", "deployment", ap["deployment"], "-o", "jsonpath=" + tpl)


def parse_state(out):
    """-> {"image", "pull_policy", "replicas", "ready"}; raises on anything
    that is not exactly the shape the fixed read produces."""
    parts = out.strip("\n").split("\t")
    if len(parts) != 4 or not parts[0]:
        raise Refused("deployment/container not found or unreadable: %r" % secretmask.mask(out)[:120])
    image, policy, replicas, ready = parts
    if policy not in ("IfNotPresent", "Never", "Always"):
        raise Refused("unexpected imagePullPolicy %r — refusing to guess" % secretmask.mask(policy)[:120])
    try:
        return {"image": image, "pull_policy": policy or "IfNotPresent",
                "replicas": int(replicas or 0), "ready": int(ready or 0)}
    except ValueError:
        raise Refused("unparseable deployment state: %r" % secretmask.mask(out)[:120])


NODES_CMD = "k3s kubectl get nodes --no-headers -o name"


def build_argv(contract, ref):
    ap = contract["apply"]
    repo = contract["repo"].rstrip("/")
    context = repo if ap.get("context", ".") == "." else "%s/%s" % (repo, ap["context"])
    return ["docker", "build", "--platform", ap.get("platform", "linux/amd64"),
            "-f", "%s/%s" % (repo, ap["dockerfile"]), "-t", ref, "--", context]


def save_argv(ref, tar_path):
    return ["docker", "save", "-o", tar_path, "--", ref]


IMPORT_CMD = "k3s ctr -n k8s.io images import -"


def set_image_cmd(contract, ref):
    ap = contract["apply"]
    return _kubectl(ap, "set", "image", "deployment/" + ap["deployment"],
                    "%s=%s" % (ap["container"], ref))


def rollout_status_cmd(contract):
    ap = contract["apply"]
    return _kubectl(ap, "rollout", "status", "deployment/" + ap["deployment"],
                    "--timeout=%ds" % timeout_seconds(ap.get("rollout_timeout")))


def planned(contract, ref):
    """Human-readable plan, every entry deny-scannable text."""
    return [" ".join(build_argv(contract, ref)),
            "docker save %s | ssh %s %s" % (ref, contract["host"], IMPORT_CMD),
            set_image_cmd(contract, ref),
            rollout_status_cmd(contract)]
