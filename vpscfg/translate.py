"""Draft-only compose and Deployment translator.

Read-only. `vpscfg fleet translate` prints one workload draft and stops.
It does not apply, write a contract, or open a network connection.

Threats:
  - Protects against: treating a draft as an executable contract; copying
    environment values, commands, or arguments into the draft; host
    networking, privileged mode, volumes, secrets, and privilege expansion
    becoming a silent mapping; a frozen namespace; an image tag or digest
    being treated as the k3s apply repository; `--run` or `--output` on
    this read.
  - Does NOT protect against: a human later applying a reviewed manifest
    by another path; copying data between volume stores; multi-node
    scheduling that is not visible in the file. `nodes_observed` stays null
    and apply preflight still refuses more than one node.
"""

import json
import os
from pathlib import Path
import re

from .gates import Refused
from .k3sapply import FROZEN_NAMESPACES, IMAGE_REPO_RE, K8S_NAME_RE

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 64
# Counts nodes as visited, so YAML aliases that fan out are charged per use.
MAX_NODES = 100000
SELECTOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
IMAGE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
SECRET_NAME_RE = re.compile(r"password|secret|token|credential|private|api_key|apikey", re.I)
LIMITS = {
    "single_node": "required-at-apply",
    "nodes_observed": None,
    "data_copy": "separate-reviewed-step",
    "teardown": "compose down without -v",
}
VOLUME_KEYS = frozenset(("volumes", "volumeMounts", "mounts", "tmpfs"))
SECRET_KEYS = frozenset(("secrets", "env_file", "configs", "envFrom", "secretKeyRef"))
PRIVILEGE_KEYS = frozenset((
    "cap_add", "cap_drop", "devices", "security_opt", "sysctls", "userns_mode",
    "device_cgroup_rules",
))
MULTI_NODE_KEYS = frozenset(("placement", "topologySpreadConstraints", "podAntiAffinity"))


class InputError(Refused):
    """The file or the argv cannot be drafted. Callers exit 2."""


def _add(items, text):
    if text not in items:
        items.append(text)


def _pairs(value, sink):
    if isinstance(value, dict):
        for key, item in value.items():
            sink.append((key, item))
            _pairs(item, sink)
    elif isinstance(value, list):
        for item in value:
            _pairs(item, sink)


def _relative(value):
    if not isinstance(value, str) or not value or os.path.isabs(value) or value.startswith("-"):
        return False
    return all(part not in ("", "..") for part in value.split("/"))


def _image_repository(image, refused, unmapped):
    if not isinstance(image, str) or ".." in image or not IMAGE_TOKEN_RE.fullmatch(image):
        _add(refused, "invalid image reference")
        return None
    if "@" in image:
        _add(refused, "image digest is not a k3s apply repository")
        return None
    name = image.rsplit("/", 1)[-1]
    repo, _, tag = name.rpartition(":")
    if tag and repo:
        repository = image[: -(len(tag) + 1)]
        _add(unmapped, "tag stripped; k3s apply derives the tag")
    else:
        repository = image
    if not IMAGE_REPO_RE.fullmatch(repository):
        _add(refused, "image repository is not a registry path without a tag")
        return None
    return repository


def _env_names(value):
    names = []
    if isinstance(value, dict):
        names.extend(key for key in value if isinstance(key, str))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                names.append(item.split("=", 1)[0])
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
    return names


def _secret_env(names, refused):
    for name in names:
        if SECRET_NAME_RE.search(name):
            _add(refused, "secret-like environment name")
            return


def _scan(value, refused, unmapped):
    pairs = []
    _pairs(value, pairs)
    for key, item in pairs:
        if key in VOLUME_KEYS:
            _add(refused, "volumes are a separate reviewed step")
        elif key in SECRET_KEYS:
            _add(refused, "secrets are not copied")
        elif key in PRIVILEGE_KEYS:
            _add(refused, "privilege expansion is not copied")
        elif key in MULTI_NODE_KEYS:
            _add(refused, "multi-node scheduling is not drafted")
        elif key == "privileged" and item is not False:
            _add(refused, "privileged mode is not copied")
        elif key == "network_mode" and isinstance(item, str) and (
                item in ("host", "hostnet") or item.startswith("container:")):
            _add(refused, "host networking is not copied")
        elif key in ("pid", "ipc") and item == "host":
            _add(refused, "host networking is not copied")
        elif key in ("hostNetwork", "hostPID", "hostIPC") and item is True:
            _add(refused, "host networking is not copied")
        elif key == "imagePullPolicy" and isinstance(item, str) and item.lower() == "always":
            _add(refused, "imagePullPolicy Always is refused")
        elif key == "imagePullPolicy":
            _add(unmapped, "imagePullPolicy not copied")
        elif key == "deploy":
            _add(unmapped, "swarm deploy is not mapped")
        elif key in ("command", "args", "entrypoint"):
            _add(unmapped, "command not copied")
        elif key in ("environment", "env"):
            _add(unmapped, "environment not copied")
            _secret_env(_env_names(item), refused)
        elif key in ("livenessProbe", "readinessProbe", "startupProbe", "healthcheck"):
            _add(unmapped, "probes not copied")
        elif key in ("replicas",):
            _add(unmapped, "replicas not copied")
        elif key == "ports":
            _add(unmapped, "ports not copied")


def _build_paths(service, refused, unmapped):
    build = service.get("build")
    if build is None:
        return None, None
    if isinstance(build, str):
        context, dockerfile = build, None
    elif isinstance(build, dict):
        context = build.get("context", ".")
        dockerfile = build.get("dockerfile")
    else:
        _add(refused, "build path must be relative")
        return None, None
    if not _relative(context) or (dockerfile is not None and not _relative(dockerfile)):
        _add(refused, "build path must be relative")
        return None, None
    _add(unmapped, "build context is recorded and not applied")
    return context, dockerfile


def _draft(direction, source_name, filename, workload, refused, unmapped):
    return {
        "schema_version": 1,
        "kind": "workload-draft",
        "direction": direction,
        "executable": False,
        "applied": False,
        "blocked": bool(refused),
        "source": {"name": source_name, "file": filename},
        "workload": workload,
        "not_a_contract": ["host", "repo", "verify", "scope_kind"],
        "refused": refused,
        "unmapped": unmapped,
        "limits": dict(LIMITS),
    }


def compose_to_k3s(doc, service_name, filename):
    refused, unmapped = [], []
    _add(unmapped, "namespace not declared; apply requires a non-frozen namespace")
    _add(unmapped, "nodes unknown")
    workload = {"kind": "Deployment", "name": None, "namespace": None,
                "container": None, "image_repository": None, "dockerfile": None, "context": None}
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict) or not doc["services"]:
        _add(refused, "compose file needs a services mapping")
        return _draft("compose-to-k3s", service_name, filename, workload, refused, unmapped)
    matched = next((key for key in ("secrets", "configs", "volumes") if key in doc), None)
    if matched == "volumes":
        _add(refused, "volumes are a separate reviewed step")
    elif matched is not None:
        _add(refused, "secrets are not copied")
    services = doc["services"]
    service = services.get(service_name)
    if not isinstance(service, dict):
        _add(refused, "named service was not found")
        return _draft("compose-to-k3s", service_name, filename, workload, refused, unmapped)
    if not K8S_NAME_RE.fullmatch(service_name):
        _add(refused, "service name is not a Kubernetes name")
    else:
        workload["name"] = service_name
        workload["container"] = service_name
    _scan(service, refused, unmapped)
    context, dockerfile = _build_paths(service, refused, unmapped)
    workload["context"] = context
    workload["dockerfile"] = dockerfile
    if "image" in service:
        workload["image_repository"] = _image_repository(service.get("image"), refused, unmapped)
    else:
        _add(refused, "image repository is not declared")
    return _draft("compose-to-k3s", service_name, filename, workload, refused, unmapped)


def k3s_to_compose(doc, container_name, filename):
    refused, unmapped = [], []
    _add(unmapped, "nodes unknown")
    workload = {"compose_service": None, "image_repository": None, "namespace": None}
    if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
        _add(refused, "kind must be Deployment")
        return _draft("k3s-to-compose", container_name, filename, workload, refused, unmapped)
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    namespace = metadata.get("namespace")
    if namespace is not None:
        if not isinstance(namespace, str) or not K8S_NAME_RE.fullmatch(namespace):
            _add(refused, "namespace is not a Kubernetes name")
        elif namespace in FROZEN_NAMESPACES:
            _add(refused, "namespace is frozen")
        else:
            workload["namespace"] = namespace
            _add(unmapped, "namespace is not represented in compose")
    _scan(doc, refused, unmapped)
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    pod = template.get("spec") if isinstance(template.get("spec"), dict) else {}
    containers = pod.get("containers") if isinstance(pod.get("containers"), list) else []
    matched = [item for item in containers if isinstance(item, dict) and item.get("name") == container_name]
    if len(matched) != 1:
        _add(refused, "name exactly one container" if len(containers) > 1 else "named container was not found")
        return _draft("k3s-to-compose", container_name, filename, workload, refused, unmapped)
    if not K8S_NAME_RE.fullmatch(container_name):
        _add(refused, "container name is not a Kubernetes name")
    else:
        workload["compose_service"] = container_name
    container = matched[0]
    if "image" in container:
        workload["image_repository"] = _image_repository(container.get("image"), refused, unmapped)
    else:
        _add(refused, "image repository is not declared")
    return _draft("k3s-to-compose", container_name, filename, workload, refused, unmapped)


def _bounded(value):
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise InputError("input has too many nodes")
        if isinstance(item, dict):
            children = list(item.values())
        elif isinstance(item, list):
            children = item
        else:
            continue
        if depth >= MAX_DEPTH and children:
            raise InputError("input is nested too deeply")
        stack.extend((child, depth + 1) for child in children)
    return value


def load_document(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise InputError("input must be a regular file")
    try:
        data = path.read_bytes()
    except OSError:
        raise InputError("input must be a regular file")
    if len(data) > MAX_BYTES:
        raise InputError("input exceeds 1 MiB")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise InputError("input is not utf-8")
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(text)
        except RecursionError:
            raise InputError("input is nested too deeply")
        except ValueError:
            raise InputError("input is not json")
        if not isinstance(value, (dict, list)):
            raise InputError("input is not json")
        return _bounded(value)
    try:
        import yaml
    except ImportError:
        raise InputError("PyYAML is required to read yaml")
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception:
        raise InputError("yaml document refused")
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise InputError("expected one document")
    return _bounded(docs[0])


def _fail(reason):
    print(json.dumps({
        "schema_version": 1, "kind": "workload-draft", "executable": False, "applied": False,
        "blocked": True, "refused": [reason], "unmapped": [], "limits": LIMITS,
    }, sort_keys=True))
    return 2


def cli(argv):
    argv = list(argv)
    if any(item == "--run" or item.startswith("--run=") or item == "--output" or item.startswith("--output=")
           for item in argv):
        return _fail("run and output are not accepted")
    if len(argv) < 2 or argv[0] not in ("compose-to-k3s", "k3s-to-compose"):
        return _fail("direction must be compose-to-k3s or k3s-to-compose")
    direction, path, rest = argv[0], argv[1], argv[2:]
    flag = "--service" if direction == "compose-to-k3s" else "--container"
    name = None
    index = 0
    while index < len(rest):
        if rest[index] == flag and index + 1 < len(rest) and name is None:
            name = rest[index + 1]
            index += 2
            continue
        return _fail("unsupported translate argument")
    if not isinstance(name, str):
        return _fail("name the service or container")
    if not SELECTOR_RE.fullmatch(name):
        return _fail("invalid workload name")
    try:
        document = load_document(path)
    except InputError as exc:
        return _fail(str(exc))
    if direction == "compose-to-k3s":
        draft = compose_to_k3s(document, name, Path(path).name)
    else:
        draft = k3s_to_compose(document, name, Path(path).name)
    print(json.dumps(draft, sort_keys=True))
    return 1 if draft["refused"] else 0
