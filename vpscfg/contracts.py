"""Contract loading and validation. Contracts are the desired state, in git."""
import json
import re

try:
    import yaml
    _HAVE_YAML = True
except ImportError:  # contracts may also be .json; yaml preferred
    _HAVE_YAML = False

from . import estate
from .gates import Refused

CONTRACT_DIR = estate.root() / "contracts"
REQUIRED = ("service", "host", "deploy_dir", "sync", "verify")
# A verify-only contract (monitor_only: true) is watched by the convergence
# sweep but has no apply path — the executor refuses to deploy it (see
# cli._deploy). It ships nothing, so it needs no deploy_dir or sync lists.
MONITOR_REQUIRED = ("service", "host", "verify")


def load(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
        raise Refused('invalid contract name')
    for ext, loader in (
        (".yaml", _load_yaml), (".yml", _load_yaml), (".json", _load_json)
    ):
        path = CONTRACT_DIR / (name + ext)
        if path.exists():
            contract = loader(path)
            _validate(contract, path)
            return contract
    raise Refused("no contract named %r in %s — mutations require a contract" % (name, CONTRACT_DIR))


def _load_yaml(path):
    if not _HAVE_YAML:
        raise Refused("contract %s is YAML but PyYAML is unavailable — failing closed" % path)
    with open(path) as f:
        return yaml.safe_load(f)


def _load_json(path):
    with open(path) as f:
        return json.load(f)


def _validate(contract, path):
    if not isinstance(contract, dict):
        raise Refused("contract %s is not a mapping" % path)
    for field in ('service', 'host'):
        if not isinstance(contract.get(field), str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,253}', contract[field]):
            raise Refused('contract %s has invalid %s' % (path, field))
    for field in ('freeze', 'monitor_only'):
        if field in contract and not isinstance(contract[field], bool):
            raise Refused('contract %s must be boolean' % field)
    from .verify import validate_checks
    validate_checks(contract)
    # Optional blocks. Absent is a no-op so existing contracts still load.
    # Present and wrong is a refusal. A contract can tighten a watch ceiling;
    # it cannot loosen the fleet maximum.
    from .authority import validate as validate_authority
    from .imagepin import validate as validate_image_policy
    from .healthdur import validate_watch
    from .pgtopology import validate as validate_postgres
    validate_authority(contract)
    validate_image_policy(contract)
    validate_watch(contract)
    validate_postgres(contract)
    from .preflight import validate_contract_block
    validate_contract_block(contract)
    from .k3sapply import is_k3s, validate as validate_apply
    validate_apply(contract)
    if contract.get("monitor_only") is True:
        missing = [k for k in MONITOR_REQUIRED if k not in contract]
        if missing:
            raise Refused("monitor_only contract %s missing required keys: %r"
                          % (path, missing))
        return
    # A k3s contract ships an image, not files into a directory: its sync
    # lists are the build inputs (bound into the image tag) and it has no
    # deploy_dir. Everything else is required exactly as before.
    required = [k for k in REQUIRED if not (k == "deploy_dir" and is_k3s(contract))]
    missing = [k for k in required if k not in contract]
    if missing:
        raise Refused("contract %s missing required keys: %r" % (path, missing))
    sync = contract["sync"]
    if not isinstance(sync, dict) or not isinstance(sync.get('include'), list) or not isinstance(sync.get('never'), list):
        raise Refused(
            "contract %s has no sync.never list — the load-bearing divergences "
            "must be declared, not remembered" % path
        )
    from .drift import validate_relpath
    from .syncplan import normalize_includes, protected_path
    if 'deploy_dir' in contract or not is_k3s(contract):
        directory = contract['deploy_dir']
        if not isinstance(directory, str) or not directory.startswith('/') or directory == '/':
            raise Refused('contract deploy_dir must be an absolute service directory')
        validate_relpath(directory.lstrip('/').rstrip('/'))
    for protected in sync['never']:
        if not isinstance(protected, str):
            raise Refused('sync.never entries must be paths')
        protected_path(protected)
    normalize_includes(sync['include'])
    if contract.get('build') is not None and not isinstance(contract['build'], str):
        raise Refused('build must be a command string')
    pre = contract.get('pre', [])
    if not isinstance(pre, list) or any(not isinstance(step, dict) or ('backup' in step and not isinstance(step['backup'], str)) for step in pre):
        raise Refused('pre must be a list of steps with command strings')
