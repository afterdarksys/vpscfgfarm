"""Typed actions: a closed vocabulary of declarative steps, expanded by door code
into a canonical gated string plus an exact, shown, hashed body, done-check and
post-condition. docs/ACTIONS.md is the contract; this package is its code.

    base.py    Action, Param, Expansion, SqlCheck, TokenCheck, sq(), register()
    types.py   the closed parameter types
    expand.py  validate(), expand(), the reserved canonical spelling, the
               `expands:` digest and its lint result
    <kind>.py  the actions themselves (container.py: wait_healthy), each
               imported here automatically

Importing this package registers every built-in action.
"""

from .base import (DONE, NEEDED, REGISTRY, TOKEN_SCRIPTS, TOKENS, Action,  # noqa: F401
                   Expansion, Param, SqlCheck, TokenCheck, plain_token, probe_text,
                   register, register_token_script, sha256_text, sq)
from .expand import (ACTION_CANONICAL, canonical, check_declared, deny_check,  # noqa: F401
                     digest_items, expand, expands_digest, expands_line, expands_mismatch,
                     get, is_reserved, lint_expands, parse_with_json, reserved_refusal,
                     step_assumes, validate)
from .types import ParamError  # noqa: F401


def _load_builtin():
    """Import every action module in this package, in name order, so each
    registers itself. A new <kind>.py needs no edit here (P1a/P1b own their
    modules; this file stays P0's)."""
    import importlib
    import pkgutil
    core = {"base", "types", "expand"}
    for mod in sorted(m.name for m in pkgutil.iter_modules(__path__)):
        if mod not in core and not mod.startswith("_"):
            importlib.import_module("%s.%s" % (__name__, mod))


_load_builtin()
