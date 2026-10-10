"""Policy verification inside the package — the second, independent door.

Threats:
  - Protects against: bypassing vpscfg-control.py by invoking the package
    directly (`python3 -m vpscfg ...`): without VPSCFG_CONTROL_TOKEN matching
    this module's OWN sha256 of the policy file, the package hard-locks to
    read-only regardless of what the policy says; a policy edited BETWEEN the
    wrapper's check and ours (hash mismatch => read-only); tampered policies
    (same floor validation as the wrapper, independently implemented).
  - Does NOT protect against: an operator editing the policy AND re-invoking
    through the wrapper — that is the sanctioned path, deliberately git-visible.

Fail-closed rule: any doubt resolves to ReadOnlyLock, never to permission.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path

from . import estate
from .gates import DENY_ALWAYS_FLOOR, READ_ONLY_VERBS, Refused

VALID_MODES = ("lockdown", "test", "supervised", "released")


class Guard(object):
    """Loaded once per invocation. Every judgment method raises Refused on
    violation; none of them return permission objects that could be reused."""

    def __init__(self, policy, verified):
        self.policy = policy
        self.verified = verified  # token matched => wrapper vouched for this exact file

    @classmethod
    def load(cls, path=None, token=None):
        """Load the policy.

        path/token kwargs exist for in-process tests ONLY (caller-controlled
        code is already trusted). At runtime the policy is ALWAYS the canonical
        governor of the estate root (vpscfg/estate.py: the tool checkout, or the
        one directory its pinned estate.path file names; never an env var);
        VPSCFG_CONTROL_PATH is accepted solely as a
        cross-check and REFUSED if it names anything else. This closes the
        wrapper-impersonation hole: an attacker who can set env vars cannot
        point the package at a permissive policy of their own, because the
        token is only ever compared against the canonical file's hash.
        """
        if path is None:
            canonical = Path(estate.current().governor)
            env_path = os.environ.get("VPSCFG_CONTROL_PATH")
            if env_path is not None:
                try:
                    if Path(env_path).resolve() != canonical:
                        raise Refused(
                            "VPSCFG_CONTROL_PATH %r is not the canonical policy %s — "
                            "control-path spoofing, refusing everything" % (env_path, canonical)
                        )
                except OSError as e:
                    raise Refused("cannot resolve VPSCFG_CONTROL_PATH (%s) — failing closed" % e)
            path = str(canonical)
            token = os.environ.get("VPSCFG_CONTROL_TOKEN")

        try:
            raw = Path(path).read_bytes()
            policy = json.loads(raw)
        except (OSError, json.JSONDecodeError) as e:
            raise Refused("control policy unreadable (%s) — failing closed" % e)

        _validate(policy)

        own_hash = hashlib.sha256(raw).hexdigest()
        verified = isinstance(token, str) and bool(token) and hmac.compare_digest(token.encode(), own_hash.encode())
        return cls(policy, verified)

    # ---- judgments -----------------------------------------------------

    def assert_verb(self, verb):
        if verb not in self.policy.get("allowed_verbs", []):
            raise Refused("verb %r not released by the governor" % verb)

    def assert_read_only_or_verified(self, verb):
        """The bypass rule: unverified invocations may only observe."""
        if verb in READ_ONLY_VERBS:
            return
        if not self.verified:
            door = "vpsexec" if verb == "exec" else "vpscfg-control.py"
            raise Refused(
                "mutation verb %r without a valid control token — invoke through "
                "%s; direct invocation is read-only by design" % (verb, door)
            )

    def assert_mutation_allowed(self, verb, host, scope):
        self.assert_read_only_or_verified(verb)
        if verb in READ_ONLY_VERBS:
            return
        p = self.policy
        if not p.get("mutation_enabled", False):
            raise Refused("mutation_enabled is false — master switch off")
        if p.get("mode") == "lockdown":
            raise Refused("mode is lockdown — no mutations")
        posture = p.get("hosts", {}).get(host, {}).get("posture", "frozen")
        if posture in ("frozen", "lockdown"):
            raise Refused("host %r posture is %r — mutations refused" % (host, posture))
        unlocked = p.get("scopes", {}).get("unlocked", [])
        if scope not in unlocked:
            raise Refused(
                "scope %r has not graduated test+verify (unlocked=%r)" % (scope, unlocked)
            )

    def assert_exec_allowed(self, host):
        """vpsexec's mutation judgment.

        Deliberately NOT assert_mutation_allowed: there is no contract scope to
        graduate, because an ad-hoc command is not a contracted service. Host
        posture therefore carries the whole weight here, which is exactly why
        vpsexec's own gates (risky tier, override file, plan-hash approval) are
        stricter than deploy's. Posture must be affirmatively test/released —
        an unlisted host defaults to frozen and refuses.
        """
        self.assert_read_only_or_verified("exec")
        p = self.policy
        if not p.get("mutation_enabled", False):
            raise Refused("mutation_enabled is false — master switch off")
        if p.get("mode") == "lockdown":
            raise Refused("mode is lockdown — no mutations")
        posture = p.get("hosts", {}).get(host, {}).get("posture", "frozen")
        if posture not in ("test", "released"):
            raise Refused(
                "host %r posture is %r — vpsexec mutations require posture "
                "'test' or 'released'" % (host, posture)
            )

    def assert_exec_elevated(self, host):
        """vpsexec break-glass: everything assert_exec_allowed checks EXCEPT
        posture, because posture is precisely what a committed break_glass
        runbook elevates past.

        Note what still applies: the wrapper token, the master switch, and
        lockdown mode. Break-glass reaches a frozen host during an incident; it
        does not turn the governor off, and it cannot be reached at all without
        a runbook that named this exact command before the incident started.
        """
        self.assert_read_only_or_verified("exec")
        p = self.policy
        if not p.get("mutation_enabled", False):
            raise Refused("mutation_enabled is false — master switch off, and "
                          "break-glass does not override the master switch")
        if p.get("mode") == "lockdown":
            raise Refused("mode is lockdown — no mutations, break-glass included")
        if host not in p.get("hosts", {}):
            raise Refused(
                "host %r has no entry in the governor at all — break-glass "
                "elevates a known posture, it does not invent one" % host)

    def deny_patterns(self):
        return self.policy.get("deny_always", DENY_ALWAYS_FLOOR)

    def no_failover(self, host):
        """True when the governor says this host has no failover
        (hosts.<name>.failover: false), so an outage there is total."""
        cfg = self.policy.get("hosts", {}).get(host, {})
        return isinstance(cfg, dict) and cfg.get("failover") is False


def _alias_problems(hosts):
    """hosts[*].alias_of declares that two names are ONE machine.

    Validated hard, because an alias whose posture disagrees with its target
    would be posture laundering: name the frozen box by its other name and get
    a different answer. Postures must match, targets must exist, and chains are
    refused so there is exactly one canonical name per machine.
    """
    problems = []
    for name, cfg in (hosts or {}).items():
        if not isinstance(cfg, dict) or not cfg.get("alias_of"):
            continue
        target = cfg["alias_of"]
        if target == name:
            problems.append("host %r is alias_of itself" % name)
            continue
        tcfg = (hosts or {}).get(target)
        if not isinstance(tcfg, dict):
            problems.append("host %r is alias_of %r, which is not a governed host"
                            % (name, target))
            continue
        if tcfg.get("alias_of"):
            problems.append(
                "host %r is alias_of %r, which is itself an alias — chains are "
                "refused so every machine has exactly one canonical name"
                % (name, target))
        if cfg.get("posture") != tcfg.get("posture"):
            problems.append(
                "host %r (posture %r) is alias_of %r (posture %r) — the same "
                "machine must not have two postures, or the alias launders the "
                "stricter one" % (name, cfg.get("posture"), target, tcfg.get("posture")))
    return problems


def _validate(policy):
    problems = []
    if policy.get("version") != 1:
        problems.append("version must be 1")
    if policy.get("mode") not in VALID_MODES:
        problems.append("invalid mode")
    if not isinstance(policy.get("mutation_enabled"), bool):
        problems.append("mutation_enabled must be boolean")
    deny = policy.get("deny_always")
    if not isinstance(deny, list) or not deny:
        problems.append("deny_always missing/empty")
    else:
        missing = [d for d in DENY_ALWAYS_FLOOR if d not in deny]
        if missing:
            problems.append("deny_always missing floor entries (tampering?): %r" % missing)
    if not isinstance(policy.get("scopes", {}).get("unlocked", None), list):
        problems.append("scopes.unlocked must be a list")
    problems.extend(_alias_problems(policy.get("hosts", {})))
    if problems:
        raise Refused("control policy failed validation: " + "; ".join(problems))
