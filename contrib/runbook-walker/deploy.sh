#!/usr/bin/env bash
# deploy.sh: one command per release. Lists the runbook's steps, mints ONE
# approval contract for it (you type its GRANT:<runbook>:<ttl> phrase once, in
# your terminal), then walks every step under that contract with walk.sh.
#
#   deploy.sh RUNBOOK --reason "why" [--ttl 30m] [--from N] [walk.sh options]
#   deploy.sh web-release-example --reason "shop 1.4.0 release" --ttl 30m \
#       --artifacts contrib/example-estate/artifacts
#
# The contract covers only that runbook's break_glass: true steps, excluding
# rollback steps; it is bound to the runbook's sha256 and expires on its own.
# Every other vpsexec gate still applies at every step. To approve each step by
# typing BREAK-GLASS:<n> instead, run walk.sh without --grant.
#
# RUNBOOK is a file name, not a path: `vpsexec grant new` mints from the
# policies vpsexec itself loads (<repo>/policies/*.yaml), so the runbook must
# be armed there. Options other than --reason, --ttl, --from and --vpsexec
# (for example --artifacts, --state-dir) are passed to walk.sh unchanged.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VPSEXEC="${VPSEXEC:-$REPO/vpsexec}"

die() { echo "deploy.sh: $*" >&2; exit 2; }
need() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }

[ $# -ge 1 ] || die 'usage: deploy.sh RUNBOOK --reason "why" [--ttl 30m] [--from N] [walk.sh options]'
case "$1" in
  -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
  -*|*/*) die "the first argument is the runbook's file name in policies/ (no path)" ;;
esac
RUNBOOK="${1%.yaml}"
shift

TTL=30m
REASON=""
WALK_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --ttl)     need "$@"; TTL="$2"; shift 2 ;;
    --reason)  need "$@"; REASON="$2"; shift 2 ;;
    --from)    need "$@"; WALK_ARGS+=(--from "$2"); shift 2 ;;
    --vpsexec) need "$@"; VPSEXEC="$2"; shift 2 ;;
    --grant|--only|--list|--runbook)
               die "$1 is not a deploy.sh option; call walk.sh directly for that" ;;
    *)         WALK_ARGS+=("$1"); shift ;;
  esac
done
[ -n "$REASON" ] || die '--reason "why" is required: vpsexec journals it with every step'
[ -x "$VPSEXEC" ] || die "vpsexec not found or not executable: $VPSEXEC (use --vpsexec or VPSEXEC=)"
[ -t 0 ] || die "run this in a real terminal: minting and using a contract both need one"

WALK=("$HERE/walk.sh" --runbook "$RUNBOOK" --vpsexec "$VPSEXEC")

echo "== steps in $RUNBOOK"
"${WALK[@]}" --list "${WALK_ARGS[@]+"${WALK_ARGS[@]}"}"
echo
echo "== minting a $TTL approval contract for $RUNBOOK (type the phrase it shows, once)"
# The output is shown as it arrives and kept, to read the MINTED line from it.
OUT="$(PYTHONUNBUFFERED=1 "$VPSEXEC" grant new "$RUNBOOK" --ttl "$TTL" --run | tee /dev/stderr)"
GRANT="$(printf '%s\n' "$OUT" | sed -n 's/^MINTED //p' | tail -n 1)"
[ -n "$GRANT" ] && [ -f "$GRANT" ] || { echo "deploy.sh: no contract was minted; nothing ran" >&2; exit 1; }

echo
echo "== walking $RUNBOOK under $GRANT"
exec "${WALK[@]}" --reason "$REASON" --grant "$GRANT" "${WALK_ARGS[@]+"${WALK_ARGS[@]}"}"
