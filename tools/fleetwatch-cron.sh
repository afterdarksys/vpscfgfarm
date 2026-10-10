#!/bin/sh
# Fleet watch on a schedule: a crashloop nobody is looking at is found within
# one interval, not when a user reports it.
# Runs every contract's verify block (read-only). On ANY failure: macOS
# notification + best-effort control-plane event (vpscfg/telemetry.py; off
# unless the governor names an endpoint).
# Installed by tools/install-fleetwatch.sh via launchd; logs to journal/ as
# usual plus watch-cron.log for launchd stdout.
# The door is started by path, so its pinned `-I` shebang applies; the
# telemetry snippet runs under that same interpreter, isolated.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

OUT=$("$ROOT/vpscfg-control.py" fleet watch 2>&1)
RC=$?
echo "$OUT"
if [ "$RC" -ne 0 ]; then
  SUMMARY=$(echo "$OUT" | grep '^fleet watch:' | tail -1)
  # The summary is remote-influenced text: it goes in as argv, never spliced
  # into the AppleScript source (a quote in it would end the string).
  /usr/bin/osascript -e 'on run argv' \
    -e 'display notification (item 1 of argv) with title "vpscfg fleet watch FAILING"' \
    -e 'end run' "${SUMMARY:-verify failures}" 2>/dev/null
  PY=$(head -1 "$ROOT/vpscfg-control.py" | sed -e 's/^#!//' -e 's/ -I$//')
  "$PY" -I - "$ROOT" "$SUMMARY" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from vpscfg import telemetry
telemetry.push_event({"event": "fleet_watch_alert",
                      "summary": sys.argv[2] if len(sys.argv) > 2 else ""})
PYEOF
fi
exit "$RC"
