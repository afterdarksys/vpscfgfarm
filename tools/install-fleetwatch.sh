#!/bin/sh
# Install (or reinstall) the launchd agent that runs fleet watch every 10 min.
# macOS only (launchd). Remove with:
#   launchctl bootout gui/$(id -u)/vpscfgfarm.fleetwatch
set -eu
LABEL="vpscfgfarm.fleetwatch"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# $ROOT is written into the plist's XML verbatim. A path holding an XML
# metacharacter (or a control character) would change the document, so it is
# refused rather than escaped.
case "$ROOT" in
  *[\&\<\>\"\']*|*[[:cntrl:]]*)
    echo "install-fleetwatch: refusing: the checkout path contains an XML metacharacter or control character: $ROOT" >&2
    exit 1 ;;
esac
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
mkdir -p "$HOME/Library/LaunchAgents" "$ROOT/journal"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>$ROOT/tools/fleetwatch-cron.sh</string>
  </array>
  <key>StartInterval</key><integer>600</integer>
  <key>StandardOutPath</key><string>$ROOT/journal/watch-cron.log</string>
  <key>StandardErrorPath</key><string>$ROOT/journal/watch-cron.log</string>
</dict>
</plist>
PLISTEOF
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed: fleet watch every 600s -> $PLIST"
echo "log: $ROOT/journal/watch-cron.log"
