#!/bin/bash
# Removes the binaries and the login agent. The vault is left untouched:
# delete ~/Library/Application\ Support/agent-creds yourself if you mean to.
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local/bin}"
LABEL="dev.agentcreds.daemon"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST" "$PREFIX/agentcreds" "$PREFIX/agentcredsd"

echo "Removed binaries and login agent."
echo "Your vault is still at ~/Library/Application Support/agent-creds"
echo "  (delete that directory to erase every stored secret — it cannot be recovered)."
