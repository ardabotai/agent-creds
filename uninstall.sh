#!/bin/bash
# Removes the binaries and the login agent. The vault is left untouched:
# delete ~/Library/Application\ Support/agent-creds yourself if you mean to.
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local/bin}"
LABEL="ai.ardabot.agentcreds.daemon"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

# Include labels used before the rename so older installs clean up fully.
for label in "$LABEL" com.ardabot.agentcreds.daemon dev.agentcreds.daemon; do
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/$label.plist"
done
rm -f "$PREFIX/agentcreds" "$PREFIX/agentcredsd"

echo "Removed binaries and login agent."
echo "Your vault is still at ~/Library/Application Support/agent-creds"
echo "  (delete that directory to erase every stored secret — it cannot be recovered)."
