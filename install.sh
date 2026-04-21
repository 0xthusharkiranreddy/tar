#!/usr/bin/env bash
# TAR installer — sync scripts, hooks, and knowledge into the Claude Code layout
# Tested on Kali / Debian / Ubuntu. Opinionated: uses /home/kali/ by default.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"
KNOWLEDGE_HOME="${KNOWLEDGE_HOME:-/home/kali/knowledge}"

echo "[+] TAR install"
echo "    repo:      $HERE"
echo "    .claude:   $CLAUDE_HOME"
echo "    knowledge: $KNOWLEDGE_HOME"

for d in scripts hooks subagents; do
  mkdir -p "$CLAUDE_HOME/$d"
  rsync -av --delete "$HERE/$d/" "$CLAUDE_HOME/$d/"
done

mkdir -p "$KNOWLEDGE_HOME"
rsync -av "$HERE/actions/"   "$KNOWLEDGE_HOME/actions/"
# Optional: the repo ships a lightweight mindmap + cypher set. If your host has
# richer knowledge trees (hacktricks / PAT) keep them in place — we don't touch them.
[ -d "$HERE/knowledge/mindmaps" ] && rsync -av "$HERE/knowledge/mindmaps/" "$KNOWLEDGE_HOME/mindmaps/"
[ -d "$HERE/knowledge/cypher" ]   && rsync -av "$HERE/knowledge/cypher/"   "$KNOWLEDGE_HOME/cypher/"

python3 -m pip install -r "$HERE/requirements.txt" --quiet

echo "[+] Rebuilding knowledge index (cold build takes ~5s)..."
rm -f /tmp/tar_knowledge_index.pkl
python3 -c "import sys; sys.path.insert(0, '$CLAUDE_HOME/scripts'); from knowledge_index import get_index; get_index()"

echo "[+] Running integration tests"
python3 "$CLAUDE_HOME/scripts/tests/test_v2_integration.py" || {
  echo "[!] Tests failed — review output above"; exit 1;
}

echo
echo "[OK] TAR installed. Next:"
echo "    1. Start a new Claude Code session (the UserPromptSubmit hook activates automatically)."
echo "    2. Try: 'plan chain domain_admin' — the planner will walk from current state to DA."
echo "    3. Read docs/USAGE.md for the operator workflow."
