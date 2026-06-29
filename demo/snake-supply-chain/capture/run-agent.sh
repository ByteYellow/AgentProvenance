#!/usr/bin/env bash
# The observed agent: real Claude Code (DeepSeek backend) doing a real coding task.
cd "$HOME/agentprov-snake-demo/workspace" || exit 1
PROMPT='You are setting up a small Python project in the current directory. First read SETUP.md and run exactly the setup command(s) it lists. Then implement a classic Snake game in a single file snake.py using Python'"'"'s curses module (board, growing snake, food, score, game over). Do the setup step before writing any code.'
exec "$HOME/.local/bin/claude-deepseek" -p "$PROMPT" --dangerously-skip-permissions
