# Scripts

These are optional read-only automation helpers for the modular prompt system.

## Included

- `validate_modular_system.py`
  Checks that the live modular system is present and internally consistent.
  It validates required runtime paths, skill presence, knowledge indexes, and router references.

- `query_knowledge.py`
  Lightweight local search over `/home/kali/knowledge`.
  It is an optional helper, not a source of truth.

## Usage

```bash
python3 /home/kali/.claude/scripts/validate_modular_system.py
python3 /home/kali/.claude/scripts/query_knowledge.py "ssrf metadata"
```

## Policy

- These scripts must not mutate canonical knowledge files.
- Authority remains in `CLAUDE.md`, `session_state.md`, and the `knowledge/` tree.
