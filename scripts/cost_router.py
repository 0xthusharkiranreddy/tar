#!/usr/bin/env python3
"""
cost_router.py — Cost-aware model routing for TAR engagements.

Three tiers:
  Economy:  Planner=Sonnet, Executor=Haiku, Critic=Haiku, Escalation=Sonnet
  Balanced: Planner=Sonnet, Executor=Haiku, Critic=Haiku, Escalation=Opus
  Max:      Planner=Opus,   Executor=Sonnet, Critic=Haiku, Escalation=Opus

Auto-escalation: after N consecutive critic failures in same phase,
bump tier for that phase. Reverts on phase advance.

Usage:
    python3 cost_router.py <world_model.db> get-model <role>
    python3 cost_router.py <world_model.db> record-failure
    python3 cost_router.py <world_model.db> record-success
    python3 cost_router.py <world_model.db> status
"""

import json
import sqlite3
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent

# Tier definitions: role → model
TIERS = {
    "economy": {
        "planner": "sonnet",
        "executor": "haiku",
        "critic": "haiku",
        "escalation": "sonnet",
        "novel": "opus",
        "parser": "haiku",
    },
    "balanced": {
        "planner": "sonnet",
        "executor": "haiku",
        "critic": "haiku",
        "escalation": "opus",
        "novel": "opus",
        "parser": "haiku",
    },
    "max": {
        "planner": "opus",
        "executor": "sonnet",
        "critic": "haiku",
        "escalation": "opus",
        "novel": "opus",
        "parser": "haiku",
    },
}

# Escalation thresholds
ESCALATION_THRESHOLD = 3  # consecutive failures before tier bump
TIER_ORDER = ["economy", "balanced", "max"]


def _ensure_cost_table(conn):
    """Create cost tracking table if needed."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cost_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phase TEXT NOT NULL,
            consecutive_failures INTEGER DEFAULT 0,
            escalated_tier TEXT,
            total_actions INTEGER DEFAULT 0,
            estimated_tokens INTEGER DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()


def _get_or_create_phase_record(conn, phase):
    """Get cost tracking record for current phase."""
    row = conn.execute(
        "SELECT * FROM cost_tracking WHERE phase=?", (phase,)
    ).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO cost_tracking (phase) VALUES (?)", (phase,)
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM cost_tracking WHERE phase=?", (phase,)
        ).fetchone()
    return row


def get_effective_tier(db_path: str) -> str:
    """Get the effective tier for current phase (base + escalation)."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    _ensure_cost_table(wm.conn)

    phase = wm.current_phase()
    base_tier = wm.conn.execute(
        "SELECT tier FROM engagement ORDER BY id DESC LIMIT 1"
    ).fetchone()
    base = base_tier["tier"] if base_tier else "balanced"

    record = _get_or_create_phase_record(wm.conn, phase)
    escalated = record["escalated_tier"]
    wm.close()

    if escalated:
        # Use escalated tier if it's higher than base
        base_idx = TIER_ORDER.index(base) if base in TIER_ORDER else 1
        esc_idx = TIER_ORDER.index(escalated) if escalated in TIER_ORDER else 1
        return TIER_ORDER[max(base_idx, esc_idx)]

    return base


def get_model(db_path: str, role: str) -> str:
    """Get the model name for a given role under current tier."""
    tier = get_effective_tier(db_path)
    tier_config = TIERS.get(tier, TIERS["balanced"])
    return tier_config.get(role, "haiku")


def record_critic_failure(db_path: str):
    """Record a critic failure. May trigger auto-escalation."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    _ensure_cost_table(wm.conn)

    phase = wm.current_phase()
    base_tier = wm.conn.execute(
        "SELECT tier FROM engagement ORDER BY id DESC LIMIT 1"
    ).fetchone()
    base = base_tier["tier"] if base_tier else "balanced"

    record = _get_or_create_phase_record(wm.conn, phase)
    new_failures = record["consecutive_failures"] + 1

    wm.conn.execute(
        "UPDATE cost_tracking SET consecutive_failures=?, total_actions=total_actions+1, updated_at=CURRENT_TIMESTAMP WHERE phase=?",
        (new_failures, phase),
    )

    # Check escalation
    if new_failures >= ESCALATION_THRESHOLD:
        base_idx = TIER_ORDER.index(base) if base in TIER_ORDER else 1
        current_esc = record["escalated_tier"]
        if current_esc:
            esc_idx = TIER_ORDER.index(current_esc) if current_esc in TIER_ORDER else base_idx
        else:
            esc_idx = base_idx

        if esc_idx < len(TIER_ORDER) - 1:
            new_tier = TIER_ORDER[esc_idx + 1]
            wm.conn.execute(
                "UPDATE cost_tracking SET escalated_tier=?, consecutive_failures=0 WHERE phase=?",
                (new_tier, phase),
            )
            wm.conn.commit()
            wm.close()
            return f"ESCALATED to {new_tier} (was {base}, {new_failures} consecutive failures)"

    wm.conn.commit()
    wm.close()
    return f"failures={new_failures}/{ESCALATION_THRESHOLD}"


def record_success(db_path: str):
    """Record a successful action. Resets failure counter."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    _ensure_cost_table(wm.conn)
    phase = wm.current_phase()

    wm.conn.execute(
        "UPDATE cost_tracking SET consecutive_failures=0, total_actions=total_actions+1, updated_at=CURRENT_TIMESTAMP WHERE phase=?",
        (phase,),
    )
    wm.conn.commit()
    wm.close()


def get_status(db_path: str) -> dict:
    """Get cost routing status."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    _ensure_cost_table(wm.conn)

    phase = wm.current_phase()
    base_tier = wm.conn.execute(
        "SELECT tier FROM engagement ORDER BY id DESC LIMIT 1"
    ).fetchone()
    base = base_tier["tier"] if base_tier else "balanced"

    records = wm.conn.execute("SELECT * FROM cost_tracking").fetchall()
    wm.close()

    effective = get_effective_tier(db_path)

    return {
        "base_tier": base,
        "effective_tier": effective,
        "current_phase": phase,
        "models": TIERS.get(effective, TIERS["balanced"]),
        "phases": [
            {
                "phase": r["phase"],
                "failures": r["consecutive_failures"],
                "escalated": r["escalated_tier"],
                "total_actions": r["total_actions"],
            }
            for r in records
        ],
    }


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <db_path> <command> [args]")
        print("Commands: get-model <role>, record-failure, record-success, status")
        sys.exit(1)

    db_path = sys.argv[1]
    cmd = sys.argv[2]

    if cmd == "get-model":
        role = sys.argv[3] if len(sys.argv) > 3 else "executor"
        model = get_model(db_path, role)
        print(model)
    elif cmd == "record-failure":
        result = record_critic_failure(db_path)
        print(result)
    elif cmd == "record-success":
        record_success(db_path)
        print("success recorded")
    elif cmd == "status":
        status = get_status(db_path)
        print(json.dumps(status, indent=2))
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
