#!/usr/bin/env python3
"""
predicate_ledger.py — Cross-Engagement Predicate Ledger.

Global store that persists (action, target_fingerprint, silence_pattern)
tuples across engagements. Actions that repeatedly fail against similar
targets get their preconditions auto-amended.

Schema:
    failure_predicates:
        - action_name: str
        - target_fingerprint: str  (os+version+service combo)
        - silence_pattern: str     (what the failure looked like)
        - count: int               (how many times this has failed)
        - last_seen: datetime
        - engagement: str          (which engagement saw it last)

    success_predicates:
        - action_name: str
        - target_fingerprint: str
        - count: int
        - last_seen: datetime

Usage:
    from predicate_ledger import PredicateLedger
    pl = PredicateLedger()
    pl.record_failure("DFSCoerce", "windows-2019-dc", "No callback received")
    pl.record_success("PrinterBug", "windows-2019-dc")
    blocked = pl.should_block("DFSCoerce", "windows-2019-dc")  # True if count >= 3
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path


DEFAULT_DB = "/home/kali/knowledge/predicate_ledger.db"
BLOCK_THRESHOLD = 3  # Block after N failures against same fingerprint


class PredicateLedger:
    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS failure_predicates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_name TEXT NOT NULL,
                target_fingerprint TEXT NOT NULL,
                silence_pattern TEXT DEFAULT '',
                count INTEGER DEFAULT 1,
                last_seen TEXT DEFAULT (datetime('now')),
                engagement TEXT DEFAULT '',
                UNIQUE(action_name, target_fingerprint, silence_pattern)
            );

            CREATE TABLE IF NOT EXISTS success_predicates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_name TEXT NOT NULL,
                target_fingerprint TEXT NOT NULL,
                count INTEGER DEFAULT 1,
                last_seen TEXT DEFAULT (datetime('now')),
                UNIQUE(action_name, target_fingerprint)
            );

            CREATE INDEX IF NOT EXISTS idx_fail_action
                ON failure_predicates(action_name);
            CREATE INDEX IF NOT EXISTS idx_fail_fp
                ON failure_predicates(target_fingerprint);
            CREATE INDEX IF NOT EXISTS idx_succ_action
                ON success_predicates(action_name);
        """)
        self.conn.commit()

    def compute_fingerprint(self, os_name: str = "", os_version: str = "",
                           services: list[tuple] = None, domain: bool = False) -> str:
        """Compute a target fingerprint from observable characteristics."""
        parts = []
        if os_name:
            parts.append(os_name.lower())
        if os_version:
            parts.append(os_version.lower())
        if domain:
            parts.append("domain-joined")
        if services:
            # Sort by port for deterministic fingerprint
            svc_parts = sorted(f"{port}/{product}" for port, product in services)
            parts.extend(svc_parts[:10])  # Cap at 10 services
        return "|".join(parts) if parts else "unknown"

    def record_failure(self, action_name: str, target_fingerprint: str,
                      silence_pattern: str = "", engagement: str = ""):
        """Record a failed action attempt."""
        self.conn.execute("""
            INSERT INTO failure_predicates (action_name, target_fingerprint, silence_pattern, engagement)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(action_name, target_fingerprint, silence_pattern)
            DO UPDATE SET
                count = count + 1,
                last_seen = datetime('now'),
                engagement = excluded.engagement
        """, (action_name, target_fingerprint, silence_pattern, engagement))
        self.conn.commit()

    def record_success(self, action_name: str, target_fingerprint: str):
        """Record a successful action attempt. Resets failure count for this combo."""
        self.conn.execute("""
            INSERT INTO success_predicates (action_name, target_fingerprint)
            VALUES (?, ?)
            ON CONFLICT(action_name, target_fingerprint)
            DO UPDATE SET
                count = count + 1,
                last_seen = datetime('now')
        """, (action_name, target_fingerprint))
        # Reset failure count since it worked
        self.conn.execute("""
            DELETE FROM failure_predicates
            WHERE action_name = ? AND target_fingerprint = ?
        """, (action_name, target_fingerprint))
        self.conn.commit()

    def should_block(self, action_name: str, target_fingerprint: str,
                    threshold: int = BLOCK_THRESHOLD) -> bool:
        """Check if action should be blocked for this target fingerprint."""
        row = self.conn.execute("""
            SELECT SUM(count) as total FROM failure_predicates
            WHERE action_name = ? AND target_fingerprint = ?
        """, (action_name, target_fingerprint)).fetchone()
        return (row["total"] or 0) >= threshold

    def get_blocked_actions(self, target_fingerprint: str,
                           threshold: int = BLOCK_THRESHOLD) -> list[dict]:
        """Get all actions blocked for a given target fingerprint."""
        rows = self.conn.execute("""
            SELECT action_name, SUM(count) as total, GROUP_CONCAT(silence_pattern, '; ') as patterns
            FROM failure_predicates
            WHERE target_fingerprint = ?
            GROUP BY action_name
            HAVING total >= ?
        """, (target_fingerprint, threshold)).fetchall()
        return [dict(row) for row in rows]

    def get_action_history(self, action_name: str) -> dict:
        """Get full history for an action across all fingerprints."""
        failures = self.conn.execute("""
            SELECT target_fingerprint, silence_pattern, count, last_seen
            FROM failure_predicates WHERE action_name = ?
            ORDER BY count DESC
        """, (action_name,)).fetchall()

        successes = self.conn.execute("""
            SELECT target_fingerprint, count, last_seen
            FROM success_predicates WHERE action_name = ?
            ORDER BY count DESC
        """, (action_name,)).fetchall()

        return {
            "action": action_name,
            "failures": [dict(r) for r in failures],
            "successes": [dict(r) for r in successes],
            "total_failures": sum(r["count"] for r in failures),
            "total_successes": sum(r["count"] for r in successes),
        }

    def get_amended_preconditions(self, action_name: str,
                                  target_fingerprint: str) -> list[str]:
        """
        Get additional preconditions that should be added to an action
        based on historical failure patterns.
        Returns list of negative preconditions like 'target.fingerprint != X'.
        """
        amendments = []
        if self.should_block(action_name, target_fingerprint):
            # Get the specific patterns
            rows = self.conn.execute("""
                SELECT silence_pattern, count FROM failure_predicates
                WHERE action_name = ? AND target_fingerprint = ?
                ORDER BY count DESC
            """, (action_name, target_fingerprint)).fetchall()
            for row in rows:
                amendments.append(
                    f"BLOCKED: {action_name} failed {row['count']}x against "
                    f"{target_fingerprint} (pattern: {row['silence_pattern']})"
                )
        return amendments

    def get_stats(self) -> dict:
        """Get overall ledger statistics."""
        fail_count = self.conn.execute(
            "SELECT COUNT(*), SUM(count) FROM failure_predicates"
        ).fetchone()
        succ_count = self.conn.execute(
            "SELECT COUNT(*), SUM(count) FROM success_predicates"
        ).fetchone()
        return {
            "unique_failure_combos": fail_count[0] or 0,
            "total_failures": fail_count[1] or 0,
            "unique_success_combos": succ_count[0] or 0,
            "total_successes": succ_count[1] or 0,
        }

    def close(self):
        self.conn.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Predicate Ledger CLI")
    sub = parser.add_subparsers(dest="command")

    p_stats = sub.add_parser("stats", help="Show ledger statistics")
    p_history = sub.add_parser("history", help="Show action history")
    p_history.add_argument("action", help="Action name")
    p_blocked = sub.add_parser("blocked", help="Show blocked actions for fingerprint")
    p_blocked.add_argument("fingerprint", help="Target fingerprint")

    args = parser.parse_args()
    pl = PredicateLedger()

    if args.command == "stats":
        print(json.dumps(pl.get_stats(), indent=2))
    elif args.command == "history":
        print(json.dumps(pl.get_action_history(args.action), indent=2))
    elif args.command == "blocked":
        blocked = pl.get_blocked_actions(args.fingerprint)
        print(json.dumps(blocked, indent=2))
    else:
        parser.print_help()

    pl.close()


if __name__ == "__main__":
    main()
