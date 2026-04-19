#!/usr/bin/env python3
"""
world_model.py — SQLite-backed structured state for TAR engagements.
Per-engagement DB at /home/kali/engagements/<name>/world_model.db

Provides typed storage and query API for hosts, services, creds, users,
shares, findings, attack paths, and failed attempts. The LLM queries this
instead of reading raw markdown state.
"""

import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Optional


SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS engagement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_ip TEXT,
    phase TEXT DEFAULT 'recon',
    tier TEXT DEFAULT 'balanced',
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    hostname TEXT,
    os TEXT,
    domain TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    product TEXT,
    version TEXT,
    cpe TEXT,
    banner TEXT,
    scripts TEXT,  -- JSON: {script_name: output}
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS creds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    hash TEXT,
    hash_type TEXT,
    domain TEXT,
    source TEXT,  -- where this cred was found
    verified INTEGER DEFAULT 0,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    domain TEXT,
    rid INTEGER,
    spn TEXT,
    is_admin INTEGER DEFAULT 0,
    groups TEXT,  -- JSON array
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, domain)
);

CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    access_level TEXT,  -- none, read, write, admin
    notes TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    UNIQUE(host_id, name)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,  -- vuln, misconfig, info, privesc_vector
    severity TEXT,  -- critical, high, medium, low, info
    description TEXT NOT NULL,
    evidence_path TEXT,
    host_id INTEGER,
    service_id INTEGER,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    action_name TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    notes TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS failed_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_name TEXT NOT NULL,
    params_hash TEXT NOT NULL,
    host_id INTEGER,
    silence_pattern TEXT,
    error_output TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class WorldModel:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(SCHEMA_SQL)
        existing = self.conn.execute(
            "SELECT value FROM schema_meta WHERE key='version'"
        ).fetchone()
        if not existing:
            self.conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self.conn.commit()

    def close(self):
        self.conn.close()

    # --- Engagement ---

    def init_engagement(self, name: str, target_ip: str, tier: str = "balanced") -> int:
        cur = self.conn.execute(
            "INSERT INTO engagement (name, target_ip, tier) VALUES (?, ?, ?)",
            (name, target_ip, tier),
        )
        self.conn.commit()
        return cur.lastrowid

    def current_phase(self) -> str:
        row = self.conn.execute(
            "SELECT phase FROM engagement ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["phase"] if row else "recon"

    def advance_phase(self, new_phase: str):
        self.conn.execute(
            "UPDATE engagement SET phase=?, updated_at=CURRENT_TIMESTAMP WHERE id=(SELECT MAX(id) FROM engagement)",
            (new_phase,),
        )
        self.conn.commit()

    # --- Hosts ---

    def add_host(self, ip: str, hostname: str = None, os: str = None, domain: str = None) -> int:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO hosts (ip, hostname, os, domain) VALUES (?, ?, ?, ?)",
            (ip, hostname, os, domain),
        )
        if cur.lastrowid == 0:
            row = self.conn.execute("SELECT id FROM hosts WHERE ip=?", (ip,)).fetchone()
            if hostname:
                self.conn.execute("UPDATE hosts SET hostname=? WHERE ip=?", (hostname, ip))
            if os:
                self.conn.execute("UPDATE hosts SET os=? WHERE ip=?", (os, ip))
            if domain:
                self.conn.execute("UPDATE hosts SET domain=? WHERE ip=?", (domain, ip))
            self.conn.commit()
            return row["id"]
        self.conn.commit()
        return cur.lastrowid

    def get_hosts(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM hosts").fetchall()
        return [dict(r) for r in rows]

    def get_host_by_ip(self, ip: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    # --- Services ---

    def add_service(self, host_id: int, port: int, protocol: str = "tcp",
                    state: str = "open", product: str = None, version: str = None,
                    cpe: str = None, banner: str = None, scripts: dict = None) -> int:
        scripts_json = json.dumps(scripts) if scripts else None
        cur = self.conn.execute(
            """INSERT OR REPLACE INTO services
               (host_id, port, protocol, state, product, version, cpe, banner, scripts)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, port, protocol, state, product, version, cpe, banner, scripts_json),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_services(self, host_id: int = None, state: str = "open",
                     port: int = None) -> list[dict]:
        query = "SELECT s.*, h.ip as host_ip FROM services s JOIN hosts h ON s.host_id=h.id WHERE 1=1"
        params = []
        if host_id:
            query += " AND s.host_id=?"
            params.append(host_id)
        if state:
            query += " AND s.state=?"
            params.append(state)
        if port:
            query += " AND s.port=?"
            params.append(port)
        rows = self.conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("scripts"):
                d["scripts"] = json.loads(d["scripts"])
            result.append(d)
        return result

    # --- Creds ---

    def add_cred(self, username: str = None, password: str = None,
                 hash: str = None, hash_type: str = None,
                 domain: str = None, source: str = None, verified: bool = False) -> int:
        cur = self.conn.execute(
            "INSERT INTO creds (username, password, hash, hash_type, domain, source, verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, password, hash, hash_type, domain, source, int(verified)),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_creds(self, domain: str = None, verified_only: bool = False) -> list[dict]:
        query = "SELECT * FROM creds WHERE 1=1"
        params = []
        if domain:
            query += " AND domain=?"
            params.append(domain)
        if verified_only:
            query += " AND verified=1"
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # --- Users ---

    def add_user(self, username: str, domain: str = None, rid: int = None,
                 spn: str = None, is_admin: bool = False, groups: list = None) -> int:
        groups_json = json.dumps(groups) if groups else None
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO users (username, domain, rid, spn, is_admin, groups) VALUES (?, ?, ?, ?, ?, ?)",
            (username, domain, rid, spn, int(is_admin), groups_json),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_users(self, domain: str = None) -> list[dict]:
        query = "SELECT * FROM users WHERE 1=1"
        params = []
        if domain:
            query += " AND domain=?"
            params.append(domain)
        rows = self.conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("groups"):
                d["groups"] = json.loads(d["groups"])
            result.append(d)
        return result

    # --- Shares ---

    def add_share(self, host_id: int, name: str, access_level: str = None,
                  notes: str = None) -> int:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO shares (host_id, name, access_level, notes) VALUES (?, ?, ?, ?)",
            (host_id, name, access_level, notes),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_shares(self, host_id: int = None) -> list[dict]:
        query = "SELECT s.*, h.ip as host_ip FROM shares s JOIN hosts h ON s.host_id=h.id WHERE 1=1"
        params = []
        if host_id:
            query += " AND s.host_id=?"
            params.append(host_id)
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # --- Findings ---

    def add_finding(self, category: str, description: str, severity: str = None,
                    evidence_path: str = None, host_id: int = None,
                    service_id: int = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (category, severity, description, evidence_path, host_id, service_id) VALUES (?, ?, ?, ?, ?, ?)",
            (category, severity, description, evidence_path, host_id, service_id),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_findings(self, category: str = None, severity: str = None) -> list[dict]:
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if category:
            query += " AND category=?"
            params.append(category)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # --- Attack Paths ---

    def add_attack_path(self, from_state: str, to_state: str,
                        action_name: str, verified: bool = False,
                        notes: str = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO attack_paths (from_state, to_state, action_name, verified, notes) VALUES (?, ?, ?, ?, ?)",
            (from_state, to_state, action_name, int(verified), notes),
        )
        self.conn.commit()
        return cur.lastrowid

    # --- Failed Attempts (retry-block enforcement) ---

    @staticmethod
    def _hash_params(params: dict) -> str:
        return hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:16]

    def record_failure(self, action_name: str, params: dict,
                       host_id: int = None, silence_pattern: str = None,
                       error_output: str = None) -> int:
        params_hash = self._hash_params(params)
        cur = self.conn.execute(
            "INSERT INTO failed_attempts (action_name, params_hash, host_id, silence_pattern, error_output) VALUES (?, ?, ?, ?, ?)",
            (action_name, params_hash, host_id, silence_pattern, error_output),
        )
        self.conn.commit()
        return cur.lastrowid

    def is_retry_blocked(self, action_name: str, params: dict) -> bool:
        """Returns True if this exact (action, params) was already attempted."""
        params_hash = self._hash_params(params)
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM failed_attempts WHERE action_name=? AND params_hash=?",
            (action_name, params_hash),
        ).fetchone()
        return row["cnt"] > 0

    def get_failed_attempts(self, action_name: str = None) -> list[dict]:
        query = "SELECT * FROM failed_attempts WHERE 1=1"
        params = []
        if action_name:
            query += " AND action_name=?"
            params.append(action_name)
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # --- Phase Progression ---

    PHASE_ORDER = ["recon", "foothold", "user", "privesc", "root"]

    def check_phase_advancement(self) -> str | None:
        """
        Check if world state signals warrant advancing to next phase.
        Returns new phase name if advancement is warranted, None otherwise.

        Phase transition signals:
          recon → foothold:   ≥3 services enumerated (version-scanned, not just port-found)
          foothold → user:    Have a credential with password OR have a shell (finding.shell)
          user → privesc:     Have user-level access confirmed (finding with 'user flag' or shell access)
          privesc → root:     Have privesc vector identified (high-severity privesc finding)
        """
        phase = self.current_phase()
        phase_idx = self.PHASE_ORDER.index(phase) if phase in self.PHASE_ORDER else 0

        if phase_idx >= len(self.PHASE_ORDER) - 1:
            return None  # Already at root

        services = self.get_services()
        creds = self.get_creds()
        findings = self.get_findings()
        failed = self.get_failed_attempts()

        # Count version-scanned services (have product info)
        scanned_services = [s for s in services if s.get("product")]
        has_password_cred = any(c.get("password") for c in creds)
        has_shell = any("shell" in f.get("category", "") or "foothold" in f.get("description", "").lower()
                        for f in findings)
        has_user_flag = any("user" in f.get("description", "").lower() and "flag" in f.get("description", "").lower()
                           for f in findings)
        has_user_access = any(f.get("category") == "access" and "user" in f.get("description", "").lower()
                             for f in findings)
        has_privesc_vector = any(f.get("category") == "privesc_vector" and f.get("severity") in ("critical", "high")
                                for f in findings)
        has_root = any("root" in f.get("description", "").lower() and "flag" in f.get("description", "").lower()
                       for f in findings)

        next_phase = None

        if phase == "recon" and len(scanned_services) >= 3:
            next_phase = "foothold"
        elif phase == "foothold" and (has_password_cred or has_shell):
            next_phase = "user"
        elif phase == "user" and (has_user_flag or has_user_access):
            next_phase = "privesc"
        elif phase == "privesc" and (has_privesc_vector or has_root):
            next_phase = "root"

        return next_phase

    def maybe_advance_phase(self) -> str | None:
        """Check and advance phase if warranted. Returns new phase or None."""
        new_phase = self.check_phase_advancement()
        if new_phase:
            self.advance_phase(new_phase)
        return new_phase

    # --- Composite Queries (for planner) ---

    def get_state_summary(self) -> dict:
        """Compact summary of current world state for LLM context injection."""
        phase = self.current_phase()
        hosts = self.get_hosts()
        services = self.get_services()
        creds = self.get_creds()
        users = self.get_users()
        shares = self.get_shares()
        findings = self.get_findings()
        failed = self.get_failed_attempts()

        return {
            "phase": phase,
            "hosts": len(hosts),
            "services": [
                {"ip": s["host_ip"], "port": s["port"], "product": s.get("product"), "version": s.get("version")}
                for s in services
            ],
            "creds": [
                {"user": c["username"], "domain": c.get("domain"), "has_password": bool(c.get("password")), "has_hash": bool(c.get("hash"))}
                for c in creds
            ],
            "users": len(users),
            "shares": [{"ip": s["host_ip"], "name": s["name"], "access": s.get("access_level")} for s in shares],
            "findings_count": len(findings),
            "critical_findings": [
                {"category": f["category"], "desc": f["description"]}
                for f in findings if f.get("severity") in ("critical", "high")
            ],
            "failed_actions": [f["action_name"] for f in failed],
        }

    def get_state_predicates(self) -> set[str]:
        """Return current state as a set of predicate strings for action matching."""
        predicates = set()
        phase = self.current_phase()
        predicates.add(f"phase={phase}")

        for svc in self.get_services():
            predicates.add(f"service.port=={svc['port']}")
            predicates.add(f"service.protocol=={svc['protocol']}")
            if svc.get("product"):
                predicates.add(f"service.product=={svc['product'].lower()}")
            if svc.get("state"):
                predicates.add(f"service.state=={svc['state']}")

        for cred in self.get_creds():
            if cred.get("password"):
                predicates.add("has_password")
            if cred.get("hash"):
                predicates.add("has_hash")
            if cred.get("domain"):
                predicates.add(f"cred.domain=={cred['domain']}")
            if cred.get("username"):
                predicates.add("has_cred")

        hosts = self.get_hosts()
        if hosts:
            predicates.add("has_target")
            for h in hosts:
                if h.get("os"):
                    predicates.add(f"os=={h['os'].lower()}")
                if h.get("domain"):
                    predicates.add("domain_joined")

        if self.get_users():
            predicates.add("has_users")

        if self.get_shares():
            predicates.add("has_shares")

        for f in self.get_findings():
            if f.get("severity") in ("critical", "high"):
                predicates.add(f"finding.{f['category']}")

        return predicates


# --- CLI for quick testing ---

def main():
    import argparse
    parser = argparse.ArgumentParser(description="World Model CLI")
    parser.add_argument("db_path", help="Path to world_model.db")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init", help="Initialize empty DB")
    sub.add_parser("summary", help="Print state summary as JSON")
    sub.add_parser("predicates", help="Print current predicates")

    p_host = sub.add_parser("add-host", help="Add a host")
    p_host.add_argument("ip")
    p_host.add_argument("--hostname")
    p_host.add_argument("--os")

    args = parser.parse_args()
    wm = WorldModel(args.db_path)

    if args.cmd == "init":
        print(f"Initialized world model at {args.db_path}")
    elif args.cmd == "summary":
        print(json.dumps(wm.get_state_summary(), indent=2))
    elif args.cmd == "predicates":
        for p in sorted(wm.get_state_predicates()):
            print(p)
    elif args.cmd == "add-host":
        hid = wm.add_host(args.ip, hostname=args.hostname, os=args.os)
        print(f"Host added with id={hid}")
    else:
        parser.print_help()

    wm.close()


if __name__ == "__main__":
    main()
