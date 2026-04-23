#!/usr/bin/env python3
"""
web_session.py — Stateful HTTP session manager for chained web actions.

Problem: each TAR web action was stateless — cookies, auth tokens, CSRF tokens
from 'login' were not reused by subsequent actions. This module provides a
persistent session store per engagement that actions can read/write.

Usage:
    from web_session import WebSession
    session = WebSession(db_path)
    session.set_cookie('PHPSESSID', 'abc123', domain='10.10.10.1')
    session.set_header('Authorization', 'Bearer eyJ...')
    session.set_csrf('_token', 'xyzdef')

    # Get curl flags for use in action command_template
    flags = session.curl_flags()  # returns '-H "Cookie: ..." -H "Authorization: ..."'

    # Get requests-style dict
    headers, cookies = session.get_http_state()

CLI:
    python3 web_session.py <db_path> set-cookie <name> <value> [--domain <d>]
    python3 web_session.py <db_path> set-header <name> <value>
    python3 web_session.py <db_path> set-csrf <name> <value>
    python3 web_session.py <db_path> set-token <token>
    python3 web_session.py <db_path> show
    python3 web_session.py <db_path> curl-flags
    python3 web_session.py <db_path> clear
"""

import json
import sqlite3
import sys
from pathlib import Path


def _ensure_session_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS web_session (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,   -- 'cookie', 'header', 'csrf', 'token', 'meta'
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            domain TEXT DEFAULT '',
            path TEXT DEFAULT '/',
            expires TEXT DEFAULT '',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(key_type, name)
        )
    """)
    conn.commit()


class WebSession:
    """Persistent HTTP session state for a TAR engagement."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        _ensure_session_table(self.conn)

    def close(self):
        self.conn.close()

    def _upsert(self, key_type: str, name: str, value: str, **kwargs):
        domain = kwargs.get('domain', '')
        path = kwargs.get('path', '/')
        expires = kwargs.get('expires', '')
        self.conn.execute("""
            INSERT INTO web_session (key_type, name, value, domain, path, expires)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(key_type, name) DO UPDATE SET
                value=excluded.value,
                domain=excluded.domain,
                path=excluded.path,
                expires=excluded.expires,
                updated_at=CURRENT_TIMESTAMP
        """, (key_type, name, value, domain, path, expires))
        self.conn.commit()

    def set_cookie(self, name: str, value: str, domain: str = '', path: str = '/'):
        """Store an HTTP cookie."""
        self._upsert('cookie', name, value, domain=domain, path=path)

    def set_header(self, name: str, value: str):
        """Store a custom HTTP header (e.g., Authorization)."""
        self._upsert('header', name, value)

    def set_csrf(self, name: str, value: str):
        """Store a CSRF token (form field or header)."""
        self._upsert('csrf', name, value)

    def set_token(self, token: str, token_type: str = 'bearer'):
        """Store an auth token (JWT, API key, etc.)."""
        self._upsert('token', token_type, token)

    def set_meta(self, name: str, value: str):
        """Store arbitrary session metadata (e.g., user_id, role, redirect_url)."""
        self._upsert('meta', name, value)

    def get_cookies(self) -> dict:
        rows = self.conn.execute(
            "SELECT name, value FROM web_session WHERE key_type='cookie'"
        ).fetchall()
        return {r['name']: r['value'] for r in rows}

    def get_headers(self) -> dict:
        rows = self.conn.execute(
            "SELECT name, value FROM web_session WHERE key_type='header'"
        ).fetchall()
        return {r['name']: r['value'] for r in rows}

    def get_csrf(self) -> dict:
        rows = self.conn.execute(
            "SELECT name, value FROM web_session WHERE key_type='csrf'"
        ).fetchall()
        return {r['name']: r['value'] for r in rows}

    def get_token(self, token_type: str = 'bearer') -> str:
        row = self.conn.execute(
            "SELECT value FROM web_session WHERE key_type='token' AND name=?",
            (token_type,)
        ).fetchone()
        return row['value'] if row else ''

    def get_meta(self, name: str) -> str:
        row = self.conn.execute(
            "SELECT value FROM web_session WHERE key_type='meta' AND name=?",
            (name,)
        ).fetchone()
        return row['value'] if row else ''

    def get_http_state(self) -> tuple[dict, dict]:
        """Return (headers_dict, cookies_dict) for use with the requests library."""
        headers = self.get_headers()
        cookies = self.get_cookies()

        token = self.get_token('bearer')
        if token and 'Authorization' not in headers:
            headers['Authorization'] = f'Bearer {token}'

        csrf = self.get_csrf()
        if csrf:
            # Inject first CSRF token as X-CSRF-Token header
            first_name, first_val = next(iter(csrf.items()))
            headers.setdefault('X-CSRF-Token', first_val)

        return headers, cookies

    def curl_flags(self) -> str:
        """Return curl -H / --cookie flags to inject session into curl commands."""
        flags = []
        headers, cookies = self.get_http_state()

        if cookies:
            cookie_str = '; '.join(f'{k}={v}' for k, v in cookies.items())
            flags.append(f'-H "Cookie: {cookie_str}"')

        for name, value in headers.items():
            flags.append(f'-H "{name}: {value}"')

        return ' '.join(flags)

    def show(self) -> str:
        """Return a human-readable session summary."""
        lines = ['## Web Session State']
        for key_type in ('token', 'cookie', 'header', 'csrf', 'meta'):
            rows = self.conn.execute(
                "SELECT name, value FROM web_session WHERE key_type=? ORDER BY name",
                (key_type,)
            ).fetchall()
            if rows:
                lines.append(f'\n{key_type.upper()}:')
                for r in rows:
                    val = r['value']
                    if len(val) > 60:
                        val = val[:57] + '...'
                    lines.append(f'  {r["name"]}: {val}')
        return '\n'.join(lines)

    def clear(self):
        """Wipe all session state."""
        self.conn.execute("DELETE FROM web_session")
        self.conn.commit()

    def import_from_curl_output(self, curl_output: str):
        """
        Parse Set-Cookie headers from curl -v or curl -D output and store them.

        Handles: Set-Cookie: name=value; Path=/; HttpOnly; SameSite=Strict
        """
        import re
        for match in re.finditer(
            r'[Ss]et-[Cc]ookie:\s*([^=\s]+)=([^;\n]+)(.*)',
            curl_output
        ):
            name = match.group(1).strip()
            value = match.group(2).strip()
            rest = match.group(3)
            domain = ''
            dm = re.search(r'[Dd]omain=([^\s;]+)', rest)
            if dm:
                domain = dm.group(1)
            self.set_cookie(name, value, domain=domain)

    def import_from_jwt(self, token: str):
        """Store a JWT token and decode its claims as metadata."""
        import base64
        self.set_token(token, 'bearer')
        try:
            parts = token.split('.')
            if len(parts) == 3:
                payload_b64 = parts[1] + '=='*((4-len(parts[1])%4)%4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                for key in ('sub', 'email', 'role', 'user_id', 'username', 'exp'):
                    if key in payload:
                        self.set_meta(f'jwt_{key}', str(payload[key]))
        except Exception:
            pass


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    db_path = sys.argv[1]
    cmd = sys.argv[2]
    session = WebSession(db_path)

    try:
        if cmd == 'set-cookie':
            name, value = sys.argv[3], sys.argv[4]
            domain = sys.argv[6] if len(sys.argv) > 6 and sys.argv[5] == '--domain' else ''
            session.set_cookie(name, value, domain=domain)
            print(f"Cookie set: {name}={value[:40]}")

        elif cmd == 'set-header':
            session.set_header(sys.argv[3], sys.argv[4])
            print(f"Header set: {sys.argv[3]}")

        elif cmd == 'set-csrf':
            session.set_csrf(sys.argv[3], sys.argv[4])
            print(f"CSRF set: {sys.argv[3]}")

        elif cmd == 'set-token':
            token = sys.argv[3]
            session.import_from_jwt(token)
            print(f"Token stored ({len(token)} chars)")

        elif cmd == 'show':
            print(session.show())

        elif cmd == 'curl-flags':
            print(session.curl_flags())

        elif cmd == 'clear':
            session.clear()
            print("Session cleared")

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)
    finally:
        session.close()


if __name__ == '__main__':
    main()
