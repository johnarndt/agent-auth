from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "agent_auth.db"


def _ensure_db_dir() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    _ensure_db_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def connection_ctx() -> sqlite3.Connection:
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connection_ctx() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                owner_type TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                created_by_user_id TEXT,
                status TEXT NOT NULL,
                trust_level TEXT NOT NULL,
                auth_method TEXT NOT NULL,
                description TEXT,
                metadata_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_credentials (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                public_id TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                last_used_at TEXT,
                expires_at TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS capabilities (
                id TEXT PRIMARY KEY,
                key TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                resource_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_capability_grants (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                scope_type TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                conditions_json TEXT,
                expires_at TEXT,
                granted_by_user_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                FOREIGN KEY(capability_id) REFERENCES capabilities(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS registration_tokens (
                id TEXT PRIMARY KEY,
                owner_type TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                intended_agent_type TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_by_user_id TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS enrollment_requests (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                requested_by_type TEXT NOT NULL,
                registration_token_id TEXT NOT NULL,
                requested_capabilities_json TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewed_by_user_id TEXT,
                review_notes TEXT,
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                FOREIGN KEY(registration_token_id) REFERENCES registration_tokens(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS agent_audit_events (
                id TEXT PRIMARY KEY,
                agent_id TEXT,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                resource_type TEXT,
                resource_id TEXT,
                capability TEXT,
                decision TEXT,
                reason TEXT,
                metadata_json TEXT,
                created_at TEXT NOT NULL
            );
            """
        )

        seed_capabilities = [
            ("files.read", "Files Read", "Read file objects", "workspace", "low"),
            ("email.send", "Email Send", "Send outbound email", "workspace", "high"),
            ("crm.contacts.write", "CRM Contacts Write", "Create/update contacts", "organization", "medium"),
            ("mcp.server.use:github", "MCP GitHub", "Use GitHub MCP server", "organization", "medium"),
        ]

        for key, name, description, resource_type, risk_level in seed_capabilities:
            conn.execute(
                """
                INSERT OR IGNORE INTO capabilities (id, key, name, description, resource_type, risk_level, created_at)
                VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, datetime('now'))
                """,
                (key, name, description, resource_type, risk_level),
            )
