"""PostgreSQL database connection and schema management."""

import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://wgadmin:wgadmin@127.0.0.1:5432/wgadmin")

_pool: pool.SimpleConnectionPool | None = None


def _get_pool() -> pool.SimpleConnectionPool:
    global _pool
    if _pool is None or _pool.closed:
        _pool = pool.SimpleConnectionPool(1, 10, DATABASE_URL)
    return _pool


def get_conn():
    return _get_pool().getconn()


def put_conn(conn):
    _get_pool().putconn(conn)


def query(sql: str, params: tuple = (), fetchone: bool = False, fetchall: bool = False, commit: bool = False):
    """Execute a query and return results."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            if commit:
                conn.commit()
                if cur.description:
                    return cur.fetchone() if fetchone else cur.fetchall()
                return cur.rowcount
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
            return cur.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        put_conn(conn)


def execute(sql: str, params: tuple = ()) -> int:
    """Execute a write query, return rowcount."""
    return query(sql, params, commit=True)


def fetchone(sql: str, params: tuple = ()) -> dict | None:
    return query(sql, params, fetchone=True)


def fetchall(sql: str, params: tuple = ()) -> list[dict]:
    return query(sql, params, fetchall=True)


def init_schema():
    """Create tables if they don't exist."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    firstname TEXT NOT NULL,
                    lastname TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'readonly',
                    active BOOLEAN NOT NULL DEFAULT FALSE,
                    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
                    totp_secret TEXT DEFAULT '',
                    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    invite_token TEXT DEFAULT '',
                    invite_expires TEXT DEFAULT '',
                    created TEXT NOT NULL,
                    accepted TEXT DEFAULT ''
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created TEXT NOT NULL,
                    expires TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS portal_sessions (
                    token TEXT PRIMARY KEY,
                    peer_id INTEGER NOT NULL,
                    created TEXT NOT NULL,
                    expires TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    customer TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'all',
                    created TEXT NOT NULL,
                    last_used TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    note TEXT DEFAULT '',
                    user_id INTEGER DEFAULT 0,
                    allowed_ips TEXT DEFAULT ''
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS request_log (
                    id SERIAL PRIMARY KEY,
                    ts TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    client_ip TEXT DEFAULT '',
                    key_prefix TEXT DEFAULT '',
                    customer TEXT DEFAULT '',
                    scope TEXT DEFAULT ''
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wg_interfaces (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    listen_port INTEGER NOT NULL DEFAULT 51820,
                    address TEXT NOT NULL,
                    subnet TEXT NOT NULL,
                    dns TEXT DEFAULT '',
                    post_up TEXT DEFAULT '',
                    post_down TEXT DEFAULT '',
                    endpoint TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    created TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wg_peers (
                    id SERIAL PRIMARY KEY,
                    interface_id INTEGER NOT NULL REFERENCES wg_interfaces(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    preshared_key TEXT DEFAULT '',
                    allowed_ips TEXT NOT NULL,
                    dns TEXT DEFAULT '',
                    persistent_keepalive INTEGER DEFAULT 25,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    hostbill_service_id INTEGER DEFAULT 0,
                    hostbill_client_id INTEGER DEFAULT 0,
                    note TEXT DEFAULT '',
                    created TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wg_acl_profiles (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT DEFAULT '',
                    allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',
                    fw_rules TEXT DEFAULT '',
                    is_default BOOLEAN DEFAULT FALSE,
                    created TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wg_ip_allocations (
                    id SERIAL PRIMARY KEY,
                    interface_id INTEGER NOT NULL REFERENCES wg_interfaces(id) ON DELETE CASCADE,
                    ip_address TEXT NOT NULL,
                    peer_id INTEGER REFERENCES wg_peers(id) ON DELETE SET NULL,
                    allocated BOOLEAN NOT NULL DEFAULT TRUE,
                    allocated_at TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wg_groups (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT DEFAULT '',
                    acl_profile_id INTEGER DEFAULT 0,
                    created TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS integrations (
                    id SERIAL PRIMARY KEY,
                    provider TEXT NOT NULL,
                    name TEXT NOT NULL,
                    config TEXT DEFAULT '{}',
                    tokens TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'pending',
                    last_sync TEXT DEFAULT '',
                    created TEXT NOT NULL
                )
            """)
            # Migrations for existing installs
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE wg_peers ADD COLUMN acl_profile_id INTEGER DEFAULT 0;
                EXCEPTION WHEN duplicate_column THEN NULL;
                END $$
            """)
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE wg_peers ADD COLUMN group_id INTEGER DEFAULT 0;
                EXCEPTION WHEN duplicate_column THEN NULL;
                END $$
            """)
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE wg_peers ADD COLUMN portal_email TEXT DEFAULT '';
                EXCEPTION WHEN duplicate_column THEN NULL;
                END $$
            """)
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE wg_peers ADD COLUMN portal_password_hash TEXT DEFAULT '';
                EXCEPTION WHEN duplicate_column THEN NULL;
                END $$
            """)
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE wg_peers ADD COLUMN activated BOOLEAN DEFAULT FALSE;
                EXCEPTION WHEN duplicate_column THEN NULL;
                END $$
            """)
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE wg_peers ADD COLUMN activation_token TEXT DEFAULT '';
                EXCEPTION WHEN duplicate_column THEN NULL;
                END $$
            """)
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE wg_peers ADD COLUMN activation_method TEXT DEFAULT '';
                EXCEPTION WHEN duplicate_column THEN NULL;
                END $$
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_wg_peers_interface ON wg_peers(interface_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_wg_peers_pubkey ON wg_peers(public_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_wg_peers_hostbill ON wg_peers(hostbill_service_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_wg_ip_alloc_interface ON wg_ip_allocations(interface_id)")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_wg_ip_unique ON wg_ip_allocations(interface_id, ip_address)")
        conn.commit()
    finally:
        put_conn(conn)
