"""
Database layer for BlockVerify using SQLite.
Stores file records, verification history, and anomaly logs.
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Optional
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.environ.get("DB_PATH", "blockverify.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name   TEXT    NOT NULL,
            file_hash   TEXT    NOT NULL,
            merkle_root TEXT    NOT NULL,
            file_size   INTEGER,
            block_id    INTEGER,
            tx_hash     TEXT,
            chain_mode  TEXT    DEFAULT 'mock',
            status      TEXT    DEFAULT 'safe',
            uploaded_at TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS verifications (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id      INTEGER NOT NULL,
            file_name    TEXT,
            new_hash     TEXT    NOT NULL,
            is_intact    INTEGER NOT NULL,
            tx_hash      TEXT,
            verified_at  TEXT    NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id)
        );

        CREATE TABLE IF NOT EXISTS anomalies (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name   TEXT,
            anom_type   TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            message     TEXT    NOT NULL,
            detected_at TEXT    NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0
        );
    """)
    conn.commit()
    
    # Add owner_email if it doesn't exist
    try:
        cur.execute("ALTER TABLE files ADD COLUMN owner_email TEXT;")
        conn.commit()
    except sqlite3.OperationalError:
        pass # Column already exists
        
    # Add auto_correct if it doesn't exist
    try:
        cur.execute("ALTER TABLE files ADD COLUMN auto_correct BOOLEAN DEFAULT 0;")
        conn.commit()
    except sqlite3.OperationalError:
        pass
        
    # Add is_admin if it doesn't exist
    try:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0;")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Seed a default admin account (change credentials immediately after first login!)
    cur.execute("SELECT id FROM users WHERE username='admin'")
    if not cur.fetchone():
        pwd_hash = generate_password_hash('admin')
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", ('admin', pwd_hash))
        conn.commit()

    conn.close()

def create_user(username, password, is_admin=False):
    conn = get_db()
    cur = conn.cursor()
    pwd_hash = generate_password_hash(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", (username, pwd_hash, 1 if is_admin else 0))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

def verify_user(username, password) -> tuple:
    """Returns (is_valid: bool, is_admin: bool)"""
    conn = get_db()
    row = conn.execute("SELECT password_hash, is_admin FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row and check_password_hash(row['password_hash'], password):
        return True, bool(row['is_admin'])
    return False, False

def get_all_users() -> List[dict]:
    conn = get_db()
    rows = conn.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_user_credentials(user_id: int, password: str, is_admin: bool):
    conn = get_db()
    if password:
        pwd_hash = generate_password_hash(password)
        conn.execute("UPDATE users SET password_hash = ?, is_admin = ? WHERE id = ?", (pwd_hash, 1 if is_admin else 0, user_id))
    else:
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if is_admin else 0, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id: int):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def delete_file_record(file_id: int):
    conn = get_db()
    conn.execute("DELETE FROM verifications WHERE file_id = ?", (file_id,))
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()


def insert_file(file_name, file_hash, merkle_root, file_size,
                block_id, tx_hash, chain_mode, owner_email="", auto_correct=False) -> int:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO files (file_name, file_hash, merkle_root, file_size,
                           block_id, tx_hash, chain_mode, status, uploaded_at, owner_email, auto_correct)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'safe', ?, ?, ?)
    """, (file_name, file_hash, merkle_root, file_size,
          block_id, tx_hash, chain_mode,
          datetime.utcnow().isoformat(), owner_email, auto_correct))
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_file_by_id(file_id: int) -> Optional[dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_files() -> List[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM files ORDER BY uploaded_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_file_status(file_id: int, status: str):
    conn = get_db()
    conn.execute("UPDATE files SET status = ? WHERE id = ?", (status, file_id))
    conn.commit()
    conn.close()


def insert_verification(file_id, file_name, new_hash, is_intact, tx_hash) -> int:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO verifications (file_id, file_name, new_hash, is_intact, tx_hash, verified_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (file_id, file_name, new_hash, 1 if is_intact else 0, tx_hash,
          datetime.utcnow().isoformat()))
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_verifications(file_id: int = None) -> List[dict]:
    conn = get_db()
    if file_id:
        rows = conn.execute(
            "SELECT * FROM verifications WHERE file_id = ? ORDER BY verified_at DESC",
            (file_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM verifications ORDER BY verified_at DESC LIMIT 50"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def insert_anomaly(file_name, anom_type, severity, message) -> int:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO anomalies (file_name, anom_type, severity, message, detected_at)
        VALUES (?, ?, ?, ?, ?)
    """, (file_name, anom_type, severity, message, datetime.utcnow().isoformat()))
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_anomalies() -> List[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM anomalies ORDER BY detected_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = get_db()
    total_files  = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    safe_files   = conn.execute("SELECT COUNT(*) FROM files WHERE status='safe'").fetchone()[0]
    tampered     = conn.execute("SELECT COUNT(*) FROM files WHERE status='tampered'").fetchone()[0]
    verif_count  = conn.execute("SELECT COUNT(*) FROM verifications").fetchone()[0]
    anomaly_count= conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    conn.close()
    return {
        "total_files": total_files,
        "safe_files": safe_files,
        "tampered_files": tampered,
        "verifications": verif_count,
        "anomalies": anomaly_count
    }
