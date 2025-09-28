# backend/db.py
import sqlite3
from pathlib import Path

DB = Path(__file__).parent / "data" / "app.db"
DB.parent.mkdir(parents=True, exist_ok=True)

def get_conn():
    return sqlite3.connect(DB, check_same_thread=False)

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    domain TEXT,
                    verdict TEXT,
                    confidence REAL,
                    model_label INTEGER,
                    external_checks TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                 )""")
    c.execute("""CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_id INTEGER,
                    user_label TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                 )""")
    conn.commit()
    conn.close()

def save_check(url, domain, verdict, confidence, model_label, external_checks=None):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO checks (url,domain,verdict,confidence,model_label,external_checks) VALUES (?,?,?,?,?,?)",
              (url, domain, verdict, confidence, model_label, external_checks))
    cid = c.lastrowid
    conn.commit()
    conn.close()
    return cid

def get_recent_checks(limit=20):
    conn = get_conn()
    c = conn.cursor()
    rows = c.execute("SELECT id,url,domain,verdict,confidence,created_at FROM checks ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [{"id":r[0],"url":r[1],"domain":r[2],"verdict":r[3],"confidence":r[4],"created_at":r[5]} for r in rows]

def save_feedback(check_id, user_label):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO feedback (check_id,user_label) VALUES (?,?)", (check_id, user_label))
    conn.commit()
    conn.close()
