import sqlite3
import os
DB_PATH = "/home/kali/current/notes/fact_lattice.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
conn = sqlite3.connect(DB_PATH)
conn.execute("CREATE TABLE IF NOT EXISTS facts (id INTEGER PRIMARY KEY AUTOINCREMENT, epoch TEXT, type TEXT, content TEXT, tags TEXT, verified INTEGER DEFAULT 0, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
conn.commit()
conn.close()
