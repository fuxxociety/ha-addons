"""SQLite persistence: hosts (one row per MAC, or per IP until its MAC is known), events, 5-minute stat buckets."""
import json
import sqlite3
import time

BUCKET = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts(
  key TEXT PRIMARY KEY,           -- 'aa:bb:cc:dd:ee:ff', or 'ip:192.168.1.5' until a MAC is learned
  data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(ts REAL, key TEXT, ip TEXT, kind TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ev_key_ts ON events(key, ts);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS stats(
  bucket INTEGER, key TEXT, probe TEXT,
  sent INTEGER DEFAULT 0, ok INTEGER DEFAULT 0, val_sum REAL DEFAULT 0, val_n INTEGER DEFAULT 0,
  PRIMARY KEY(bucket, key, probe));
"""


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        self.db.commit()

    # hosts -------------------------------------------------------------
    def load_hosts(self):
        return {k: json.loads(d) for k, d in self.db.execute("SELECT key, data FROM hosts")}

    def save_host(self, key, data):
        self.db.execute("INSERT INTO hosts(key, data) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET data=excluded.data",
                        (key, json.dumps(data)))
        self.db.commit()

    def delete_host(self, key):
        self.db.execute("DELETE FROM hosts WHERE key=?", (key,))
        self.db.commit()

    def rekey(self, old, new):
        """Move an IP-keyed host's history onto its MAC key."""
        self.db.execute("UPDATE events SET key=? WHERE key=?", (new, old))
        self.db.execute("""INSERT INTO stats(bucket, key, probe, sent, ok, val_sum, val_n)
                           SELECT bucket, ?, probe, sent, ok, val_sum, val_n FROM stats WHERE key=? AND true
                           ON CONFLICT(bucket, key, probe) DO UPDATE SET
                             sent=sent+excluded.sent, ok=ok+excluded.ok,
                             val_sum=val_sum+excluded.val_sum, val_n=val_n+excluded.val_n""", (new, old))
        self.db.execute("DELETE FROM stats WHERE key=?", (old,))
        self.db.commit()

    # events / stats ----------------------------------------------------
    def event(self, key, ip, kind, detail="", ts=None):
        self.db.execute("INSERT INTO events VALUES(?, ?, ?, ?, ?)", (ts or time.time(), key, ip, kind, detail))
        self.db.commit()

    def stat(self, key, probe, ok, value=None, ts=None):
        b = int((ts or time.time()) // BUCKET * BUCKET)
        self.db.execute("""INSERT INTO stats(bucket, key, probe, sent, ok, val_sum, val_n) VALUES(?, ?, ?, 1, ?, ?, ?)
                           ON CONFLICT(bucket, key, probe) DO UPDATE SET
                             sent=sent+1, ok=ok+excluded.ok,
                             val_sum=val_sum+excluded.val_sum, val_n=val_n+excluded.val_n""",
                        (b, key, probe, int(bool(ok)), value or 0.0, int(value is not None)))
        # committed by flush(); stats are high-volume

    def flush(self):
        self.db.commit()

    def stats_since(self, since):
        q = "SELECT key, probe, SUM(sent), SUM(ok), SUM(val_sum), SUM(val_n) FROM stats WHERE bucket>=? GROUP BY key, probe"
        return self.db.execute(q, (int(since // BUCKET * BUCKET),)).fetchall()

    def events_since(self, since, key=None):
        if key:
            q, a = "SELECT ts, key, ip, kind, detail FROM events WHERE ts>=? AND key=? ORDER BY ts DESC", (since, key)
        else:
            q, a = "SELECT ts, key, ip, kind, detail FROM events WHERE ts>=? ORDER BY ts", (since,)
        return self.db.execute(q, a).fetchall()

    def clear_history(self):
        self.db.execute("DELETE FROM events")
        self.db.execute("DELETE FROM stats")
        self.db.commit()

    def prune(self, days):
        cut = time.time() - days * 86400
        self.db.execute("DELETE FROM events WHERE ts<?", (cut,))
        self.db.execute("DELETE FROM stats WHERE bucket<?", (cut,))
        self.db.commit()
