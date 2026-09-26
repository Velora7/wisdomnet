"""Build incidents from the event log.

For each source IP:
  - replay events through the state machine
  - sum weighted scores with per-type caps (diminishing returns)
  - apply sequence bonus if state >= EXECUTION
  - collect MITRE techniques
  - classify severity
  - persist to SQLite
"""
import json
import os
import sqlite3
import yaml
from collections import defaultdict

from state_machine import advance, classify, ORDER

ROOT = os.path.join(os.path.dirname(__file__), "..")
LOG_PATH = os.path.join(ROOT, "logs", "events.jsonl")
DB_PATH = os.path.join(ROOT, "db", "honeycampus.db")
SCORING = yaml.safe_load(open(os.path.join(ROOT, "engine", "scoring.yaml")))
MITRE = yaml.safe_load(open(os.path.join(ROOT, "engine", "mitre.yaml")))["mapping"]

# Max number of events of each type that contribute to score.
# Beyond this, additional events add 0 points (still logged/counted).
SCORE_CAPS = {
    "service_discovery": 3,
    "http_probe": 3,
    "ssh_failed_login": 3,
    "ftp_login_attempt": 3,
    "db_connection_attempt": 3,
    "ssh_successful_login": 1,
    "command_execution": 5,
    "credential_access": 1,
    "file_access": 1,
}


def load_events():
    if not os.path.exists(LOG_PATH):
        return []
    events = []
    with open(LOG_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def build_incidents():
    events = load_events()
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["source_ip"]].append(e)

    incidents = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda x: x["timestamp"])
        state = "IDLE"
        score = 0
        techniques = set()
        event_types = defaultdict(int)
        scored_counts = defaultdict(int)

        for e in evs:
            et = e["event_type"]
            event_types[et] += 1
            cap = SCORE_CAPS.get(et, 999)
            if scored_counts[et] < cap:
                score += SCORING["weights"].get(et, 0)
                scored_counts[et] += 1
            if et in MITRE:
                techniques.add(MITRE[et]["id"])
            state = advance(state, et)

        if ORDER[state] >= ORDER["EXECUTION"]:
            score += SCORING["sequence_bonus"]

        severity = classify(score)

        incidents.append({
            "source_ip": ip,
            "state": state,
            "score": score,
            "severity": severity,
            "first_seen": evs[0]["timestamp"],
            "last_seen": evs[-1]["timestamp"],
            "event_count": len(evs),
            "event_types": dict(event_types),
            "techniques": sorted(techniques),
            "services": sorted({e["service"] for e in evs}),
        })
    return incidents


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            source_ip     TEXT PRIMARY KEY,
            state         TEXT,
            score         INTEGER,
            severity      TEXT,
            first_seen    TEXT,
            last_seen     TEXT,
            event_count   INTEGER,
            event_types   TEXT,
            techniques    TEXT,
            services      TEXT
        )
    """)
    db.commit()
    return db


def persist(incidents):
    db = init_db()
    for i in incidents:
        db.execute("""
            INSERT OR REPLACE INTO incidents
            (source_ip, state, score, severity, first_seen, last_seen,
             event_count, event_types, techniques, services)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            i["source_ip"], i["state"], i["score"], i["severity"],
            i["first_seen"], i["last_seen"], i["event_count"],
            json.dumps(i["event_types"]),
            json.dumps(i["techniques"]),
            json.dumps(i["services"]),
        ))
    db.commit()
    db.close()


if __name__ == "__main__":
    incidents = build_incidents()
    persist(incidents)
    print(f"Built {len(incidents)} incident(s):")
    for i in incidents:
        print(f"  {i['source_ip']}  state={i['state']:12s} "
              f"score={i['score']:4d}  severity={i['severity']}")
