"""WisdomNet analyst dashboard."""
import json
import os
import sqlite3
from flask import Flask, render_template

ROOT = os.path.join(os.path.dirname(__file__), "..")
DB_PATH = os.path.join(ROOT, "db", "honeycampus.db")

app = Flask(__name__)


def load_incidents():
    if not os.path.exists(DB_PATH):
        return []
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    rows = db.execute("""
        SELECT * FROM incidents
        ORDER BY
          CASE severity
            WHEN 'Critical' THEN 1
            WHEN 'High'     THEN 2
            WHEN 'Medium'   THEN 3
            ELSE 4
          END,
          last_seen DESC
    """).fetchall()
    db.close()

    incidents = []
    for r in rows:
        incidents.append({
            "source_ip":   r["source_ip"],
            "state":       r["state"],
            "score":       r["score"],
            "severity":    r["severity"],
            "first_seen":  r["first_seen"],
            "last_seen":   r["last_seen"],
            "event_count": r["event_count"],
            "event_types": json.loads(r["event_types"]),
            "techniques":  json.loads(r["techniques"]),
            "services":    json.loads(r["services"]),
        })
    return incidents


RECOMMENDED = {
    "Critical": [
        "Block source IP at perimeter",
        "Review adjacent hosts for lateral movement",
        "Check for credential reuse across services",
        "Preserve event log (hash chain)",
        "Escalate to security team",
    ],
    "High": [
        "Monitor source IP for continued activity",
        "Verify no legitimate use of targeted services",
        "Preserve logs",
    ],
    "Medium": [
        "Log for trend analysis",
        "Watch for escalation",
    ],
    "Informational": [
        "No action required",
    ],
}


@app.route("/")
def index():
    incidents = load_incidents()
    return render_template("index.html",
                           incidents=incidents,
                           recommended=RECOMMENDED)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
