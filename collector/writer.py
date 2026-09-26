import hashlib, json, os, uuid
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "events.jsonl")
GENESIS = "0" * 64


def _last_hash():
    if not os.path.exists(LOG_PATH) or os.path.getsize(LOG_PATH) == 0:
        return GENESIS
    last_valid = GENESIS
    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                last_valid = json.loads(line)["hash"]
            except (json.JSONDecodeError, KeyError):
                continue
    return last_valid


def write_event(source_ip, source_port, service, event_type, payload):
    prev = _last_hash()
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": source_port,
        "service": service,
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev,
    }
    body = json.dumps(event, sort_keys=True).encode()
    event["hash"] = hashlib.sha256(prev.encode() + body).hexdigest()
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    return event


if __name__ == "__main__":
    write_event("10.10.10.50", 51422, "research-server",
                "ssh_failed_login", {"username": "root", "password": "toor"})
    write_event("10.10.10.50", 51422, "research-server",
                "command_execution", {"command": "whoami"})
    print("Wrote 2 test events to", LOG_PATH)
