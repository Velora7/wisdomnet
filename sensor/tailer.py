"""Bridge: tail OpenCanary's JSON log to WisdomNet hash-chained event log."""
import json
import os
import sys
import time

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "collector"))
from writer import write_event

OPENCANARY_LOG = os.path.join(ROOT, "logs", "opencanary.log")
POS_FILE = os.path.join(ROOT, "logs", ".tailer_pos")


def map_event(entry):
    src = entry.get("src_host") or entry.get("src_ip")
    if not src:
        return None

    port = int(entry.get("src_port") or 0)
    logtype = int(entry.get("logtype") or 0)
    payload = entry.get("logdata", {}) or {}

    # OpenCanary Docker image uses these SSH logtypes:
    #   4000 = new connection
    #   4001 = version exchange (banner grab)
    #   4002 = login attempt (has USERNAME / PASSWORD)
    if logtype == 4000:
        return (src, port, "research-server", "service_discovery",
                {"probe": "ssh_connect"})
    if logtype == 4001:
        return (src, port, "research-server", "service_discovery",
                {"probe": "ssh_version",
                 "remote": payload.get("REMOTEVERSION", "")})
    if logtype == 4002:
        user = payload.get("USERNAME") or "unknown"
        pw = payload.get("PASSWORD") or "unknown"
        return (src, port, "research-server", "ssh_failed_login",
                {"username": user, "password": pw})

    # Older doc logtypes (still supported if the image emits them):
    if logtype == 3000:
        return (src, port, "research-server", "service_discovery",
                {"probe": "ssh_connect"})
    if logtype == 5000:
        user = payload.get("USERNAME") or "unknown"
        pw = payload.get("PASSWORD") or "unknown"
        return (src, port, "research-server", "ssh_failed_login",
                {"username": user, "password": pw})
    if logtype == 6000:
        cmd = payload.get("COMMAND") or payload.get("command") or ""
        return (src, port, "research-server", "command_execution",
                {"command": cmd})

    # HTTP
    if logtype == 2000:
        path = payload.get("PATH") or payload.get("path") or "/"
        return (src, port, "library-system", "http_probe", {"path": path})
    if logtype == 3001:
        # HTTP POST with credentials
        user = payload.get("USERNAME") or payload.get("username") or "unknown"
        pw = payload.get("PASSWORD") or payload.get("password") or "unknown"
        return (src, port, "student-portal", "ssh_failed_login",
                {"username": user, "password": pw})

    # FTP / MySQL
    if logtype == 1000:
        return (src, port, "staff-admin", "ftp_login_attempt", {})
    if logtype == 8000:
        return (src, port, "finance-test", "db_connection_attempt", {})
    if logtype == 12000:
        return (src, port, "multiple", "service_discovery", {})

    return None


def follow(path=OPENCANARY_LOG, poll=0.5):
    print(f"[tailer] following {path}")
    while not os.path.exists(path):
        time.sleep(poll)
    pos = 0
    if os.path.exists(POS_FILE):
        try:
            pos = int(open(POS_FILE).read().strip())
        except (ValueError, OSError):
            pos = 0
    with open(path) as f:
        f.seek(pos)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            mapped = map_event(entry)
            open(POS_FILE, "w").write(str(f.tell()))
            if mapped is None:
                continue
            write_event(*mapped)
            print(f"[tailer] {mapped[3]:22s} from {mapped[0]}")


if __name__ == "__main__":
    try:
        follow()
    except KeyboardInterrupt:
        print("\n[tailer] stopped")
