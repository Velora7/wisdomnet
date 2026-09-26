import hashlib, json, os

GENESIS = "0" * 64
LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "events.jsonl")


def verify(path=LOG_PATH):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None, "empty"     # distinct from "OK"
    prev = GENESIS
    count = 0
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            count += 1
            e = json.loads(line)
            stored = e.pop("hash")
            body = json.dumps(e, sort_keys=True).encode()
            expected = hashlib.sha256(prev.encode() + body).hexdigest()
            if expected != stored:
                return False, i
            prev = stored
    return True, count


if __name__ == "__main__":
    ok, info = verify()
    if ok is None:
        print("EMPTY LOG — nothing to verify")
    elif ok:
        print(f"Chain OK ({info} events)")
    else:
        print(f"CHAIN BROKEN at line {info}")
