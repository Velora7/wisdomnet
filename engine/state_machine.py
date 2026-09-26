"""WisdomNet per-source-IP attack state machine.

Models the progression:
    IDLE → RECON → CREDENTIAL → ACCESS → EXECUTION → EXFIL_ATTEMPT

Higher states imply all earlier stages occurred. Once a source reaches a
state, it never regresses. This is intentional: an attacker who obtained
decoy access remains 'ACCESS' even if they later send a probe.
"""

STATES = ["IDLE", "RECON", "CREDENTIAL", "ACCESS", "EXECUTION", "EXFIL_ATTEMPT"]
ORDER = {s: i for i, s in enumerate(STATES)}

# Which state each event_type advances the attacker to.
TRANSITIONS = {
    "service_discovery":     "RECON",
    "http_probe":            "RECON",
    "ssh_failed_login":      "CREDENTIAL",
    "ftp_login_attempt":     "CREDENTIAL",
    "db_connection_attempt": "CREDENTIAL",
    "ssh_successful_login":  "ACCESS",
    "command_execution":     "EXECUTION",
    "credential_access":     "EXFIL_ATTEMPT",
    "file_access":           "EXFIL_ATTEMPT",
}


def advance(current_state, event_type):
    """Return the new state after seeing event_type. Never regresses."""
    target = TRANSITIONS.get(event_type)
    if target is None:
        return current_state
    if ORDER[target] > ORDER[current_state]:
        return target
    return current_state


def classify(score):
    if score <= 30:
        return "Informational"
    if score <= 70:
        return "Medium"
    if score <= 140:
        return "High"
    return "Critical"


if __name__ == "__main__":
    # Quick self-test
    s = "IDLE"
    for e in ["service_discovery", "ssh_failed_login",
              "ssh_failed_login", "ssh_successful_login",
              "command_execution", "http_probe"]:
        s = advance(s, e)
        print(f"{e:25s} → {s}")
    print()
    for score in [10, 50, 100, 225]:
        print(f"score {score:4d} → {classify(score)}")
