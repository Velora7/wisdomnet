"""Seed a realistic multi-stage attack from a single source IP."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "collector"))
from writer import write_event

IP = "10.10.10.50"
PORT = 51422

# Stage 1: recon
write_event(IP, PORT, "student-portal", "service_discovery", {})
write_event(IP, PORT, "library-system", "http_probe", {"path": "/"})

# Stage 2: credential attack
for i in range(5):
    write_event(IP, PORT, "research-server", "ssh_failed_login",
                {"username": "root", "password": f"attempt{i}"})

# Stage 3: decoy access
write_event(IP, PORT, "research-server", "ssh_successful_login",
            {"username": "admin", "password": "decoy123"})

# Stage 4: execution
write_event(IP, PORT, "research-server", "command_execution",
            {"command": "whoami"})

print("Seeded 9 events from", IP)
