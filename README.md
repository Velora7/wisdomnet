WisdomNet

A simple network security project that uses fake services to catch suspicious activity early.

WHAT IT DOES

WisdomNet puts fake services on a network. These services look real, but they are not connected to anything real. No normal user has a reason to touch them. So when anyone does, the system records it, groups the events, gives them a score, and shows the result on a web page.

THE IDEA

Think of a bank that puts a fake vault in a back room. Real customers never go near it. But a robber tries to open it. That is how this project works on a network.

FILES AND FOLDERS

sensor folder: the fake services. This has OpenCanary for FTP, HTTP, and MySQL. It also has a fake SSH shell written in Python.

collector folder: the event writer and the verifier. These save events and check the hash chain.

engine folder: the state machine, the scoring rules, and the incident builder.

dashboard folder: the web page that shows the incidents.

logs folder: the event log files.

db folder: the SQLite database that stores the incidents.

docs folder: the documentation.

HOW TO RUN

First, start the fake services.

  docker compose up -d

Then start the tailer and the fake shell.

  python sensor/tailer.py > /tmp/tailer.log 2>&1 &
  python sensor/fake_shell.py > /tmp/fake_shell.log 2>&1 &

Now run a scan to act as an attacker.

  nmap -p 2121,8080,3306 -sV 127.0.0.1

Then build the incidents and start the dashboard.

  python engine/incident.py
  python dashboard/app.py

Open this address in your browser.

  http://127.0.0.1:5000/

THE FIVE STATES

The state machine moves each source through five stages.

  IDLE
  RECON
  CREDENTIAL
  ACCESS
  EXECUTION

The state never moves backward. Once a source reaches EXECUTION, it stays there. This stops an attacker from hiding by doing something small later.

THE SCORE

Each event type has a score.

  Service discovery: 10
  HTTP probe: 15
  Failed login: 25
  Successful login: 70
  Command execution: 90

Repeated events are capped so a long scan cannot inflate the score. A bonus of 40 points is added when the source reaches the EXECUTION stage.

THE MITRE MAPPING

Events are labelled with MITRE ATT&CK technique IDs.

  T1046: Network Service Discovery
  T1110: Brute Force
  T1078: Valid Accounts
  T1059: Command and Scripting Interpreter

TEST RESULT

Two incidents were produced.

  172.18.0.1: state CREDENTIAL, score 105, severity High
  127.0.0.1:  state EXECUTION,  score 290, severity Critical

The hash chain was verified and no change was found.

TOOLS USED

  Python 3.12
  Docker and Docker Compose
  OpenCanary
  Paramiko
  Flask
  SQLite
  YAML
  SHA-256
  nmap
  sshpass

WHAT THE PROJECT DOES NOT DO

  It does not block attackers.
  It does not detect every attack.
  It only sees activity that touches the fake services.
  It is not a replacement for a full SIEM.

AUTHOR

GitHub: velora7
