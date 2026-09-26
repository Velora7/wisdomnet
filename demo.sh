#!/bin/bash

cd ~/wisdomnet

echo "=== 1. Project folder ==="
tree -L 2 -I '.venv|.git|__pycache__'

echo ""
echo "=== 2. Start the fake services ==="
docker compose up -d
sleep 10
docker ps | grep opencanary
ss -tlnp | grep -E ':(2121|8080|3306)\b'

echo ""
echo "=== 3. Start the sensors ==="
pkill -f sensor/tailer.py
pkill -f sensor/fake_shell.py
rm -f logs/events.jsonl logs/.tailer_pos db/honeycampus.db
python sensor/tailer.py > /tmp/tailer.log 2>&1 &
python sensor/fake_shell.py > /tmp/fake_shell.log 2>&1 &
sleep 2

echo ""
echo "=== 4. The fake attacker ==="
nmap -p 2121,8080,3306 -sV 127.0.0.1
sshpass -p 'wrongpass' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -p 2222 testuser@127.0.0.1 exit
sshpass -p 'anything' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -p 2222 testuser@127.0.0.1 'whoami' 2>/dev/null
sshpass -p 'anything' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -p 2222 testuser@127.0.0.1 'ls -la' 2>/dev/null
sleep 3

echo ""
echo "=== 5. Show the events ==="
tail -10 logs/events.jsonl

echo ""
echo "=== 6. Verify the hash chain ==="
python collector/verify.py

echo ""
echo "=== 7. Build incidents ==="
pkill -f sensor/tailer.py
pkill -f sensor/fake_shell.py
python engine/incident.py

echo ""
echo "=== 8. Show the incidents ==="
sqlite3 db/honeycampus.db "SELECT source_ip, state, score, severity FROM incidents;"

echo ""
echo "=== 9. Starting the dashboard ==="
echo "Open http://127.0.0.1:5000/ in your browser."
python dashboard/app.py
