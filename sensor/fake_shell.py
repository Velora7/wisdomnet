"""WisdomNet fake SSH shell."""
import os
import socket
import sys
import threading

import paramiko

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "collector"))
from writer import write_event

HOST_KEY_PATH = os.path.join(ROOT, "sensor", "fake_shell_host_key")
LISTEN_PORT = 2222
FAKE_HOSTNAME = "research-server"

BANNER = (
    f"Welcome to {FAKE_HOSTNAME} (Ubuntu 22.04.3 LTS)\n"
    "All activity on this system is monitored.\n"
)
PROMPT = f"{FAKE_HOSTNAME}:~$ "

FAKE_OUTPUT = {
    "whoami": "research\n",
    "id": "uid=1001(research) gid=1001(research) groups=1001(research)\n",
    "pwd": "/home/research\n",
    "ls": "notes.txt  data.csv  backup.tar.gz\n",
    "ls -la": (
        "total 24\n"
        "drwxr-xr-x 3 research research 4096 Sep 20 02:00 .\n"
        "drwxr-xr-x 3 root     root     4096 Sep 15 02:00 ..\n"
        "-rw-r--r-- 1 research research  312 Sep 20 02:00 notes.txt\n"
        "-rw-r--r-- 1 research research 8192 Sep 20 02:00 data.csv\n"
    ),
    "cat notes.txt": "Meeting at 14:00. Backup complete.\n",
    "hostname": f"{FAKE_HOSTNAME}\n",
    "uname -a": "Linux research-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
}


def ensure_host_key():
    if not os.path.exists(HOST_KEY_PATH):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)


class FakeShellServer(paramiko.ServerInterface):
    def __init__(self, source_ip):
        self.source_ip = source_ip
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, command):
        # Attacker sent a one-shot command like: ssh host 'whoami'
        cmd = command.decode(errors="ignore") if isinstance(command, bytes) else command
        write_event(self.source_ip, 0, FAKE_HOSTNAME,
                    "command_execution", {"command": cmd})
        print(f"[fake-shell] exec from {self.source_ip}: {cmd!r}")
        # Send fake output then close
        out = FAKE_OUTPUT.get(cmd.strip(), f"bash: {cmd.split()[0]}: command not found\n")
        channel.send(out.replace("\n", "\r\n"))
        channel.send_exit_status(0)
        channel.close()
        return True
    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True


def handle_client(client_sock, addr):
    source_ip = addr[0]
    source_port = addr[1]
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(paramiko.RSAKey(filename=HOST_KEY_PATH))
        server = FakeShellServer(source_ip)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            return

        channel.send(BANNER)
        write_event(source_ip, source_port, FAKE_HOSTNAME,
                    "ssh_successful_login",
                    {"username": server.username or "unknown",
                     "password": "<accepted>"})

        buffer = ""
        while True:
            channel.send(PROMPT)
            while True:
                char = channel.recv(1)
                if not char:
                    return
                char = char.decode(errors="ignore")
                if char in ("\r", "\n"):
                    channel.send("\r\n")
                    break
                if char == "\x03":
                    channel.send("^C\r\n")
                    buffer = ""
                    break
                if char in ("\x7f", "\x08"):
                    if buffer:
                        buffer = buffer[:-1]
                        channel.send("\b \b")
                    continue
                if 32 <= ord(char) < 127:
                    buffer += char
                    channel.send(char)

            cmd = buffer.strip()
            buffer = ""

            if not cmd:
                continue
            if cmd in ("exit", "logout", "quit"):
                channel.send("logout\r\n")
                channel.close()
                return

            write_event(source_ip, source_port, FAKE_HOSTNAME,
                        "command_execution", {"command": cmd})
            print(f"[fake-shell] command from {source_ip}: {cmd!r}")

            out = FAKE_OUTPUT.get(cmd, f"bash: {cmd.split()[0]}: command not found\n")
            channel.send(out.replace("\n", "\r\n"))

    except Exception as e:
        print(f"[fake-shell] error handling {source_ip}: {e}")
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


def main():
    ensure_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    sock.listen(10)
    print(f"[fake-shell] listening on port {LISTEN_PORT}")
    while True:
        client, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(client, addr),
                             daemon=True)
        t.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[fake-shell] stopped")
