#!/usr/bin/env python3
"""Root-only isolated Linux E2E test; does not modify installed SSH/services/accounts."""
import argparse
import base64
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import shutil
import signal
import socket
import subprocess as sp
import tempfile
import time


def wait_for(predicate, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("condition did not become true")


def run(argv, code=0, **kwargs):
    result = sp.run([str(a) for a in argv], capture_output=True, timeout=30, **kwargs)
    assert result.returncode == code, (argv, result.returncode, result.stdout, result.stderr)
    return result


class Session:
    def __init__(self, path, body):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(10)
        self.socket.connect(str(path))
        self.file = self.socket.makefile("rb")
        self.socket.sendall(json.dumps(dict(version=1, id=7, body=body)).encode() + b"\n")

    def next(self):
        value = json.loads(self.file.readline())
        assert value["version"] == 1 and value["id"] == 7, value
        return value["body"]

    def close(self):
        self.file.close()
        self.socket.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iroh", action="store_true", help="also test installed iroh-ssh with real discovery")
    parser.add_argument("--bridge-user", default=pwd.getpwuid(int(os.environ.get("SUDO_UID", "1000"))).pw_name)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run using sudo after cargo build --workspace"
    bridge = pwd.getpwnam(args.bridge_user)
    execution = pwd.getpwnam("nobody")
    assert bridge.pw_uid not in (0, execution.pw_uid)
    root = Path(__file__).resolve().parents[1]
    processes, handles, sessions = [], [], []
    with tempfile.TemporaryDirectory(prefix="zondd-test-", dir="/run") as directory:
        temp = Path(directory)
        temp.chmod(0o755)
        runtime = temp / "run"
        daemon, ctl = temp / "zondd", temp / "zondctl"
        for name in ("zondd", "zondctl"):
            shutil.copyfile(root / "target/debug" / name, temp / name)
            (temp / name).chmod(0o755)
        config = temp / "config.toml"
        policy = f'''runtime_dir = "{runtime}"
[approvals]
enabled = true
timeout_secs = 4
max_pending = 2
[limits]
command_timeout_secs = 2
max_output_bytes = 1024
max_connections = 4
max_running = 2
[principals.exec]
bridge_uid = {bridge.pw_uid}
run_uid = {execution.pw_uid}
run_gid = {execution.pw_gid}
cwd = "/tmp"
allow_exec = true
default = "ask"
[[principals.exec.rules]]
program = "/usr/bin/printf"
args = ["%s", "hello"]
decision = "allow"
[[principals.exec.rules]]
program = "/usr/bin/id"
args = ["-u"]
decision = "allow"
[[principals.exec.rules]]
program = "/usr/bin/false"
decision = "deny"
[[principals.exec.rules]]
program = "/usr/bin/sleep"
decision = "allow"
[[principals.exec.rules]]
program = "/usr/bin/yes"
decision = "allow"
[principals.ops]
bridge_uid = {bridge.pw_uid}
run_uid = {execution.pw_uid}
run_gid = {execution.pw_gid}
cwd = "/tmp"
operations = ["greet"]
[operations.greet]
program = "/usr/bin/printf"
fixed_args = ["hello %s"]
arguments = [{{name = "who", choices = ["world", "λ"]}}]
decision = "allow"
'''
        config.write_text(policy)
        config.chmod(0o600)

        def start(argv, logname):
            log = open(temp / logname, "wb")
            handles.append(log)
            proc = sp.Popen([str(a) for a in argv], stdout=log, stderr=log, start_new_session=True)
            processes.append(proc)
            return proc

        def session(body, principal="exec"):
            s = Session(runtime / f"{principal}.sock", body)
            sessions.append(s)
            return s

        def request(body, principal="exec"):
            s = session(body, principal)
            try:
                return s.next()
            finally:
                s.close()

        def command(program, *argv):
            return dict(method="run", command=dict(program=program, args=list(argv)))

        def resolve(identifier, approve):
            event = request(dict(method="resolve", approval_id=identifier, approve=approve), "admin")
            assert event["type"] == "resolved", event

        def queued():
            return request(dict(method="pending"), "admin")["requests"]

        def check(label):
            print(f"PASS {label}", flush=True)

        try:
            run([daemon, "check", "--config", config])
            service = start([daemon, "serve", "--config", config], "daemon.log")
            wait_for(lambda: (runtime / "ops.sock").exists())
            run([daemon, "serve", "--config", config], code=1)
            check("policy validation and exclusive runtime lock")
            assert base64.b64decode(request(command("/usr/bin/id", "-u"))["stdout"]) == f"{execution.pw_uid}\n".encode()
            assert request(command("/usr/bin/false"))["type"] == "rejected"
            assert request(dict(method="pending"))["type"] == "rejected"
            assert request(command("/usr/bin/id", "-u"), "ops")["type"] == "rejected"
            assert request(dict(method="invoke", operation="greet", args=["--help"]), "ops")["type"] == "error"
            event = request(dict(method="invoke", operation="greet", args=["λ"]), "ops")
            assert base64.b64decode(event["stdout"]).decode() == "hello λ"
            check("execution UID, hard denial, admin isolation, closed operation schemas")

            for approve in (True, False):
                s = session(command("/usr/bin/printf", "%s", "manual"))
                pending = s.next()["request"]
                assert queued()[0]["command"]["args"] == ["%s", "manual"]
                resolve(pending["approval_id"], approve)
                event = s.next()
                assert event["type"] == ("completed" if approve else "rejected"), event
                if approve:
                    assert base64.b64decode(event["stdout"]) == b"manual"
                s.close()
                assert request(dict(method="resolve", approval_id=pending["approval_id"], approve=True), "admin")["type"] == "error"
            check("one-time approval, denial, and replay rejection")

            s = session(command("/usr/bin/printf", "%s", "cancel"))
            s.next()
            s.close()
            wait_for(lambda: not queued())
            s = session(command("/usr/bin/printf", "%s", "expire"))
            s.next()
            assert s.next()["type"] == "rejected"
            s.close()
            assert not queued()
            check("disconnect removes pending request; unapproved request expires")

            pending_sessions = [session(command("/usr/bin/printf", str(i))) for i in range(2)]
            pending_ids = [s.next()["request"]["approval_id"] for s in pending_sessions]
            assert request(command("/usr/bin/printf", "full"))["type"] == "error"
            idle = []
            for _ in range(2):
                sock = socket.socket(socket.AF_UNIX)
                sock.connect(str(runtime / "exec.sock"))
                idle.append(sock)
            time.sleep(0.1)
            for identifier in pending_ids:
                resolve(identifier, False)
            for s in pending_sessions:
                assert s.next()["type"] == "rejected"
                s.close()
            for sock in idle:
                sock.close()
            check("bounded queue; admin remains reachable with full remote connection capacity")

            assert "output limit" in request(command("/usr/bin/yes"))["message"]
            assert "timed out" in request(command("/usr/bin/sleep", "10"))["message"]
            s = session(command("/usr/bin/sleep", "10"))
            wait_for(lambda: request(dict(method="status"), "admin")["running"] == 1)
            s.close()
            wait_for(lambda: request(dict(method="status"), "admin")["running"] == 0)
            check("output limit, execution timeout, running-request disconnect")

            # An approved interpreter still cannot access either control-plane socket.
            code = "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])"
            for path in [runtime / "admin.sock", runtime / "exec.sock"]:
                s = session(command(shutil.which("python3"), "-c", code, str(path)))
                resolve(s.next()["request"]["approval_id"], True)
                event = s.next()
                assert event["code"] != 0 and b"PermissionError" in base64.b64decode(event["stderr"]), event
                s.close()
            check("approved child cannot reach approval or bridge sockets")

            binary_code = "import os,sys; os.write(1, bytes([0,255])); os.write(2,b'err'); sys.exit(7)"
            s = session(command(shutil.which("python3"), "-c", binary_code))
            resolve(s.next()["request"]["approval_id"], True)
            event = s.next()
            assert event["code"] == 7 and base64.b64decode(event["stdout"]) == b"\x00\xff"
            assert base64.b64decode(event["stderr"]) == b"err"
            s.close()
            work = temp / "work"
            work.mkdir()
            os.chown(work, execution.pw_uid, execution.pw_gid)
            marker = work / "child.pid"
            child_code = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
            s = session(command(shutil.which("python3"), "-c", child_code, str(marker)))
            resolve(s.next()["request"]["approval_id"], True)
            wait_for(marker.exists)
            pid = int(marker.read_text())
            s.close()
            wait_for(lambda: not Path(f"/proc/{pid}").exists())
            check("binary stdout/stderr and exit status preserved; disconnected process actually reaped")

            for frame in [
                b'{"version":99,"id":1,"body":{"method":"status"}}\n',
                b'{"version":1,"id":1,"body":{"method":"run","principal":"admin","command":{"program":"/usr/bin/id"}}}\n',
                b'x' * (64 * 1024 + 1),
            ]:
                with socket.socket(socket.AF_UNIX) as sock:
                    sock.settimeout(5)
                    sock.connect(str(runtime / "exec.sock"))
                    sock.sendall(frame)
                    try:
                        assert sock.recv(1) == b""
                    except ConnectionResetError:
                        pass
            check("wire rejects spoofed identity, oversized frames, and unknown protocol version")

            # Exercise actual terminal review instead of only the resolve RPC.
            s = session(command("/usr/bin/printf", "%s", "terminal"))
            s.next()
            master, slave = pty.openpty()
            review = sp.Popen([str(ctl), "--socket", str(runtime / "admin.sock"), "review"], stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
            processes.append(review)
            os.close(slave)
            output = bytearray()
            def prompt_ready():
                if select.select([master], [], [], 0.1)[0]:
                    output.extend(os.read(master, 8192))
                return b"Approve once" in output
            wait_for(prompt_ready)
            os.write(master, b"a\n")
            assert s.next()["type"] == "completed"
            review.send_signal(signal.SIGINT)
            review.wait(timeout=5)
            os.close(master)
            s.close()
            check("interactive approval through a real PTY")

            for key in ("host", "exec-key", "ops-key", "unknown-key"):
                run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", temp / key])
            authorized = temp / "authorized_keys"
            authorized.write_text("".join(f'restrict,command="{daemon} bridge --runtime-dir {runtime} --principal {p}" {(temp / (p + "-key.pub")).read_text()}' for p in ("exec", "ops")))
            authorized.chmod(0o644)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            sshd_config = temp / "sshd_config"
            sshd_config.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {temp / "host"}
PidFile {temp / "sshd.pid"}
AuthorizedKeysFile {authorized}
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
PermitRootLogin no
StrictModes yes
AllowUsers {bridge.pw_name}
LogLevel VERBOSE
''')
            run([shutil.which("sshd"), "-t", "-f", sshd_config])
            sshd = start([shutil.which("sshd"), "-D", "-e", "-f", sshd_config], "sshd.log")
            def listening():
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        return True
                except OSError:
                    return False
            wait_for(listening)
            known = temp / "known_hosts"
            known.write_text("zondd-test " + (temp / "host.pub").read_text())
            ssh_config = temp / "ssh_config"
            ssh_config.write_text(f'''Host *
  HostKeyAlias zondd-test
  UserKnownHostsFile {known}
  StrictHostKeyChecking yes
  ConnectTimeout 10
  LogLevel ERROR
''')
            remote = [ctl, "--host", f"{bridge.pw_name}@127.0.0.1", "--port", str(port), "--ssh-config", ssh_config]
            assert run(remote + ["--identity", temp / "exec-key", "exec", "/usr/bin/printf", "%s", "hello"]).stdout == b"hello"
            assert run(remote + ["--identity", temp / "ops-key", "invoke", "greet", "world"]).stdout == b"hello world"
            run(remote + ["--identity", temp / "ops-key", "exec", "/usr/bin/id", "-u"], code=126)
            run(remote + ["--identity", temp / "unknown-key", "exec", "/usr/bin/id", "-u"], code=125)
            ssh = ["ssh", "-F", ssh_config, "-p", str(port), "-i", temp / "exec-key", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", f"{bridge.pw_name}@127.0.0.1"]
            result = run(ssh + ["/usr/bin/id"], code=1)
            assert b"protocol only" in result.stderr
            check("real sshd: per-key policy, operation-only key, unknown key, SSH command rejection")

            # Keep stdin open until the terminal response: EOF deliberately cancels work.
            remote_proc = sp.Popen([str(a) for a in remote + ["--identity", temp / "exec-key", "--json", "exec", "/usr/bin/printf", "%s", "ssh-approved"]], stdout=sp.PIPE, stderr=sp.PIPE, start_new_session=True)
            processes.append(remote_proc)
            pending = json.loads(remote_proc.stdout.readline())["request"]
            run([ctl, "--socket", runtime / "admin.sock", "approve", pending["approval_id"]])
            event = json.loads(remote_proc.stdout.readline())
            assert base64.b64decode(event["stdout"]) == b"ssh-approved"
            assert remote_proc.wait(timeout=5) == 0
            check("SSH request waits for local CLI approval and returns output")

            raw = sp.Popen([str(a) for a in ssh], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, start_new_session=True)
            processes.append(raw)
            raw.stdin.write(json.dumps(dict(version=1, id=1, body=command("/usr/bin/id", "-u"))).encode() + b"\n")
            raw.stdin.flush()
            assert json.loads(raw.stdout.readline())["body"]["type"] == "completed"
            assert raw.wait(timeout=5) == 0
            raw.stdin.close()
            check("forced bridge exits with client stdin still open")

            if args.iroh:
                start(["iroh-ssh", "server", "--ssh-port", str(port), "--persist", "--key-dir", temp / "iroh"], "iroh.log")
                def endpoint_id():
                    match = re.search(r"\b[0-9a-f]{64}\b", (temp / "iroh.log").read_text())
                    return match.group() if match else None
                endpoint = wait_for(endpoint_id, 20)
                iroh = [ctl, "--host", f"{bridge.pw_name}@{endpoint}", "--iroh", "--identity", temp / "ops-key", "--ssh-config", ssh_config, "invoke", "greet", "world"]
                # The server prints its ID before publishing discovery information.
                deadline = time.monotonic() + 30
                while True:
                    result = sp.run([str(a) for a in iroh], capture_output=True, timeout=20)
                    if result.returncode == 0:
                        assert result.stdout == b"hello world", result
                        break
                    assert b"No addressing information available" in result.stderr and time.monotonic() < deadline, result.stderr
                    time.sleep(1)
                check("iroh-ssh + OpenSSH + forced protocol bridge end to end")

            s = session(command("/usr/bin/printf", "%s", "restart"))
            pending_id = s.next()["request"]["approval_id"]
            service.terminate()
            service.wait(timeout=5)
            assert not (runtime / "admin.sock").exists()
            s.close()
            config.write_text(policy.replace("enabled = true", "enabled = false"))
            service = start([daemon, "serve", "--config", config], "restarted.log")
            wait_for(lambda: (runtime / "ops.sock").exists())
            assert not queued()
            assert request(dict(method="resolve", approval_id=pending_id, approve=True), "admin")["type"] == "error"
            assert request(command("/usr/bin/printf", "%s", "disabled"))["type"] == "rejected"
            check("restart discards approval queue; disabled approvals reject without waiting")
            check("all requested smoke checks")
        except BaseException:
            for name in ("daemon.log", "sshd.log", "iroh.log"):
                path = temp / name
                if path.exists():
                    print(f"--- {name} ---\n{path.read_text()[-12000:]}", flush=True)
            raise
        finally:
            for s in sessions:
                s.close()
            for proc in reversed(processes):
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=5)
                    except sp.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=5)
            for handle in handles:
                handle.close()


if __name__ == "__main__":
    main()
