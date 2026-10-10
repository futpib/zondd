#!/usr/bin/env python3
"""Loopback SSH authentication fixture executing the real control helper."""
import json
import shlex
import socket
import subprocess
import sys
import threading
import time

import paramiko
from paramiko.auth_handler import AuthHandler
from paramiko.message import Message


host_key = paramiko.Ed25519Key.from_private_key_file(sys.argv[1])
command = sys.argv[2:]


class PasswordChangeHandler(AuthHandler):
    # Paramiko's default server rejects password changes. Exercise the actual
    # SSH password-change packets and verify both old and new credentials.
    def _parse_userauth_request(self, message):
        probe = Message(message.asbytes())
        username, service, method = [probe.get_text() for _ in range(3)]
        if username != "expired" or method != "password":
            return super()._parse_userauth_request(message)
        if self.authenticated or service != "ssh-connection":
            return
        self.auth_username = username
        changing, old = probe.get_boolean(), probe.get_text()
        if not changing and old == "android test password":
            response = Message()
            response.add_byte(bytes([60]))
            response.add_string("Your password expired. Choose a new password.")
            response.add_string("")
            self.transport._send_message(response)
            return
        result = paramiko.AUTH_FAILED
        if changing and old == "android test password" and probe.get_text() == "new test password":
            result = paramiko.AUTH_SUCCESSFUL
        self._send_auth_result(username, method, result)


paramiko.transport.AuthHandler = PasswordChangeHandler


class Authentication(paramiko.ServerInterface):
    def __init__(self):
        self.round = 0

    def get_allowed_auths(self, username):
        return "keyboard-interactive" if username in ("interactive", "push") else "password"

    def check_auth_password(self, username, password):
        if username == "password" and password == "android test password":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        if username == "push":
            self.round = 2
            return paramiko.InteractiveQuery(
                "Push approval", "Approve this login on your other device.",
            )
        if username != "interactive":
            return paramiko.AUTH_FAILED
        self.round = 0
        return paramiko.InteractiveQuery(
            "Server sign-in", "Enter the test account and password.",
            ("Account", True), ("Password", False),
        )

    def check_auth_interactive_response(self, responses):
        if self.round == 2 and responses == []:
            time.sleep(4)
            self.round = 1
            return paramiko.InteractiveQuery(
                "Verification", "Enter the verification code.", ("Code", False),
            )
        if self.round == 0 and responses == ["test account", "android test password"]:
            self.round = 1
            return paramiko.InteractiveQuery(
                "Verification", "Enter the verification code.", ("Code", False),
            )
        if self.round == 1 and responses == ["123456"]:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, channel_id):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, requested):
        if shlex.split(requested.decode()) != command:
            return False

        def execute():
            try:
                request = channel.makefile("rb").readline(1024 * 1024)
                result = subprocess.run(command, input=request, capture_output=True, timeout=45)
                channel.sendall(result.stdout)
                channel.sendall_stderr(result.stderr)
                channel.send_exit_status(result.returncode)
            finally:
                channel.close()

        threading.Thread(target=execute, daemon=True).start()
        return True


def serve(connection):
    with paramiko.Transport(connection) as transport:
        transport.add_server_key(host_key)
        transport.start_server(server=Authentication())
        channels = []
        while transport.is_active():
            channel = transport.accept(1)
            channels = [c for c in channels if not c.closed]
            if channel is not None:
                channels.append(channel)


with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    print(json.dumps({"port": listener.getsockname()[1]}), flush=True)
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=serve, args=(connection,), daemon=True).start()
