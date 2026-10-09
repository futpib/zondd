#!/usr/bin/env python3
"""Capture the real Android workflow with adb while Rust owns the SSH fixture."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--device", default="emulator-5554")
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
adb = shutil.which("adb")
if adb is None:
    parser.error("adb must be on PATH")


class CaptureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.removeprefix("/")
        if not re.fullmatch(r"[0-9]{2}-[a-z0-9-]+", name):
            self.send_error(400)
            return
        try:
            shot = subprocess.check_output(
                [adb, "-s", args.device, "exec-out", "screencap", "-p"], timeout=20
            )
            if not shot.startswith(b"\x89PNG\r\n\x1a\n"):
                raise ValueError("adb did not return a PNG")
            path = args.output / (name + ".png")
            path.write_bytes(shot)
            print(path, flush=True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self.send_error(500, str(error))

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    result = subprocess.run(
        ["cargo", "test", "-p", "zondctl", "--test", "android", "--", "--ignored", "--nocapture"],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "ZONDD_ANDROID_DEVICE": args.device, "ZONDD_SCREENSHOT_PORT": str(server.server_port)},
    )
finally:
    server.shutdown()
    server.server_close()
    thread.join()
raise SystemExit(result.returncode)
