#!/usr/bin/env python3
"""Exercise QR import using real frames from an emulator's virtual-scene camera."""
import argparse
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from PIL import Image, ImageOps

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--device", default="emulator-5554")
args = parser.parse_args()


def adb(*arguments):
    output = subprocess.check_output(
        ["adb", "-s", args.device, *arguments], timeout=20
    )
    if b"KO:" in output:
        raise RuntimeError(output.decode(errors="replace"))
    return output


def camera_pose(path):
    # Emulator automation v2 FileHeader with initial physical position/rotation.
    def parameter(kind, values):
        value = b"\x0a\x0c" + struct.pack("<fff", *values)
        event = b"\x08" + bytes([kind]) + b"\x12\x0e" + value + b"\x1a\x0e" + value
        return b"\x12" + bytes([len(event)]) + event

    state = parameter(0, (-2.507, 0.8, 2.372)) + parameter(1, (200, -37, 180))
    header = b"\x08\x02\x12" + bytes([len(state)]) + state
    path.write_bytes(struct.pack(">I", len(header)) + header)


with tempfile.TemporaryDirectory(prefix="zondd-qr-") as directory:
    previous_pose = Path(directory) / "previous-pose"
    adb("emu", "automation", "record", str(previous_pose))
    adb("emu", "automation", "stop-record")
    pose = Path(directory) / "camera-pose"
    camera_pose(pose)
    adb("emu", "automation", "play", str(pose))

    class QrHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/qr" or not 0 <= length <= 4096:
                self.send_error(400)
                return
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".png", dir=directory, delete=False
                ) as image:
                    if length:
                        subprocess.run(
                            ["qrencode", "-8", "-s", "12", "-m", "0", "-o", image.name],
                            input=self.rfile.read(length), check=True, timeout=20,
                        )
                        # Keep the code visible above the scene furniture.
                        with Image.open(image.name) as qr:
                            ImageOps.expand(
                                qr, border=qr.width // 2, fill="white"
                            ).save(image.name)
                    else:
                        Image.new("RGB", (512, 512), "white").save(image.name)
                    adb("emu", "virtualscene-image", "wall", image.name)
                    # The console acknowledges before the renderer loads the texture.
                    time.sleep(1)
                adb(
                    "shell", "pm", "grant", "io.github.futpib.zondd_control",
                    "android.permission.CAMERA",
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                self.send_error(500, str(error))

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), QrHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [os.environ.get("FLUTTER", "flutter"), "test", "--reporter", "expanded",
             "integration_test/qr_test.dart", "-d", args.device,
             f"--dart-define=QR_TEST_PORT={server.server_port}"],
            cwd=Path(__file__).resolve().parents[1],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        adb("emu", "virtualscene-image", "wall")
        adb("emu", "automation", "play", str(previous_pose))
    raise SystemExit(result.returncode)
