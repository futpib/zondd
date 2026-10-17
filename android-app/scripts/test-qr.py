#!/usr/bin/env python3
"""Exercise QR import using real frames from an emulator's virtual-scene camera."""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import threading
import time
import uuid
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


def wait_for_camera_close():
    # Flutter route teardown does not await the native camera's disposal.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        cameras = adb("shell", "dumpsys", "media.camera")
        if re.search(rb"Active Camera Clients:\s*\[\s*\]", cameras):
            return
        time.sleep(0.1)
    raise RuntimeError("Previous QR scanner did not release the camera")


@contextmanager
def preserved_camera_pose():
    name = f"zondd-qr-{uuid.uuid4().hex}.recording"
    avd_path = adb("emu", "avd", "path").decode().splitlines()[0].strip()
    avd = Path(avd_path)
    if not avd.is_absolute() or not avd.is_dir():
        raise RuntimeError(f"Cannot access emulator AVD directory: {avd_path}")
    # New emulators restrict recording to a bare filename under the AVD.
    # Older versions resolve bare recording names relative to the user's home.
    candidates = [avd / "console_out" / name, avd / name, Path.home() / name]
    previous_pose = None
    recording = False
    try:
        adb("emu", "automation", "record", name)
        recording = True
        adb("emu", "automation", "stop-record")
        recording = False
        previous_pose = next((path for path in candidates if path.is_file()), None)
        if previous_pose is None:
            raise RuntimeError(f"Emulator did not create the pose recording {name}")
        yield
    finally:
        try:
            if recording:
                adb("emu", "automation", "stop-record")
            if previous_pose is not None:
                adb("emu", "automation", "play", str(previous_pose))
        finally:
            for path in candidates:
                path.unlink(missing_ok=True)


with tempfile.TemporaryDirectory(prefix="zondd-qr-") as directory, preserved_camera_pose():
    pose = Path(directory) / "camera-pose"
    camera_pose(pose)
    adb("emu", "automation", "play", str(pose))
    blank = Path(directory) / "blank.png"
    Image.new("RGB", (512, 512), "white").save(blank)

    class QrHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if self.path not in ("/qr", "/qr-live") or not 0 <= length <= 4096:
                self.send_error(400)
                return
            try:
                if self.path == "/qr":
                    wait_for_camera_close()
                    adb("emu", "virtualscene-image", "wall", str(blank))
                    time.sleep(2)
                if length:
                    with tempfile.NamedTemporaryFile(
                        suffix=".png", dir=directory, delete=False
                    ) as image:
                        subprocess.run(
                            ["qrencode", "-8", "-s", "12", "-m", "0", "-o", image.name],
                            input=self.rfile.read(length), check=True, timeout=20,
                        )
                        # Keep the code visible above the scene furniture.
                        with Image.open(image.name) as qr:
                            ImageOps.expand(
                                qr, border=qr.width // 2, fill="white"
                            ).save(image.name)
                        adb("emu", "virtualscene-image", "wall", image.name)
                        # The console acknowledges before the renderer loads the texture.
                        time.sleep(2)
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
    raise SystemExit(result.returncode)
