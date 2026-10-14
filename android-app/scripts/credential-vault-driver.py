#!/usr/bin/env python3
"""Drive real Android biometric prompts for saved_credentials_test.dart on an isolated emulator."""
import argparse
import json
import re
import shlex
import signal
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--device", required=True)
parser.add_argument("--log", type=Path, required=True)
args = parser.parse_args()
if not args.device.startswith("emulator-"):
    parser.error("Use an isolated emulator; this test temporarily advances its clock.")


def adb(*command, input=None):
    return subprocess.run(["adb", "-s", args.device, *command], input=input, capture_output=True, text=True, timeout=15, check=True).stdout


def set_clock(offset):
    adb("shell", "settings", "put", "global", "auto_time", "0")
    adb("shell", "date", "-u", "-s", time.strftime("%m%d%H%M%Y.%S", time.gmtime(time.time() + offset)))


def acknowledge(mode, path):
    command = "printf %s " + shlex.quote(mode) + " > " + shlex.quote(path + "-ready")
    adb("shell", "run-as io.github.futpib.zondd_control sh -c " + shlex.quote(command))


def stop(signum, frame):
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)


mode = "allow"
shifted = False
handled_clock = False
backgrounded = False
inspected = False
signal_path = None
try:
    for _ in range(250):
        if args.log.exists():
            paths = re.findall(r"CREDENTIAL_VAULT_SIGNAL=(/[^\s]+)", args.log.read_text(errors="replace"))
            if paths:
                signal_path = paths[-1]
        try:
            if signal_path is None:
                raise RuntimeError("Mode path is not available yet")
            requested = adb("exec-out", "run-as", "io.github.futpib.zondd_control", "cat", signal_path).strip()
            if requested in {"allow", "cancel", "background", "expire", "restore"}:
                mode = requested
                acknowledge(mode, signal_path)
        except (subprocess.SubprocessError, RuntimeError):
            pass
        if mode == "expire" and not handled_clock:
            set_clock(1800)
            shifted = True
            handled_clock = True
        if mode == "restore":
            break
        try:
            if not inspected:
                try:
                    stored = adb("exec-out", "run-as", "io.github.futpib.zondd_control", "cat", "shared_prefs/credential-vault-v1.xml")
                    records = list(ET.fromstring(stored))
                except (subprocess.SubprocessError, ET.ParseError):
                    stored, records = "", []
                if records:
                    for secret in ("test-vault-secret", "test-vault-forever", "test-vault-expiring"):
                        assert secret not in stored, "Credential appeared unencrypted on disk"
                    for item in records:
                        entry = json.loads(item.text)
                        assert "ciphertext" in entry and "iv" in entry and "values" not in entry
                    inspected = True
                    print("Encrypted credential storage inspected.", flush=True)
            adb("shell", "uiautomator", "dump", "/sdcard/zond-vault-window.xml")
            root = ET.fromstring(adb("exec-out", "cat", "/sdcard/zond-vault-window.xml"))
            nodes = list(root.iter("node"))
            prompt = any(n.get("text") in {"Save credentials", "Unlock saved credentials"} and
                n.get("package") == "com.android.systemui" for n in nodes)
            if prompt:
                latest = adb("exec-out", "run-as", "io.github.futpib.zondd_control", "cat", signal_path).strip()
                if latest != mode:
                    continue
                if mode == "cancel":
                    cancel = next(n for n in nodes if n.get("text", "").lower() == "cancel" and n.get("package") == "com.android.systemui")
                    x1, y1, x2, y2 = map(int, re.findall(r"\d+", cancel.get("bounds")))
                    adb("shell", "input", "tap", str((x1+x2)//2), str((y1+y2)//2))
                elif mode == "background" and not backgrounded:
                    adb("shell", "input", "keyevent", "3")
                    time.sleep(0.5)
                    adb("shell", "am", "start", "-n", "io.github.futpib.zondd_control/.MainActivity")
                    backgrounded = True
                elif mode == "allow":
                    adb("emu", "finger", "touch", "1")
                    time.sleep(0.2)
                    adb("emu", "finger", "remove")
        except (subprocess.SubprocessError, ET.ParseError, StopIteration):
            pass
        time.sleep(0.25)
    if not inspected:
        raise RuntimeError("No encrypted credential record was inspected")
finally:
    if shifted:
        set_clock(0)
    adb("shell", "settings", "put", "global", "auto_time", "1")
    adb("shell", "rm", "-f", "/sdcard/zond-vault-window.xml")
