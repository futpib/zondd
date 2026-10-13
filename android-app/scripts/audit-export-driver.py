#!/usr/bin/env python3
"""Exercise Android's real document saver and verify the bytes it wrote."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

device, ctl = sys.argv[1:]
adb = [os.environ.get("ADB", "adb"), "-s", device]
deadline = time.monotonic() + 1100
verified = 0
seen = set()

while verified < 2 and time.monotonic() < deadline:
    time.sleep(1)
    # UIAutomator enables accessibility while dumping. Restrict it to the
    # native saver so it cannot leave Flutter test semantics handles active.
    window = subprocess.run(adb + ["shell", "dumpsys", "window", "displays"], capture_output=True, text=True, timeout=10)
    if not any("documentsui" in line for line in window.stdout.splitlines() if "mCurrentFocus=" in line):
        continue
    dumped = subprocess.run(adb + ["shell", "uiautomator", "dump", "/sdcard/zond-audit-window.xml"], capture_output=True, timeout=15)
    if dumped.returncode:
        continue
    xml = subprocess.run(adb + ["exec-out", "cat", "/sdcard/zond-audit-window.xml"], capture_output=True, timeout=10)
    try:
        nodes = list(ET.fromstring(xml.stdout).iter("node"))
    except ET.ParseError:
        continue
    names = [n.get("text", "") for n in nodes if re.fullmatch(r"zond-audit-\d+\.json", n.get("text", ""))]
    saves = [n for n in nodes if (n.get("resource-id", "").endswith("action_menu_save") or (n.get("resource-id") == "android:id/button1" and n.get("text", "").upper() == "SAVE")) and n.get("enabled") == "true"]
    if not names or not saves or names[0] in seen:
        continue
    name = names[0]
    bounds = [int(v) for v in re.findall(r"\d+", saves[0].get("bounds", ""))]
    if len(bounds) != 4:
        continue
    subprocess.run(adb + ["shell", "input", "tap", str((bounds[0] + bounds[2]) // 2), str((bounds[1] + bounds[3]) // 2)], check=True, timeout=10)
    with tempfile.TemporaryDirectory(prefix="zond-audit-export-") as directory:
        target = Path(directory) / name
        for attempt in range(30):
            pulled = subprocess.run(adb + ["pull", f"/sdcard/Download/{name}", str(target)], capture_output=True, timeout=10)
            if pulled.returncode == 0 and target.exists() and target.stat().st_size:
                break
            time.sleep(1)
        else:
            raise RuntimeError(f"Android did not save {name} in Downloads")
        bundle = json.loads(target.read_text())
        # This driver checks the saved bytes. The phone's independently stored
        # checkpoint and rollback checks are exercised by the Android test.
        result = subprocess.run([ctl, "verify-audit", str(target)], capture_output=True, text=True, check=True, timeout=15)
        report = json.loads(result.stdout)
        assert report["signed_decisions"] >= 1, report
        assert bundle["range"]["through"] == report["checkpoint"]["sequence"]
        print(f"Verified native Android export {name}, {report['signed_decisions']} device signatures", flush=True)
    subprocess.run(adb + ["shell", "rm", f"/sdcard/Download/{name}"], check=True, timeout=10)
    seen.add(name)
    verified += 1

subprocess.run(adb + ["shell", "rm", "-f", "/sdcard/zond-audit-window.xml"], timeout=10)
assert verified == 2, f"Expected two real Android exports, got {verified}"
