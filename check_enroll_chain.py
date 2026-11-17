"""Windows Qt binding -> same WSL HTTPS service -> existing Linux C++ Agent."""

import argparse
import base64
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication
from binding import load_test_identity
from main import DeviceManager


def main(distro, binary):
    root = Path(__file__).resolve().parent
    prefix = ["wsl", "-d", distro, "-u", "felix", "--exec", "/usr/bin/python3"]
    files = {name: base64.b64encode((root / name).read_bytes()).decode("ascii") for name in
             ("identity_validation.py", "mock_bind_server.py", "chain_linux.py")}
    bootstrap = ("import pathlib,base64,json; "
                 "p=pathlib.Path('/home/felix/Projects/DeviceManager-chain');p.mkdir(exist_ok=True); "
                 f"files=json.loads({json.dumps(json.dumps(files))}); "
                 "[(p/n).write_bytes(base64.b64decode(v)) for n,v in files.items()]")
    copied = subprocess.run(prefix + ["-"], input=bootstrap, text=True, capture_output=True, timeout=30)
    assert copied.returncode == 0, "Could not prepare Linux-side test helper"
    worker = subprocess.Popen(prefix + ["/home/felix/Projects/DeviceManager-chain/chain_linux.py", "--binary", binary],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, encoding="utf-8", errors="replace", bufsize=1)
    lines = queue.Queue()
    def collect():
        for line in worker.stdout:
            lines.put(line.strip())
        lines.put(None)
    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    app = QApplication.instance() or QApplication([])
    report = None
    window = None
    try:
        with tempfile.TemporaryDirectory(prefix="qt-chain-public-") as temporary:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                line = lines.get(timeout=45)
                if line is None:
                    raise AssertionError("Linux chain test exited before completion; inspect stderr below")
                if line.startswith("PASS "):
                    print(line, flush=True)
                elif line.startswith("READY "):
                    manifest = json.loads(line[6:])
                    directory = Path(temporary)
                    ca = directory / "ca.pem"
                    ca.write_text(manifest["ca_pem"], encoding="ascii")
                    identity = directory / "test_identity.json"
                    identity.write_text(json.dumps(manifest["identity"]), encoding="utf-8")
                    window = DeviceManager()
                    window.set_binding_identity(load_test_identity(identity))
                    assert window.binding_identity is not None
                    window.bind_server.setText(manifest["server"])
                    loop = QEventLoop()
                    results = []
                    def done(result):
                        results.append(result)
                        loop.quit()
                    window.binding_client.completed.connect(done)
                    guard = QTimer()
                    guard.setSingleShot(True)
                    guard.timeout.connect(loop.quit)
                    guard.start(25000)
                    window.submit_binding(str(ca), 20000)  # Actual UI submit path, not a separate HTTP implementation.
                    loop.exec()
                    guard.stop()
                    assert results and results[0].success and results[0].http_status == 201, (
                        "Qt bind failed: " + window.bind_status.text())
                    print("PASS actual Qt submit -> WSL HTTPS bind returned 201 (verified TLS)", flush=True)
                    worker.stdin.write("bound\n")
                    worker.stdin.flush()
                elif line.startswith("REPORT "):
                    report = json.loads(line[7:])
                    break
            assert report and report["passed"], "Full-chain test did not finish"
        worker.stdin.close()
        assert worker.wait(15) == 0, "Linux chain test failed"
        report["qt_http_status"] = 201
        output = root / "tmp" / "chain-last-result.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("PASS complete shared-registry chain; sanitized evidence: tmp/chain-last-result.json", flush=True)
    finally:
        if window is not None:
            window.close()
        if not worker.stdin.closed:
            worker.stdin.close()  # EOF makes the Linux helper clean up if binding failed.
        if worker.poll() is None:
            try:
                worker.wait(30)
            except subprocess.TimeoutExpired:
                worker.terminate()
        errors = worker.stderr.read()
        if worker.returncode:
            # Test helper only prints assertions/traceback, never keys, signatures or Token values.
            print(errors.replace("\x00", ""), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distro", default="Ubuntu-22.04")
    parser.add_argument("--binary", default="/home/felix/Projects/DeviceAgent-b2278e1/build/device-agent")
    args = parser.parse_args()
    main(args.distro, args.binary)
