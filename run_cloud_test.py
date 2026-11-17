"""EXPLICIT real-cloud binding/enroll test for the one approved whitelist SN.

Never imported or automatically run by the GUI. Existing keys and Tokens are reused.
"""

from datetime import datetime, timezone
import base64
import json
import os
from pathlib import Path
import subprocess

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication
from binding import load_test_identity
from main import DeviceManager

SN = "NTX_w1_v1.1.0.5_BJ_61026LV97"
SERVER = "https://logserver.test.humanuniverse.cn"


def main():
    root = Path(__file__).resolve().parent
    output = root / "tmp/real-cloud" / SN
    output.mkdir(parents=True, exist_ok=True)
    result_path = output / "result.json"
    report = {"sn": SN, "server": SERVER, "started_utc": datetime.now(timezone.utc).isoformat(),
              "binding": {"submitted": False}, "agent": {"started": False}}
    def save():
        result_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    save()
    prefix = ["wsl", "-d", "Ubuntu-22.04", "-u", "felix", "--exec", "/usr/bin/python3"]
    script_path = "/home/felix/Projects/DeviceManager-chain/cloud_test_linux.py"
    contents = base64.b64encode((root / "cloud_test_linux.py").read_bytes()).decode()
    bootstrap = ("from pathlib import Path;import base64;"
                 f"p=Path({script_path!r});p.parent.mkdir(parents=True,exist_ok=True);"
                 f"p.write_bytes(base64.b64decode({contents!r}))")
    copied = subprocess.run(prefix + ["-"], input=bootstrap, text=True, capture_output=True, timeout=30)
    if copied.returncode:
        raise RuntimeError("Cannot prepare WSL helper")
    prepared = subprocess.run(prefix + [script_path, "prepare"], capture_output=True, text=True, timeout=30)
    if prepared.returncode:
        raise RuntimeError("Stored identity unavailable or inconsistent; stopped without binding")
    manifest = json.loads(prepared.stdout)
    identity = manifest.pop("identity")
    assert identity["sn"] == SN
    report["identity"] = manifest
    save()
    print("Identity prepared; reused:", manifest["key_reused"], "; RSA-2048, private key stays in WSL", flush=True)
    identity_path = output / "identity-public.json"
    identity_path.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    app = QApplication.instance() or QApplication([])
    window = DeviceManager()
    window.set_binding_identity(load_test_identity(identity_path))
    window.bind_server.setText(SERVER)
    loop, results = QEventLoop(), []
    def done(result):
        results.append(result)
        loop.quit()
    window.binding_client.completed.connect(done)
    guard = QTimer()
    guard.setSingleShot(True)
    guard.timeout.connect(loop.quit)
    guard.start(25000)
    report["binding"]["submitted"] = True
    save()
    window.submit_binding(timeout_ms=20000)  # The actual existing PC binding implementation.
    loop.exec()
    guard.stop()
    window.close()
    if not results:
        report["binding"]["result"] = "unknown; no automatic retry"
        save()
        print("STOP: binding result unknown; no enroll attempted", flush=True)
        return
    result = results[0]
    report["binding"].update(http_status=result.http_status, verified_response=result.success)
    try:
        data = json.loads(result.server_result)
        report["binding"]["server_result"] = {key: data[key] for key in ("sn", "status", "error") if key in data}
    except (ValueError, TypeError):
        report["binding"]["server_result"] = "non-JSON response"
    save()
    print("Qt bind HTTP:", result.http_status, "; response confirmed:", result.success, flush=True)
    if result.http_status == 409:
        report["stopped_on_conflict"] = True
        save()
        print("STOP: HTTP 409; no enroll, no key replacement, no binding overwrite", flush=True)
        return
    if not result.success or result.http_status not in (200, 201):
        print("STOP: binding not confirmed; no enroll attempted", flush=True)
        return
    settings = {}
    for line in (root.parent / "DeviceAgent/device-agent.cloud.conf.example").read_text(encoding="utf-8").splitlines():
        if line.startswith(("host=", "port=")):
            key, value = line.split("=", 1)
            settings[key] = int(value) if key == "port" else value
    settings["expected_binary_sha256"] = json.loads((root / "tmp/chain-last-result.json").read_text())["binary_sha256"]
    report["agent"]["started"] = True
    save()
    print("Starting existing native Agent for HTTPS enroll and MQTT READY check", flush=True)
    agent = subprocess.run(prefix + [script_path, "run"], input=json.dumps(settings), capture_output=True,
                           text=True, timeout=100)
    if agent.returncode:
        report["agent"].update(error="Helper stopped; stored key and Token preserved")
        save()
        print("STOP: native Agent test helper failed; credentials preserved", flush=True)
        return
    report["agent"].update(json.loads(agent.stdout))
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    save()
    print("Enroll succeeded:", report["agent"]["enroll_succeeded"],
          "; cached Token reused:", report["agent"]["cached_token_reused"], flush=True)
    print("MQTT READY:", report["agent"]["mqtt"]["ready"], "; Agent stopped:", report["agent"]["agent_stopped"], flush=True)
    print("Sanitized report saved; private key and Token are not included", flush=True)


if __name__ == "__main__":
    main()
