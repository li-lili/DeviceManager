"""Explicit enroll/MQTT retry using the already-bound test key; never binds or creates keys."""

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

SN = "NTX_w1_v1.1.0.5_BJ_61026LV97"
EXPECTED_PUBLIC_SHA256 = "f53ec815f157909af3311903bc274023d267a258fc6619c3b0eefe630bf3a68c"


def main():
    root = Path(__file__).resolve().parent
    settings = {}
    for line in (root.parent / "DeviceAgent/device-agent.cloud.conf.example").read_text(encoding="utf-8").splitlines():
        if line.startswith(("host=", "port=")):
            key, value = line.split("=", 1)
            settings[key] = int(value) if key == "port" else value
    settings["expected_binary_sha256"] = json.loads((root / "tmp/chain-last-result.json").read_text())["binary_sha256"]
    helper = base64.b64encode((root / "cloud_test_linux.py").read_bytes()).decode("ascii")
    # Executed entirely inside WSL: only the sanitized result crosses back to Windows.
    program = f'''
import base64, hashlib, json, os, fcntl
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
os.umask(0o077)
scope = {{"__name__": "cloud_helper"}}
exec(compile(base64.b64decode({helper!r}), "cloud_test_linux.py", "exec"), scope)
directory = scope["ROOT"]
assert directory.is_dir(), "Existing test directory missing; stopped"
with (directory / ".lock").open("a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    private = directory / "test-private.pem"
    public = directory / "test-public.pem"
    identity_path = directory / "identity.json"
    assert all(p.is_file() and not p.is_symlink() for p in (private, public, identity_path)), "Existing identity missing; stopped"
    key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048, "Invalid stored test key"
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(der).hexdigest()
    assert fingerprint == {EXPECTED_PUBLIC_SHA256!r}, "Key differs from exported bound public key; stopped"
    assert public.read_text() == pem and json.loads(identity_path.read_text()) == {{"sn": {SN!r}, "public_key": pem}}, "Stored identity mismatch; stopped"
    assert private.stat().st_mode & 0o077 == 0, "Private key permissions too broad; stopped"
    result = scope["run"]({settings!r})
    result.update(sn={SN!r}, public_key_sha256=fingerprint, existing_key_verified=True, binding_submitted=False)
    print(json.dumps(result), flush=True)
'''
    print("Verifying existing key, then running native Agent enroll/MQTT; no binding or key generation.", flush=True)
    process = subprocess.run(["wsl", "-d", "Ubuntu-22.04", "-u", "felix", "--exec", "/usr/bin/python3", "-"],
                             input=program, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=110)
    if process.returncode:
        # Do not expose WSL/helper output that might contain credentials.
        raise RuntimeError("WSL identity validation or Agent execution failed; credentials retained; no raw logs displayed")
    report = json.loads(process.stdout)
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    output = root / "tmp/real-cloud" / SN / "enroll-result.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)
    print("Sanitized report:", output, flush=True)


if __name__ == "__main__":
    main()
