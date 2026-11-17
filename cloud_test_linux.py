"""Explicit real-cloud test helper; keeps reusable credentials only inside WSL."""

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SN = "NTX_w1_v1.1.0.5_BJ_61026LV97"
SERVER = "https://logserver.test.humanuniverse.cn"
ROOT = Path.home() / ".local/share/device-manager/cloud-tests" / SN
BINARY = Path("/home/felix/Projects/DeviceAgent-b2278e1/build/device-agent")


def write_json(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def prepare():
    private = ROOT / "test-private.pem"
    public = ROOT / "test-public.pem"
    identity = ROOT / "identity.json"
    if private.is_symlink() or public.is_symlink() or identity.is_symlink():
        raise ValueError("Refusing symlink identity paths")
    reused = private.exists()
    if not reused:
        if public.exists() or identity.exists():
            raise ValueError("Public identity exists without its private key; do not regenerate")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with private.open("xb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    else:
        key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
        raise ValueError("Stored test private key is not RSA-2048")
    private.chmod(0o600)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    if public.exists() and public.read_text(encoding="ascii") != pem:
        raise ValueError("Stored public/private keys mismatch; refusing replacement")
    data = {"sn": SN, "public_key": pem}
    if identity.exists() and json.loads(identity.read_text()) != data:
        raise ValueError("Stored identity mismatch; refusing replacement")
    if not public.exists():
        public.write_text(pem, encoding="ascii")
    if not identity.exists():
        write_json(identity, data)
    public.chmod(0o600)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"identity": data, "key_reused": reused, "public_key_sha256": hashlib.sha256(der).hexdigest(),
            "storage_directory": str(ROOT), "private_key_mode": oct(stat.S_IMODE(private.stat().st_mode)),
            "directory_mode": oct(stat.S_IMODE(ROOT.stat().st_mode))}


def run(settings):
    # Never generates a key during enroll; prepare must already have succeeded.
    private = ROOT / "test-private.pem"
    if not private.is_file():
        raise ValueError("Prepared test identity not found")
    expected_hash = settings["expected_binary_sha256"]
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != expected_hash:
        raise ValueError("Agent binary differs from the locally verified binary")
    source = BINARY.parent.parent / "src/main.cpp"
    if "EVP_PKEY_CTX_set_rsa_pss_saltlen(params,RSA_PSS_SALTLEN_DIGEST)" not in source.read_text():
        raise ValueError("Agent source does not specify digest-length PSS salt")
    if settings["host"] != "emqx.test.humanuniverse.cn" or settings["port"] != 1883:
        raise ValueError("MQTT configuration differs from the reviewed repository template")
    sources = ROOT / "log-sources.json"
    log_root = ROOT / "empty-test-logs"
    log_root.mkdir(exist_ok=True)
    write_json(sources, {"log_sources": [{"source_id": "cloud_test", "path": str(log_root), "recursive": False,
                                          "file_patterns": ["*.log"], "filename_date_formats": ["%Y-%m-%d"]}]})
    token = ROOT / "state/tokens" / (SN + ".token")
    token.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    cached_before = token.exists()
    config = ROOT / "device-agent.conf"
    config.write_text(f"device={SN}\nprivate-key={private}\nenroll-url={SERVER}/v1/enroll\n"
                      f"host={settings['host']}\nport={settings['port']}\nusername={SN}\n"
                      f"model=cloud-integration-test\nsources-config={sources}\nstate-dir=state\nwork-dir=work\n"
                      "log-file=agent.log\n", encoding="utf-8")
    config.chmod(0o600)
    started = datetime.now(timezone.utc).isoformat()
    transcript = ROOT / ("process-" + str(time.time_ns()) + ".log")
    env = os.environ.copy()
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"):
        env.pop(name, None)
    with transcript.open("x") as handle:
        process = subprocess.Popen([str(BINARY)], cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                text = transcript.read_text(encoding="utf-8", errors="replace")
                if ("READY hello handshake complete" in text or process.poll() is not None
                        or "connect rejected" in text or "subscription rejected" in text):
                    break
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)
    transcript.chmod(0o600)
    text = transcript.read_text(encoding="utf-8", errors="replace")
    error = re.search(r"HTTP (\d{3}) (bad_request|unauthorized|sn_key_mismatch|rate_limited|request_failed|ip_not_allowed)", text)
    # Report only fixed diagnostic labels, never arbitrary server or Agent log content.
    network_errors = [label for needle, label in (
        ("Could not resolve host", "dns_resolution_failed"),
        ("Couldn't connect to server", "connection_failed"),
        ("Timeout was reached", "network_timeout"),
        ("SSL peer certificate or SSH remote key was not OK", "tls_certificate_validation_failed"),
        ("SSL connect error", "tls_connection_failed"),
    ) if needle in text]
    result = {"started_utc": started, "binary_sha256": expected_hash, "private_key_retained": private.exists(),
              "enroll_requested": "ENROLL requesting device token" in text,
              "enroll_succeeded": "ENROLL succeeded" in text,
              "cached_token_reused": "AUTH loaded cached device token" in text,
              "token_present_before": cached_before, "token_retained": token.is_file() and token.stat().st_size > 0,
              "token_mode": oct(stat.S_IMODE(token.stat().st_mode)) if token.exists() else None,
              "enroll_error_http": int(error[1]) if error else None,
              "enroll_error_code": error[2] if error else None,
              "network_errors": network_errors,
              "mqtt": {"host": settings["host"], "port": settings["port"], "tls": False,
                       "connected": "MQTT cloud connected;" in text,
                       "subscription_confirmed": "MQTT cloud subscription confirmed" in text,
                       "hello_reply": "HELLO_REPLY received" in text,
                       "ready": "READY hello handshake complete" in text,
                       "rejected_codes": re.findall(r"connect rejected code=(\d+)", text)},
              "agent_exit_code": process.returncode, "agent_stopped": process.poll() is not None,
              "https_trust": "system CA; no custom CA; verification enabled", "pss_salt_length": 32}
    write_json(ROOT / "last-run-result.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run"])
    args = parser.parse_args()
    os.umask(0o077)
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    ROOT.chmod(0o700)
    with (ROOT / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output = prepare() if args.action == "prepare" else run(json.load(__import__("sys").stdin))
        print(json.dumps(output), flush=True)
