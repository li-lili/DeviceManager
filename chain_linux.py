"""Linux side of the Windows Qt -> HTTPS bind -> native Agent enroll test."""

import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

from mock_bind_server import MockBindingServer, create_fixture


def wait_for(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for local test state")


def main(binary):
    assert binary.is_file(), "Previously compiled Agent binary not found"
    report = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix="device-manager-chain-") as temporary:
        directory = Path(temporary)
        sn = "LOCAL-CHAIN-" + uuid.uuid4().hex[:16]
        ca, cert, tls_key, identity_path = create_fixture(directory)
        device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = device_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        identity = {"sn": sn, "public_key": public_pem}
        identity_path.write_text(json.dumps(identity), encoding="utf-8")
        private_path = directory / "device-test-private.pem"
        private_path.write_bytes(device_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private_path.chmod(0o600)
        wrong_path = directory / "wrong-test-private.pem"
        wrong_path.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        wrong_path.chmod(0o600)
        logs = directory / "business-logs"
        logs.mkdir()
        sources = directory / "sources.json"
        sources.write_text(json.dumps({"log_sources": [{"source_id": "business", "path": str(logs),
            "recursive": True, "file_patterns": ["*.log"], "filename_date_formats": ["%Y-%m-%d"]}]}))
        with MockBindingServer(0, cert, tls_key, {sn}) as server:
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            processes, handles = [], []
            cloud = None
            try:
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    broker_port = sock.getsockname()[1]
                password_file = directory / "mqtt-test-passwords"
                password_result = subprocess.run(["mosquitto_passwd", "-b", "-c", str(password_file),
                                                   sn, server.test_token], capture_output=True)
                assert password_result.returncode == 0, "Cannot prepare test broker authentication"
                broker_config = directory / "mosquitto.conf"
                broker_config.write_text(f"listener {broker_port} 127.0.0.1\nallow_anonymous false\n"
                                         f"password_file {password_file}\n")
                broker_log = open(directory / "broker.log", "w")
                handles.append(broker_log)
                broker = subprocess.Popen(["mosquitto", "-c", str(broker_config)], stdout=broker_log,
                                          stderr=subprocess.STDOUT)
                processes.append(broker)

                def listening():
                    try:
                        with socket.create_connection(("127.0.0.1", broker_port), .1):
                            return True
                    except OSError:
                        return False
                wait_for(listening)

                def make_case(name, private_key):
                    case = directory / name
                    case.mkdir()
                    (case / "device-agent.conf").write_text(
                        f"host=127.0.0.1\nport={broker_port}\ndevice={sn}\n"
                        f"private-key={private_key}\nhttps-ca={ca}\n"
                        f"enroll-url=https://127.0.0.1:{server.server_port}/v1/enroll\n"
                        f"sources-config={sources}\nstate-dir=state\nwork-dir=work\nlog-file=agent.log\n")
                    return case, case / "state/tokens" / (sn + ".token")

                def reject_native(case, token_path, reason):
                    result = subprocess.run([str(binary)], cwd=case, capture_output=True, timeout=20)
                    assert result.returncode == 1 and b"HTTP 401" in result.stdout + result.stderr
                    assert not token_path.exists(), "Rejected Agent unexpectedly received a Token"
                    assert server.enroll_events[-1]["reason"] == reason

                unbound, unbound_token = make_case("unbound", private_path)
                reject_native(unbound, unbound_token, "not_bound")
                print("PASS native Agent rejected before public-key binding; no Token created", flush=True)
                assert not server.bindings, "Binding registry must start empty"
                print("READY " + json.dumps({"server": f"https://localhost:{server.server_port}",
                                             "ca_pem": ca.read_text(), "identity": identity}), flush=True)
                assert sys.stdin.readline().strip() == "bound", "Qt binding did not complete"
                public_der = device_key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                assert server.bindings.get(sn) == public_der, "Qt-bound key differs from Agent key"
                assert len(server.requests) == 1 and server.requests[0] == identity
                fingerprint = hashlib.sha256(server.bindings[sn]).hexdigest()
                report.update(sn=sn, bound_public_key_sha256=fingerprint)
                print("PASS Qt-bound public key matches native Agent test identity: SHA256 " + fingerprint, flush=True)

                wrong, wrong_token = make_case("wrong-key", wrong_path)
                reject_native(wrong, wrong_token, "invalid_signature")
                print("PASS native Agent with a different private key rejected; no Token created", flush=True)

                bad_signature = device_key.sign(("noetix-enroll-v1|" + sn).encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                connection = http.client.HTTPSConnection("127.0.0.1", server.server_port,
                    context=ssl.create_default_context(cafile=str(ca)), timeout=5)
                try:
                    connection.request("POST", "/v1/enroll", json.dumps({"sn": sn,
                        "signature": base64.b64encode(bad_signature).decode("ascii")}),
                        {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    assert response.status == 401
                    response.read()
                finally:
                    connection.close()
                print("PASS MAX_LENGTH salt rejected by the same bound public key; verifier requires salt=32", flush=True)

                subscribed = threading.Event()
                cloud = mqtt.Client(client_id="local-chain-cloud", protocol=mqtt.MQTTv5)
                cloud.username_pw_set(sn, server.test_token)
                cloud.on_connect = lambda client, *args: client.subscribe(f"v1/d/{sn}/up/#", qos=1)
                cloud.on_subscribe = lambda *args: subscribed.set()
                def on_message(client, userdata, message):
                    if message.topic.endswith("/hello"):
                        props = Properties(PacketTypes.PUBLISH)
                        props.ContentType = "application/json"
                        props.UserProperty = [("proto", "1"), ("ct", "json")]
                        client.publish(f"v1/d/{sn}/down/hello_reply", "{}", qos=1, properties=props)
                cloud.on_message = on_message
                cloud.connect("127.0.0.1", broker_port)
                cloud.loop_start()
                assert subscribed.wait(5), "Local MQTT observer failed to subscribe"
                correct, token_path = make_case("correct-key", private_path)

                def launch(name):
                    logfile = correct / name
                    handle = open(logfile, "w")
                    handles.append(handle)
                    process = subprocess.Popen([str(binary)], cwd=correct, stdout=handle, stderr=subprocess.STDOUT)
                    processes.append(process)
                    wait_for(lambda: "READY hello handshake complete" in logfile.read_text() or process.poll() is not None)
                    assert process.poll() is None, "Agent exited before authenticated MQTT handshake"
                    assert "READY hello handshake complete" in logfile.read_text()
                    return process

                agent = launch("first-run.log")
                assert token_path.read_text() == server.test_token
                assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
                assert server.enroll_events[-1]["verified"]
                assert sum(event["verified"] for event in server.enroll_events) == 1
                print("PASS native Agent RSA-PSS salt32 verified with Qt-bound key; HTTPS Token saved mode 0600; MQTT READY", flush=True)
                agent.send_signal(signal.SIGTERM)
                agent.wait(10)
                before = len(server.enroll_events)
                restarted = launch("restart.log")
                assert len(server.enroll_events) == before
                assert "loaded cached device token" in (correct / "restart.log").read_text()
                print("PASS Agent restart reuses issued Token without another enroll request", flush=True)
                restarted.send_signal(signal.SIGTERM)
                restarted.wait(10)
                report.update(passed=True, bind_requests=len(server.requests),
                              enroll_events=server.enroll_events, token_saved_0600=True,
                              mqtt_ready=True, restart_reused_token=True)
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        process.wait(10)
                if cloud is not None:
                    cloud.disconnect()
                    cloud.loop_stop()
                server.shutdown()
                server_thread.join(3)
                for handle in handles:
                    handle.close()
    report["temporary_keys_and_tokens_removed"] = not Path(temporary).exists()
    assert report["temporary_keys_and_tokens_removed"]
    print("REPORT " + json.dumps(report), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    main(parser.parse_args().binary)
