"""Real Qt client/UI + loopback HTTPS integration checks; no cloud or ADB calls."""

import json
import os
from pathlib import Path
import socket
import tempfile
import threading

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from binding import BindingClient, BindingIdentity, binding_url, load_test_identity, validate_identity
from main import DeviceManager
from mock_bind_server import MockBindingServer, create_fixture


def rejected(call):
    try:
        call()
    except (ValueError, TypeError):
        return
    raise AssertionError("Expected validation failure")


def main():
    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory(prefix="binding-check-") as temporary:
        directory = Path(temporary)
        ca, cert, key, path = create_fixture(directory)
        identity = load_test_identity(path)
        for sn in ("", "a" * 65, "bad/sn", "含中文", "trailing\n"):
            rejected(lambda: validate_identity(sn, identity.public_key))
        for bad_key in ("invalid", rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key(),
                        ec.generate_private_key(ec.SECP256R1()).public_key()):
            pem = bad_key if isinstance(bad_key, str) else bad_key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            rejected(lambda: validate_identity(identity.sn, pem))
        for url in ("http://localhost", "https://user:pass@localhost", "https://localhost/path", "https://localhost?x=1"):
            rejected(lambda: binding_url(url))
        private_json = directory / "invalid.json"
        private_json.write_text(json.dumps({"sn": identity.sn, "public_key": identity.public_key, "private_key": "test"}))
        rejected(lambda: load_test_identity(private_json))
        print("PASS SN/RSA/PEM/HTTPS validation and private-field rejection")

        with MockBindingServer(0, cert, key) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"https://localhost:{server.server_port}"
            client = BindingClient()

            def send(current=identity, trust=str(ca), timeout=15000, target=url):
                results = []
                loop = QEventLoop()
                def done(result):
                    results.append(result)
                    loop.quit()
                client.completed.connect(done)
                watchdog = QTimer()
                watchdog.setSingleShot(True)
                watchdog.timeout.connect(loop.quit)
                watchdog.start(20000)
                client.start(current, target, trust, timeout)
                loop.exec()
                client.completed.disconnect(done)
                watchdog.stop()
                assert results, "Qt request failed to finish"
                return results[0]

            try:
                before = len(server.requests)
                result = send(trust="")
                assert not result.success and result.http_status is None, result
                assert len(server.requests) == before, "Untrusted TLS server received identity"
                print("PASS TLS verification rejects untrusted CA before HTTP submission")
                result = send()
                assert result.success and result.http_status == 201, result
                assert server.requests[-1] == json.loads(identity.payload())
                assert server.requests[-1]["public_key"] == identity.public_key
                assert send().http_status == 200
                assert send().success
                crlf_identity = BindingIdentity(identity.sn, identity.public_key.replace("\n", "\r\n"), "test", "test")
                assert send(crlf_identity).success
                assert server.requests[-1]["public_key"] == crlf_identity.public_key
                other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                assert send(BindingIdentity(identity.sn, other_key, "test", "test")).http_status == 409
                assert send(BindingIdentity("NOT-WHITELISTED", identity.public_key, "test", "test")).http_status == 401
                print("PASS real HTTPS POST 201/200, two-field JSON and exact PEM newline preservation")
                for code in (400, 401, 409, 429, 500):
                    server.forced_status = code
                    result = send()
                    assert result.http_status == code and not result.success, result
                server.forced_status = None
                server.response_override = b"not JSON"
                assert not send().success
                server.response_override = b'{"sn":"wrong","status":"already_bound"}'
                assert not send().success
                server.response_override = None
                print("PASS 400/401/409/429/500 and malformed/mismatched success response handling")
                other_ca, wrong_cert, wrong_key, _ = create_fixture(directory / "wrong-host", "wrong.invalid")
                with MockBindingServer(0, wrong_cert, wrong_key) as wrong_server:
                    wrong_thread = threading.Thread(target=wrong_server.serve_forever, daemon=True)
                    wrong_thread.start()
                    result = send(trust=str(other_ca), target=f"https://localhost:{wrong_server.server_port}")
                    assert not result.success and result.http_status is None and not wrong_server.requests
                    wrong_server.shutdown()
                    wrong_thread.join(timeout=3)
                print("PASS trusted CA still rejects mismatched TLS hostname")
                server.delay = 0.3
                ticks = []
                heartbeat = QTimer()
                heartbeat.timeout.connect(lambda: ticks.append(1))
                heartbeat.start(10)
                result = send(timeout=100)
                heartbeat.stop()
                assert not result.success and "超时" in result.message and len(ticks) >= 2, result
                server.delay = 0
                with socket.socket() as unused:
                    unused.bind(("127.0.0.1", 0))
                    port = unused.getsockname()[1]
                result = send(target=f"https://127.0.0.1:{port}")
                assert result.http_status is None and not result.success
                print("PASS total timeout, responsive Qt event loop and refused connection")

                window = DeviceManager()
                window.show()
                app.processEvents()
                window.set_binding_identity(identity)
                assert window.binding_identity == identity
                window.bind_server.setText(url)
                loop = QEventLoop()
                window.binding_client.completed.connect(loop.quit)
                window.submit_binding(str(ca), 15000)
                assert not window.bind_button.isEnabled() and not window.read_button.isEnabled()
                guard = QTimer()
                guard.setSingleShot(True)
                guard.timeout.connect(loop.quit)
                guard.start(5000)
                loop.exec()
                guard.stop()
                assert window.bind_button.isEnabled() and "HTTP 200" in window.bind_status.text()
                rejected(lambda: window.set_binding_identity(
                    BindingIdentity("bad/sn", identity.public_key, "test", "test")))
                assert window.binding_identity == identity and window.bind_button.isEnabled()
                window.close()
                print("PASS UI submit/result and fail-closed identity validation")
            finally:
                server.shutdown()
                thread.join(timeout=3)
    print("PASS all binding checks; temporary TLS keys removed; no real cloud or board access")


if __name__ == "__main__":
    main()
