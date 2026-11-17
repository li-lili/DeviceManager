"""Loopback HTTPS binding/enrollment simulator; never use with real identities."""

import argparse
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import ssl
import secrets
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from identity_validation import validate_identity, validate_sn


TEST_SN = "LOCAL-BIND-TEST-001"


def create_fixture(directory: Path, hostname="localhost"):
    """Create a local CA, TLS server cert and public-only paired identity JSON."""
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DeviceManager temporary local CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(server_name).issuer_name(name)
            .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(hostname)] + ([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                                           if hostname == "localhost" else [])), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, cert_path, key_path = (directory / name for name in ("ca.pem", "server.pem", "tls-test-private.pem"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    key_path.chmod(0o600)
    # The device test private key is never serialized or saved.
    device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = device_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    identity_path = directory / "test_identity.json"
    identity_path.write_text(json.dumps({"sn": TEST_SN, "public_key": public}, indent=2), encoding="utf-8")
    return ca_path, cert_path, key_path, identity_path


class MockBindingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, cert_path, key_path, allowed_sns=None):
        super().__init__(("127.0.0.1", port), Handler)
        self.bindings = {}
        self.allowed_sns = set(allowed_sns) if allowed_sns is not None else {TEST_SN}
        self.test_token = "lsd_local_test_" + secrets.token_hex(16)
        self.enroll_events = []  # Metadata only; signatures, private keys and Tokens are not logged.
        self.requests = []
        self.forced_status = None
        self.response_override = None
        self.delay = 0
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        self.socket = context.wrap_socket(self.socket, server_side=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path not in ("/v1/device-keys/bind", "/v1/enroll"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid length")
            body = json.loads(self.rfile.read(length))
            if self.path == "/v1/enroll":
                self.enroll(body)
                return
            if not isinstance(body, dict) or set(body) != {"sn", "public_key"}:
                raise ValueError("invalid fields")
            self.server.requests.append(body)
            validate_identity(body["sn"], body["public_key"])
        except (ValueError, TypeError):
            self.respond(400, {"error": "bad_request"})
            return
        sn, public = body["sn"], body["public_key"]
        public_der = serialization.load_pem_public_key(public.encode("ascii")).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if self.server.forced_status:
            status = self.server.forced_status
            self.respond(status, {"error": {400: "bad_request", 401: "unauthorized",
                                          409: "sn_key_mismatch", 429: "rate_limited"}.get(status, "test_error")})
        elif sn not in self.server.allowed_sns:
            self.respond(401, {"error": "unauthorized"})
        elif sn in self.server.bindings and self.server.bindings[sn] != public_der:
            self.respond(409, {"error": "sn_key_mismatch"})
        else:
            status = 200 if sn in self.server.bindings else 201
            self.server.bindings[sn] = public_der
            self.respond(status, {"sn": sn, "status": "bound" if status == 201 else "already_bound"})

    def enroll(self, body):
        if (not isinstance(body, dict) or set(body) != {"sn", "signature"}
                or not isinstance(body["sn"], str) or not isinstance(body["signature"], str)):
            self.respond(400, {"error": "bad_request"})
            return
        sn = body["sn"]
        try:
            validate_sn(sn)
        except ValueError:
            self.respond(400, {"error": "bad_request"})
            return
        bound_key = self.server.bindings.get(sn)
        event = {"sn": sn, "verified": False, "expected_salt_length": 32}
        self.server.enroll_events.append(event)
        if sn not in self.server.allowed_sns or bound_key is None:
            event["reason"] = "not_bound"
            self.respond(401, {"error": "unauthorized"})
            return
        event["verification_key_sha256"] = hashlib.sha256(bound_key).hexdigest()
        try:
            signature = base64.b64decode(body["signature"], validate=True)
            if len(signature) != 256:
                raise ValueError("invalid signature length")
        except (ValueError, UnicodeError):
            event["reason"] = "bad_signature_encoding"
            self.respond(400, {"error": "bad_request"})
            return
        try:
            # The ONLY verification key comes from the preceding bind request.
            serialization.load_der_public_key(bound_key).verify(
                signature, ("noetix-enroll-v1|" + sn).encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        except InvalidSignature:
            event["reason"] = "invalid_signature"
            self.respond(401, {"error": "unauthorized"})
            return
        event["verified"] = True
        event["reason"] = "verified_with_bound_public_key"
        self.respond(200, {"device_id": sn, "token": self.server.test_token, "reissued": False})

    def respond(self, status, body):
        time.sleep(self.server.delay)
        data = self.server.response_override
        if data is None:
            data = json.dumps(body).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if status == 429:
                self.send_header("Retry-After", "5")
            self.end_headers()
            self.wfile.write(data)
        except (OSError, ssl.SSLError):
            pass  # The timeout test deliberately closes the connection.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--status", type=int, choices=[400, 401, 409, 429])
    parser.add_argument("--delay", type=float, default=0)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="device-manager-bind-") as temporary:
        ca, cert, key, identity = create_fixture(Path(temporary))
        with MockBindingServer(args.port, cert, key) as server:
            server.forced_status, server.delay = args.status, args.delay
            print(f"本地 HTTPS 模拟接口：https://localhost:{server.server_port}", flush=True)
            print(f"附加 CA：{ca}\n导入测试身份：{identity}", flush=True)
            print("仅本机模拟；Ctrl+C 停止后自动清理临时证书和测试身份。", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
