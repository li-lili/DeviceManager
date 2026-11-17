"""Offline response/worker/GUI checks; no sockets, credential reads or real identities."""
import http.client
import json
import os
import ssl
import unittest
from unittest.mock import Mock, patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PySide6.QtWidgets import QApplication
from binding import BindingIdentity, BindingTask, interpret_response
from main import DeviceManager
CASES = (
    (201, "status", "bound", "首次绑定成功", True),
    (200, "status", "already_bound", "无需更新", True),
    (200, "status", "updated", "原绑定公钥已被替换", True),
    (400, "error", "bad_request", "SN 或公钥不合法", False),
    (403, "error", "ip_not_allowed", "出口 IP 不在工厂白名单", False),
    (404, "error", "sn_not_found", "台账查无该 SN", False),
    (409, "error", "sn_key_mismatch", "公钥指纹冲突", False),
    (429, "error", "rate_limited", "请求被限流", False),
    (503, "error", "sn_lookup_unavailable", "台账服务不可用或超时", False),
)


class ResponseChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        cls.identity = BindingIdentity("TEST-SN-001", pem, "test", "test")

    def interpret(self, code, data, retry_after=""):
        return interpret_response(self.identity, code, json.dumps(data).encode(), retry_after)

    def payload(self, field, value):
        data = {"sn": self.identity.sn, "message": "服务端说明"}
        data[field] = value if field == "status" else {"code": value, "message": "错误详情"}
        return data

    def test_nine_documented_pairs(self):
        for code, field, value, hint, success in CASES:
            with self.subTest(code=code, value=value):
                data = self.payload(field, value)
                result = self.interpret(code, data)
                self.assertEqual(result.success, success)
                self.assertEqual(result.http_status, code)
                self.assertIn(hint, result.message)
                self.assertEqual(json.loads(result.server_result), data)
                self.assertIn("服务端说明", result.server_message)
                self.assertEqual(result.response_status if field == "status" else result.error_code, value)
                if field == "error":
                    self.assertIn("错误详情", result.server_message)

    def test_all_wrong_http_marker_pairs_fail(self):
        # Only the exact three HTTP/status pairs may be successful.
        for code in (200, 201, 202, 204, 301, 400, 401, 403, 404, 409, 429, 500, 503, 599):
            for value in ("bound", "already_bound", "updated", "unknown", "", None, 1, {}, []):
                with self.subTest(code=code, value=value):
                    result = self.interpret(code, {"sn": self.identity.sn, "status": value})
                    allowed = ((201, "bound"), (200, "already_bound"), (200, "updated"))
                    self.assertEqual(result.success, (code, value) in allowed)

    def test_missing_invalid_fields_and_conflicting_errors(self):
        for code in (200, 201):
            for data in ({}, {"status": "bound"}, {"sn": self.identity.sn},
                         {"sn": "wrong", "status": "bound"},
                         {"sn": self.identity.sn, "status": "bound", "error": {"code": "bad_request"}},
                         {"sn": self.identity.sn, "status": "bound", "error": None},
                         {"sn": self.identity.sn, "status": "already_bound", "error": "bad_request"}):
                with self.subTest(code=code, data=data):
                    result = self.interpret(code, data)
                    self.assertFalse(result.success)
                    self.assertIn("未确认绑定成功", result.message)
        for error in ({}, {"code": 1}, {"code": None}, {"code": "unknown"}, "bad_request", None, []):
            with self.subTest(error=error):
                result = self.interpret(400, {"error": error})
                self.assertFalse(result.success)
                self.assertIn("字段", result.message)
        result = self.interpret(409, self.payload("error", "bad_request"))
        self.assertIn("未匹配", result.message)
        result = self.interpret(403, {"status": "error", "error": {"code": "ip_not_allowed"}})
        self.assertIn("出口 IP 不在工厂白名单", result.message)

    def test_unknown_http_status_and_error_code(self):
        for code in (202, 301, 401, 418, 500, 599):
            result = self.interpret(code, {"status": "bound", "sn": self.identity.sn})
            self.assertFalse(result.success)
            self.assertIn(f"未知 HTTP 状态码 {code}", result.message)
        result = self.interpret(403, {"error": {"code": "future_code"}, "message": "未知错误"})
        self.assertIn("未匹配", result.message)
        self.assertEqual(result.error_code, "future_code")
        self.assertIn("未知错误", result.display_details())

    def test_non_json_empty_non_object_duplicate_fields_invalid_utf8(self):
        for body in (b"", b"<html>Bad Gateway</html>", b"not JSON", b"null", b"[]", b'"bound"',
                     b"42", b'{"status":"bound",', b'{"status":"bound","status":"bound"}',
                     b'{"value":NaN}', b'{"message":"\xff"}'):
            with self.subTest(body=body):
                result = interpret_response(self.identity, 201, body)
                self.assertFalse(result.success)
                self.assertIn("JSON", result.message)
                self.assertEqual(result.http_status, 201)
                self.assertTrue(result.server_result)

    def test_retry_after_is_information_only(self):
        result = self.interpret(429, self.payload("error", "rate_limited"), "60")
        self.assertFalse(result.success)
        self.assertIn("Retry-After: 60", result.message)
        self.assertIn("不会自动重试", result.message)

    def test_redaction_json_nested_and_plaintext(self):
        data = self.payload("status", "bound")
        data.update({"access_token": "FAKE_ACCESS", "nested": [{"private_key": "FAKE_PRIVATE"},
                     {"Authorization": "FAKE_AUTH", "api-key": "FAKE_API"}],
                     "message": "token=FAKE_MESSAGE Bearer FAKE_BEARER"})
        result = self.interpret(201, data)
        details = result.display_details()
        for secret in ("FAKE_ACCESS", "FAKE_PRIVATE", "FAKE_AUTH", "FAKE_API", "FAKE_MESSAGE", "FAKE_BEARER"):
            self.assertNotIn(secret, details)
        self.assertIn(self.identity.sn, details)
        self.assertIn("已脱敏", details)
        raw = (b'<html>token="FAKE_TOKEN" password=FAKE_PASSWORD '
               b'Bearer FAKE_BEARER -----BEGIN PRIVATE KEY-----\nFAKE_PEM\n'
               b'-----END PRIVATE KEY-----</html>')
        details = interpret_response(self.identity, 502, raw).display_details()
        for secret in ("FAKE_TOKEN", "FAKE_PASSWORD", "FAKE_BEARER", "FAKE_PEM"):
            self.assertNotIn(secret, details)

    def run_worker(self, connection):
        task = BindingTask(self.identity, "https://offline.invalid/v1/device-keys/bind", None, 1000)
        results = []
        task.signals.finished.connect(results.append)
        with patch("binding.http.client.HTTPSConnection", return_value=connection) as factory:
            task.run()
        factory.assert_called_once()
        connection.connect.assert_called_once()
        connection.close.assert_called_once()
        self.assertEqual(len(results), 1)
        return results[0]

    def test_worker_connect_errors_have_no_retry(self):
        for error, hint in ((TimeoutError(), "请求超时"), (ConnectionRefusedError("refused"), "网络"),
                            (ssl.SSLCertVerificationError("untrusted"), "TLS"),
                            (http.client.HTTPException("broken response"), "响应错误")):
            with self.subTest(error=type(error).__name__):
                connection = Mock()
                connection.connect.side_effect = error
                result = self.run_worker(connection)
                self.assertFalse(result.success)
                self.assertIsNone(result.http_status)
                self.assertIn(hint, result.message)
                connection.request.assert_not_called()

    def test_worker_body_timeout_partial_or_oversize_never_succeeds(self):
        for failure in (TimeoutError(), OSError("connection lost"), "incomplete", "oversize"):
            with self.subTest(failure=str(failure)):
                connection, response = Mock(), Mock()
                connection.getresponse.return_value = response
                response.status = 201
                body = json.dumps(self.payload("status", "bound")).encode()
                response.isclosed.side_effect = (False, False, True)
                response.length = 10 if failure == "incomplete" else 0
                response.read1.side_effect = ([body, failure] if isinstance(failure, Exception) else
                                             [b"x" * 65537] if failure == "oversize" else [body, b""])
                result = self.run_worker(connection)
                self.assertFalse(result.success)
                self.assertEqual(result.http_status, 201)
                self.assertIn("结果待核实", result.message)
                connection.request.assert_called_once()
                response.close.assert_called_once()

    def test_gui_nine_results_and_exceptions_without_submission(self):
        window = DeviceManager()
        try:
            window.show()
            self.app.processEvents()
            window.set_binding_identity(self.identity)
            original = window.binding_identity
            with patch.object(window.binding_client, "start") as start:
                results = [self.interpret(code, self.payload(field, value))
                           for code, field, value, _, _ in CASES]
                results.append(interpret_response(self.identity, 502, b"Bad Gateway"))
                connection = Mock()
                connection.connect.side_effect = TimeoutError()
                results.append(self.run_worker(connection))
                for result in results:
                    window.set_binding_controls(False)
                    window.binding_finished(result)
                    details = window.bind_response.toPlainText()
                    self.assertIn(result.message, details)
                    self.assertIn("status：", details)
                    self.assertIn("error.code：", details)
                    self.assertIn("服务端 message：", details)
                    self.assertNotIn("脱敏原始响应：", details)
                    self.assertNotIn(result.server_result, details)
                    self.assertIn(result.message, window.bind_status.text())
                    self.assertTrue(window.bind_button.isEnabled())
                start.assert_not_called()
                self.assertEqual(window.binding_identity, original)
                self.assertEqual(window.bind_public_key.toPlainText(), original.public_key)
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
