"""Offline URL/transport/GUI checks. No sockets, binding submissions or key changes."""
import json
import os
import ssl
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PySide6.QtWidgets import QApplication

from binding import BindingClient, BindingIdentity, BindingTask, binding_url
from main import DeviceManager

HTTP_ROOT = "http://10.40.5.227:8080"


class BindingChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        cls.identity = BindingIdentity("TEST-SN-001", pem, "test", "test")

    def test_https_remains_default_with_or_without_test_mode(self):
        for enabled in (False, True):
            for root in ("https://localhost:8443", "https://example.test/", "https://[::1]:8443"):
                with self.subTest(root=root, enabled=enabled):
                    self.assertEqual(binding_url(root, allow_internal_http=enabled),
                                     root.rstrip("/") + "/v1/device-keys/bind")

    def test_internal_http_requires_opt_in_and_exact_authority(self):
        for root in (HTTP_ROOT, HTTP_ROOT + "/"):
            with self.assertRaises(ValueError):
                binding_url(root)
            self.assertEqual(binding_url(root, allow_internal_http=True), HTTP_ROOT + "/v1/device-keys/bind")
        for root in ("http://localhost:8080", "http://10.40.5.228:8080", "http://10.40.5.227",
                     "http://10.40.5.227:80", "http://10.40.5.227:8081", "http://10.40.5.227.:8080",
                     "http://10.40.5.227:08080", "http://10.40.5.227:8080.evil.test",
                     "http://10.40.5.227:8080@evil.test", "http://user@10.40.5.227:8080",
                     "http://[::ffff:10.40.5.227]:8080"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                binding_url(root, allow_internal_http=True)

    def test_rejects_paths_queries_fragments_and_obscured_urls(self):
        for root in (HTTP_ROOT + "/v1/device-keys/bind", HTTP_ROOT + "//", HTTP_ROOT + "?x=1",
                     HTTP_ROOT + "?", HTTP_ROOT + "#", HTTP_ROOT + "#part", HTTP_ROOT + "\\path",
                     HTTP_ROOT + "\n", "\x00" + HTTP_ROOT, " " + HTTP_ROOT,
                     "https://user:pass@example.test", "https://example.test/path",
                     "https://example.test:0", "https://example.test:65536", "ftp://example.test", ""):
            for enabled in (False, True):
                with self.subTest(root=root, enabled=enabled), self.assertRaises(ValueError):
                    binding_url(root, allow_internal_http=enabled)

    def test_client_opt_in_and_https_trust_are_independent(self):
        client = BindingClient()
        tasks = []
        client.pool = SimpleNamespace(start=tasks.append)
        with self.assertRaises(ValueError):
            client.start(self.identity, HTTP_ROOT)
        self.assertFalse(tasks)
        client.start(self.identity, HTTP_ROOT, "unused-missing-ca.pem", allow_internal_http=True)
        self.assertIsNone(tasks[-1].context)
        self.assertEqual(tasks[-1].endpoint, HTTP_ROOT + "/v1/device-keys/bind")
        client.reply = None
        client.start(self.identity, "https://example.test", allow_internal_http=True)
        self.assertTrue(tasks[-1].context.check_hostname)
        self.assertEqual(tasks[-1].context.verify_mode, ssl.CERT_REQUIRED)
        client.reply = None
        with self.assertRaises(ValueError):
            client.start(self.identity, "https://example.test", "unused-missing-ca.pem", allow_internal_http=True)

    def test_http_worker_serializes_unchanged_two_field_payload_without_network(self):
        response = Mock()
        response.status = 201
        response.length = 0
        response.isclosed.side_effect = (False, True)
        response.read1.return_value = json.dumps({"sn": self.identity.sn, "status": "bound"}).encode()
        response.getheader.return_value = ""
        connection = Mock()
        connection.getresponse.return_value = response
        task = BindingTask(self.identity, binding_url(HTTP_ROOT, allow_internal_http=True), None, 15000)
        results = []
        task.signals.finished.connect(results.append)
        with patch("binding.http.client.HTTPConnection", return_value=connection) as http, \
                patch("binding.http.client.HTTPSConnection") as https:
            task.run()
        http.assert_called_once_with("10.40.5.227", 8080, timeout=15.0)
        https.assert_not_called()
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("POST", "/v1/device-keys/bind"))
        self.assertEqual(kwargs["body"], self.identity.payload())
        self.assertEqual(json.loads(kwargs["body"])["public_key"], self.identity.public_key)
        self.assertTrue(results[0].success)
        connection.close.assert_called_once()

    def test_minimal_binding_page_and_manual_submit(self):
        window = DeviceManager()
        try:
            window.show()
            self.app.processEvents()
            self.assertEqual(window.windowTitle(), "设备公钥绑定工具")
            self.assertTrue(window.read_button.isVisible())
            self.assertFalse(window.bind_button.isEnabled())
            for removed in ("bind_import", "bind_mock", "bind_ca", "bind_internal_http",
                            "mock_button", "device_page"):
                self.assertFalse(hasattr(window, removed), removed)
            with patch.object(window.binding_client, "start") as start:
                start.assert_not_called()
                window.set_binding_identity(self.identity)
                self.assertEqual(window.bind_sn.text(), self.identity.sn)
                self.assertEqual(window.bind_public_key.toPlainText(), self.identity.public_key)
                self.assertTrue(window.bind_button.isEnabled())
                start.assert_not_called()
                window.bind_server.setText(HTTP_ROOT + "/")
                window.bind_button.click()  # Mocked: no thread, socket or real submission.
                start.assert_called_once()
                self.assertEqual(start.call_args.args[1], HTTP_ROOT + "/")
                self.assertFalse(window.bind_button.isEnabled())
                result = SimpleNamespace(
                    http_status=200, message="已绑定", success=True,
                    display_details=lambda include_raw=False: "details")
                window.binding_finished(result)
                self.assertTrue(window.bind_button.isEnabled())
                self.assertIn("HTTP 200", window.bind_status.text())
                self.assertEqual(window.bind_sn.text(), self.identity.sn)
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
