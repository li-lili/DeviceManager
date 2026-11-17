"""Paired identities and async binding; HTTPS or explicitly allowed internal HTTP."""

from dataclasses import dataclass, replace
import json
import re
from pathlib import Path
import http.client
import socket
import ssl
import time
from urllib.parse import urlsplit

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QUrl, Signal
from identity_validation import validate_identity


@dataclass(frozen=True)
class BindingIdentity:
    sn: str
    public_key: str
    sn_source: str
    public_key_source: str

    def payload(self) -> bytes:
        validate_identity(self.sn, self.public_key)
        # Serialize the original PEM text including its line breaks.
        return json.dumps({"sn": self.sn, "public_key": self.public_key}).encode("utf-8")


def load_test_identity(path: Path) -> BindingIdentity:
    if path.stat().st_size > 65536:
        raise ValueError("测试身份 JSON 文件过大")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or set(data) != {"sn", "public_key"}:
        raise ValueError("测试身份 JSON 只能包含 sn 和 public_key 两个字段；不得包含私钥或 Token")
    validate_identity(data["sn"], data["public_key"])
    origin = f"导入测试身份：{path.resolve()}"
    return BindingIdentity(data["sn"], data["public_key"], origin + " #sn", origin + " #public_key")


INTERNAL_HTTP_SERVER = "10.40.5.227:8080"
# 界面启动时默认填入的云端根地址，与 Agent 的 enroll-url 同源。
DEFAULT_SERVER = "https://logserver.test.humanuniverse.cn"


def binding_url(server: str, *, allow_internal_http: bool = False) -> str:
    if not isinstance(server, str) or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in server):
        raise ValueError("服务器地址无效：不能包含空白或控制字符")
    try:
        parsed = urlsplit(server)
        port = parsed.port
    except ValueError as error:
        raise ValueError("服务器地址或端口无效") from error
    if (not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or (port is not None and port == 0)
            or "\\" in server or "?" in server or "#" in server):
        raise ValueError("请输入服务器根地址，不含账号、接口路径、查询参数或片段")
    if parsed.scheme == "http":
        if not allow_internal_http:
            raise ValueError("正式模式要求 HTTPS；使用指定内网 HTTP 服务器需先勾选“内网 HTTP 测试模式”")
        if parsed.netloc != INTERNAL_HTTP_SERVER:
            raise ValueError(f"内网 HTTP 测试仅允许 http://{INTERNAL_HTTP_SERVER}/")
    elif parsed.scheme != "https":
        raise ValueError("正式模式请输入 HTTPS 服务器根地址；内网测试模式仅允许指定 HTTP 地址")
    url = server.rstrip("/") + "/v1/device-keys/bind"
    if not QUrl(url).isValid():
        raise ValueError("服务器地址无效")
    return url


SUCCESS_TEXT = {
    (201, "bound"): "首次绑定成功，公钥已保存。",
    (200, "already_bound"): "相同 SN 和公钥已绑定，无需更新。",
    (200, "updated"): "公钥覆盖更新成功：原绑定公钥已被替换。",
}
ERROR_TEXT = {
    (400, "bad_request"): "SN 或公钥不合法，请核对输入。",
    (403, "ip_not_allowed"): "当前出口 IP 不在工厂白名单，请联系云端同事确认。",
    (404, "sn_not_found"): "机器人台账查无该 SN，请核对 SN 和台账记录。",
    (409, "sn_key_mismatch"): "公钥指纹冲突，需要人工排查；请勿直接重新绑定或覆盖。",
    (429, "rate_limited"): "请求被限流；请核对后再手动重试。",
    (503, "sn_lookup_unavailable"): "台账服务不可用或超时，请联系云端同事确认。",
}


@dataclass(frozen=True)
class BindingResult:
    http_status: int | None
    message: str
    server_result: str
    success: bool = False
    response_status: str = "（缺失）"
    error_code: str = "（缺失）"
    server_message: str = "（缺失）"

    def display_details(self, *, include_raw=True):
        code = str(self.http_status) if self.http_status is not None else "（无 HTTP 响应）"
        details = (f"HTTP 状态码：{code}\n处理结果：{self.message}\n"
                   f"status：{self.response_status}\nerror.code：{self.error_code}\n"
                   f"服务端 message：{self.server_message}")
        if include_raw:
            details += f"\n\n脱敏原始响应：\n{self.server_result}"
        return details


_SECRET_KEYS = {"token", "accesstoken", "refreshtoken", "idtoken", "authorization",
                "password", "passwd", "secret", "clientsecret", "apikey", "privatekey",
                "privatekeypem", "signature", "credential", "credentials", "cookie", "setcookie"}
_CREDENTIAL_NAME = (r"(?:[\w-]*token|authorization|password|passwd|secret|client[_-]?secret|"
                    r"api[_-]?key|private[_-]?key|signature|credentials?|cookie|set-cookie)")


def redact_text(text):
    """Best-effort display redaction, including non-JSON error pages and messages."""
    text = re.sub(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?"
                  r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)",
                  "[已脱敏私钥]", text, flags=re.S)
    text = re.sub(r"\bBearer\s+[^\s\"'<>]+", "Bearer [已脱敏]", text, flags=re.I)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
                  "[已脱敏 JWT]", text)
    text = re.sub(rf"(\b{_CREDENTIAL_NAME}[\"']?\s*[:=]\s*)([\"'])(.*?)(\2)",
                  r"\1\2[已脱敏]\2", text, flags=re.I | re.S)
    return re.sub(rf"(\b{_CREDENTIAL_NAME}\s*[:=]\s*)[^\s,;<>\"']+",
                  r"\1[已脱敏]", text, flags=re.I)


def redact_response(data):
    if isinstance(data, dict):
        return {key: "[已脱敏]" if re.sub(r"[^a-z0-9]", "", key.lower()) in _SECRET_KEYS
                or key.lower().replace("-", "_").endswith("_token")
                else redact_response(value) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_response(value) for value in data]
    return redact_text(data) if isinstance(data, str) else data


def _unique_object(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("重复 JSON 字段")
        data[key] = value
    return data


def _invalid_constant(value):
    raise ValueError("非标准 JSON 常量")


def interpret_response(identity, status, body, retry_after=""):
    text = bytes(body).decode("utf-8", errors="replace")
    success = False
    response_status = error_code = server_message = "（缺失）"
    try:
        data = json.loads(bytes(body).decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
        rendered = json.dumps(redact_response(data), ensure_ascii=False, indent=2)
    except (ValueError, RecursionError):
        data = None
        rendered = redact_text(text) or "（空响应）"
        message = "响应为空或不是有效 JSON 对象；未确认绑定成功，结果待核实。"
    else:
        message = "响应必须为 JSON 对象；未确认绑定成功，结果待核实。"
    if isinstance(data, dict):
        def field(value):
            return redact_text(value) if isinstance(value, str) else "（字段类型错误）"
        if "status" in data:
            response_status = field(data["status"])
        error = data.get("error")
        if isinstance(error, dict) and "code" in error:
            error_code = field(error["code"])
        elif "error" in data:
            error_code = "（error.code 缺失或 error 类型错误）"
        messages = []
        if "message" in data:
            messages.append(field(data["message"]))
        if isinstance(error, dict) and "message" in error:
            messages.append("error.message：" + field(error["message"]))
        server_message = "\n".join(messages) or "（缺失）"
        expected = SUCCESS_TEXT.get((status, response_status))
        if expected is not None:
            if data.get("sn") != identity.sn:
                message = "响应 SN 缺失或与提交值不一致；未确认绑定成功，结果待核实。"
            elif "error" in data:
                message = "响应同时含成功 status 与 error，字段冲突；未确认绑定成功。"
            else:
                message, success = expected, True
        elif ((status, error_code) in ERROR_TEXT
              and data.get("status") not in ("bound", "already_bound", "updated")):
            message = ERROR_TEXT[(status, error_code)]
        else:
            message = "HTTP 状态码与 status/error.code 未匹配已知组合，或字段缺失/冲突；未确认绑定成功，需人工核实。"
    if status not in {200, 201, 400, 403, 404, 409, 429, 503}:
        message = f"未知 HTTP 状态码 {status}；" + message
    if status == 429 and retry_after:
        message += f"；Retry-After: {redact_text(retry_after[:128])}（不会自动重试）"
    return BindingResult(status, message, rendered, success, response_status, error_code, server_message)


def incomplete_response(identity, status, body, message):
    if body:
        result = interpret_response(identity, status, body)
        return replace(result, message=message + "；仅取得部分响应，绑定结果待核实。", success=False)
    else:
        return BindingResult(status, message, "（未取得完整响应）")


class WorkerSignals(QObject):
    finished = Signal(object)


class BindingTask(QRunnable):
    def __init__(self, identity, endpoint, context, timeout_ms):
        super().__init__()
        self.signals = WorkerSignals()
        self.identity, self.endpoint, self.context = identity, endpoint, context
        self.timeout = timeout_ms / 1000

    def run(self):
        parsed = urlsplit(self.endpoint)
        if parsed.scheme == "http":
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80,
                                                    timeout=self.timeout)
        else:
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                                     context=self.context, timeout=self.timeout)
        deadline = time.monotonic() + self.timeout
        status = None
        response = None
        body = bytearray()
        try:
            connection.connect()  # HTTPS retains certificate and hostname verification.
            transport = connection.sock
            def remaining():
                seconds = deadline - time.monotonic()
                if seconds <= 0:
                    raise TimeoutError()
                transport.settimeout(seconds)
                return seconds
            remaining()
            connection.request("POST", parsed.path, body=self.identity.payload(),
                               headers={"Content-Type": "application/json", "Accept": "application/json"})
            remaining()
            response = connection.getresponse()
            status = response.status
            while not response.isclosed():
                remaining()
                chunk = response.read1(8192)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > 65536:
                    raise ValueError("服务端响应超过 64 KiB，已停止读取")
            if response.length not in (None, 0):
                raise http.client.HTTPException("服务端响应不完整")
            result = interpret_response(self.identity, status, body, response.getheader("Retry-After", ""))
        except (TimeoutError, socket.timeout):
            result = incomplete_response(self.identity, status, body,
                                         "请求超时；结果可能未知，请核对后再手动重试")
        except ssl.SSLError as error:
            result = incomplete_response(self.identity, status, body,
                                         f"TLS 证书验证或握手失败：{redact_text(str(error))}")
        except (OSError, http.client.HTTPException, ValueError) as error:
            result = incomplete_response(self.identity, status, body,
                                         f"网络或响应错误：{redact_text(str(error))}")
        finally:
            if response is not None:
                response.close()
            connection.close()
        self.signals.finished.emit(result)


class BindingClient(QObject):
    completed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)
        self.reply = None

    def start(self, identity: BindingIdentity, server: str, ca_path: str = "", timeout_ms: int = 15000,
              *, allow_internal_http: bool = False):
        if self.reply is not None:
            raise ValueError("绑定请求正在进行")
        identity.payload()
        endpoint = binding_url(server, allow_internal_http=allow_internal_http)
        if timeout_ms <= 0:
            raise ValueError("超时时间必须大于零")
        context = None
        if urlsplit(endpoint).scheme == "https":
            context = ssl.create_default_context()
            if ca_path:
                try:
                    context.load_verify_locations(cafile=ca_path)
                except (OSError, ssl.SSLError) as error:
                    raise ValueError("无法读取 PEM CA 证书；TLS 校验不能关闭") from error
        # Python SSL provides app-local CA trust without editing the Windows certificate store.
        task = BindingTask(identity, endpoint, context, timeout_ms)
        task.signals.finished.connect(self._finished)
        self.reply = task
        self.pool.start(task)

    def _finished(self, result):
        self.reply = None
        self.completed.emit(result)
