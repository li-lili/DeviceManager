"""factory_service 串口协议实现。

对应 docs/PROTOCOL_FACTORY_SERVICE.md v1.4：
AA 55 | LEN(u16,LE) | CMD | STATUS | PAYLOAD | CRC16(u16,LE)。
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization

SOF = b"\xaa\x55"
MAX_PAYLOAD = 2048
FRAME_OVERHEAD = 8

CMD_CHECK_CONNECTION = 0x01
CMD_GET_SN = 0x02
CMD_GET_PUBKEY = 0x03
CMD_SET_SN = 0x04
CMD_GEN_KEYS = 0x05
CMD_SCAN_WIRELESS = 0x06

STATUS_OK = 0x00
STATUS_UNSUPPORTED = 0x01
STATUS_BAD_PARAM = 0x02
STATUS_MISSING = 0x03
STATUS_FAILED = 0x04
STATUS_BUSY = 0x05

COMMAND_NAMES = {
    CMD_CHECK_CONNECTION: "检测设备连接",
    CMD_GET_SN: "获取 SN",
    CMD_GET_PUBKEY: "获取公钥",
    CMD_SET_SN: "写入 SN",
    CMD_GEN_KEYS: "生成并写入密钥",
    CMD_SCAN_WIRELESS: "扫描 Wi-Fi / 蓝牙",
}

STATUS_NAMES = {
    STATUS_OK: "成功",
    STATUS_UNSUPPORTED: "不支持的 CMD",
    STATUS_BAD_PARAM: "请求参数无效",
    STATUS_MISSING: "数据不存在或格式不符合要求",
    STATUS_FAILED: "执行失败",
    STATUS_BUSY: "设备繁忙",
}


def crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE：poly=0x1021，init=0xFFFF，refin/refout=false。"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def pack_frame(cmd: int, status: int = 0, payload: bytes = b"") -> bytes:
    if not 0 <= cmd <= 0xFF or not 0 <= status <= 0xFF:
        raise ValueError("CMD/STATUS 必须是单字节")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"Payload 超过 {MAX_PAYLOAD} 字节")
    body = struct.pack("<HBB", len(payload), cmd, status) + payload
    return SOF + body + struct.pack("<H", crc16_ccitt_false(body))


def format_hex(data: bytes, max_bytes: int | None = None) -> str:
    shown = data if max_bytes is None else data[:max_bytes]
    text = " ".join(f"{byte:02X}" for byte in shown)
    if max_bytes is not None and len(data) > max_bytes:
        text += f" … (+{len(data) - max_bytes} B)"
    return text


@dataclass(frozen=True)
class Frame:
    cmd: int
    status: int
    payload: bytes


class FrameParser:
    """增量解析：可接收任意分片，自动跳过噪声并重同步。"""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.crc_errors = 0
        self.length_errors = 0

    def reset(self) -> None:
        self.buf.clear()

    def feed(self, data: bytes) -> list[Frame]:
        self.buf.extend(data)
        frames: list[Frame] = []
        while True:
            start = self.buf.find(SOF)
            if start < 0:
                # 保留末尾的 0xAA，它可能是下一帧帧头的首字节。
                if self.buf and self.buf[-1] == 0xAA:
                    del self.buf[:-1]
                else:
                    self.buf.clear()
                break
            if start:
                del self.buf[:start]
            if len(self.buf) < 4:
                break
            length = self.buf[2] | (self.buf[3] << 8)
            if length > MAX_PAYLOAD:
                self.length_errors += 1
                del self.buf[0]
                continue
            total = FRAME_OVERHEAD + length
            if len(self.buf) < total:
                break
            raw = bytes(self.buf[:total])
            received = raw[6 + length] | (raw[7 + length] << 8)
            if crc16_ccitt_false(raw[2:6 + length]) != received:
                self.crc_errors += 1
                del self.buf[0]
                continue
            del self.buf[:total]
            frames.append(Frame(raw[4], raw[5], raw[6:6 + length]))
        return frames


def parse_public_key(payload: bytes) -> tuple[str, str]:
    """返回 (OpenSSH 公钥文本, SHA256 指纹)。"""
    try:
        text = payload.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError("公钥不是 ASCII 文本") from error
    if not text:
        raise ValueError("公钥内容为空")
    parts = text.split()
    if len(parts) < 2:
        raise ValueError("公钥格式无效")
    serialization.load_ssh_public_key(text.encode("ascii"))
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("公钥 Base64 无效") from error
    digest = hashlib.sha256(blob).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    return " ".join(parts), fingerprint


@dataclass(frozen=True)
class WifiEntry:
    signal: int
    bssid: str
    ssid: str


@dataclass(frozen=True)
class BluetoothEntry:
    rssi: int | None
    address: str
    name: str


@dataclass(frozen=True)
class ScanResult:
    wifi: list[WifiEntry]
    bluetooth: list[BluetoothEntry]
    wifi_total: int
    bt_total: int
    wifi_ok: bool
    bt_ok: bool


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in raw)


def parse_scan_result(payload: bytes) -> ScanResult:
    if len(payload) < 8:
        raise ValueError("扫描结果头不足 8 字节")
    (version, wifi_status, bt_status, wifi_count, bt_count,
     wifi_total, bt_total, _reserved) = payload[:8]
    if version != 0x01:
        raise ValueError(f"不支持的扫描结果版本 {version}")
    if wifi_count > 5 or bt_count > 5:
        raise ValueError("扫描条目数超过协议上限 5")

    offset = 8
    wifi: list[WifiEntry] = []
    for _ in range(wifi_count):
        if len(payload) < offset + 8:
            raise ValueError("Wi-Fi 条目被截断")
        signal = payload[offset]
        bssid = _format_mac(payload[offset + 1:offset + 7])
        ssid_len = payload[offset + 7]
        offset += 8
        if ssid_len > 32 or len(payload) < offset + ssid_len:
            raise ValueError("Wi-Fi SSID 长度无效")
        ssid = payload[offset:offset + ssid_len].decode("utf-8", errors="replace")
        offset += ssid_len
        wifi.append(WifiEntry(signal, bssid, ssid))

    bluetooth: list[BluetoothEntry] = []
    for _ in range(bt_count):
        if len(payload) < offset + 8:
            raise ValueError("蓝牙条目被截断")
        raw_rssi = payload[offset]
        address = _format_mac(payload[offset + 1:offset + 7])
        name_len = payload[offset + 7]
        offset += 8
        if name_len > 32 or len(payload) < offset + name_len:
            raise ValueError("蓝牙名称长度无效")
        name = payload[offset:offset + name_len].decode("utf-8", errors="replace")
        offset += name_len
        rssi = None if raw_rssi == 0x80 else struct.unpack("b", bytes([raw_rssi]))[0]
        bluetooth.append(BluetoothEntry(rssi, address, name))

    return ScanResult(
        wifi=wifi, bluetooth=bluetooth,
        wifi_total=wifi_total, bt_total=bt_total,
        wifi_ok=wifi_status == 0, bt_ok=bt_status == 0,
    )


def format_scan_result(result: ScanResult) -> str:
    lines = [
        f"Wi-Fi：{'成功' if result.wifi_ok else '失败/不可用'}"
        f"（返回 {len(result.wifi)} / 共 {result.wifi_total}）"
    ]
    if result.wifi:
        for index, item in enumerate(result.wifi, 1):
            ssid = item.ssid or "<隐藏 SSID>"
            lines.append(f"  {index}. {ssid}    信号 {item.signal}/100    {item.bssid}")
    else:
        lines.append("  未发现 Wi-Fi")

    lines.append("")
    lines.append(
        f"蓝牙：{'成功' if result.bt_ok else '失败/不可用'}"
        f"（返回 {len(result.bluetooth)} / 共 {result.bt_total}）"
    )
    if result.bluetooth:
        for index, item in enumerate(result.bluetooth, 1):
            rssi = "未报告" if item.rssi is None else f"{item.rssi} dBm"
            name = item.name or "<未命名>"
            lines.append(f"  {index}. {name}    {rssi}    {item.address}")
    else:
        lines.append("  未发现蓝牙")
    return "\n".join(lines)
