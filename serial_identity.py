"""设备串口协议：读取业务 SN 与 RSA 公钥（115200、8N1、无流控）。"""

from dataclasses import dataclass
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import serial
from serial.tools import list_ports

from identity_validation import SUPPORTED_KEY_SIZES, validate_sn

FRAME_HEADER = b"\xaa\x55"
CMD_SN = 0x02
CMD_PUBLIC_KEY = 0x03
CMD_SET_SN = 0x04
CMD_GENERATE_KEYS = 0x05
RESPONSE_FLAG = 0x80
MAX_REQUEST_PAYLOAD = 2048
# 协议文档写 2048，但 RSA-3072 OpenSSH 私钥文本约 2.5 KB，接收侧需留出余量。
MAX_RECEIVE_PAYLOAD = 8192


class SerialProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class SerialIdentity:
    sn: str
    public_key_pem: str


def list_serial_ports():
    return sorted((port.device, port.description or port.device) for port in list_ports.comports())


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def build_frame(command: int, payload: bytes = b"", status: int = 0) -> bytes:
    if len(payload) > MAX_REQUEST_PAYLOAD:
        raise ValueError("串口请求 Payload 超过 2048 字节")
    body = bytes([len(payload) & 0xFF, len(payload) >> 8, command, status]) + payload
    checksum = crc16_ccitt_false(body)
    return FRAME_HEADER + body + bytes([checksum & 0xFF, checksum >> 8])


def normalize_public_key(payload: bytes) -> str:
    """把 PEM / OpenSSH 公钥（或私钥）统一转成 SubjectPublicKeyInfo PEM。

    串口返回 OpenSSH 私钥时只在内存中推导公钥，私钥不会显示、保存或上传。
    """
    try:
        text = payload.decode("ascii", errors="strict").replace("\r\n", "\n").strip("\x00 \t\r\n")
    except UnicodeDecodeError as error:
        raise SerialProtocolError("设备返回的公钥不是 ASCII 文本") from error
    if not text:
        raise SerialProtocolError("设备返回的公钥为空")
    data = text.encode("ascii")
    try:
        if "PRIVATE KEY-----" in text:
            if text.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
                key = serialization.load_ssh_private_key(data, password=None)
            else:
                key = serialization.load_pem_private_key(data, password=None)
        elif text.startswith("ssh-rsa "):
            key = serialization.load_ssh_public_key(data)
        else:
            key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError, UnicodeError) as error:
        raise SerialProtocolError("无法解析设备返回的公钥") from error
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise SerialProtocolError("设备公钥不是 RSA 公钥")
    if key.key_size not in SUPPORTED_KEY_SIZES:
        raise SerialProtocolError(f"不支持的 RSA 密钥长度 {key.key_size}，仅支持 2048/3072")
    pem = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem.decode("ascii")


def _read_frame(connection, expected_command: int, deadline: float, buffer: bytearray) -> bytes:
    while True:
        while True:
            index = buffer.find(FRAME_HEADER)
            if index < 0:
                # 只保留最后 1 字节，避免丢掉可能是帧头首字节的 0xAA。
                if len(buffer) > 1:
                    del buffer[:-1]
                break
            if index:
                del buffer[:index]
            if len(buffer) < 6:
                break
            length = buffer[2] | (buffer[3] << 8)
            if length > MAX_RECEIVE_PAYLOAD:
                del buffer[0]
                continue
            total = 6 + length + 2
            if len(buffer) < total:
                break
            frame = bytes(buffer[:total])
            del buffer[:total]
            command, status = frame[4], frame[5]
            crc_received = frame[6 + length] | (frame[7 + length] << 8)
            if crc16_ccitt_false(frame[2:6 + length]) != crc_received:
                continue
            if command != expected_command:
                continue
            if status != 0:
                raise SerialProtocolError(f"设备返回错误状态 0x{status:02X}")
            return frame[6:6 + length]
        if time.monotonic() >= deadline:
            raise SerialProtocolError("等待串口响应超时")
        chunk = connection.read(64)
        if chunk:
            buffer.extend(chunk)


class SerialIdentityReader:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def _open(self, port: str):
        try:
            return serial.Serial(
                port=port, baudrate=115200, bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                timeout=0.1, write_timeout=self.timeout,
                xonxoff=False, rtscts=False, dsrdtr=False)
        except (serial.SerialException, OSError) as error:
            raise SerialProtocolError(f"无法打开串口 {port}：{error}") from error

    def read_identity(self, port: str) -> SerialIdentity:
        connection = self._open(port)
        buffer = bytearray()
        with connection:
            sn_payload = self._command(connection, CMD_SN, buffer)
            key_payload = self._command(connection, CMD_PUBLIC_KEY, buffer)
        sn = sn_payload.decode("utf-8", errors="strict").strip("\x00 \t\r\n")
        try:
            validate_sn(sn)
        except ValueError as error:
            raise SerialProtocolError(f"设备 SN 无效：{error}") from error
        return SerialIdentity(sn, normalize_public_key(key_payload))

    def write_sn(self, port: str, sn: str) -> str:
        """写入 SN 并校验设备回显的 SEQ；成功后返回写入的 SN。"""
        try:
            validate_sn(sn)
        except ValueError as error:
            raise SerialProtocolError(f"SN 无效：{error}") from error
        sequence = int(time.time() * 1_000_000) & 0xFFFFFFFF
        payload = sequence.to_bytes(4, "little") + sn.encode("ascii")
        connection = self._open(port)
        with connection:
            response = self._command(connection, CMD_SET_SN, bytearray(), payload, timeout=8.0)
        if len(response) != 4 or int.from_bytes(response, "little") != sequence:
            raise SerialProtocolError("设备未回显本次写入的 SEQ，写入结果未确认")
        return sn

    def generate_keys(self, port: str) -> str:
        """让设备生成并写入 RSA-2048 密钥对，返回公钥 PEM。"""
        connection = self._open(port)
        with connection:
            key_payload = self._command(
                connection, CMD_GENERATE_KEYS, bytearray(), timeout=20.0)
        return normalize_public_key(key_payload)

    def _command(self, connection, command: int, buffer: bytearray,
                 payload: bytes = b"", timeout: float | None = None) -> bytes:
        try:
            connection.reset_input_buffer()
            connection.write(build_frame(command, payload))
            connection.flush()
        except (serial.SerialException, OSError) as error:
            raise SerialProtocolError(f"串口写入失败：{error}") from error
        return _read_frame(
            connection, command | RESPONSE_FLAG,
            time.monotonic() + (timeout or self.timeout), buffer)
