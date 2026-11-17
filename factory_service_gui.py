"""factory_service Windows PyQt6 GUI: serial connection, SN read/write, RSA keys.

Install requirements.txt then: py -3 factory_service_gui.py
Do not open the same COM port in a serial monitor at the same time.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import serial
from serial.tools import list_ports
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QGridLayout, QGroupBox,
    QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from factory_service_protocol import (
    CMD_CHECK_CONNECTION, CMD_GEN_KEYS, CMD_GET_PUBKEY, CMD_GET_SN,
    CMD_SCAN_WIRELESS, CMD_SET_SN, COMMAND_NAMES, Frame, FrameParser,
    STATUS_NAMES, STATUS_OK, format_hex, format_scan_result, pack_frame,
    parse_public_key, parse_scan_result,
)


class FactoryServiceWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("factory_service | 设备串口配置工具")
        self.resize(860, 800)
        self.serial_port: Optional[serial.Serial] = None
        self.parser = FrameParser()
        self.pending_cmd: Optional[int] = None
        self.pending_packet = b""
        self.pending_sn: Optional[str] = None
        self.pending_seq: Optional[int] = None
        self.attempts = 0
        self.max_attempts = 3  # first + two retries
        self.retry_timeout_ms = 3000
        self.public_key: bytes = b""
        self.device_online = False
        self.last_received_ms = 0
        self.partial_gap_ms = 1200
        self._build_ui()
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(25)
        self.poll_timer.timeout.connect(self._poll_serial)
        self.timeout_timer = QTimer(self)
        self.timeout_timer.setSingleShot(True)
        self.timeout_timer.timeout.connect(self._on_request_timeout)
        self.refresh_ports()
        self._update_buttons()

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setSpacing(12)
        self.setCentralWidget(root)

        header = QLabel("factory_service · 设备串口配置工具")
        header.setStyleSheet("font-size: 19px; font-weight: 700; margin: 6px 0")
        layout.addWidget(header)

        link_box = QGroupBox("串口连接")
        grid = QGridLayout(link_box)
        self.port_combo = QComboBox()
        self.port_combo.setMinimumWidth(210)
        self.baud_combo = QComboBox()
        self.baud_combo.addItems(["9600", "19200", "38400", "57600", "115200", "230400"])
        self.baud_combo.setCurrentText("115200")
        self.refresh_button = QPushButton("刷新串口")
        self.refresh_button.clicked.connect(self.refresh_ports)
        self.connect_button = QPushButton("打开串口并检测设备")
        self.connect_button.clicked.connect(self._toggle_connection)
        self.conn_status = QLabel("状态：未连接")
        self.conn_status.setStyleSheet("font-weight: bold")
        grid.addWidget(QLabel("串口"), 0, 0)
        grid.addWidget(self.port_combo, 0, 1)
        grid.addWidget(QLabel("波特率"), 0, 2)
        grid.addWidget(self.baud_combo, 0, 3)
        grid.addWidget(self.refresh_button, 0, 4)
        grid.addWidget(self.connect_button, 1, 1, 1, 3)
        grid.addWidget(self.conn_status, 1, 4)
        layout.addWidget(link_box)

        action_box = QGroupBox("设备操作")
        action_layout = QGridLayout(action_box)
        self.ping_button = QPushButton("检测设备连接")
        self.ping_button.clicked.connect(lambda: self.send_request(CMD_CHECK_CONNECTION))
        self.sn_button = QPushButton("获取 SN")
        self.sn_button.clicked.connect(lambda: self.send_request(CMD_GET_SN))
        self.set_sn_button = QPushButton("写入 SN")
        self.set_sn_button.clicked.connect(self.write_sn)
        self.pub_button = QPushButton("获取公钥")
        self.pub_button.clicked.connect(lambda: self.send_request(CMD_GET_PUBKEY))
        self.gen_button = QPushButton("生成并写入密钥 (RSA-2048)")
        self.gen_button.clicked.connect(self.generate_keys)
        self.save_button = QPushButton("保存公钥文件")
        self.save_button.clicked.connect(self.save_public_key)
        self.scan_button = QPushButton("扫描 Wi-Fi / 蓝牙")
        self.scan_button.clicked.connect(self.scan_wireless)
        for button in (self.ping_button, self.sn_button, self.set_sn_button,
                       self.pub_button, self.gen_button, self.save_button,
                       self.scan_button):
            button.setMinimumHeight(34)
        action_layout.addWidget(self.ping_button, 0, 0)
        action_layout.addWidget(self.sn_button, 0, 1)
        action_layout.addWidget(self.set_sn_button, 0, 2)
        action_layout.addWidget(self.pub_button, 1, 0)
        action_layout.addWidget(self.gen_button, 1, 1)
        action_layout.addWidget(self.save_button, 1, 2)
        action_layout.addWidget(self.scan_button, 2, 0, 1, 3)
        layout.addWidget(action_box)

        result_box = QGroupBox("读取结果")
        result_layout = QGridLayout(result_box)
        self.sn_output = QLineEdit()
        self.sn_output.setReadOnly(True)
        self.sn_output.setPlaceholderText("尚未获取设备 SN")
        self.fingerprint_output = QLineEdit()
        self.fingerprint_output.setReadOnly(True)
        self.fingerprint_output.setPlaceholderText("尚未获取设备公钥")
        self.pub_output = QPlainTextEdit()
        self.pub_output.setReadOnly(True)
        self.pub_output.setPlaceholderText("OpenSSH 公钥文本将显示在这里，私钥不会通过串口发送。")
        self.pub_output.setMaximumHeight(110)
        self.scan_output = QPlainTextEdit()
        self.scan_output.setReadOnly(True)
        self.scan_output.setPlaceholderText(
            "Wi-Fi SSID / 信号与蓝牙名称 / RSSI 将显示在这里。")
        self.scan_output.setMaximumHeight(180)
        result_layout.addWidget(QLabel("设备 SN"), 0, 0)
        result_layout.addWidget(self.sn_output, 0, 1)
        result_layout.addWidget(QLabel("公钥指纹"), 1, 0)
        result_layout.addWidget(self.fingerprint_output, 1, 1)
        result_layout.addWidget(QLabel("公钥内容"), 2, 0)
        result_layout.addWidget(self.pub_output, 2, 1)
        result_layout.addWidget(QLabel("无线扫描"), 3, 0)
        result_layout.addWidget(self.scan_output, 3, 1)
        layout.addWidget(result_box)

        logs_box = QGroupBox("通信日志（HEX）")
        logs_layout = QVBoxLayout(logs_box)
        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        logs_layout.addWidget(self.logs)
        clear_btn = QPushButton("清空日志")
        clear_btn.clicked.connect(self.logs.clear)
        logs_layout.addWidget(clear_btn, alignment=Qt.AlignmentFlag.AlignRight)
        layout.addWidget(logs_box, stretch=1)
        self.statusBar().showMessage("factory_service：AA 55 | LEN(2,LE) | CMD | STATUS | DATA | CRC16(2,LE)")

    def _log(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.logs.appendPlainText(f"[{stamp}] {text}")

    def refresh_ports(self) -> None:
        selected = self.port_combo.currentData()
        self.port_combo.clear()
        ports = sorted(list_ports.comports(), key=lambda p: p.device)
        for port in ports:
            self.port_combo.addItem(f"{port.device}  ({port.description})", port.device)
        if not ports:
            self.port_combo.addItem("未找到串口，请检查 USB-TTL", None)
        elif selected:
            for idx in range(self.port_combo.count()):
                if self.port_combo.itemData(idx) == selected:
                    self.port_combo.setCurrentIndex(idx)
                    break
        self._update_buttons()

    def _update_buttons(self) -> None:
        opened = self.serial_port is not None and self.serial_port.is_open
        idle = self.pending_cmd is None
        self.connect_button.setText("断开串口" if opened else "打开串口并检测设备")
        self.port_combo.setEnabled(not opened)
        self.baud_combo.setEnabled(not opened)
        self.refresh_button.setEnabled(not opened)
        self.ping_button.setEnabled(opened and idle)
        self.sn_button.setEnabled(opened and idle)
        self.set_sn_button.setEnabled(opened and idle)
        self.pub_button.setEnabled(opened and idle)
        self.gen_button.setEnabled(opened and idle)
        self.save_button.setEnabled(bool(self.public_key) and idle)
        self.scan_button.setEnabled(opened and idle)

    def _toggle_connection(self) -> None:
        if self.serial_port is not None and self.serial_port.is_open:
            self._disconnect()
        else:
            self._connect()

    def _connect(self) -> None:
        device = self.port_combo.currentData()
        if not device:
            QMessageBox.warning(self, "无法连接", "请先选择有效串口。")
            return
        try:
            self.serial_port = serial.Serial(
                port=device, baudrate=int(self.baud_combo.currentText()),
                bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE, timeout=0, write_timeout=1,
                xonxoff=False, rtscts=False, dsrdtr=False,
            )
            self.serial_port.reset_input_buffer()  # avoid stale bytes from a prior session
            self.parser.reset()
            self.device_online = False
            self.public_key = b""
            self.sn_output.clear()
            self.pub_output.clear()
            self.fingerprint_output.clear()
            self.scan_output.clear()
            self.conn_status.setText("状态：串口已打开，正在检测设备…")
            self._log(f"串口打开：{device} @ {self.baud_combo.currentText()} 8N1 无流控")
            self.poll_timer.start()
            self._update_buttons()
            self.send_request(CMD_CHECK_CONNECTION)
        except (serial.SerialException, OSError, ValueError) as exc:
            self._log(f"打开串口失败：{exc}")
            self._disconnect()
            QMessageBox.critical(self, "串口错误", str(exc))

    def _disconnect(self) -> None:
        self.timeout_timer.stop()
        self.poll_timer.stop()
        self.pending_cmd = None
        self.pending_packet = b""
        self.pending_sn = None
        self.pending_seq = None
        self.device_online = False
        self.public_key = b""
        self.sn_output.clear()
        self.pub_output.clear()
        self.fingerprint_output.clear()
        self.scan_output.clear()
        self.parser.reset()
        if self.serial_port is not None:
            try:
                self.serial_port.close()
            except (serial.SerialException, OSError):
                pass
        self.serial_port = None
        self.conn_status.setText("状态：未连接")
        self._log("串口已断开")
        self._update_buttons()

    def send_request(self, cmd: int, payload: bytes = b"",
                     sn: Optional[str] = None, timeout_ms: int = 3000) -> None:
        if self.serial_port is None or not self.serial_port.is_open:
            self._log("未连接串口")
            return
        if self.pending_cmd is not None:
            self._log("已有请求正在等待响应，请勿并发发送")
            return
        if cmd in (CMD_GET_PUBKEY, CMD_GEN_KEYS):
            self.public_key = b""
            self.pub_output.clear()
            self.fingerprint_output.clear()
        self.pending_cmd = cmd
        self.pending_sn = sn
        self.pending_seq = (int.from_bytes(payload[:4], "little")
                            if cmd == CMD_SET_SN and len(payload) >= 4 else None)
        self.pending_packet = pack_frame(cmd, 0, payload)
        self.retry_timeout_ms = timeout_ms
        self.attempts = 0
        self._send_current_attempt()
        self._update_buttons()

    def write_sn(self) -> None:
        if self.serial_port is None or not self.serial_port.is_open:
            self._log("未连接串口")
            return
        text, ok = QInputDialog.getText(self, "写入 SN", "输入新的设备 SN：")
        if not ok or not text:
            return
        try:
            sn_bytes = text.encode("ascii")
        except UnicodeEncodeError:
            QMessageBox.warning(self, "SN 无效", "SN 必须只包含可打印 ASCII 字符。")
            return
        if not (1 <= len(sn_bytes) <= 508) or any(
                byte < 0x20 or byte > 0x7E for byte in sn_bytes):
            QMessageBox.warning(self, "SN 无效",
                                "SN 长度必须为 1..508，且只能包含可打印 ASCII 字符。")
            return
        answer = QMessageBox.question(
            self, "确认写入 SN",
            f"将把 Vendor Storage 中的 SN 改写为：\n\n{text}\n\n"
            "此操作会写入 eMMC 的新槽位，请确认设备型号和序列号正确。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        seq = int(datetime.now().timestamp() * 1_000_000) & 0xFFFFFFFF
        payload = seq.to_bytes(4, "little") + sn_bytes
        self._log(f"准备写入 SN：{text}（SEQ={seq}）")
        self.send_request(CMD_SET_SN, payload, sn=text, timeout_ms=8000)

    def generate_keys(self) -> None:
        if self.serial_port is None or not self.serial_port.is_open:
            self._log("未连接串口")
            return
        answer = QMessageBox.question(
            self, "确认生成并写入密钥",
            "将在设备上生成 RSA-2048 密钥对（OpenSSH）：\n\n"
            "• 私钥写入 Vendor Storage item 101，不会通过串口发送\n"
            "• 公钥写入 item 100，并返回到上位机显示\n\n"
            "如果设备已有完整密钥对，将直接返回现有公钥，不会重新生成。\n"
            "确认继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._log("请求设备生成并写入 RSA-2048 密钥对…")
        self.send_request(CMD_GEN_KEYS, timeout_ms=20000)

    def scan_wireless(self) -> None:
        if self.serial_port is None or not self.serial_port.is_open:
            self._log("未连接串口")
            return
        self.scan_output.setPlainText("正在扫描 Wi-Fi 和蓝牙，通常需要 10–30 秒…")
        self._log("请求扫描 Wi-Fi / 蓝牙（最长等待 40 秒）")
        self.send_request(CMD_SCAN_WIRELESS, timeout_ms=40000)

    def _send_current_attempt(self) -> None:
        try:
            assert self.serial_port is not None
            self.attempts += 1
            count = self.serial_port.write(self.pending_packet)
            if count != len(self.pending_packet):
                raise serial.SerialTimeoutException(f"只发送了 {count}/{len(self.pending_packet)} 字节")
            self._log(f"TX[{self.attempts}] {COMMAND_NAMES.get(self.pending_cmd, '?')}: "
                      f"{format_hex(self.pending_packet)}")
            self.timeout_timer.start(self.retry_timeout_ms)
        except (serial.SerialException, OSError) as exc:
            self._log(f"写串口失败：{exc}")
            self._finish_pending()

    def _finish_pending(self) -> None:
        self.timeout_timer.stop()
        self.pending_cmd = None
        self.pending_packet = b""
        self.pending_sn = None
        self.pending_seq = None
        self._update_buttons()

    def _on_request_timeout(self) -> None:
        if self.pending_cmd is None:
            return
        if self.attempts < self.max_attempts:
            self._log(f"{self.retry_timeout_ms / 1000:.0f} 秒没有收到匹配响应，重试相同命令")
            self.parser.reset()  # discard stale partial bytes before retry
            self._send_current_attempt()
        else:
            self._log("请求最终超时：已发送 3 次，仍无有效响应")
            if self.pending_cmd == CMD_CHECK_CONNECTION:
                self.conn_status.setText("状态：串口已打开，但设备没有应答")
                self.device_online = False
            if self.pending_cmd == CMD_SCAN_WIRELESS:
                self.scan_output.setPlainText("扫描请求超时：设备未在规定时间内返回结果。")
            self._finish_pending()

    def _poll_serial(self) -> None:
        port = self.serial_port
        if port is None or not port.is_open:
            return
        try:
            waiting = port.in_waiting
            if waiting:
                data = port.read(min(waiting, 4096))
                if data:
                    self.last_received_ms = int(datetime.now().timestamp() * 1000)
                    self._log(f"RX bytes: {format_hex(data, 72)}")
                    old_crc = self.parser.crc_errors
                    old_len = self.parser.length_errors
                    for frame in self.parser.feed(data):
                        self._on_frame(frame)
                    if self.parser.crc_errors != old_crc:
                        self._log("丢弃 CRC16 校验失败的数据帧")
                    if self.parser.length_errors != old_len:
                        self._log("丢弃 Payload 长度超限的数据帧")
            elif self.parser.buf:
                now = int(datetime.now().timestamp() * 1000)
                if now - self.last_received_ms > self.partial_gap_ms:
                    self._log("未完成帧超过 1.2 秒，重置接收缓存")
                    self.parser.reset()
        except (serial.SerialException, OSError) as exc:
            self._log(f"串口读取异常：{exc}")
            self._disconnect()

    def _on_frame(self, frame: Frame) -> None:
        self._log(f"RX frame: CMD=0x{frame.cmd:02X}, STATUS=0x{frame.status:02X}, "
                  f"LEN={len(frame.payload)}")
        cmd = self.pending_cmd
        if cmd is None or frame.cmd != (cmd | 0x80):
            self._log("忽略不匹配当前请求的响应帧（factory_service 没有请求序号）")
            return
        if frame.status != STATUS_OK:
            self._log(f"设备返回错误：0x{frame.status:02X} "
                      f"{STATUS_NAMES.get(frame.status, '未知错误')}")
            self._finish_pending()
            return
        if (cmd == CMD_SET_SN and frame.payload and
                (len(frame.payload) != 4 or
                 int.from_bytes(frame.payload, "little") != self.pending_seq)):
            self._log("忽略 SEQ 不匹配当前 SET_SN 请求的响应")
            return
        try:
            if cmd == CMD_CHECK_CONNECTION:
                if frame.payload:
                    raise ValueError("连接检测响应 Payload 必须为空")
                self.conn_status.setText("状态：设备通信正常")
                self.device_online = True
                self._log("设备连接检测成功：CMD=0x81 STATUS=0x00，无 PONG 字符串")
            elif cmd == CMD_GET_SN:
                sn = frame.payload.decode("ascii", errors="strict")
                if not sn or any(ord(c) < 32 or ord(c) > 126 for c in sn):
                    raise ValueError("收到无效的 SN 内容")
                self.sn_output.setText(sn)
                self._log(f"获取 SN 成功：{sn}")
            elif cmd in (CMD_GET_PUBKEY, CMD_GEN_KEYS):
                keytext, fingerprint = parse_public_key(frame.payload)
                self.public_key = frame.payload
                self.pub_output.setPlainText(keytext)
                self.fingerprint_output.setText(fingerprint)
                action = ("生成并写入密钥成功（私钥已存 item 101）"
                          if cmd == CMD_GEN_KEYS else "获取公钥成功")
                self._log(f"{action}：{len(frame.payload)} 字节，OpenSSH 指纹 {fingerprint}")
            elif cmd == CMD_SET_SN:
                if self.pending_sn is None:
                    raise ValueError("内部错误：缺少待写入的 SN")
                self.sn_output.setText(self.pending_sn)
                self._log(f"写入 SN 成功并已读回校验：{self.pending_sn}")
            elif cmd == CMD_SCAN_WIRELESS:
                result = parse_scan_result(frame.payload)
                self.scan_output.setPlainText(format_scan_result(result))
                self._log(
                    f"无线扫描完成：Wi-Fi {len(result.wifi)}/{result.wifi_total}，"
                    f"蓝牙 {len(result.bluetooth)}/{result.bt_total}")
        except (ValueError, UnicodeDecodeError) as exc:
            self._log(f"设备返回内容校验失败：{exc}")
        finally:
            self._finish_pending()

    def save_public_key(self) -> None:
        if not self.public_key:
            QMessageBox.information(self, "提示", "请先点击获取公钥。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "保存 OpenSSH 公钥", "device_rsa.pub",
                                               "OpenSSH Public Key (*.pub);;All Files (*)")
        if not path:
            return
        try:
            Path(path).write_bytes(self.public_key.rstrip(b"\r\n") + b"\n")
            self._log(f"公钥已保存：{path}")
        except OSError as exc:
            QMessageBox.critical(self, "保存失败", str(exc))

    def closeEvent(self, event) -> None:
        self._disconnect()
        event.accept()


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = FactoryServiceWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
