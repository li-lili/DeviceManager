"""设备公钥绑定工具：串口读取 SN 与公钥，手动提交云端绑定。"""

import sys
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFormLayout, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTextEdit, QVBoxLayout, QWidget,
)

from binding import BindingClient, BindingIdentity, DEFAULT_SERVER
from identity_validation import validate_sn
from serial_identity import SerialIdentityReader, SerialProtocolError, list_serial_ports


STYLE = """
QWidget#root {
    background: #F3F6FB;
    font-size: 13px;
    color: #1F2937;
}
QLabel#title {
    font-size: 22px;
    font-weight: 700;
    color: #111827;
}
QLabel#subtitle {
    font-size: 12px;
    color: #6B7280;
}
QLabel#cardTitle {
    font-size: 14px;
    font-weight: 600;
    color: #1F2937;
}
QLabel#fieldLabel {
    font-size: 12px;
    color: #64748B;
}
QLabel#hint {
    font-size: 11px;
    color: #94A3B8;
}
QFrame#card {
    background: #FFFFFF;
    border: 1px solid #E4E9F2;
    border-radius: 12px;
}
QComboBox, QLineEdit {
    background: #FFFFFF;
    border: 1px solid #D7DEEA;
    border-radius: 8px;
    padding: 8px 10px;
    min-height: 20px;
    color: #1F2937;
    selection-background-color: #DBEAFE;
}
QComboBox:hover, QLineEdit:hover {
    border-color: #B9C4D6;
}
QComboBox:focus, QLineEdit:focus {
    border: 1px solid #2563EB;
}
QComboBox:disabled, QLineEdit:disabled {
    background: #F2F4F8;
    color: #9AA4B5;
}
QLineEdit:read-only {
    background: #F8FAFC;
}
QComboBox {
    padding-right: 34px;
}
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: center right;
    width: 34px;
    border: none;
    background: transparent;
}
QComboBox::down-arrow {
    image: url("__ARROW__");
    width: 14px;
    height: 14px;
}
QComboBox QAbstractItemView {
    background: #FFFFFF;
    border: 1px solid #D7DEEA;
    border-radius: 8px;
    selection-background-color: #EEF3FF;
    selection-color: #1D4ED8;
    outline: none;
}
QTextEdit {
    background: #F8FAFC;
    border: 1px solid #D7DEEA;
    border-radius: 8px;
    padding: 8px;
    color: #1F2937;
}
QTextEdit:read-only {
    background: #F8FAFC;
}
QTextEdit#keyView {
    font-family: Consolas, "Courier New", monospace;
    font-size: 12px;
    color: #334155;
}
QTextEdit#responseView {
    font-size: 12px;
    color: #475569;
}
QPushButton {
    border-radius: 8px;
    padding: 9px 16px;
    font-size: 13px;
}
QPushButton#primary {
    background: #2563EB;
    color: #FFFFFF;
    border: none;
    font-weight: 600;
}
QPushButton#primary:hover {
    background: #1D4ED8;
}
QPushButton#primary:pressed {
    background: #1E40AF;
}
QPushButton#primary:disabled {
    background: #E2E8F0;
    color: #94A3B8;
}
QPushButton#secondary {
    background: #EEF3FF;
    color: #1D4ED8;
    border: 1px solid #CFDCFB;
    font-weight: 600;
}
QPushButton#secondary:hover {
    background: #E1EAFE;
}
QPushButton#secondary:disabled {
    background: #F2F4F8;
    color: #A3ADBF;
    border-color: #E4E9F2;
}
QLineEdit#statusField {
    background: #F1F5FF;
    border: 1px solid #D9E3FB;
    border-radius: 8px;
    padding: 9px 12px;
    color: #1D4ED8;
}
QLineEdit#statusField[state="success"] {
    background: #ECFDF3;
    border-color: #BBF7D0;
    color: #15803D;
}
QLineEdit#statusField[state="error"] {
    background: #FEF2F2;
    border-color: #FECACA;
    color: #B91C1C;
}
QLineEdit#statusField[state="info"] {
    background: #F1F5FF;
    border-color: #D9E3FB;
    color: #1D4ED8;
}
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #CBD5E1;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
"""

RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))

STYLE = STYLE.replace(
    "__ARROW__",
    (RESOURCE_DIR / "assets" / "chevron-down.svg").as_posix(),
)


class SerialReadSignals(QObject):
    succeeded = Signal(object)
    failed = Signal(str)


class SerialReadTask(QRunnable):
    def __init__(self, port: str, reader: SerialIdentityReader):
        super().__init__()
        self.port = port
        self.reader = reader
        self.signals = SerialReadSignals()

    def run(self):
        try:
            identity = self.reader.read_identity(self.port)
        except (SerialProtocolError, OSError, ValueError) as error:
            self.signals.failed.emit(str(error))
        else:
            self.signals.succeeded.emit(identity)


class SerialOperationSignals(QObject):
    succeeded = Signal(str)
    failed = Signal(str)


class SerialWriteSnTask(QRunnable):
    def __init__(self, port: str, sn: str, reader: SerialIdentityReader):
        super().__init__()
        self.port = port
        self.sn = sn
        self.reader = reader
        self.signals = SerialOperationSignals()

    def run(self):
        try:
            self.reader.write_sn(self.port, self.sn)
        except (SerialProtocolError, OSError, ValueError) as error:
            self.signals.failed.emit(str(error))
        else:
            self.signals.succeeded.emit(self.sn)


class SerialGenerateKeysTask(QRunnable):
    def __init__(self, port: str, reader: SerialIdentityReader):
        super().__init__()
        self.port = port
        self.reader = reader
        self.signals = SerialOperationSignals()

    def run(self):
        try:
            public_key_pem = self.reader.generate_keys(self.port)
        except (SerialProtocolError, OSError, ValueError) as error:
            self.signals.failed.emit(str(error))
        else:
            self.signals.succeeded.emit(public_key_pem)


class DeviceManager(QWidget):
    DEFAULT_TIMEOUT_MS = 20000

    def __init__(self):
        super().__init__()
        self.setWindowTitle("设备公钥绑定工具")
        self.resize(800, 960)
        self.setMinimumSize(720, 900)
        self.setObjectName("root")
        self.setStyleSheet(STYLE)

        self.serial_reader = SerialIdentityReader()
        self.serial_pool = QThreadPool(self)
        self.serial_task = None
        self.pending_port = ""
        self.binding_identity = None
        self.binding_client = BindingClient(self)
        self.binding_client.completed.connect(self.binding_finished)

        self.port_combo = QComboBox()
        self.port_refresh = QPushButton("刷新")
        self.port_refresh.setObjectName("secondary")
        self.read_button = QPushButton("读取 SN 与公钥")
        self.read_button.setObjectName("primary")
        self.sn_input = QLineEdit()
        self.sn_input.setPlaceholderText("输入要写入的 SN（1–64 位字母、数字、. _ -）")
        self.write_sn_button = QPushButton("写入 SN")
        self.write_sn_button.setObjectName("secondary")
        self.gen_keys_button = QPushButton("生成并写入密钥")
        self.gen_keys_button.setObjectName("secondary")
        self.bind_sn = QLineEdit()
        self.bind_sn.setReadOnly(True)
        self.bind_sn.setPlaceholderText("读取后显示设备 SN")
        self.bind_public_key = QTextEdit()
        self.bind_public_key.setObjectName("keyView")
        self.bind_public_key.setReadOnly(True)
        self.bind_public_key.setAcceptRichText(False)
        self.bind_public_key.setFixedHeight(140)
        self.bind_public_key.setPlaceholderText("读取后显示设备公钥 PEM")
        self.bind_server = QLineEdit(DEFAULT_SERVER)
        self.bind_button = QPushButton("提交公钥绑定")
        self.bind_button.setObjectName("primary")
        self.bind_button.setEnabled(False)
        self.bind_status = QLineEdit("请先读取设备 SN 与公钥")
        self.bind_status.setObjectName("statusField")
        self.bind_status.setReadOnly(True)
        self.bind_response = QTextEdit()
        self.bind_response.setObjectName("responseView")
        self.bind_response.setReadOnly(True)
        self.bind_response.setFixedHeight(90)
        self.bind_response.setPlaceholderText("提交后显示服务端处理结果")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 18)
        outer.setSpacing(12)
        outer.addWidget(self._build_header())
        outer.addWidget(self._build_device_card())
        outer.addWidget(self._build_write_card())
        outer.addWidget(self._build_identity_card())
        outer.addWidget(self._build_bind_card())
        outer.addStretch(1)

        self.port_refresh.clicked.connect(self.refresh_ports)
        self.read_button.clicked.connect(self.read_serial_identity)
        self.write_sn_button.clicked.connect(self.write_device_sn)
        self.gen_keys_button.clicked.connect(self.generate_device_keys)
        self.bind_button.clicked.connect(lambda: self.submit_binding())
        self.refresh_ports()

    def _build_header(self):
        header = QWidget()
        layout = QVBoxLayout(header)
        layout.setContentsMargins(2, 0, 2, 2)
        layout.setSpacing(3)
        title = QLabel("设备公钥绑定")
        title.setObjectName("title")
        subtitle = QLabel("通过串口读取设备 SN 与 RSA 公钥，核对后提交云端绑定")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        return header

    def _card(self, title_text):
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 16)
        layout.setSpacing(8)
        title = QLabel(title_text)
        title.setObjectName("cardTitle")
        layout.addWidget(title)
        return card, layout

    def _field_label(self, text):
        label = QLabel(text)
        label.setObjectName("fieldLabel")
        return label

    def _build_device_card(self):
        card, layout = self._card("设备连接")
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.port_combo, 1)
        row.addWidget(self.port_refresh)
        layout.addLayout(row)
        hint = QLabel("115200 · 8N1 · 无流控")
        hint.setObjectName("hint")
        layout.addWidget(hint)
        return card

    def _build_identity_card(self):
        card, layout = self._card("身份信息")
        layout.addWidget(self.read_button)
        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(8)
        form.addRow(self._field_label("SN"), self.bind_sn)
        key_label = self._field_label("公钥 PEM")
        key_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        key_label.setContentsMargins(0, 10, 0, 0)
        form.addRow(key_label, self.bind_public_key)
        layout.addLayout(form)
        return card

    def _build_write_card(self):
        card, layout = self._card("设备写入")
        sn_row = QHBoxLayout()
        sn_row.setSpacing(8)
        sn_row.addWidget(self._field_label("SN"))
        sn_row.addWidget(self.sn_input, 1)
        layout.addLayout(sn_row)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.write_sn_button)
        row.addWidget(self.gen_keys_button)
        layout.addLayout(row)
        hint = QLabel("写入 0x04 · 生成密钥 0x05    私钥在设备内生成，不会通过串口发送")
        hint.setObjectName("hint")
        layout.addWidget(hint)
        return card

    def _build_bind_card(self):
        card, layout = self._card("云端绑定")
        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(8)
        form.addRow(self._field_label("服务器根地址"), self.bind_server)
        layout.addLayout(form)
        layout.addWidget(self.bind_button)
        layout.addWidget(self._set_status_widget())
        layout.addWidget(self.bind_response)
        return card

    def _set_status_widget(self):
        self._refresh_status_style("info")
        return self.bind_status

    def _refresh_status_style(self, state):
        self.bind_status.setProperty("state", state)
        self.bind_status.style().unpolish(self.bind_status)
        self.bind_status.style().polish(self.bind_status)

    def _set_status(self, text, state="info"):
        self.bind_status.setText(text)
        self.bind_status.setToolTip(text)
        self.bind_status.setCursorPosition(0)
        self._refresh_status_style(state)

    def refresh_ports(self):
        current = self.port_combo.currentData()
        ports = list_serial_ports()
        self.port_combo.blockSignals(True)
        self.port_combo.clear()
        for device, description in ports:
            self.port_combo.addItem(f"{device} · {description}", device)
        if current:
            index = self.port_combo.findData(current)
            if index >= 0:
                self.port_combo.setCurrentIndex(index)
        self.port_combo.blockSignals(False)
        self.read_button.setEnabled(bool(ports))
        if not ports:
            self._set_status("未发现可用串口，请连接设备后刷新", "error")

    def read_serial_identity(self):
        port = self.port_combo.currentData()
        if not port:
            self._set_status("未发现可用串口，请连接设备后刷新", "error")
            return
        self.pending_port = port
        self.set_controls_enabled(False)
        self._set_status(f"正在通过 {port} 读取…", "info")
        task = SerialReadTask(port, self.serial_reader)
        task.signals.succeeded.connect(self.serial_identity_ready)
        task.signals.failed.connect(self.serial_read_failed)
        self.serial_task = task
        self.serial_pool.start(task)

    def serial_identity_ready(self, identity):
        self.serial_task = None
        source = f"串口 {self.pending_port}"
        self.sn_input.setText(identity.sn)
        self.set_binding_identity(BindingIdentity(
            identity.sn, identity.public_key_pem, source, source))
        self.set_controls_enabled(True)
        self._set_status("读取成功，请核对 SN 与公钥后手动提交", "success")

    def serial_read_failed(self, message):
        self.serial_task = None
        self.binding_identity = None
        self.bind_sn.clear()
        self.bind_public_key.clear()
        self.set_controls_enabled(True)
        self._set_status(f"读取失败：{message}", "error")

    def write_device_sn(self):
        port = self.port_combo.currentData()
        if not port:
            self._set_status("未发现可用串口，请连接设备后刷新", "error")
            return
        sn = self.sn_input.text().strip()
        if not sn:
            self._set_status("请先在“设备写入”中填写要写入的 SN", "error")
            self.sn_input.setFocus()
            return
        try:
            validate_sn(sn)
        except ValueError as error:
            QMessageBox.warning(self, "SN 无效", str(error))
            return
        answer = QMessageBox.question(
            self, "确认写入 SN",
            f"将把设备 SN 改写为：\n\n{sn}\n\n"
            "该操作会写入设备存储，请确认设备型号与序列号正确。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.pending_port = port
        self.set_controls_enabled(False)
        self._set_status(f"正在通过 {port} 写入 SN…", "info")
        task = SerialWriteSnTask(port, sn, self.serial_reader)
        task.signals.succeeded.connect(self.write_sn_finished)
        task.signals.failed.connect(self.operation_failed)
        self.serial_task = task
        self.serial_pool.start(task)

    def generate_device_keys(self):
        port = self.port_combo.currentData()
        if not port:
            self._set_status("未发现可用串口，请连接设备后刷新", "error")
            return
        answer = QMessageBox.question(
            self, "确认生成并写入密钥",
            "将在设备上生成 RSA-2048 密钥对：\n\n"
            "• 私钥写入设备 Vendor Storage，不会通过串口发送\n"
            "• 公钥返回并更新到“身份信息”\n\n"
            "如果设备已有完整密钥对，将直接返回现有公钥，不会重新生成。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.pending_port = port
        self.set_controls_enabled(False)
        self._set_status(f"正在请求 {port} 生成密钥，最长等待 20 秒…", "info")
        task = SerialGenerateKeysTask(port, self.serial_reader)
        task.signals.succeeded.connect(self.generate_keys_finished)
        task.signals.failed.connect(self.operation_failed)
        self.serial_task = task
        self.serial_pool.start(task)

    def write_sn_finished(self, sn):
        self.serial_task = None
        key_text = (self.binding_identity.public_key if self.binding_identity
                    else self.bind_public_key.toPlainText().strip())
        if key_text:
            source = f"串口 {self.pending_port}"
            try:
                self.set_binding_identity(BindingIdentity(sn, key_text, source, source))
            except ValueError as error:
                self.bind_sn.setText(sn)
                self.set_controls_enabled(True)
                self._set_status(f"SN 已写入，但身份校验失败：{error}", "error")
                return
            self.set_controls_enabled(True)
            self._set_status(f"SN 已写入并读回校验：{sn}，请核对后提交绑定", "success")
        else:
            self.bind_sn.setText(sn)
            self.set_controls_enabled(True)
            self._set_status(f"SN 已写入并读回校验：{sn}；请读取公钥后再提交绑定", "success")

    def generate_keys_finished(self, public_key_pem):
        self.serial_task = None
        sn = (self.binding_identity.sn if self.binding_identity
              else self.bind_sn.text().strip())
        if sn:
            source = f"串口 {self.pending_port}"
            try:
                self.set_binding_identity(BindingIdentity(sn, public_key_pem, source, source))
            except ValueError as error:
                self.bind_public_key.setPlainText(public_key_pem)
                self.set_controls_enabled(True)
                self._set_status(f"密钥已生成，但身份校验失败：{error}", "error")
                return
            self.set_controls_enabled(True)
            self._set_status("密钥已生成并写入设备，请核对后提交绑定", "success")
        else:
            self.bind_public_key.setPlainText(public_key_pem)
            self.set_controls_enabled(True)
            self._set_status("密钥已生成并写入设备；请读取 SN 后再提交绑定", "success")

    def operation_failed(self, message):
        self.serial_task = None
        self.set_controls_enabled(True)
        self._set_status(f"操作失败：{message}", "error")

    def set_controls_enabled(self, enabled):
        has_port = self.port_combo.count() > 0
        self.port_combo.setEnabled(enabled)
        self.port_refresh.setEnabled(enabled)
        self.sn_input.setEnabled(enabled)
        self.read_button.setEnabled(enabled and has_port)
        self.write_sn_button.setEnabled(enabled and has_port)
        self.gen_keys_button.setEnabled(enabled and has_port)
        self.bind_server.setEnabled(enabled)
        self.bind_button.setEnabled(enabled and self.binding_identity is not None)

    def set_binding_identity(self, identity):
        identity.payload()  # Validate before changing any selected field.
        self.binding_identity = identity
        self.bind_sn.setText(identity.sn)
        self.bind_public_key.setPlainText(identity.public_key)
        self.bind_response.clear()
        self.bind_button.setEnabled(True)
        self._set_status("身份已载入，尚未提交；请核对 SN 与服务器地址", "info")

    def submit_binding(self, ca_path="", timeout_ms=None):
        if self.binding_identity is None:
            self._set_status("请先读取设备 SN 与公钥", "error")
            return
        try:
            self.binding_client.start(
                self.binding_identity, self.bind_server.text().strip(), ca_path,
                timeout_ms or self.DEFAULT_TIMEOUT_MS)
        except (OSError, ValueError, TypeError) as error:
            self._set_status(f"未提交：{error}", "error")
            return
        self._set_status("正在提交公钥绑定，请稍候…", "info")
        self.bind_response.clear()
        self.set_controls_enabled(False)

    def set_binding_controls(self, enabled):
        self.set_controls_enabled(enabled)

    def binding_finished(self, result):
        code = f"HTTP {result.http_status}" if result.http_status is not None else "无 HTTP 响应"
        self._set_status(f"{code}：{result.message}", "success" if result.success else "error")
        self.bind_response.setPlainText(result.display_details(include_raw=False))
        self.set_controls_enabled(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DeviceManager()
    window.show()
    sys.exit(app.exec())
