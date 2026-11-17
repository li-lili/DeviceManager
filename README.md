# 设备公钥绑定工具

通过串口读取设备的 SN 与 RSA 公钥，核对后手动提交到云端绑定接口。

## 启动

```powershell
.\.venv\Scripts\python.exe main.py
```

首次使用或迁移环境时安装依赖：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 界面流程

1. 连接设备串口，点击“刷新”，选择对应 COM 口。
2. 点击“读取 SN 与公钥”。界面只读显示 SN 与 PEM 公钥。
3. 确认“服务器根地址”后点击“提交公钥绑定”。

程序不会自动读取、自动提交或自动重试；仅手动点击按钮时才发请求。界面不提供本地身份导入、Mock、CA 选择或内网 HTTP 开关。

图文版操作说明见 [docs/ui-guide.md](docs/ui-guide.md)。

## 串口协议

- 参数：`115200 bit/s`、8 数据位、无校验、1 停止位、无流控（8N1）。
- 数据帧：`帧头(2) + 长度(2) + 命令(1) + 状态(1) + Payload(N) + CRC16(2)`。
- 帧头固定 `AA 55`；长度为 Payload 字节数，2 字节小端；响应命令 = 请求命令 `| 0x80`；状态 `0x00` 表示成功。
- CRC16 使用 CCITT-FALSE（poly `0x1021`、init `0xFFFF`），计算范围为“长度、命令、状态、Payload”，低字节先发。

| 操作 | 请求 | 成功响应 |
|---|---|---|
| 获取 SN | `0x02` | `0x82`，Payload 为设备 SN |
| 获取公钥 | `0x03` | `0x83`，Payload 为完整公钥 |

设备端密钥为 RSA-3072，私钥文件为 OpenSSH 格式，位于 Ubuntu 容器
`/userdata/container/android_data/data_0/local/factory/keys/device_rsa`；SN 位于
`/userdata/container/android_data/data_0/local/factory/sn.txt`。PC 工具只通过串口读取，
不直接访问上述路径。

串口返回的 Payload 支持 PEM 公钥、OpenSSH 公钥（`ssh-rsa ...`），以及 OpenSSH/PEM
私钥。若返回私钥，工具仅在内存中推导公钥；私钥不会显示、保存或上传。上传前统一转换为
`SubjectPublicKeyInfo` PEM，并校验为 RSA-2048/3072。

## 公钥绑定

请求格式见 `docs/device-key-auth-cpp-spec.md` 第二节。请求体只有 `sn` 和 `public_key`
两个字段，程序自动拼接 `/v1/device-keys/bind`。

正式连接保持 TLS 证书链、有效期和主机名验证，使用系统信任库；总超时固定 20 秒。
提交期间锁定串口与服务器输入。

| HTTP | 标识 | 界面含义 |
|---|---|---|
| 201 | `status=bound` | 首次绑定成功，公钥已保存 |
| 200 | `status=already_bound` | 相同 SN 和公钥已绑定，无需更新 |
| 200 | `status=updated` | 覆盖更新成功，原公钥已被替换 |
| 400 | `error.code=bad_request` | SN 或公钥不合法 |
| 403 | `error.code=ip_not_allowed` | 出口 IP 不在工厂白名单 |
| 404 | `error.code=sn_not_found` | 机器人台账查无该 SN |
| 409 | `error.code=sn_key_mismatch` | 公钥指纹冲突，需人工排查 |
| 429 | `error.code=rate_limited` | 请求被限流 |
| 503 | `error.code=sn_lookup_unavailable` | 台账服务不可用或超时 |

成功必须同时匹配 HTTP/status，且响应 SN 与提交值一致。超时、响应不完整、未知组合均不会
判为成功；不会自动重试或跟随重定向。结果详情中的 Token、私钥等凭证会被脱敏。

## 离线检查

```powershell
.\.venv\Scripts\python.exe -B check_binding_ui.py
.\.venv\Scripts\python.exe -B check_binding_responses.py
.\.venv\Scripts\python.exe -B check_binding.py
```

以上脚本不访问真实云端，不读写真实设备密钥。`check_binding.py` 使用 `mock_bind_server.py`
的临时本地 HTTPS 服务验证完整绑定链路；`check_enroll_chain.py` 需要 WSL 与已编译 Agent。
