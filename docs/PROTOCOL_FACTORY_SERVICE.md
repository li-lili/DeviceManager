# factory_service 二进制串口通信协议（试运行版）

版本：v1.4；用途：Noetix 产测设备配置（连接检测、SN 读写、RSA-2048 密钥生成/写入、公钥读取、Wi-Fi/蓝牙扫描）。

> 注意：**本协议与此前的文本协议不兼容**。升级下位机后，上位机必须使用本协议实现。

## 1. UART 配置

- 波特率：115200（两端需一致；GUI 可调整 PC 波特率，但板端默认 115200）
- 8 数据位、无校验、1 停止位、无软/硬流控（8N1）
- Windows 端：例如 COM3；板端 Ubuntu 端：`/dev/ttyUSB0`。
- PC USB-TTL TX → 板端 USB-TTL RX，PC RX ← 板端 TX，GND 共地；USB-TTL 板端通过 USB 插到 RK3588，产生 `/dev/ttyUSB0`。

## 2. 帧结构（严格定义）

| 偏移量 | 字段 | 字节数 | 值/字节序 |
|---:|---|---:|---|
| 0 | SOF | 2 | 固定 `AA 55` |
| 2 | LEN | 2 | **Payload 字节数**，uint16，低字节先发（little-endian），范围 0–2048 |
| 4 | CMD | 1 | 请求代码 01–7F，应答代码=请求代码 OR 80 |
| 5 | STATUS | 1 | 请求帧必须 00；应答帧 00 表示成功 |
| 6 | PAYLOAD | LEN | 原始字节；不使用 Base64，允许任何值，包括 00 或 AA55 |
| 6+LEN | CRC16 | 2 | uint16，小端，低字节先发 |

固定开销 **8 字节**，总帧长 = `8 + LEN`，最大总帧长 2056 字节。
没有帧尾，也没有协议版本或请求序号；接收端按 LEN 判断长度，按 CRC 判断完整性。

### CRC 参数

CRC-16/CCITT-FALSE（又称 CRC-16/IBM-3740）：宽度 16、poly=0x1021、init=0xFFFF、refin=false、refout=false、xorout=0x0000。标准自检字符串 `123456789` → CRC `0x29B1`。

**CRC 只覆盖 `LEN[2] + CMD[1] + STATUS[1] + PAYLOAD[LEN]`**，不覆盖帧头和 CRC 字段本身。CRC 数值按小端字节发送。CRC 用于意外错误检测，不提供身份认证或防篡改能力。

## 3. 命令定义

| Qt 上位机按钮 | 请求 CMD | 应答 CMD | 请求 Payload | 成功响应 Payload |
|---|---:|---:|---|---|
| 检测设备连接 | `01` | `81` | 空 | 空，`STATUS=00` 即表示设备可应答 |
| 获取 SN | `02` | `82` | 空 | Vendor Storage 中的可打印 ASCII 字节（item 1）；例如 `noetixw3` |
| 获取公钥 | `03` | `83` | 空 | 设备上的一行 OpenSSH 公钥（原始 ASCII 字节，无换行） |
| 写入 SN | `04` | `84` | `SEQ:u32le` + SN 可打印 ASCII（1–508 字节） | 成功时回显 `SEQ:u32le` |
| 生成并写入密钥 | `05` | `85` | 空 | 设备生成的 RSA-2048 OpenSSH 公钥（一行原始 ASCII，无换行） |
| 扫描 Wi-Fi/蓝牙 | `06` | `86` | 空 | 见下方 SCAN_WIRELESS：Wi-Fi/蓝牙名称与信号强度 |

### SET_SN（`04` / `84`）

- 请求 Payload：`SEQ`（4 字节小端，调用方生成）+ SN 原始 ASCII，不带换行。
- SN 校验：长度 1–508，字节范围 `0x20..0x7E`；不合法返回 `STATUS=02`。
- 写入方式：通过 `libfactory_service.so` 的 `fs_write_sn_at()` 写入 Vendor Storage
  item 1，保留其他 item，执行 fsync 和读回校验；不依赖任何外部脚本。
- 幂等性：相同 `SEQ` 的重试直接返回第一次的结果，不重复写槽；如果目标 SN 与当前
  SN 相同，则跳过 eMMC 写入并返回成功。
- 写入并读回校验成功才返回 `STATUS=00`；设备/权限/校验失败返回 `04`。
- 成功应答 Payload 为 4 字节 `SEQ` 回显；错误应答 Payload 为空。
- **没有鉴权**：串口物理可达即可改写 SN。产线环境应通过工装/物理管理控制，后续如
  有更高安全要求，需要增加 token/HMAC 或写保护机制。

### GEN_KEYS（`05` / `85`）

- 请求 Payload：空。**上位机只发命令，不发送任何密钥材料。**
- 板端执行：调用 OpenSSH `ssh-keygen -q -t rsa -b 2048` 生成 RSA-2048 密钥对。
- 写入方式：私钥写入 Vendor Storage item 101，公钥写入 item 100；均通过
  `fs_write_item_at()` 写槽、fsync 并读回校验，保留 SN 等其他 item。
- 成功应答 Payload：公钥文本（一行 OpenSSH 格式，例如 `ssh-rsa AAAAB3... factory_service`），
  即 GET_PUBKEY 将返回的内容。**私钥绝不会通过串口发送。**
- 幂等性：若 item 100 和 item 101 已存在且格式有效，直接返回现有公钥，**不会重新生成**；
  这样上位机超时重试不会意外轮换设备密钥。若只有其中一个（例如上次写了一半），会重新
  生成并覆盖两者。
- 生成/写入/读回校验失败返回 `STATUS=04`；请求 Payload 非空或 STATUS≠0 返回 `STATUS=02`。
- 密钥生成通常需要 0.2–2 秒，上位机超时应不小于 20 秒；重试是安全的（幂等）。
- 临时私钥文件只存在于板端 `/tmp` 的 0700 临时目录，读取后立即 unlink；内存中的私钥
  缓冲区在返回前清零。

### SCAN_WIRELESS（`06` / `86`）

- 请求 Payload：空。带 Payload 或 `STATUS≠00` 返回 `02`。
- 板端执行：Ubuntu agent 通过内部 TCP 协议请求 Android 侧
  `factory_service_android` 执行扫描；Android 调用 `cmd wifi start-scan` /
  `cmd wifi list-scan-results` 扫描 Wi-Fi，使用 `BluetoothLeScanner` 扫描 BLE。
  内部协议见 `docs/PROTOCOL_ANDROID_HELPER.md`。扫描不修改网络配置，也不连接
  任何 AP 或蓝牙设备。Android 服务由 Ubuntu agent 按需自动启动。
- 成功应答 Payload（版本 1；以下字段均为单字节）：

| 偏移 | 字段 | 类型 | 说明 |
|---:|---|---|---|
| 0 | version | u8 | 固定 `01` |
| 1 | wifi_status | u8 | `00` Wi-Fi 扫描成功；`01` 失败/不可用 |
| 2 | bt_status | u8 | `00` 蓝牙扫描成功；`01` 失败/不可用 |
| 3 | wifi_count | u8 | 后续 Wi-Fi 条目数，0–5 |
| 4 | bt_count | u8 | 后续蓝牙条目数，0–5 |
| 5 | wifi_total | u8 | 去重后发现的 Wi-Fi 总数（超过 255 截为 255） |
| 6 | bt_total | u8 | 去重后发现的蓝牙总数（超过 255 截为 255） |
| 7 | reserved | u8 | 固定 `00` |
| 8 起 | Wi-Fi 条目 × `wifi_count` | — | 见下表 |
| 其后 | 蓝牙条目 × `bt_count` | — | 见下表 |

Wi-Fi 条目（每项 `8 + ssid_len` 字节）：

| 字段 | 类型 | 说明 |
|---|---|---|
| signal | u8 | Android dBm 转换后的 0–100 信号质量（**不是 dBm**） |
| bssid | u8[6] | AP 的 BSSID 原始字节，例如 `0C EF AF D5 62 90` |
| ssid_len | u8 | SSID 字节数，0–32 |
| ssid | u8[ssid_len] | SSID 原始字节（通常为 UTF-8；空表示隐藏 SSID） |

蓝牙条目（每项 `8 + name_len` 字节）：

| 字段 | 类型 | 说明 |
|---|---|---|
| rssi | u8（按 int8 解释） | dBm，例如 `0xA8` = -88；`0x80` 表示设备未报告 RSSI |
| address | u8[6] | 蓝牙地址原始字节，例如 `A8 A0 92 37 18 7F` |
| name_len | u8 | 名称字节数，0–32 |
| name | u8[name_len] | 名称原始字节（通常为 UTF-8；空表示未广播名称） |

- 条目按信号强度从强到弱排序，**每类最多返回 5 条**；`wifi_total` /
  `bt_total` 是去重后的实际数量，上位机可显示“返回 5 / 共 76”。
- Wi-Fi 信号质量由 Android dBm 线性转换：`dBm >= -50` 为 100，`dBm <= -100`
  为 0，其余为 `2 * (dBm + 100)`；蓝牙保持 dBm。
- SSID/名称超过 32 字节时按 UTF-8 边界截断。Wi-Fi 按 BSSID 去重，蓝牙按地址去重。
- 扫描耗时：Android Wi-Fi 扫描等待约 4 秒，BLE 扫描 8 秒，总耗时通常
  12–15 秒。上位机超时应 **≥ 40 秒**；重试会重新扫描，不修改设备状态。
- Android 容器未运行、helper 无法启动，或两个扫描都失败时返回 `STATUS=04`；
  只有单个失败时仍返回 `STATUS=00`，由 `wifi_status` / `bt_status` 指示，
  Payload 中的另一类结果仍然有效。
- 空列表（没有发现任何 AP/设备）且扫描成功时返回 `STATUS=00`、计数为 0。

### Android 属性同步

Vendor Storage 的 SN 会在 agent 启动后（以及 SET_SN 成功后一个同步周期内）写入
Android 持久化属性 `persist.NX_DEVIECE_SN`，供旧 Android 程序读取。该同步只从
Vendor Storage 到 Android 单向进行，Android 内的修改会被覆盖。协议本身不变。

### 数据来源

- SN 的唯一权威来源是 RK3588 Vendor Storage（item 1）。原生 Ubuntu agent 通过
  `libfactory_service.so` 直接读取 `/dev/mmcblk0`。
- 公钥来源：Vendor Storage item 100。只读取公钥，绝不传输私钥。
- 公钥响应数据使用原始文本，例如 `ssh-rsa AAAAB... factory_service`，不需要 Base64 二次编码。PC 保存时可额外加 LF 到文件末尾。

## 4. 状态码（仅应答帧有意义）

| STATUS | 说明 | Payload |
|---:|---|---|
| `00` | 成功 | 按命令定义 |
| `01` | 不支持的 CMD | 空 |
| `02` | 请求参数无效：STATUS≠00、只读命令带 Payload、`SET_SN` 的 SN 非法，或 `GEN_KEYS` 带 Payload | 空 |
| `03` | 数据不存在或格式不符合要求（SN、公钥） | 空 |
| `04` | 执行失败（`SET_SN` 写入/读回校验失败，`GEN_KEYS` 生成/写入/校验失败，或 `SCAN_WIRELESS` 两个扫描均失败） | 空 |
| `05` | 设备繁忙（保留） | 空 |

设备收到 CRC 错误或超长 LEN：直接丢弃该帧、尝试重新寻找帧头，**不返回错误帧**。收到高位为 1 的 CMD：视作非预期响应，直接忽略，避免应答循环。对于 CRC 正确的未知请求 CMD（高位为 0），回复 `CMD|0x80`、`STATUS=01`、空 Payload。

## 5. 确认过的完整十六进制测试向量

### 连接检测

请求（8 字节）：

```text
AA 55 00 00 01 00 F1 B7
```

成功应答（8 字节）：

```text
AA 55 00 00 81 00 69 AC
```

Qt 收到有效的应答 CMD 81、STATUS 00 和空 Payload 后显示：**设备通信正常**。不再发送、返回文本 `PING/PONG`。

### 获取 SN（示例属性值 noetixw3）

请求（8 字节）：

```text
AA 55 00 00 02 00 A2 E2
```

成功应答（16 字节）：

```text
AA 55 08 00 82 00 6E 6F 65 74 69 78 77 33 DE 4B
```

`08 00` 表示 Payload 为 8 字节，`6E 6F 65 74 69 78 77 33` 为 ASCII `noetixw3`。

### 获取公钥

请求（8 字节）：

```text
AA 55 00 00 03 00 93 D1
```

你目前公钥文本去掉末尾 LF 后为 566 字节，所以**若该文件保持不变**，应答布局为：

```text
AA 55 36 02 83 00 [566 字节实际公钥] [2 字节实际 CRC16]
```

其中 `36 02` 表示 566，小端格式。CRC 与公钥真实字节有关，此处不虚构省略的 CRC。

### 写入 SN（SEQ=1，SN=`NEW_SN`）

请求（18 字节）：

```text
AA 55 0A 00 04 00 01 00 00 00 4E 45 57 5F 53 4E D1 AA
```

- `0A 00`：Payload 10 字节 = SEQ(4) + `NEW_SN`(6)
- `01 00 00 00`：SEQ = 1，小端

成功应答（12 字节）：

```text
AA 55 04 00 84 00 01 00 00 00 66 9A
```

- `04 00`：Payload 4 字节
- `01 00 00 00`：回显 SEQ = 1

### 生成并写入密钥（RSA-2048）

请求（8 字节，空 Payload）：

```text
AA 55 00 00 05 00 35 7B
```

成功应答布局（长度取决于实际公钥，RSA-2048 公钥通常约 380–400 字节）：

```text
AA 55 [LEN_LO LEN_HI] 85 00 [OpenSSH 公钥 ASCII 字节] [CRC16_LO CRC16_HI]
```

例如 LEN=396（`8C 01`）时，应答为：

```text
AA 55 8C 01 85 00 [396 字节 ssh-rsa ... 公钥] [2 字节实际 CRC16]
```

应答 Payload 与随后执行 GET_PUBKEY（`03`）得到的公钥完全一致。CRC 与公钥真实字节
有关，此处不虚构省略的 CRC。

### 扫描 Wi-Fi/蓝牙

请求（8 字节，空 Payload）：

```text
AA 55 00 00 06 00 66 2E
```

成功应答布局（长度与发现结果有关，示例 LEN=164，5 条 Wi-Fi + 5 条蓝牙）：

```text
AA 55 A4 00 86 00 [version=01][wifi_status][bt_status][wifi_count][bt_count]
                [wifi_total][bt_total][reserved=00]
                [Wi-Fi 条目...][蓝牙条目...] [2 字节实际 CRC16]
```

`A4 00` 表示 Payload 164 字节。条目的实际字节取决于周围 Wi-Fi/蓝牙环境；
上位机必须按 `wifi_count` / `bt_count` 和每条的 `*_len` 字段解析，不要假设固定长度。

## 6. Qt/Windows 上位机接收规定

1. 使用 `readyRead`/串口接收缓存或等效轮询方式积累字节，**不能假设一次 read 就是一整帧**。
2. 寻找 `AA 55`，先等 4 字节读取 LEN。LEN > 2048 时丢弃一个字节，重新寻找 SOF。
3. 等待总长度 `8 + LEN` 字节，然后计算 CRC；CRC 不符同样丢弃一个字节并重同步。
4. 只接受当前请求的应答 CMD（`request CMD | 0x80`）；`SET_SN` 还要校验应答
   Payload 中回显的 `SEQ` 与当前请求一致。检查 STATUS，再解析 Payload。
5. 每次只允许一个待完成请求。普通命令接收超时建议 3 秒，最多重试 2 次；`GEN_KEYS`
   超时应不小于 20 秒（密钥生成需要时间），`SCAN_WIRELESS` 超时应不小于 40 秒
   （Wi-Fi 扫描加蓝牙扫描通常 10–25 秒）。重试是安全的：`GEN_KEYS` 幂等，
   扫描只是重新执行。
6. **协议没有全局请求序号**；`SET_SN` 自带 `SEQ` 做单次重试去重，`GEN_KEYS` 以
   “已有完整密钥对则不重新生成”实现幂等；但迟到的旧响应
   与新的请求仍可能无法严格区分。上位机必须串行发送请求，并只接受当前请求的应答。
   写 SN 不做鉴权，产线需控制物理访问。
7. 收到半帧后若 1.2 秒内没有新的字节，可丢弃未完成缓存，重新寻找 SOF。
8. 断开/切换设备时清空当前缓存及原设备的 SN、公钥显示，避免使用旧数据。

## 7. 不兼容性与安全边界

- factory_service 是自定义应用层协议，不是行业标准协议，不与此前的文本通信协议兼容。
- 最大 Payload 2048；如以后更换更大的公钥，需评估容量。
- 串口数据未加密，无设备身份认证；CRC 不能作为防恶意篡改安全机制。
- 私钥由板端 OpenSSH 现场生成并写入 Vendor Storage item 101，只存在于板端；临时文件
  读取后立即 unlink，内存缓冲区清零。私钥属于文件/设备权限保护，**不是
  TEE/Keystore 不可导出密钥**。
- `GEN_KEYS` 与 `SET_SN` 一样没有鉴权：串口物理可达即可生成/替换设备密钥。产线需控制
  物理访问；如需更强安全，后续应增加 token/HMAC、一次性授权或写保护。
