#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""产品 SN 暗码转明码工具

依据《产品SN暗码编码规则》实现：把 16 位对外暗码 SN 还原为产品线、机型、
软件主版本、生产工厂、生产日期、序号等信息，并拼出内部明码 SN。

暗码结构（16 位，连续书写、无分隔符）：
    产品代码(1-4) + 版本代码(5-6) + 生产地代码(7-8) + 生产日期代码(9-12) + 序号(13-16)

用法：
    python sn_decode.py 0101010100LR1001
    python sn_decode.py 0101010100LR1001 0401010100LR1010
    python sn_decode.py --json 0101010100LR1001
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from datetime import date, timedelta

# 统一基准日，第 0 天
BASE_DATE = date(2023, 9, 15)

BASE36_DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASE36_INDEX = {c: i for i, c in enumerate(BASE36_DIGITS)}

# 表 3-1 产品线代码对照表
PRODUCT_LINES = {
    "01": "Xiaonuo3",
    "02": "W1",
    "03": "W3",
    "04": "X-Head",
    "05": "X-Head CQ",
}

# 表 3-2 产品代码完整对照表
PRODUCTS = {
    "0101": "Xiaonuo3",
    "0201": "W1",
    "0301": "W3",
    "0401": "X-Head 1 标准版",
    "0402": "X-Head 1 Lite",
    "0403": "X-Head 1 Ultra",
    "0404": "X-Head 1 EDU",
    "0405": "X-Head 1 Lite EDU",
    "0406": "X-Head 1 Ultra EDU",
    "0501": "X-Head CustomQ",
}

# 表 3-4 生产地代码对照表：代码 -> (工厂名称, 明码缩写)
SITES = {
    "01": ("北京第一工厂", "BJ01"),
    "02": ("北京第二工厂", "BJ02"),
    "03": ("深圳第一工厂", "SZ01"),
    "04": ("苏州第一工厂", "SU01"),
}

# 序号起始值（36 进制字符串形式）
SERIAL_START = "1001"
SERIAL_START_VALUE = int(SERIAL_START, 36)


class SNError(ValueError):
    """SN 校验或解码失败。"""


@dataclass
class DecodedSN:
    sn: str
    product_code: str
    product_line: str
    product_name: str
    version_code: str
    version: str
    site_code: str
    site_name: str
    site_abbr: str
    date_code: str
    days: int
    prod_date: str
    serial_code: str
    serial_no: int
    plain_sn: str


def _base36_value(text: str, field: str) -> int:
    """把 36 进制字符串转为十进制；非法字符直接报错。"""
    value = 0
    for ch in text:
        if ch not in BASE36_INDEX:
            raise SNError(f"{field} 含非法字符 '{ch}'，36 进制只允许 0-9、A-Z")
        value = value * 36 + BASE36_INDEX[ch]
    return value


def normalize(sn: str) -> str:
    """去掉空格、下划线、连字符并统一大写。"""
    cleaned = "".join(ch for ch in sn if ch not in " \t\r\n_-")
    return cleaned.upper()


def decode(raw_sn: str) -> DecodedSN:
    """解码 16 位暗码 SN。"""
    sn = normalize(raw_sn)

    if len(sn) != 16:
        raise SNError(f"SN 长度应为 16 位，当前为 {len(sn)} 位：{sn}")

    product_code = sn[0:4]
    version_code = sn[4:6]
    site_code = sn[6:8]
    date_code = sn[8:12]
    serial_code = sn[12:16]

    # 产品代码：前两位产品线，后两位产品线内机型版本
    if product_code not in PRODUCTS:
        line_hint = PRODUCT_LINES.get(product_code[:2])
        if line_hint is None:
            raise SNError(f"产品代码 {product_code} 无效：产品线代码 {product_code[:2]} 不在对照表中")
        raise SNError(
            f"产品代码 {product_code} 无效：产品线 {line_hint}（{product_code[:2]}）下没有版本 {product_code[2:]}"
        )

    # 版本代码：仅含主版本号
    if not version_code.isdigit():
        raise SNError(f"版本代码 {version_code} 应为两位数字（主版本号）")
    major = int(version_code)
    if major < 1:
        raise SNError(f"版本代码 {version_code} 无效：主版本号应不小于 1")

    # 生产地代码
    if site_code not in SITES:
        raise SNError(f"生产地代码 {site_code} 不在对照表中")
    site_name, site_abbr = SITES[site_code]

    # 生产日期代码：36 进制天数 + 基准日
    days = _base36_value(date_code, f"生产日期代码 {date_code}")
    prod_date = BASE_DATE + timedelta(days=days)

    # 序号：36 进制，从 1001 开始
    serial_value = _base36_value(serial_code, f"序号 {serial_code}")
    serial_no = serial_value - SERIAL_START_VALUE + 1
    if serial_no < 1:
        raise SNError(f"序号 {serial_code} 小于起始值 {SERIAL_START}")

    product_name = PRODUCTS[product_code]
    version = f"V{major}.x"

    plain_sn = (
        f"NTX_{product_name}XX_{version}_{site_abbr}_"
        f"{prod_date:%Y%m%d}_{serial_no:04d}"
    )

    return DecodedSN(
        sn=sn,
        product_code=product_code,
        product_line=PRODUCT_LINES[product_code[:2]],
        product_name=product_name,
        version_code=version_code,
        version=version,
        site_code=site_code,
        site_name=site_name,
        site_abbr=site_abbr,
        date_code=date_code,
        days=days,
        prod_date=prod_date.isoformat(),
        serial_code=serial_code,
        serial_no=serial_no,
        plain_sn=plain_sn,
    )


def format_report(d: DecodedSN) -> str:
    """生成人读的解码结果。"""
    lines = [
        f"暗码 SN : {d.sn}",
        "─" * 46,
        f"产品代码   {d.product_code}  → 产品线 {d.product_line}（{d.product_code[:2]}）"
        f" / 机型 {d.product_name}（{d.product_code[2:]}）",
        f"版本代码   {d.version_code}      → 软件主版本 {d.version}（次版本需查 MES）",
        f"生产地代码 {d.site_code}      → {d.site_name}",
        f"日期代码   {d.date_code}    → 距基准日 {d.days} 天 → {d.prod_date}",
        f"序号       {d.serial_code}    → 该型号第 {d.serial_no} 台",
        "─" * 46,
        f"明码 SN : {d.plain_sn}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="产品 SN 暗码转明码工具")
    parser.add_argument("sn", nargs="+", help="一个或多个 16 位暗码 SN")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    args = parser.parse_args(argv)

    results: list[dict] = []
    failed = False

    for raw in args.sn:
        try:
            decoded = decode(raw)
        except SNError as exc:
            failed = True
            if args.json:
                results.append({"sn": normalize(raw), "ok": False, "error": str(exc)})
            else:
                print(f"解析失败 {raw}：{exc}", file=sys.stderr)
            continue

        if args.json:
            results.append({"ok": True, **asdict(decoded)})
        else:
            print(format_report(decoded))
            print()

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
