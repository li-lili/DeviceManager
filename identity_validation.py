"""Shared identity validation; usable by Qt and headless Linux test services."""

import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def validate_sn(sn: str) -> None:
    if not isinstance(sn, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", sn):
        raise ValueError("SN 必须为 1–64 位英文字母、数字、点、下划线或连字符")


SUPPORTED_KEY_SIZES = (2048, 3072)


def validate_identity(sn: str, pem: str) -> None:
    validate_sn(sn)
    if not isinstance(pem, str) or len(pem) > 16384:
        raise ValueError("公钥必须为 RSA-2048/3072 PEM 文本")
    lines = pem.splitlines()
    if (len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----"
            or lines[-1] != "-----END PUBLIC KEY-----"
            or any(not re.fullmatch(r"[A-Za-z0-9+/=]{1,64}", line) for line in lines[1:-1])
            or any(len(line) != 64 for line in lines[1:-2])):
        raise ValueError("公钥必须为完整 SubjectPublicKeyInfo PEM，保留每行换行")
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as error:
        raise ValueError("无法解析公钥 PEM") from error
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size not in SUPPORTED_KEY_SIZES:
        raise ValueError("公钥必须为 RSA-2048 或 RSA-3072")
