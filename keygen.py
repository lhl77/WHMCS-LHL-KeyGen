#!/usr/bin/env python3
"""
授权密钥生成工具（仅开发者使用，请勿随源码分发）

支持两种加密方案:
  1. HMAC-SHA256 with Salt（对称密钥，长度35）
  2. ECC P-256 ECDSA-SHA256 签名（非对称密钥，长度88）

用法:
  ── HMAC 方案 ──
    python keygen.py hmac <input>
    python keygen.py hmac <input> --salt "自定义盐值"

  ── ECC 方案 ──
    python keygen.py ecc-gen                          # 生成 ECC P-256 密钥对
    python keygen.py ecc-sign <input> --key private.pem
    python keygen.py ecc-verify <input> --key public.pem --license <license>
"""
import sys
import hmac
import hashlib
import argparse
import base64
import os

# ──────────────────────────────────────────────
#  方案一: HMAC-SHA256 with Salt
# ──────────────────────────────────────────────

# 默认盐值
_LICENSE_SALT = b"LHL-App-Gen-2026-Salt!@#$%(^&*"


def generate_license_key_hmac(input_str: str, salt: bytes | None = None) -> str:
    """
    HMAC-SHA256 生成 License Key
    算法: HMAC-SHA256(salt, lowercase(input)) -> 取前32位hex -> 大写 -> 每8位用-分隔
    """
    if salt is None:
        salt = _LICENSE_SALT
    raw = hmac.new(
        salt,
        input_str.lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32].upper()
    return "-".join([raw[i : i + 8] for i in range(0, 32, 8)])


# ──────────────────────────────────────────────
#  方案二: ECC P-256 ECDSA-SHA256 非对称签名
# ──────────────────────────────────────────────
# 签名固定 64 字节 (r‖s 各 32 字节) → 88 字符 base64

def generate_ecc_keypair() -> tuple[str, str]:
    """
    生成 ECC P-256 (secp256r1/prime256v1) 密钥对
    返回 (private_pem, public_pem)
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    private_key = ec.generate_private_key(ec.SECP256R1())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _ecdsa_sig_to_raw(der_signature: bytes) -> bytes:
    """将 DER 编码的 ECDSA 签名转为固定 64 字节 r‖s 格式"""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_to_ecdsa_sig(raw: bytes) -> bytes:
    """将 64 字节 r‖s 格式转回 DER 编码"""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    return encode_dss_signature(r, s)


def generate_license_key_ecc(private_key_pem: str, input_str: str) -> str:
    """
    使用 ECC 私钥签名生成 License Key
    算法: ECDSA-SHA256(private_key, lowercase(trim(input))) -> 提取 r‖s (64 bytes) -> base64
    输出: 88 字符 base64 字符串
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    message = input_str.lower().strip().encode("utf-8")
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    raw_sig = _ecdsa_sig_to_raw(der_sig)
    return base64.b64encode(raw_sig).decode("utf-8")


def verify_license_key_ecc(public_key_pem: str, input_str: str, license_key: str) -> bool:
    """
    使用 ECC 公钥验证 License Key
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8"),
    )

    message = input_str.lower().strip().encode("utf-8")
    try:
        raw_sig = base64.b64decode(license_key)
        if len(raw_sig) != 64:
            return False
        der_sig = _raw_to_ecdsa_sig(raw_sig)
        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# ──────────────────────────────────────────────
#  CLI 入口
# ──────────────────────────────────────────────

def cmd_hmac(args):
    """HMAC-SHA256 License 生成"""
    input_str = args.input.lstrip("@").strip()
    if not input_str:
        print("❌ 输入不能为空")
        sys.exit(1)

    salt = args.salt.encode("utf-8") if args.salt else None
    key = generate_license_key_hmac(input_str, salt)

    print(f"方案: HMAC-SHA256 with Salt")
    print(f"输入: {input_str}")
    print(f"License Key: {key}")
    print()
    print("请将以下内容填入 config.json:")
    print(f'  "license_key": "{key}"')


def cmd_ecc_gen(args):
    """生成 ECC P-256 密钥对"""
    output_dir = args.output or "."

    print("正在生成 ECC P-256 密钥对...")
    private_pem, public_pem = generate_ecc_keypair()

    os.makedirs(output_dir, exist_ok=True)
    priv_path = os.path.join(output_dir, "private.pem")
    pub_path = os.path.join(output_dir, "public.pem")

    with open(priv_path, "w") as f:
        f.write(private_pem)
    with open(pub_path, "w") as f:
        f.write(public_pem)

    print(f"✅ 私钥已保存: {priv_path}  (⚠️ 请妥善保管，勿泄露！)")
    print(f"✅ 公钥已保存: {pub_path}  (嵌入客户端应用用于验证)")


def cmd_ecc_sign(args):
    """ECC 签名生成 License"""
    input_str = args.input.lstrip("@").strip()
    if not input_str:
        print("❌ 输入不能为空")
        sys.exit(1)

    with open(args.key, "r") as f:
        private_pem = f.read()

    key = generate_license_key_ecc(private_pem, input_str)

    print(f"方案: ECC P-256 ECDSA-SHA256")
    print(f"输入: {input_str}")
    print(f"License Key: {key}")
    print(f"长度: {len(key)} 字符")
    print()
    print("请将以下内容填入 config.json:")
    print(f'  "license_key": "{key}"')


def cmd_ecc_verify(args):
    """ECC 验证 License"""
    input_str = args.input.lstrip("@").strip()
    if not input_str:
        print("❌ 输入不能为空")
        sys.exit(1)

    with open(args.key, "r") as f:
        public_pem = f.read()

    ok = verify_license_key_ecc(public_pem, input_str, args.license)
    if ok:
        print("✅ License 验证通过")
    else:
        print("❌ License 验证失败：签名无效或输入不匹配")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="授权密钥生成工具（仅开发者使用）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python keygen.py hmac <input>
  python keygen.py hmac <input> --salt "自定义盐值"
  python keygen.py ecc-gen
  python keygen.py ecc-gen -o ./keys
  python keygen.py ecc-sign <input> --key private.pem
  python keygen.py ecc-verify <input> --key public.pem --license "base64..."
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="加密方案")

    # ── hmac 子命令 ──
    p_hmac = subparsers.add_parser("hmac", help="HMAC-SHA256 with Salt")
    p_hmac.add_argument("input", help="授权绑定的输入值")
    p_hmac.add_argument("--salt", default=None, help="自定义 HMAC 盐值（默认使用内置盐值）")
    p_hmac.set_defaults(func=cmd_hmac)

    # ── ecc-gen 子命令 ──
    p_ecc_gen = subparsers.add_parser("ecc-gen", help="生成 ECC P-256 密钥对")
    p_ecc_gen.add_argument("--output", "-o", default=None, help="密钥文件输出目录 (默认当前目录)")
    p_ecc_gen.set_defaults(func=cmd_ecc_gen)

    # ── ecc-sign 子命令 ──
    p_ecc_sign = subparsers.add_parser("ecc-sign", help="ECC 签名生成 License")
    p_ecc_sign.add_argument("input", help="授权绑定的输入值")
    p_ecc_sign.add_argument("--key", "-k", required=True, help="ECC 私钥文件路径 (PEM)")
    p_ecc_sign.set_defaults(func=cmd_ecc_sign)

    # ── ecc-verify 子命令 ──
    p_ecc_verify = subparsers.add_parser("ecc-verify", help="ECC 验证 License")
    p_ecc_verify.add_argument("input", help="授权绑定的输入值")
    p_ecc_verify.add_argument("--key", "-k", required=True, help="ECC 公钥文件路径 (PEM)")
    p_ecc_verify.add_argument("--license", "-l", required=True, help="待验证的 License Key (base64)")
    p_ecc_verify.set_defaults(func=cmd_ecc_verify)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
