# WHMCS License 模块 （纯本地验证）

WHMCS 产品授权密钥（License Key）自动生成模块，支持两种加密方案：

| 方案 | 类型 | License 长度 | 安全模型 |
|------|------|-------------|---------|
| **HMAC-SHA256 with Salt** | 对称密钥 | 35 字符 | 盐值泄露 = 可伪造 |
| **ECC P-256 ECDSA** | 非对称密钥 | **88 字符** | 公钥泄露也无法伪造 |

---

## 快速开始

### 1. HMAC-SHA256 方案

```bash
# 使用内置盐值
python keygen.py hmac <input>

# 使用自定义盐值
python keygen.py hmac <input> --salt "my-custom-salt"
```

输出：
```
License Key: AE17E866-9B639493-BB23B0F6-D93063FA
```

### 2. ECC P-256 方案（非对称签名）

```bash
# 第一步：生成密钥对（仅需一次）
python keygen.py ecc-gen                    # 输出到当前目录
python keygen.py ecc-gen -o ./keys          # 指定输出目录

# 第二步：用私钥签名生成 License
python keygen.py ecc-sign <input> --key private.pem

# 第三步：用公钥验证 License（可选）
python keygen.py ecc-verify <input> --key public.pem --license "base64..."
```

输出：
```
License Key: EeAz1+aOE6kzWeTALqx38SWwwO6KU1JUiBGHtiL4xJRRJXs8HbRloXa+NQk/MWlvwHgGa9yUSlxLxT0EvgTP9w==
长度: 88 字符
```

#### 密钥分发

| 文件 | 放在哪 | 说明 |
|------|--------|------|
| `private.pem` | WHMCS 服务器 / 开发者本地 | ⚠️ **绝对保密**，用于签发 License |
| `public.pem` | 客户端应用（程序）内 | 可公开，仅用于验证签名 |

---

## WHMCS 模块配置

将 `lhlappGen.php` 和 `whmcs.json` 放入 WHMCS 的 `modules/servers/lhlappGen/` 目录。

在产品配置中设置以下选项：

| 配置项 | 说明 |
|--------|------|
| **APP名称** | 产品显示名称 |
| **APP文档** | 文档链接 |
| **APP下载地址** | 下载链接 |
| **License 加密方案** | 下拉选 `hmac` 或 `ecc` |
| **License Salt / ECC 私钥** | hmac 时填盐值字符串；ecc 时粘贴 `private.pem` 全文 |
| **License 变量名** | 自定义字段名 |

---

## 依赖

### Python（keygen.py）

```bash
pip install cryptography   # 仅 ECC 方案需要，HMAC 方案无额外依赖
```

### PHP（lhlappGen.php）

- HMAC 方案：无额外扩展
- ECC 方案：需要 `ext-openssl`（绝大部分 PHP 环境默认已启用）

---

## 安全建议

1. **HMAC 方案**：盐值等同于私钥，一旦泄露攻击者可批量伪造。适合内部使用或信任环境。
2. **ECC 方案**：客户端应用只需内嵌公钥即可验证，即使被反编译提取公钥也无法伪造签名。**推荐面向外部发布的产品使用此方案。**
3. 两种方案都不包含过期时间/机器绑定，如需要可在签名 payload 中扩展字段。
