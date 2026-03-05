<?php
/* LHL's App Selling Plugin WHMCS Module
   https://shop.lhl.one
*/

use Illuminate\Database\Capsule\Manager as Capsule;

function lhlappGen_MetaData()
{
    return array(
        'DisplayName' => 'LHL\'s App Gen',
        'APIVersion' => '1.1',
        'RequiresServer' => false,
    );
}

function lhlappGen_ConfigOptions($params)
{
    return [
        'APP名称' => [
            'Type' => 'text',
            'Description' => '产品显示名称',
        ],
        'APP文档' => [
            'Type' => 'text',
            'Description' => '文档链接地址',
        ],
        'APP下载地址' => [
            'Type' => 'text',
            'Description' => '下载链接地址',
        ],
        'License 加密方案' => [
            'Type' => 'dropdown',
            'Options' => 'hmac,ecc',
            'Description' => '选择 License 生成方案：hmac = HMAC-SHA256 对称盐值，ecc = ECC P-256 ECDSA-SHA256 非对称签名',
            'Default' => 'hmac',
        ],
        'License Salt / ECC 私钥' => [
            'Type' => 'textarea',
            'Rows' => '6',
            'Description' => '当方案为 hmac 时填写 HMAC 盐值；当方案为 ecc 时粘贴 ECC P-256 私钥 PEM 全文（含 BEGIN/END 行）',
        ],
        'License 变量名' => [
            'Type' => 'text',
            'Description' => '产品自定义字段中用于生成 License 的字段名称（如：Bot Username）',
        ],
    ];
}

/**
 * 生成 License Key (HMAC-SHA256 方案)
 *
 * 算法：HMAC-SHA256(salt, lowercase(input)) -> 取前32位hex -> 大写 -> 每8位用-分隔
 *
 * @param string $salt   HMAC 密钥（盐值）
 * @param string $input  用户输入的变量值（如 bot_username）
 * @return string 格式化的 License Key，如 XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
 */
function lhlappGen_GenerateLicense($salt, $input)
{
    $raw = strtoupper(substr(
        hash_hmac('sha256', strtolower(trim($input)), $salt),
        0,
        32
    ));
    return implode('-', str_split($raw, 8));
}

/**
 * 将 openssl_sign 输出的 DER 编码 ECDSA 签名转为固定 64 字节 r‖s 格式
 *
 * @param string $der  DER 编码的签名
 * @return string|false 64 字节二进制字符串，失败返回 false
 */
function lhlappGen_ECDSADerToRaw($der)
{
    // DER: 0x30 <len> 0x02 <rLen> <r> 0x02 <sLen> <s>
    $offset = 0;
    if (ord($der[$offset++]) !== 0x30) return false;

    // 跳过 sequence 长度
    $seqLen = ord($der[$offset++]);
    if ($seqLen > 127) {
        $offset += ($seqLen & 0x7F);
    }

    // 读取 r
    if (ord($der[$offset++]) !== 0x02) return false;
    $rLen = ord($der[$offset++]);
    $r = substr($der, $offset, $rLen);
    $offset += $rLen;

    // 读取 s
    if (ord($der[$offset++]) !== 0x02) return false;
    $sLen = ord($der[$offset++]);
    $s = substr($der, $offset, $sLen);

    // 去掉前导 0x00 (正整数补位) 并填充到 32 字节
    $r = str_pad(ltrim($r, "\x00"), 32, "\x00", STR_PAD_LEFT);
    $s = str_pad(ltrim($s, "\x00"), 32, "\x00", STR_PAD_LEFT);

    return $r . $s;
}

/**
 * ECC P-256 ECDSA-SHA256 非对称签名方案生成 License Key
 *
 * 算法：ECDSA-SHA256(private_key, lowercase(trim(input))) -> 提取 r‖s (64 bytes) -> base64
 * 输出：88 字符 base64 字符串
 *
 * @param string $privateKeyPem  ECC P-256 私钥 PEM 全文
 * @param string $input          用户输入的变量值（如 bot_username）
 * @return string|false          base64 编码的签名(88字符)，失败返回 false
 */
function lhlappGen_GenerateLicenseECC($privateKeyPem, $input)
{
    $privateKey = openssl_pkey_get_private($privateKeyPem);
    if ($privateKey === false) {
        return false;
    }

    $message = strtolower(trim($input));
    $derSignature = '';
    $ok = openssl_sign($message, $derSignature, $privateKey, OPENSSL_ALGO_SHA256);

    if (!$ok) {
        return false;
    }

    // DER → 固定 64 字节 r‖s
    $rawSig = lhlappGen_ECDSADerToRaw($derSignature);
    if ($rawSig === false || strlen($rawSig) !== 64) {
        return false;
    }

    return base64_encode($rawSig);
}

/**
 * 根据所选方案分发生成
 *
 * @param string $method        'hmac' 或 'ecc'
 * @param string $secretOrKey   hmac 时为盐值，ecc 时为私钥 PEM
 * @param string $input         用户输入值
 * @return string|false
 */
function lhlappGen_GenerateLicenseByMethod($method, $secretOrKey, $input)
{
    if ($method === 'ecc') {
        return lhlappGen_GenerateLicenseECC($secretOrKey, $input);
    }
    // 默认 hmac
    return lhlappGen_GenerateLicense($secretOrKey, $input);
}

function lhlappGen_CreateAccount($params)
{
    return 'success';
}

function lhlappGen_TerminateAccount($params)
{
    return 'success';
}
function lhlappGen_ClientArea($params)
{
    ob_start();

    $appName = isset($params['configoption1']) ? htmlspecialchars($params['configoption1']) : '未设置名称';
    $appDoc = isset($params['configoption2']) ? htmlspecialchars($params['configoption2']) : '';
    $appDownload = isset($params['configoption3']) ? htmlspecialchars($params['configoption3']) : '';
    $licenseMethod = isset($params['configoption4']) ? strtolower(trim($params['configoption4'])) : 'hmac';
    $licenseSecretOrKey = isset($params['configoption5']) ? $params['configoption5'] : '';
    $licenseVarName = isset($params['configoption6']) ? trim($params['configoption6']) : '';

    // 从产品自定义字段中读取用户填写的变量值
    $licenseInput = '';
    if ($licenseVarName && isset($params['customfields'][$licenseVarName])) {
        $licenseInput = trim($params['customfields'][$licenseVarName]);
    }

    // 生成 License Key
    $licenseKey = '';
    $isECC = ($licenseMethod === 'ecc');
    if ($licenseSecretOrKey && $licenseInput) {
        $licenseKey = lhlappGen_GenerateLicenseByMethod($licenseMethod, $licenseSecretOrKey, $licenseInput);
        if ($licenseKey === false) {
            $licenseKey = '';
        }
    }

    ?>
    <div class="card border-0 mb-4" style="border-radius: 12px; overflow: hidden;">
        <div class="card-header bg-primary text-white py-3">
            <h3 class="card-title m-0 d-flex align-items-center justify-content-center" style="font-weight: 600; font-size: 1.5rem;">
                <i class="fas fa-cube" style="margin-right: 8px;"></i> <?php echo $appName; ?>
            </h3>
        </div>
        <div class="card-body p-4 text-center">

            <?php if ($licenseKey): ?>
                <div class="license-section bg-light p-4 rounded mb-4" style="border-radius: 8px">
                    <h5 class="text-muted mb-3" style="font-weight: 500;">
                        <i class="fas fa-key" style="margin-right: 6px;"></i> 产品授权密钥 (License Key)
                    </h5>

                    <?php if ($isECC): ?>
                    <!-- ECC 签名 88 字符，使用单行 input -->
                    <div class="input-group justify-content-center mb-2" style="max-width: 700px; margin: 0 auto; border-radius: 6px;">
                        <input type="text" class="form-control text-center font-monospace bg-white"
                               id="lhlapp-license-key"
                               value="<?php echo htmlspecialchars($licenseKey); ?>"
                               readonly style="border-radius:5px 0 0 5px !important;font-size: 0.92em; letter-spacing: 0.5px; color: #0d6efd; font-weight: 600;">
                        <button class="btn btn-primary px-4" type="button" 
                                style="border-radius: 0 5px 5px 0 !important;" onclick="var btn=this; navigator.clipboard.writeText(document.getElementById('lhlapp-license-key').value).then(function(){btn.innerHTML='<i class=\'fas fa-check\'></i> 已复制';setTimeout(function(){btn.innerHTML='<i class=\'far fa-copy\'></i> 复制'},2000)})">
                            <i class="far fa-copy"></i> 复制
                        </button>
                    </div>
                    <?php else: ?>
                    <!-- HMAC 短 key，使用 input -->
                    <div class="input-group justify-content-center mb-2" style="max-width: 600px; margin: 0 auto; border-radius: 6px;">
                        <input type="text" class="form-control text-center font-monospace bg-white"
                               id="lhlapp-license-key"
                               value="<?php echo htmlspecialchars($licenseKey); ?>"
                               readonly style="border-radius:5px 0 0 5px !important;font-size: 1.15em; letter-spacing: 1px; color: #198754; font-weight: 600;">
                        <button class="btn btn-primary px-4" type="button" 
                                style="border-radius: 0 5px 5px 0 !important;" onclick="var btn=this; navigator.clipboard.writeText(document.getElementById('lhlapp-license-key').value).then(function(){btn.innerHTML='<i class=\'fas fa-check\'></i> 已复制';setTimeout(function(){btn.innerHTML='<i class=\'far fa-copy\'></i> 复制'},2000)})">
                            <i class="far fa-copy"></i> 复制
                        </button>
                    </div>
                    <?php endif; ?>
                    <?php if ($licenseVarName): ?>
                        <div class="mt-3 text-muted small">
                            <?php echo htmlspecialchars($licenseVarName); ?>: 
                            <span class="badge" style="background-color: #6c757d; padding: 0.4em 0.6em; border-radius: 4px;">
                                <?php echo htmlspecialchars($licenseInput); ?>
                            </span>
                        </div>
                    <?php endif; ?>
                </div>
            <?php elseif ($licenseSecretOrKey && $licenseVarName && !$licenseInput): ?>
                <div class="alert alert-warning d-flex align-items-center justify-content-center p-4 rounded mb-4 shadow-sm" style="border-left: 5px solid #ffc107; text-align: left;">
                    <i class="fas fa-exclamation-triangle fa-2x text-warning" style="margin-right: 15px;"></i>
                    <div>
                        <strong class="d-block mb-1" style="font-size: 1.1em;">授权生成失败</strong>
                        未检测到 <strong><?php echo htmlspecialchars($licenseVarName); ?></strong> 的值，无法生成 License。请确认下单时自定义字段已正确填写。
                    </div>
                </div>
            <?php endif; ?>

            <div class="action-buttons mt-4 pt-2" style="border-top: 1px solid #eee;">
                <div class="d-flex justify-content-center" style="gap: 1rem; display: flex; flex-wrap: wrap;">
                    <?php if ($appDoc): ?>
                        <a href="<?php echo $appDoc; ?>" target="_blank" rel="noopener noreferrer"
                           class="btn btn-outline-primary shadow-sm px-4 py-2" style="border-radius: 8px; font-weight: 500; margin: 0 5px;">
                            <i class="fas fa-book" style="margin-right: 6px;"></i> 文档
                        </a>
                    <?php endif; ?>

                    <?php if ($appDownload): ?>
                        <a href="<?php echo $appDownload; ?>" target="_blank" rel="noopener noreferrer" download
                           class="btn btn-success shadow-sm px-4 py-2" style="border-radius: 8px; font-weight: 500; background-color: #198754; color: #fff; margin: 0 5px;">
                            <i class="fas fa-cloud-download-alt" style="margin-right: 6px;"></i> 下载
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    <style>
        .panel-body{
            padding:0 !important;
        }
    </style>
    <?php

    return ob_get_clean();
}






