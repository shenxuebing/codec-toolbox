// ============================================================
// 增强版编解码工具 - 国密 SM2/SM4 页（page-gmsm）
// 功能：SM4 加解密（ECB/CBC × PKCS7/无填充）/ SM3 摘要 /
//       SM2 密钥对生成 / PKCS#8 PEM 私钥提取 / SM2 加解密 / SM2 签名验签
// 依赖（须先于本文件加载）：
//   js/vendor/sm-crypto.js → window.smCrypto = { sm2, sm3, sm4 }（0.3.2 本地化打包）
//   js/app.js              → showNotification / copyTextToClipboard / bytesToBinaryString
//
// ===== sm-crypto 0.3.2 实测 API 坑点（以 vendor 源码为准，务必照此使用）=====
// 1. sm4.encrypt(input, keyHex32, cfg)：
//    - input 为字符串时按 UTF-8 文本编码（内部 utf8ToArray）；二进制数据必须传字节数组
//      （Array of number）——Hex 输入绝不能把 hex 字符串直接传进去（会被当成 UTF-8 文本再编一次）。
//    - 加密的字符串输出恒为 hex（小写）；cfg = { padding: 'pkcs#5'(默认)|'none',
//      mode: 'cbc'（缺省 ECB）, iv: 32位hex（仅 CBC，长度必须 16 字节）, output: 'string'(默认)|'array' }。
// 2. sm4.decrypt(inputHex, keyHex32, cfg)：
//    - 字符串输入按 hex 解释（与加密侧不对称！）；二进制密文传字节数组。
//    - 字符串输出按 UTF-8 解释（非对称设计）；解密二进制数据必须 output: 'array' 拿字节数组自行转换。
//    - padding 'none' 时库不校验长度：尾部不足 16 字节的块会被静默丢弃，必须调用方先行校验。
// 3. sm2.generateKeyPairHex() → { privateKey: 64位hex, publicKey: 130位hex（04 开头未压缩点） }
// 4. sm2.doEncrypt(msg, publicKeyHex, cipherMode)：msg 是 UTF-8 明文文本——库内部执行
//    utf8ToHex(msg)（vendor 源码 /sm2/index.js 首行），并不接受 hex 串；若先自行转 Hex
//    会被当作文本二次编码。cipherMode 1=C1C3C2（新国标，默认）、0=C1C2C3（旧标准）；
//    返回 hex 且不含 04 前缀（C1 为 128 位 x||y 坐标）。
// 5. sm2.doDecrypt(cipherHex, privateKeyHex, cipherMode)：0.3.2 只有 3 个参数，
//    没有 output 选项；直接返回 UTF-8 文本，C3 校验失败时返回空串 ''。
// 6. sm2.doSignature(msg, privateKeyHex, { hash, der, userId })：
//    msg 同样按 UTF-8 文本处理（字符串→utf8ToHex，数组→按字节）；
//    hash:true 走国标 ZA 预处理（userId 默认 '1234567812345678'，按文本 UTF-8 编码）。
// 7. sm2.doVerifySignature(msg, signHex, publicKeyHex, { hash, der, userId }) → boolean，
//    选项须与签名时完全一致。
// 8. sm3(strOrArray)：字符串按 UTF-8、数组按字节，返回 64 位 hex。
// ============================================================

// ---------------- 通用小工具（不依赖 app.js 内部函数） ----------------

// 取单选组当前选中值（无选中时返回 null）
function gmGetRadio(name) {
    var checked = document.querySelector('input[name="' + name + '"]:checked');
    return checked ? checked.value : null;
}

// 清洗 Hex 输入：去掉空白与常见的分隔符（空格/换行/冒号/逗号），统一小写
function gmCleanHex(str) {
    return str.replace(/[\s:,]/g, '').toLowerCase();
}

// Hex 字符串 → 字节数组（Array of number，与库期望的输入形态一致）；非法则抛中文错误
function gmHexToBytes(hex) {
    if (!/^[0-9a-f]*$/.test(hex) || hex.length % 2 !== 0) {
        throw new Error('不是合法的 Hex 字符串（长度须为偶数且仅含 0-9 a-f）');
    }
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// 字节数组 → Hex 字符串（小写）
function gmBytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
}

// 文本 → UTF-8 字节数组
function gmUtf8ToBytes(text) {
    return Array.prototype.slice.call(new TextEncoder().encode(text));
}

// Base64 → 字节数组；兼容 base64url 变体（-_ → +/），非法则抛中文错误
function gmBase64ToBytes(b64) {
    var cleaned = b64.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
    var binary;
    try {
        binary = atob(cleaned);
    } catch (e) {
        throw new Error('不是合法的 Base64 字符串');
    }
    var bytes = [];
    for (var i = 0; i < binary.length; i++) {
        bytes.push(binary.charCodeAt(i));
    }
    return bytes;
}

// 字节数组 → Base64（bytesToBinaryString 为 app.js 全局函数）
function gmBytesToBase64(bytes) {
    return btoa(bytesToBinaryString(bytes));
}

// 校验 32 位 Hex（密钥/IV 共用），通过返回清洗后的小写串，否则抛中文错误
function gmRequireHex32(value, what) {
    var cleaned = gmCleanHex(value);
    if (!/^[0-9a-f]{32}$/.test(cleaned)) {
        throw new Error(what + '必须是 32 位 Hex（16 字节）');
    }
    return cleaned;
}

// 统一错误出口：结果区显示 ❌ 前缀消息 + 弹出通知
function gmShowError(resultId, err) {
    var msg = err && err.message ? err.message : String(err);
    var el = document.getElementById(resultId);
    if (el) {
        el.textContent = '❌ ' + msg;
        el.className = el.className.replace(/\s*(jwt-valid|jwt-invalid)/g, '');
    }
    showNotification(msg);
}

// 校验 64 位 Hex 私钥，返回清洗后的小写串
function gmRequirePrivKey(priv) {
    var cleaned = gmCleanHex(priv);
    if (!/^[0-9a-f]{64}$/.test(cleaned)) {
        throw new Error('私钥必须是 64 位 Hex（可先"生成密钥对"或从 PEM 提取）');
    }
    return cleaned;
}

// 校验/归一化公钥：接受 130 位（04 开头）或 128 位（缺 04 前缀的裸坐标）Hex
function gmNormalizePubKey(pub) {
    var cleaned = gmCleanHex(pub);
    if (/^[0-9a-f]{128}$/.test(cleaned)) {
        cleaned = '04' + cleaned; // 库的 decodePointHex 需要未压缩点前缀
    }
    if (!/^04[0-9a-f]{128}$/.test(cleaned)) {
        throw new Error('公钥必须是 04 开头的 130 位 Hex（或 128 位坐标 Hex）');
    }
    return cleaned;
}

// 复制输入框（input）内容：copyToClipboard 只认 textContent，input 需走 value
function gmCopyInput(id) {
    var value = document.getElementById(id).value.trim();
    if (value) {
        copyTextToClipboard(value);
    } else {
        showNotification('内容为空，无以复制');
    }
}

// ---------------- Section 1：SM4 加解密 ----------------

// 模式切换：仅 CBC 时显示 IV 输入行（所在行整体 display 切换）
function sm4ModeChanged() {
    var isCbc = gmGetRadio('sm4-mode') === 'cbc';
    document.getElementById('sm4-iv-row').style.display = isCbc ? '' : 'none';
}

// 组装 SM4 cfg（密钥/IV 校验 + CBC 时附带 iv）；ECB 不带 mode（库缺省即 ECB）
function sm4BuildCfg() {
    var cfg = { padding: gmGetRadio('sm4-padding') };
    if (gmGetRadio('sm4-mode') === 'cbc') {
        cfg.mode = 'cbc';
        cfg.iv = gmRequireHex32(document.getElementById('sm4-iv').value, 'CBC 模式的 IV ');
    }
    return cfg;
}

// 生成 16 字节随机 SM4 密钥（crypto.getRandomValues → 32 位 hex）
function sm4GenKey() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    document.getElementById('sm4-key').value = gmBytesToHex(bytes);
    showNotification('已生成随机 SM4 密钥（16 字节 / 32 位 Hex）');
}

// 生成 16 字节随机 IV（顺手，与密钥同款）
function sm4GenIv() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    document.getElementById('sm4-iv').value = gmBytesToHex(bytes);
    showNotification('已生成随机 IV（16 字节 / 32 位 Hex）');
}

// 无填充模式的通用长度校验：数据必须是 16 字节整数倍（库会静默丢弃尾部不足一块的数据）
function gmRequireFullBlocks(byteLength) {
    if (byteLength % 16 !== 0) {
        throw new Error('无填充时要求数据长度是 16 字节的整数倍（当前 ' + byteLength + ' 字节，差 ' + (16 - byteLength % 16) + ' 字节）');
    }
}

function sm4DoEncrypt() {
    try {
        var input = document.getElementById('sm4-input').value;
        if (!input) {
            throw new Error('请输入明文内容');
        }
        var key = gmRequireHex32(document.getElementById('sm4-key').value, 'SM4 密钥');
        var cfg = sm4BuildCfg();
        var inFormat = gmGetRadio('sm4-input-format');
        var noPadding = cfg.padding === 'none';

        // 输入解析：
        // - 文本：库对字符串输入按 UTF-8 处理，直接传字符串即可（库内部 utf8ToArray）；
        // - Hex/Base64：必须转字节数组传入——不能把 hex 字符串直接传（会被当 UTF-8 文本）。
        var data;
        if (inFormat === 'text') {
            if (noPadding) {
                // 无填充需先拿到字节长度做校验，统一走数组路径
                data = gmUtf8ToBytes(input);
                gmRequireFullBlocks(data.length);
            } else {
                data = input; // 字符串直传，库按 UTF-8 编码
            }
        } else if (inFormat === 'hex') {
            data = gmHexToBytes(gmCleanHex(input));
            if (noPadding) {
                gmRequireFullBlocks(data.length);
            }
        } else {
            data = gmBase64ToBytes(input);
            if (noPadding) {
                gmRequireFullBlocks(data.length);
            }
        }

        // 加密的字符串输出恒为 hex
        var cipherHex = smCrypto.sm4.encrypt(data, key, cfg);

        var outFormat = gmGetRadio('sm4-output-format');
        var display;
        if (outFormat === 'base64') {
            display = gmBytesToBase64(gmHexToBytes(cipherHex));
        } else {
            // 加密输出是二进制密文，"文本(UTF-8)" 仅解密有意义，此处按 Hex 展示
            if (outFormat === 'text') {
                showNotification('加密输出为二进制密文，已按 Hex 显示');
            }
            display = cipherHex;
        }
        document.getElementById('sm4-result').textContent = display;
    } catch (e) {
        gmShowError('sm4-result', e);
    }
}

function sm4DoDecrypt() {
    try {
        var input = document.getElementById('sm4-input').value;
        if (!input) {
            throw new Error('请输入密文内容');
        }
        var key = gmRequireHex32(document.getElementById('sm4-key').value, 'SM4 密钥');
        var cfg = sm4BuildCfg();
        var inFormat = gmGetRadio('sm4-input-format');
        var noPadding = cfg.padding === 'none';

        // 输入是密文："文本"选项按 Hex 处理（密文即十六进制），Hex 同理；
        // 库的 decrypt 对字符串输入按 hex 解释（与加密侧不对称），
        // Base64 密文则先解出字节数组传入。
        var data;
        var byteLen;
        if (inFormat === 'text' || inFormat === 'hex') {
            data = gmCleanHex(input);
            if (!/^[0-9a-f]*$/.test(data) || data.length % 2 !== 0) {
                throw new Error('密文不是合法的 Hex 字符串（解密时"文本"输入即按 Hex 密文处理）');
            }
            byteLen = data.length / 2;
        } else {
            data = gmBase64ToBytes(input);
            byteLen = data.length;
        }
        if (noPadding) {
            gmRequireFullBlocks(byteLen);
        }

        // 输出：文本走库的字符串输出（按 UTF-8 解释）；
        // Hex/Base64 必须 output:'array' 拿字节数组自行转换（decrypt 的字符串输出只会是 UTF-8 文本）。
        var outFormat = gmGetRadio('sm4-output-format');
        if (outFormat === 'text') {
            var plainText = smCrypto.sm4.decrypt(data, key, cfg);
            document.getElementById('sm4-result').textContent = plainText;
        } else {
            cfg.output = 'array';
            var plainBytes = smCrypto.sm4.decrypt(data, key, cfg);
            document.getElementById('sm4-result').textContent = (outFormat === 'base64')
                ? gmBytesToBase64(plainBytes)
                : gmBytesToHex(plainBytes);
        }
    } catch (e) {
        gmShowError('sm4-result', e);
    }
}

function sm4Clear() {
    document.getElementById('sm4-input').value = '';
    document.getElementById('sm4-result').textContent = '';
}

// ---------------- SM3 摘要（Section 1 顺手区） ----------------

function sm3Calc() {
    try {
        var input = document.getElementById('sm3-input').value;
        if (!input) {
            throw new Error('请输入 SM3 摘要的输入内容');
        }
        // sm3：字符串按 UTF-8、数组按字节；文本直传字符串，Hex 转数组（不能传 hex 串）
        var result;
        if (gmGetRadio('sm3-format') === 'text') {
            result = smCrypto.sm3(input);
        } else {
            result = smCrypto.sm3(gmHexToBytes(gmCleanHex(input)));
        }
        document.getElementById('sm3-result').textContent = result;
    } catch (e) {
        gmShowError('sm3-result', e);
    }
}

// ---------------- Section 2：SM2 密钥对 / PEM 提取 / 加解密 ----------------

// 生成 SM2 密钥对：privateKey 64 位 hex，publicKey 130 位 hex（04 开头）
function sm2GenPair() {
    var pair = smCrypto.sm2.generateKeyPairHex();
    document.getElementById('sm2-privkey').value = pair.privateKey;
    document.getElementById('sm2-pubkey').value = pair.publicKey;
    showNotification('已生成 SM2 密钥对');
}

// 从 PKCS#8 PEM/Base64 提取 SM2 私钥。
// 简化口径：不做完整 ASN.1 解析——PKCS#8 EC 私钥结构固定为
//   SEQUENCE { INTEGER 1, OCTET STRING(32 字节私钥), [0] OID, [1] 公钥 BIT STRING }
// Base64 解码后的 DER 中，OCTET STRING 头即 0x04 0x20（长度 32），
// 从前往后扫描首个 `04 20` 并取其后 32 字节即为私钥；OID/公钥段中即使再
// 出现 04 20 也不影响（OCTET STRING 一定在它们之前）。
function sm2FromPem() {
    try {
        var raw = document.getElementById('sm2-pem-input').value
            .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, '')
            .replace(/-----END [A-Z ]*PRIVATE KEY-----/g, '')
            .replace(/\s/g, '');
        if (!raw) {
            throw new Error('请粘贴 PKCS#8 PEM 或 Base64 私钥');
        }
        var der = gmBase64ToBytes(raw);
        for (var i = 0; i + 33 < der.length; i++) {
            if (der[i] === 0x04 && der[i + 1] === 0x20) {
                var priv = gmBytesToHex(der.slice(i + 2, i + 34));
                document.getElementById('sm2-privkey').value = priv;
                showNotification('已提取 32 字节 SM2 私钥并填入上方私钥框');
                return;
            }
        }
        throw new Error('不是有效的 PKCS#8 SM2 私钥（未找到 32 字节 OCTET STRING 私钥段）');
    } catch (e) {
        // 统一提示口径：解析失败一律报"不是有效的 PKCS#8 SM2 私钥"，附带原因
        showNotification('不是有效的 PKCS#8 SM2 私钥：' + (e.message || e));
    }
}

function sm2ClearPem() {
    document.getElementById('sm2-pem-input').value = '';
}

// 取密文排布（加解密共用一组单选）：1=C1C3C2（新国标），0=C1C2C3（旧标准）
function sm2GetCipherMode() {
    return parseInt(gmGetRadio('sm2-cipher'), 10);
}

function sm2Encrypt() {
    try {
        var text = document.getElementById('sm2-enc-input').value;
        if (!text) {
            throw new Error('请输入 SM2 加密的明文文本');
        }
        var pub = gmNormalizePubKey(document.getElementById('sm2-pubkey').value);
        var cipherMode = sm2GetCipherMode();

        // 坑点：doEncrypt 的 msg 是 UTF-8 明文文本（库内部 utf8ToHex），
        // 直接传文本即可，切勿先转 Hex（会被当作文本再编码一次）。
        // 返回 hex 且不含 04 前缀。
        var cipherHex = smCrypto.sm2.doEncrypt(text, pub, cipherMode);

        var display = gmGetRadio('sm2-enc-out') === 'base64'
            ? gmBytesToBase64(gmHexToBytes(cipherHex))
            : cipherHex;
        document.getElementById('sm2-enc-result').textContent = display;
    } catch (e) {
        gmShowError('sm2-enc-result', e);
    }
}

function sm2Decrypt() {
    try {
        var input = document.getElementById('sm2-dec-input').value.replace(/\s/g, '');
        if (!input) {
            throw new Error('请输入 SM2 密文（Hex 或 Base64）');
        }
        var priv = gmRequirePrivKey(document.getElementById('sm2-privkey').value);
        var cipherMode = sm2GetCipherMode();

        // 密文格式自动识别：先按 Hex（密文即十六进制），否则按 Base64 解出再转 hex
        var cipherHex;
        if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0) {
            cipherHex = input.toLowerCase();
        } else {
            cipherHex = gmBytesToHex(gmBase64ToBytes(input));
        }

        // 兼容其他工具输出的带 04 前缀密文：库要求密文不含 04 前缀，
        // 去掉首个 04 后剩余长度仍 ≥ 192 位 hex（C1=128 + C3=64，C2 至少 0 字节）才视为多余前缀
        if (cipherHex.substr(0, 2) === '04' && cipherHex.length >= 194 && (cipherHex.length - 2) % 2 === 0) {
            cipherHex = cipherHex.substr(2);
        }

        // 坑点：0.3.2 的 doDecrypt 只有 3 参、无 output 选项，直接返回 UTF-8 文本；
        // C3 校验失败（密文/私钥/排布不匹配）返回空串。
        var plain = smCrypto.sm2.doDecrypt(cipherHex, priv, cipherMode);
        if (plain === '') {
            throw new Error('解密失败：C3 校验未通过（请核对密文、私钥及"密文排布"是否一致，明文为空也视为失败）');
        }
        document.getElementById('sm2-enc-result').textContent = plain;
    } catch (e) {
        gmShowError('sm2-enc-result', e);
    }
}

// ---------------- Section 3：SM2 签名 / 验签 ----------------

// 组装签名/验签选项：SM3 预处理(ZA)、DER 编码、UserId（留空回退国标默认值）
function sm2SignOptions() {
    return {
        hash: gmGetRadio('sm2-sign-hash') === 'yes',
        der: gmGetRadio('sm2-sign-der') === 'yes',
        userId: document.getElementById('sm2-userid').value.trim() || '1234567812345678'
    };
}

function sm2Sign() {
    try {
        var msg = document.getElementById('sm2-sign-input').value;
        if (!msg) {
            throw new Error('请输入待签名消息');
        }
        var priv = gmRequirePrivKey(document.getElementById('sm2-privkey').value);
        var opts = sm2SignOptions();

        // 坑点：doSignature 的 msg 按字符串即 UTF-8 文本处理（内部 utf8ToHex），
        // 直接传消息文本；hash:true 走国标 ZA 预处理（userId 按 UTF-8 编码参与运算）。
        var sign = smCrypto.sm2.doSignature(msg, priv, opts);

        // 签名值回填单行框，便于直接点击"SM2 验签"自测
        document.getElementById('sm2-signvalue-input').value = sign;
        var result = document.getElementById('sm2-sign-result');
        result.className = 'result-area gm-oneline';
        result.textContent = '签名完成（' + (opts.der ? 'DER ' : 'r||s ') + (opts.hash ? 'SM3 预处理' : '无预处理')
            + '，UserId=' + opts.userId + '）：\n' + sign;
        showNotification('SM2 签名完成，签名值已填入上方输入框');
    } catch (e) {
        gmShowError('sm2-sign-result', e);
    }
}

function sm2Verify() {
    try {
        var msg = document.getElementById('sm2-sign-input').value;
        if (!msg) {
            throw new Error('请输入待验签消息');
        }
        var sign = document.getElementById('sm2-signvalue-input').value.replace(/\s/g, '');
        if (!sign) {
            throw new Error('请粘贴待验证的签名值（Hex）');
        }
        var pub = gmNormalizePubKey(document.getElementById('sm2-pubkey').value);
        var opts = sm2SignOptions();

        // 验签选项必须与签名侧完全一致（hash/der/userId），否则必然失败
        var ok = smCrypto.sm2.doVerifySignature(msg, sign, pub, opts);

        var result = document.getElementById('sm2-sign-result');
        result.className = 'result-area gm-oneline ' + (ok ? 'jwt-valid' : 'jwt-invalid');
        result.textContent = ok
            ? '✅ 验签通过（' + (opts.der ? 'DER ' : 'r||s ') + (opts.hash ? 'SM3 预处理' : '无预处理') + '，UserId=' + opts.userId + '）'
            : '❌ 验签失败：签名与消息/公钥不匹配，或双方 SM3 预处理、DER 编码、UserId 设置不一致';
        showNotification(ok ? '验签通过' : '验签失败');
    } catch (e) {
        gmShowError('sm2-sign-result', e);
    }
}

// ===================== EnDataUtil.dll 格式兼容（SM4EnData / SM4DeData） =====================
// 封装口径自 EnDataUtil.dll 源码（enDataUtil.cpp v1.x）逐行复刻，与 C 端实现完全互通：
//   加密：SM4-ECB/PKCS7，密钥 = makeEnDataKey(yKey, random)；
//         输出 = 大写Hex(密文) + 16字符随机数Hex串（ASCII，直接拼接在末尾）
//   解密：从末尾取 16 字符为 random，前面为 Hex 密文，同密钥解密
// 关键对拍：明文 Aa123456 ↔ B9F2EF5560D0FDBCF83E1B67B2A68E9452941FF1C11D798C 逐字节一致；
//           2.txt 解出 "88888888"；sm2_app.enc(368字符) 解出 164 字节 PKCS#8 私钥 Base64 文本

// enDataUtil.cpp 第 55 行的固定 35 字节 yKey（密钥派生的"口令"输入，逐字节照抄源码）
var GM_COMPAT_YKEY = [0x30, 0x82, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];

// 原始字节 MD5（对齐源码 MD5(data, len, out) 接口；CryptoJS 已由 index.html 先行加载）
// 注意：WordArray.create 对普通 Array 按 32 位字解释，必须传 Uint8Array 才按字节解释
function gmMd5Raw(bytes) {
    var wa = CryptoJS.lib.WordArray.create(new Uint8Array(bytes));
    var hex = CryptoJS.MD5(wa).toString(CryptoJS.enc.Hex);
    var out = [];
    for (var i = 0; i < hex.length; i += 2) {
        out.push(parseInt(hex.substr(i, 2), 16));
    }
    return out;
}

// enDataUtil.cpp 第 57-107 行 makeEnDataKey 的逐步复刻：
// SM3(pwd) → 前后16B对折(后前) → 逐字节取反 → MD5 → 逐字节取反 → 前后8B对折(后前) → SM3 → MD5 → 与 random 异或
function gmMakeEnDataKey(pwdBytes, randomBytes16) {
    // sm3 返回 hex 字符串，直接按 2 字符一字节还原（不可过 gmBytesToHex——它吃字节数组）
    var digestHex = smCrypto.sm3(pwdBytes.slice());
    var dg = [];
    for (var i = 0; i < digestHex.length; i += 2) dg.push(parseInt(digestHex.substr(i, 2), 16));
    var folded = dg.slice(16, 32).concat(dg.slice(0, 16));
    var inverted = folded.map(function (b) { return ~b & 0xff; });
    var m1 = gmMd5Raw(inverted).map(function (b) { return ~b & 0xff; });
    var folded2 = m1.slice(8, 16).concat(m1.slice(0, 8));
    var mk = [];
    var mkHex = smCrypto.sm3(folded2);
    for (var j = 0; j < mkHex.length; j += 2) mk.push(parseInt(mkHex.substr(j, 2), 16));
    var ekey = gmMd5Raw(mk);
    return ekey.map(function (b, k) { return b ^ randomBytes16[k]; });
}

// 生成 8 字节随机数的大写 Hex 串（16 字符，对齐源码 makeRandomStr 的输出形态）
function gmCompatRandom() {
    var bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    return gmBytesToHex(Array.from(bytes)).toUpperCase();
}

// SM4EnData 复刻：明文字节数组 → "大写Hex密文 + 16字符random" 字符串
function gmCompatEncryptBytes(plainBytes) {
    var random = gmCompatRandom();
    // random 以 ASCII 字符形态参与密钥派生（对齐源码 makeEnDataKey(yKey, 35, (UCHAR*)random, mkey)）
    var randomBytes = [];
    for (var i = 0; i < random.length; i++) randomBytes.push(random.charCodeAt(i));
    var key = gmMakeEnDataKey(GM_COMPAT_YKEY, randomBytes);
    var cipherHex = smCrypto.sm4.encrypt(plainBytes, key, { padding: 'pkcs#5' });
    return cipherHex.toUpperCase() + random;
}

// SM4DeData 复刻：兼容密文串（Hex密文 + 末尾16字符random）→ 明文字节数组
// random 大小写自适应：DLL 源码 iConvertBytesToHexStr 用 MyHEXSTR="0123456789ABCDEF"
// 固定输出大写，但实际数据可能被外部工具转成小写（如实测样例 2.txt）。
// random 以 ASCII 形态参与密钥派生，大小写不同密钥完全不同——
// 先按原样派生解密，PKCS7 校验失败再依次尝试大写/小写变体。
function gmCompatDecryptString(enDataStr) {
    var str = enDataStr.trim().replace(/\s/g, '');
    if (str.length < 34 || str.length % 2 !== 0) {
        throw new Error('兼容密文应为"偶数位 Hex（≥18字节密文 + 16字符随机数）"，当前长度 ' + str.length);
    }
    var randomStr = str.slice(-16);
    var cipherHex = str.slice(0, str.length - 16).toLowerCase();
    if (!/^[0-9a-f]+$/.test(cipherHex) || cipherHex.length % 32 !== 0) {
        throw new Error('密文部分不是合法的 Hex，或长度不是 16 字节的整数倍');
    }
    var variants = [randomStr];
    if (randomStr !== randomStr.toUpperCase()) variants.push(randomStr.toUpperCase());
    if (randomStr !== randomStr.toLowerCase()) variants.push(randomStr.toLowerCase());
    var lastErr = null;
    for (var v = 0; v < variants.length; v++) {
        var random = [];
        for (var i = 0; i < 16; i++) random.push(variants[v].charCodeAt(i));
        var key = gmMakeEnDataKey(GM_COMPAT_YKEY, random);
        try {
            // 二进制解密取字节数组（库的字符串输出按 UTF-8 解释，不适用于任意数据）
            var plainBytes = smCrypto.sm4.decrypt(cipherHex, key, { padding: 'pkcs#5', output: 'array' });
            // 解密错误时库可能静默返回空数组（去填充失败），视为未命中继续尝试
            if (plainBytes && plainBytes.length > 0) {
                return { bytes: plainBytes, key: key, random: variants[v] };
            }
        } catch (e) {
            lastErr = e;
        }
    }
    throw new Error('解密失败：PKCS7 去填充校验未通过（' +
        (lastErr && lastErr.message ? lastErr.message : '密文与随机数不匹配或数据被篡改') + '）');
}

// 页面入口：按方向单选执行加密/解密
// Hex 转储多行格式：偏移(4位hex) + 前8字节 + 后8字节 + 右侧 ASCII 预览，
// 便于人工按行对照/分段复制（与常见 hexdump 工具观感一致）
function gmHexDumpLines(bytes) {
    var lines = [];
    for (var off = 0; off < bytes.length; off += 16) {
        var hexCells = [];
        var ascii = '';
        for (var i = 0; i < 16; i++) {
            if (off + i < bytes.length) {
                var b = bytes[off + i];
                hexCells.push((b < 16 ? '0' : '') + b.toString(16).toUpperCase());
                ascii += (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '.';
            } else {
                hexCells.push('  ');
                ascii += ' ';
            }
        }
        var offsetLabel = ('0000' + off.toString(16).toUpperCase()).slice(-4);
        lines.push(offsetLabel + '  ' + hexCells.slice(0, 8).join(' ') + '  ' + hexCells.slice(8).join(' ') + '  ' + ascii);
    }
    return lines.join('\n');
}

function gmCompatRun() {
    var resultEl = document.getElementById('gm-compat-result');
    var input = document.getElementById('gm-compat-input').value;
    var mode = gmGetRadio('gm-compat-mode') || 'enc';
    try {
        if (mode === 'enc') {
            if (!input) throw new Error('请输入明文');
            // 文本按 UTF-8 编为字节（对齐 C 端接收原始字节、由调用方编码的口径）
            var out = gmCompatEncryptBytes(gmUtf8ToBytes(input));
            resultEl.textContent = out;
            showNotification('已加密（EnDataUtil 兼容格式，可被 SM4DeData 解密）');
        } else {
            if (!input.trim()) throw new Error('请输入兼容密文');
            var r = gmCompatDecryptString(input);
            // 明文尽力按 UTF-8 展示；同时给 Hex 便于处理二进制内容
            var utf8Text;
            try {
                utf8Text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(r.bytes));
            } catch (e) {
                utf8Text = '(非 UTF-8 数据)';
            }
            var replaced = (utf8Text.match(/\uFFFD/g) || []).length;
            resultEl.textContent = '明文（' + r.bytes.length + ' 字节）：\n' +
                (replaced === 0 ? utf8Text : utf8Text + '\n[含 ' + replaced + ' 个无法按 UTF-8 解码的字节，二进制数据请看下方 Hex]\n') +
                'Hex（每行 16 字节，带偏移）：\n' + gmHexDumpLines(r.bytes) +
                '\nHex（单行复制用）：' + gmBytesToHex(r.bytes).toUpperCase() +
                '\n——\n派生密钥：' + gmBytesToHex(r.key).toUpperCase() + '（由固定 yKey + 随机数 ' + r.random + ' 派生）';
            showNotification('已解密（EnDataUtil 兼容格式）');
        }
    } catch (e) {
        gmShowError('gm-compat-result', e);
    }
}

function gmCompatClear() {
    document.getElementById('gm-compat-input').value = '';
    document.getElementById('gm-compat-result').textContent = '';
}

// Node 环境导出兼容层纯函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        gmMakeEnDataKey: gmMakeEnDataKey,
        gmCompatEncryptBytes: gmCompatEncryptBytes,
        gmCompatDecryptString: gmCompatDecryptString
    };
}
