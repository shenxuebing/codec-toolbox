// ============================================================
// 增强版编解码工具 - AES 加解密页（page-aes）
// 功能：AES-128/192/256 加解密（ECB/CBC × PKCS7/无填充）+
//       PBKDF2-SHA256 口令派生密钥
// 依赖（须先于本文件加载）：
//   js/vendor/crypto-js.js → 全局 CryptoJS（index.html 已在更早位置加载）
//   js/app.js              → showNotification（通知）
//
// ===== CryptoJS 关键坑点（务必照此使用，血泪教训）=====
// 1. CryptoJS.AES.encrypt(message, key, cfg) 的 key 参数若传【字符串】，
//    会走 OpenSSL 的口令派生路径（EVP_BytesToKey：随机 8 字节 salt + MD5
//    迭代推密钥，输出带 "Salted__" 前缀的 Base64）——即把字符串当"口令"
//    而不是"裸密钥"。本工具必须传 CryptoJS.lib.WordArray（Hex/UTF-8 解析
//    所得），语义明确为裸密钥，才能与 Node crypto 等标准实现对拍一致。
// 2. 解密同理：密文必须以 { ciphertext: wa } 对象传入（_parse 对非字符串
//    原样放行）；传 Base64 字符串会被按 OpenSSL 格式解析（找 salt 头），
//    与本页"裸密文"口径不符。
// 3. WordArray.create 必须传 Uint8Array——传普通 Array 会按 32 位字解释
//    （与 gmsm.js gmMd5Raw 同款坑）。
// 4. CryptoJS 的 PKCS7 去填充不校验填充字节合法性：密钥/IV 不匹配时按
//    "最后一个字节的值"盲目裁剪，常见结果是空/负长度 → 解出空串，
//    本页以"空结果"作为解密失败的判定信号。
// ============================================================

// ---------------- 本页自带的字节/编码小工具 ----------------
// （与 gmsm.js 的 gm* 系列实现一致；独立命名便于 Node 环境只注入 CryptoJS 即可对拍）

// 取单选组当前选中值（无选中时返回 fallback）
function aesGetRadio(name, fallback) {
    var checked = document.querySelector('input[name="' + name + '"]:checked');
    return checked ? checked.value : fallback;
}

// Hex 字符串 → 字节数组；非法则抛中文错误
function aesHexToBytes(hex) {
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
        throw new Error('不是合法的 Hex 字符串（长度须为偶数且仅含 0-9 a-f）');
    }
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// 字节数组 → Hex 字符串（小写）
function aesBytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
}

// 文本 → UTF-8 字节数组
function aesUtf8ToBytes(text) {
    return Array.prototype.slice.call(new TextEncoder().encode(text));
}

// Base64 → 字节数组（容忍空白与 base64url 变体）；非法则抛中文错误
function aesBase64ToBytes(b64) {
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

// 字节数组 → Base64
function aesBytesToBase64(bytes) {
    var str = '';
    for (var i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str);
}

// 字节数组 → WordArray（必须经 Uint8Array，见文件头坑点 3）
function aesBytesToWa(bytes) {
    return CryptoJS.lib.WordArray.create(new Uint8Array(bytes));
}

// WordArray → 字节数组（按 sigBytes 截取）
function aesWaToBytes(wa) {
    var bytes = [];
    for (var i = 0; i < wa.sigBytes; i++) {
        bytes.push((wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    }
    return bytes;
}

// ---------------- 纯核心函数（不碰 DOM，页面与 Node 对拍共用） ----------------

// 模式字符串 → CryptoJS.mode 对象
function aesModeObj(modeStr) {
    return modeStr === 'cbc' ? CryptoJS.mode.CBC : CryptoJS.mode.ECB;
}

// 填充字符串 → CryptoJS.pad 对象
function aesPaddingObj(padStr) {
    return padStr === 'NoPadding' ? CryptoJS.pad.NoPadding : CryptoJS.pad.Pkcs7;
}

// 纯核心：AES 加密（明文字节 + 裸密钥字节 → 密文 hex 小写）
// opts: { mode: 'ecb'|'cbc', padding: 'Pkcs7'|'NoPadding', iv: 16字节数组（CBC 必填） }
function aesEncryptCore(plainBytes, keyBytes, opts) {
    if ([16, 24, 32].indexOf(keyBytes.length) < 0) {
        throw new Error('AES 密钥长度须为 16/24/32 字节（当前 ' + keyBytes.length + ' 字节）');
    }
    var cfg = { mode: aesModeObj(opts.mode), padding: aesPaddingObj(opts.padding) };
    if (opts.mode === 'cbc') {
        if (!opts.iv || opts.iv.length !== 16) {
            throw new Error('CBC 模式必须提供 16 字节 IV');
        }
        cfg.iv = aesBytesToWa(opts.iv);
    }
    if (opts.padding === 'NoPadding' && plainBytes.length % 16 !== 0) {
        throw new Error('无填充时明文长度必须是 16 字节的整数倍（当前 ' + plainBytes.length + ' 字节，差 ' + (16 - plainBytes.length % 16) + ' 字节）');
    }
    // 坑点 1：key 一律传 WordArray（裸密钥），绝不传字符串（会走 EVP_BytesToKey 口令派生）
    return CryptoJS.AES.encrypt(aesBytesToWa(plainBytes), aesBytesToWa(keyBytes), cfg)
        .ciphertext.toString(CryptoJS.enc.Hex);
}

// 纯核心：AES 解密（密文字节 + 裸密钥字节 → 明字节数组；失败返回空数组由调用方判定）
function aesDecryptCore(cipherBytes, keyBytes, opts) {
    if ([16, 24, 32].indexOf(keyBytes.length) < 0) {
        throw new Error('AES 密钥长度须为 16/24/32 字节（当前 ' + keyBytes.length + ' 字节）');
    }
    var cfg = { mode: aesModeObj(opts.mode), padding: aesPaddingObj(opts.padding) };
    if (opts.mode === 'cbc') {
        if (!opts.iv || opts.iv.length !== 16) {
            throw new Error('CBC 模式必须提供 16 字节 IV');
        }
        cfg.iv = aesBytesToWa(opts.iv);
    }
    if (cipherBytes.length === 0 || cipherBytes.length % 16 !== 0) {
        throw new Error('密文长度必须是 16 字节的整数倍（当前 ' + cipherBytes.length + ' 字节）');
    }
    // 坑点 2：密文以 { ciphertext: wa } 传入，避开 OpenSSL 字符串格式解析
    var plainWA = CryptoJS.AES.decrypt({ ciphertext: aesBytesToWa(cipherBytes) }, aesBytesToWa(keyBytes), cfg);
    return aesWaToBytes(plainWA);
}

// 纯核心：PBKDF2-SHA256 口令派生（口令/盐均按 UTF-8 编码）→ Promise<hex 小写>
async function aesPbkdf2Core(pass, salt, iterations, keyBytes) {
    var enc = new TextEncoder();
    var baseKey = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: enc.encode(salt), iterations: iterations, hash: 'SHA-256' },
        baseKey, keyBytes * 8
    );
    return aesBytesToHex(new Uint8Array(bits));
}

// ---------------- 页面交互函数 ----------------

// 所选密钥长度 → 字节数（128→16 / 192→24 / 256→32）
function aesKeyLenBytes() {
    return parseInt(aesGetRadio('aes-keylen', '128'), 10) / 8;
}

// 模式切换：仅 CBC 时显示 IV 输入行
function aesModeChanged() {
    var isCbc = aesGetRadio('aes-mode', 'ecb') === 'cbc';
    document.getElementById('aes-iv-row').style.display = isCbc ? '' : 'none';
}

// 清洗 Hex 输入：去空白与分隔符，统一小写（与 gmCleanHex 同口径）
function aesCleanHexLocal(str) {
    return str.replace(/[\s:,]/g, '').toLowerCase();
}

// 密钥/IV 输入 → 字节数组（按"密钥格式"单选解析；长度不符抛中文错误）
function aesParseKeyBytes(value, format, expectedBytes, what) {
    var bytes = (format === 'text')
        ? aesUtf8ToBytes(value)                       // 文本按 UTF-8 编码后须恰好等于目标字节数
        : aesHexToBytes(aesCleanHexLocal(value));     // Hex 按 2 字符一字节
    if (bytes.length !== expectedBytes) {
        throw new Error(what + '长度须为 ' + expectedBytes + ' 字节（当前 ' + bytes.length +
            ' 字节），与所选密钥长度 / IV 要求不符');
    }
    return bytes;
}

// 输入内容 → 字节数组（按"输入格式"单选解析）
function aesParseInputBytes(str, format) {
    if (format === 'hex') {
        return aesHexToBytes(aesCleanHexLocal(str));
    }
    if (format === 'base64') {
        return aesBase64ToBytes(str);
    }
    return aesUtf8ToBytes(str); // 文本按 UTF-8
}

// 汇总加密/解密选项：{ mode, padding, iv? }（CBC 时解析并校验 IV 恰为 16 字节）
function aesCollectOpts(keyFormat) {
    var opts = {
        mode: aesGetRadio('aes-mode', 'ecb'),
        padding: aesGetRadio('aes-padding', 'Pkcs7')
    };
    if (opts.mode === 'cbc') {
        opts.iv = aesParseKeyBytes(document.getElementById('aes-iv').value, keyFormat, 16, 'CBC 模式的 IV ');
    }
    return opts;
}

// "加密"按钮
function aesEncrypt() {
    try {
        var input = document.getElementById('aes-input').value;
        if (!input) {
            throw new Error('请输入明文内容');
        }
        var keyFormat = aesGetRadio('aes-key-format', 'hex');
        var keyBytes = aesParseKeyBytes(
            document.getElementById('aes-key').value, keyFormat, aesKeyLenBytes(), 'AES 密钥');
        var opts = aesCollectOpts(keyFormat);
        var plainBytes = aesParseInputBytes(input, aesGetRadio('aes-input-format', 'text'));

        var cipherHex = aesEncryptCore(plainBytes, keyBytes, opts);

        // 按输出格式展示（Base64 / 大写 Hex）
        var outFormat = aesGetRadio('aes-output-format', 'base64');
        document.getElementById('aes-result').textContent = (outFormat === 'hex')
            ? cipherHex.toUpperCase()
            : aesBytesToBase64(aesHexToBytes(cipherHex));
        showNotification('AES-' + (keyBytes.length * 8) + '-' + opts.mode.toUpperCase() + '/' +
            (opts.padding === 'NoPadding' ? '无填充' : 'PKCS7') + ' 加密完成（密文 ' + cipherHex.length / 2 + ' 字节）');
    } catch (e) {
        gmShowError('aes-result', e);
    }
}

// "解密"按钮（输入格式 = 密文格式；输出 Base64 选项 = 按 UTF-8 文本展示明文）
function aesDecrypt() {
    try {
        var input = document.getElementById('aes-input').value;
        if (!input) {
            throw new Error('请输入密文内容');
        }
        var inFormat = aesGetRadio('aes-input-format', 'text');
        if (inFormat === 'text') {
            throw new Error('解密时"输入格式"须选择密文格式（Base64 或 Hex，与加密输出对应）');
        }
        var keyFormat = aesGetRadio('aes-key-format', 'hex');
        var keyBytes = aesParseKeyBytes(
            document.getElementById('aes-key').value, keyFormat, aesKeyLenBytes(), 'AES 密钥');
        var opts = aesCollectOpts(keyFormat);
        var cipherBytes = aesParseInputBytes(input, inFormat);

        var plainBytes = aesDecryptCore(cipherBytes, keyBytes, opts);

        // 坑点 4：PKCS7 去填充不做完整校验，密钥/IV/填充不匹配时常见结果为空串
        if (plainBytes.length === 0) {
            throw new Error('解密失败：密钥/IV/填充不匹配或密文损坏');
        }

        var outFormat = aesGetRadio('aes-output-format', 'base64');
        var resultEl = document.getElementById('aes-result');
        if (outFormat === 'hex') {
            resultEl.textContent = aesBytesToHex(plainBytes).toUpperCase();
        } else {
            // 按 UTF-8 文本展示；出现 U+FFFD 替换符说明解出的多半不是文本数据
            var text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(plainBytes));
            var replaced = (text.match(/�/g) || []).length;
            resultEl.textContent = (replaced > 0)
                ? text + '\n[提示：含 ' + replaced + ' 个无法按 UTF-8 解码的字节，可能为非文本数据，请改用 Hex 输出查看]'
                : text;
        }
        showNotification('AES-' + (keyBytes.length * 8) + '-' + opts.mode.toUpperCase() + '/' +
            (opts.padding === 'NoPadding' ? '无填充' : 'PKCS7') + ' 解密完成（明文 ' + plainBytes.length + ' 字节）');
    } catch (e) {
        gmShowError('aes-result', e);
    }
}

// "派生密钥"按钮：PBKDF2-SHA256 结果（Hex）直接填入密钥框
async function aesPbkdf2() {
    var pass = document.getElementById('aes-pbkdf2-pass').value;
    var salt = document.getElementById('aes-pbkdf2-salt').value;
    if (!pass) {
        showNotification('请输入口令');
        return;
    }
    if (!salt) {
        showNotification('请输入盐（Salt）');
        return;
    }
    var iter = parseInt(document.getElementById('aes-pbkdf2-iter').value, 10);
    if (!iter || iter < 1) {
        showNotification('迭代次数必须是正整数');
        return;
    }
    var keyBytes = aesKeyLenBytes(); // 派生长度沿用"密钥长度"单选
    try {
        var hex = await aesPbkdf2Core(pass, salt, iter, keyBytes);
        document.getElementById('aes-key').value = hex;
        // 派生结果是 Hex 形态，密钥格式同步切回 Hex，避免残留"文本"格式造成误解析
        var hexRadio = document.querySelector('input[name="aes-key-format"][value="hex"]');
        if (hexRadio) {
            hexRadio.checked = true;
        }
        showNotification('PBKDF2-SHA256 派生完成：' + keyBytes + ' 字节密钥已填入密钥框（密钥格式已切回 Hex）');
    } catch (e) {
        showNotification('PBKDF2 派生失败：' + (e && e.message ? e.message : e));
    }
}

// "生成随机密钥"按钮：按所选密钥长度生成随机字节 → hex（小写）
function aesGenKey() {
    var len = aesKeyLenBytes();
    var bytes = new Uint8Array(len);
    crypto.getRandomValues(bytes);
    document.getElementById('aes-key').value = aesBytesToHex(bytes);
    showNotification('已生成随机 AES-' + (len * 8) + ' 密钥（' + len + ' 字节 / ' + (len * 2) + ' 位 Hex）');
}

// "生成 IV"按钮：16 字节随机 IV → hex（小写）
function aesGenIv() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    document.getElementById('aes-iv').value = aesBytesToHex(bytes);
    showNotification('已生成随机 IV（16 字节 / 32 位 Hex）');
}

// "清空"按钮：清空输入与结果（密钥/IV 保留，便于连续测试）
function aesClear() {
    document.getElementById('aes-input').value = '';
    document.getElementById('aes-result').textContent = '';
}

// 页面初始化：密钥/IV 框回车触发加密，PBKDF2 口令框回车触发派生
function aesInit() {
    var bind = function (id, fn) {
        var el = document.getElementById(id);
        if (el && typeof el.addEventListener === 'function') {
            el.addEventListener('keydown', function (event) {
                if (event.key === 'Enter') {
                    fn();
                }
            });
        }
    };
    bind('aes-key', aesEncrypt);
    bind('aes-iv', aesEncrypt);
    bind('aes-pbkdf2-pass', aesPbkdf2);
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// typeof document 判断用于兜底：Node 环境 require 时跳过 DOM 绑定
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', aesInit);
    } else {
        aesInit();
    }
}

// Node 环境导出纯核心（浏览器中 module 未定义，此块自动跳过，便于对拍自测；
// Node 18+ 自带全局 crypto.subtle / TextEncoder / btoa，仅需先注入全局 CryptoJS）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        aesEncryptCore: aesEncryptCore,
        aesDecryptCore: aesDecryptCore,
        aesPbkdf2Core: aesPbkdf2Core,
        aesHexToBytes: aesHexToBytes,
        aesBytesToHex: aesBytesToHex
    };
}
