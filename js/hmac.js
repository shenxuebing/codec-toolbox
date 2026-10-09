// ============================================================
// 增强版编解码工具 - HMAC 计算页（page-hmac）
// 功能：消息 + 密钥 → 一次算出 HMAC-SHA1 / SHA-256 / SHA-384 / SHA-512
// 依赖（须先于本文件加载）：
//   js/app.js  → showNotification / bytesToBinaryString
//   js/gmsm.js → gmCopyInput（结果行复制按钮）
// 实现口径：
//   全部走浏览器 Web Crypto 标准路径（crypto.subtle.importKey + sign），
//   消息按 UTF-8 编码；密钥按所选格式解码（文本 UTF-8 / Hex / Base64）；
//   输出可选 Hex（大写）或 Base64
// ============================================================

// 四种哈希算法与其结果输入框 id 的对应关系（渲染顺序即计算顺序）
var HMAC_ALGOS = [
    { hash: 'SHA-1', outId: 'hmac-out-sha1' },
    { hash: 'SHA-256', outId: 'hmac-out-sha256' },
    { hash: 'SHA-384', outId: 'hmac-out-sha384' },
    { hash: 'SHA-512', outId: 'hmac-out-sha512' }
];

// 密钥字符串 → 字节数组（按页面单选的格式解码）
//   text   按 UTF-8 编码（TextEncoder）
//   hex    去空白、去 0x/0X 前缀后须为偶数个十六进制字符（如 0xdeadbeef）
//   base64 标准 Base64（atob 解码，容忍空白字符）
// 格式非法时抛出带中文提示的错误
function hmacDecodeKey(keyText, format) {
    if (format === 'hex') {
        var hex = keyText.replace(/\s+/g, '');
        if (/^0[xX]/.test(hex)) { hex = hex.slice(2); } // 容忍 0x / 0X 前缀
        if (hex === '') { throw new Error('Hex 密钥为空'); }
        if (!/^[0-9a-fA-F]+$/.test(hex)) { throw new Error('Hex 密钥含非十六进制字符'); }
        if (hex.length % 2 !== 0) { throw new Error('Hex 密钥长度须为偶数位'); }
        var bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }
    if (format === 'base64') {
        var cleaned = keyText.replace(/\s+/g, ''); // 容忍换行 / 空格（如 PEM 风格折行）
        if (cleaned === '') { throw new Error('Base64 密钥为空'); }
        var binary;
        try {
            binary = atob(cleaned);
        } catch (e) {
            throw new Error('Base64 密钥格式非法');
        }
        var arr = new Uint8Array(binary.length);
        for (var j = 0; j < binary.length; j++) {
            arr[j] = binary.charCodeAt(j);
        }
        return arr;
    }
    // 默认文本：按 UTF-8 编码（与消息编码方式一致）
    return new TextEncoder().encode(keyText);
}

// 字节数组 → 大写 Hex 字符串（每字节两位，前导零补齐）
function hmacBytesToHex(bytes) {
    var out = [];
    for (var i = 0; i < bytes.length; i++) {
        out.push(bytes[i].toString(16).toUpperCase().padStart(2, '0'));
    }
    return out.join('');
}

// 字节数组 → Base64 字符串（bytesToBinaryString + btoa 标准做法，
// bytesToBinaryString 来自 js/app.js，内部分块拼接可避免大数组的栈溢出）
function hmacBytesToBase64(bytes) {
    return btoa(bytesToBinaryString(bytes));
}

// 读取页面单选的当前值（找不到选中项时回退默认值）
function hmacGetRadio(name, fallback) {
    var el = document.querySelector('input[name="' + name + '"]:checked');
    return el ? el.value : fallback;
}

// "计算"按钮：对四种哈希逐一 importKey('raw', key, HMAC) + sign，
// 任何一步都走 Web Crypto 标准接口；四个结果框一次性填值
async function hmacRun() {
    var message = document.getElementById('hmac-message').value;
    var keyText = document.getElementById('hmac-key').value;
    if (!message) {
        showNotification('请先输入消息');
        return;
    }
    if (!keyText) {
        showNotification('请先输入密钥');
        return;
    }
    var keyFormat = hmacGetRadio('hmac-key-format', 'text');
    var outputFormat = hmacGetRadio('hmac-output', 'hex');

    var keyBytes;
    try {
        keyBytes = hmacDecodeKey(keyText, keyFormat);
    } catch (e) {
        showNotification(e.message);
        return;
    }
    if (keyBytes.length === 0) {
        showNotification('密钥解码后为空');
        return;
    }

    var msgBytes = new TextEncoder().encode(message); // 消息统一按 UTF-8 编码
    try {
        for (var i = 0; i < HMAC_ALGOS.length; i++) {
            var algo = HMAC_ALGOS[i];
            var cryptoKey = await crypto.subtle.importKey(
                'raw', keyBytes, { name: 'HMAC', hash: { name: algo.hash } }, false, ['sign']
            );
            var signature = await crypto.subtle.sign({ name: 'HMAC' }, cryptoKey, msgBytes);
            var sigBytes = new Uint8Array(signature);
            document.getElementById(algo.outId).value =
                outputFormat === 'base64' ? hmacBytesToBase64(sigBytes) : hmacBytesToHex(sigBytes);
        }
        showNotification('HMAC 计算完成');
    } catch (e) {
        showNotification('计算失败：' + (e && e.message ? e.message : e));
    }
}

// "清空"按钮：清空消息、密钥与四行结果，焦点回到消息框
function hmacClear() {
    var message = document.getElementById('hmac-message');
    if (message) { message.value = ''; message.focus(); }
    var key = document.getElementById('hmac-key');
    if (key) { key.value = ''; }
    for (var i = 0; i < HMAC_ALGOS.length; i++) {
        var out = document.getElementById(HMAC_ALGOS[i].outId);
        if (out) { out.value = ''; }
    }
}

// 页面初始化：密钥输入框回车直接触发计算
function hmacInit() {
    var keyInput = document.getElementById('hmac-key');
    if (keyInput && typeof keyInput.addEventListener === 'function') {
        keyInput.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                hmacRun();
            }
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// typeof document 判断用于兜底：Node 环境 require 时跳过 DOM 绑定
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', hmacInit);
    } else {
        hmacInit();
    }
}

// Node 环境导出（浏览器中 module 未定义，此块自动跳过，便于对拍自测；
// Node 18+ 自带全局 crypto.subtle 与 TextEncoder，hmacRun 可直接调用）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        HMAC_ALGOS: HMAC_ALGOS,
        hmacDecodeKey: hmacDecodeKey,
        hmacBytesToHex: hmacBytesToHex,
        hmacBytesToBase64: hmacBytesToBase64,
        hmacRun: hmacRun,
        hmacClear: hmacClear
    };
}
