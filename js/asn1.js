// ============================================================
// ASN.1 查看器（DER 解析）—— page-asn1
// 体验参考 asn1editor / Lapo ASN.1 JavaScript decoder：
//   PEM / Base64 / Hex 输入 → TLV 树形展示（tag/偏移/长度/内容预览）
// 本文件自包含（不依赖其他 js 文件），纯解析函数（asn1ExtractDer /
// asn1ExtractDerBytes / asn1ParseTlv / asn1DecodeOid / asn1TagName /
// asn1FormatTime / asn1Preview）不触碰 DOM，可在 Node 中单独加载打桩测试
// ============================================================

// ---------- 基础工具 ----------

// 字节数组 → 小写 Hex 字符串（无分隔）
function asn1BytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
}

// Hex 预览：前 maxBytes 字节转大写空格分组 Hex，超长追加 …（完整内容可点击节点复制）
function asn1HexPreview(bytes, maxBytes) {
    var n = Math.min(bytes.length, maxBytes);
    var parts = [];
    for (var i = 0; i < n; i++) {
        parts.push((bytes[i] < 16 ? '0' : '') + bytes[i].toString(16).toUpperCase());
    }
    var s = parts.join(' ');
    if (bytes.length > maxBytes) s += ' …';
    return s;
}

// HTML 转义工具已移除：树形渲染改为全 DOM API + textContent，天然防内容注入

// 字节数组 → Latin-1 字符串（每字节一字符，供时间 / Base64 判头等 ASCII 场景）
function asn1BytesToLatin1(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += String.fromCharCode(bytes[i]);
    }
    return out;
}

// UTF-8 手工解码（不依赖 TextDecoder，非法 / 截断序列返回 null 由调用方回退 Hex）
function asn1DecodeUtf8(bytes) {
    var out = '';
    var i = 0;
    while (i < bytes.length) {
        var b = bytes[i];
        var cp;
        if (b < 0x80) {
            cp = b; i += 1;
        } else if (b >= 0xC2 && b <= 0xDF && i + 1 < bytes.length) {
            cp = ((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F); i += 2;
        } else if (b >= 0xE0 && b <= 0xEF && i + 2 < bytes.length) {
            cp = ((b & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F); i += 3;
        } else if (b >= 0xF0 && b <= 0xF4 && i + 3 < bytes.length) {
            // 四字节码点超出 UTF-16 单字符范围，需拆代理对
            cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12) | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
            cp -= 0x10000;
            out += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
            i += 4;
            continue;
        } else {
            return null; // 非法或截断的 UTF-8 序列
        }
        out += String.fromCharCode(cp);
    }
    return out;
}

// UTF-16BE 解码（BMPString 用，落单的尾字节忽略）
function asn1DecodeUtf16be(bytes) {
    var out = '';
    for (var i = 0; i + 1 < bytes.length; i += 2) {
        out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return out;
}

// 字符串超长截断（预览统一 80 字符 + …）
function asn1Truncate(s) {
    s = String(s);
    return s.length > 80 ? s.slice(0, 80) + '…' : s;
}

// ---------- 输入识别：PEM / Hex / Base64 → DER 字节数组 ----------

// Base64 → 字节数组：去空白、兼容 base64url 变体（-_ → +/）、按长度补齐填充；
// 非法则抛中文错误
function asn1Base64ToBytes(b64) {
    var cleaned = String(b64).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    cleaned = cleaned.replace(/=+$/, ''); // 去掉原填充，按剩余长度统一补
    if (cleaned === '') {
        throw new Error('Base64 数据为空');
    }
    if (!/^[A-Za-z0-9+/]+$/.test(cleaned)) {
        throw new Error('不是合法的 Base64 字符串（含非法字符）');
    }
    var pad = cleaned.length % 4;
    if (pad === 1) {
        throw new Error('不是合法的 Base64 字符串（长度不合法）');
    }
    if (pad === 2) { cleaned += '=='; } else if (pad === 3) { cleaned += '='; }
    var bin;
    try {
        bin = atob(cleaned);
    } catch (e) {
        throw new Error('不是合法的 Base64 字符串');
    }
    var out = new Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
        out[i] = bin.charCodeAt(i);
    }
    return out;
}

// 按优先级识别输入：1) PEM 块（多个取第一个并提示） 2) 偶数长度纯 Hex 3) Base64
// 返回 { bytes, format, note }；识别失败抛中文错误
function asn1ExtractDer(rawStr) {
    var text = String(rawStr == null ? '' : rawStr);

    // 1. PEM：-----BEGIN LABEL----- ... -----END LABEL-----，取第一个块的 Base64 体
    var pemRe = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END [A-Z0-9 ]+-----/g;
    var matches = [];
    var m;
    while ((m = pemRe.exec(text)) !== null) {
        matches.push(m);
    }
    if (matches.length > 0) {
        var first = matches[0];
        var pemBytes = asn1Base64ToBytes(first[2]);
        if (pemBytes.length === 0) {
            throw new Error('PEM 块（' + first[1] + '）内没有可解码的数据');
        }
        return {
            bytes: pemBytes,
            format: 'PEM（' + first[1] + '）',
            note: matches.length > 1 ? '检测到 ' + matches.length + ' 个 PEM 块，已解析第一个（' + first[1] + '）' : ''
        };
    }

    // 2. 无 PEM 头：去空白后整体为偶数长度 Hex 串 → 按 Hex
    var cleaned = text.replace(/\s+/g, '');
    if (cleaned === '') {
        throw new Error('输入内容为空');
    }
    if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0) {
        var hb = new Array(cleaned.length / 2);
        for (var i = 0; i < cleaned.length; i += 2) {
            hb[i / 2] = parseInt(cleaned.substr(i, 2), 16);
        }
        return { bytes: hb, format: 'Hex', note: '' };
    }

    // 3. 否则按 Base64 处理
    var bb = asn1Base64ToBytes(cleaned);
    return { bytes: bb, format: 'Base64', note: '' };
}

// 字节输入识别（文件上传路径）：直接接受 Uint8Array / 字节数组，返回与
// asn1ExtractDer 同构的 { bytes, format, note }；fileName 仅用于按扩展名给
// PKCS 容器提示（可省略）。识别失败抛中文错误
function asn1ExtractDerBytes(bytes, fileName) {
    if (!bytes || bytes.length === 0) {
        throw new Error('输入内容为空');
    }
    // JKS/JCEKS 魔数（FE ED FE ED）：Java 私有密钥库格式，不是 ASN.1 结构，明确拒绝
    if (bytes.length >= 4 && bytes[0] === 0xFE && bytes[1] === 0xED &&
        bytes[2] === 0xFE && bytes[3] === 0xED) {
        throw new Error('这是 JKS/JCEKS 密钥库（Java 私有格式），不是 ASN.1 结构，无法解析');
    }
    // 前 64 字节查 PEM 头（PEM 为纯 ASCII，按 Latin-1 逐字节比对即可），
    // 命中则整体转 Latin-1 字符串走 asn1ExtractDer（PEM / Base64 识别逻辑复用）
    var head = '';
    for (var i = 0; i < Math.min(bytes.length, 64); i++) {
        head += String.fromCharCode(bytes[i]);
    }
    if (head.indexOf('-----BEGIN') >= 0) {
        // 分块转字符串，避免大文件 fromCharCode 参数超限
        var text = '';
        for (var j = 0; j < bytes.length; j += 4096) {
            text += String.fromCharCode.apply(null,
                bytes.subarray ? bytes.subarray(j, Math.min(j + 4096, bytes.length))
                    : bytes.slice(j, Math.min(j + 4096, bytes.length)));
        }
        return asn1ExtractDer(text);
    }
    // 裸二进制直接按 DER 解析；按扩展名附容器类型提示
    // （PKCS#7 ContentInfo 外层是 SEQUENCE{OID, [0]}，现有 TLV 解析天然能展示，无需特判）
    var extMatch = String(fileName == null ? '' : fileName).toLowerCase().match(/\.([a-z0-9]+)$/);
    var ext = extMatch ? extMatch[1] : '';
    var note = '';
    if (ext === 'pfx' || ext === 'p12') {
        note = 'PKCS#12 容器（内层多为加密数据，带口令部分无法展开，仅可查看外层结构）';
    } else if (ext === 'p7b' || ext === 'p7c' || ext === 'spc') {
        note = 'PKCS#7 证书链容器';
    }
    return { bytes: bytes, format: '二进制 DER', note: note };
}

// ---------- ASN.1 Tag 名称映射 ----------

var ASN1_TAG_NAMES = {
    0x01: 'BOOLEAN',           0x02: 'INTEGER',        0x03: 'BIT STRING',
    0x04: 'OCTET STRING',      0x05: 'NULL',           0x06: 'OID',
    0x0A: 'ENUMERATED',        0x0C: 'UTF8String',     0x13: 'PrintableString',
    0x14: 'T61String',         0x16: 'IA5String',      0x17: 'UTCTime',
    0x18: 'GeneralizedTime',   0x1B: 'GeneralString',  0x1E: 'BMPString',
    0x30: 'SEQUENCE',          0x31: 'SET'
};

// tag 首字节 → 显示名：通用类查表；上下文类（0x80-0xBF）显示 [上下文 n]
// （构造 / 原始按 bit5 区分）；多字节 tag（低 5 位全 1）与其余显示 TAG_0xNN
function asn1TagName(tagByte, constructed) {
    if (tagBytesIsMulti(tagByte)) {
        return 'TAG_0x' + (tagByte < 16 ? '0' : '') + tagByte.toString(16).toUpperCase() + '…';
    }
    if (ASN1_TAG_NAMES.hasOwnProperty(tagByte)) {
        return ASN1_TAG_NAMES[tagByte];
    }
    if ((tagByte & 0xC0) === 0x80) {
        return '[上下文 ' + (tagByte & 0x1F) + (constructed ? '' : ' 原始') + ']';
    }
    return 'TAG_0x' + (tagByte < 16 ? '0' : '') + tagByte.toString(16).toUpperCase();
}

// tag 首字节是否为多字节 tag 起始（低 5 位全 1，正常证书用不到，仅防异常数据）
function tagBytesIsMulti(tagByte) {
    return (tagByte & 0x1F) === 0x1F;
}

// ---------- OID 解码与名称映射 ----------

// base-128 变体解码：首字节按 40*X+Y 拆出前两节点，后续字节续位累积；
// 截断 / 溢出返回 null（调用方回退 Hex 显示）
function asn1DecodeOid(contentBytes) {
    if (!contentBytes || contentBytes.length === 0) {
        return null;
    }
    var first = contentBytes[0];
    var parts;
    if (first < 40) {
        parts = [0, first];
    } else if (first < 80) {
        parts = [1, first - 40];
    } else {
        parts = [2, first - 80];
    }
    var val = 0;
    var pending = false;
    for (var i = 1; i < contentBytes.length; i++) {
        val = val * 128 + (contentBytes[i] & 0x7F);
        if (val > 0xFFFFFFFFFFFF) {
            return null; // 数值超出安全范围
        }
        if (contentBytes[i] & 0x80) {
            pending = true;
        } else {
            parts.push(val);
            val = 0;
            pending = false;
        }
    }
    if (pending) {
        return null; // 末尾截断在续位中
    }
    return parts.join('.');
}

// OID 名称映射表：只收录确信的标准项，未命中返回 ''（显示点分串本身，绝不编造）
var ASN1_OID_NAMES = {
    // ---- 国密（GM/T 标准 OID 分支 1.2.156.10197）----
    '1.2.156.10197.1.301': 'SM2 椭圆曲线',
    '1.2.156.10197.1.301.1': 'SM2-1 数字签名',
    '1.2.156.10197.1.301.2': 'SM2-2 密钥交换',
    '1.2.156.10197.1.301.3': 'SM2-3 公钥加密',
    '1.2.156.10197.1.401': 'SM3',
    '1.2.156.10197.1.104': 'SM4',
    '1.2.156.10197.1.501': 'SM2-1 with SM3',
    // ---- RSA / PKCS#1（1.2.840.113549.1.1）----
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    // ---- 摘要算法（md5 与 SHA-2 族）----
    '1.2.840.113549.2.5': 'md5',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
    '2.16.840.1.101.3.4.2.4': 'SHA-224',
    // ---- 椭圆曲线 / ECDSA（1.2.840.10045）----
    '1.2.840.10045.2.1': 'ECDSA',
    '1.2.840.10045.3.1.7': 'prime256v1 (P-256)',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    // ---- X.500 属性（2.5.4）----
    '2.5.4.3': 'CN',
    '2.5.4.4': 'SN',
    '2.5.4.5': 'serialNumber',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.9': 'street',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.42': 'GN',
    // ---- X.509 扩展（2.5.29）----
    '2.5.29.14': 'subjectKeyIdentifier',
    '2.5.29.15': 'keyUsage',
    '2.5.29.17': 'subjectAltName',
    '2.5.29.19': 'basicConstraints',
    '2.5.29.31': 'cRLDistributionPoints',
    '2.5.29.32': 'certificatePolicies',
    '2.5.29.35': 'authorityKeyIdentifier',
    '2.5.29.37': 'extKeyUsage',
    // ---- PKIX（1.3.6.1.5.5.7）----
    '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
    '1.3.6.1.5.5.7.3.1': 'serverAuth',
    '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '1.3.6.1.5.5.7.3.3': 'codeSigning',
    '1.3.6.1.5.5.7.3.4': 'emailProtection',
    '1.3.6.1.5.5.7.48.1': 'OCSP',
    '1.3.6.1.5.5.7.48.2': 'caIssuers',
    // ---- PKCS#7 内容类型（1.2.840.113549.1.7，RFC 2315 标准全集）----
    '1.2.840.113549.1.7.1': 'pkcs7-data',
    '1.2.840.113549.1.7.2': 'pkcs7-signedData',
    '1.2.840.113549.1.7.3': 'pkcs7-envelopedData',
    '1.2.840.113549.1.7.4': 'pkcs7-signedAndEnvelopedData',
    '1.2.840.113549.1.7.5': 'pkcs7-digestedData',
    '1.2.840.113549.1.7.6': 'pkcs7-encryptedData',
    // ---- PKCS#9 签名属性（1.2.840.113549.1.9）----
    '1.2.840.113549.1.9.3': 'contentType',
    '1.2.840.113549.1.9.4': 'messageDigest',
    '1.2.840.113549.1.9.5': 'signingTime'
};

// 点分 OID → 名称；未命中时按前缀给出安全提示（Microsoft / 国密），均无则返回 ''
function asn1OidName(dot) {
    if (ASN1_OID_NAMES.hasOwnProperty(dot)) {
        return ASN1_OID_NAMES[dot];
    }
    if (dot === '1.3.6.1.4.1.311' || dot.indexOf('1.3.6.1.4.1.311.') === 0) {
        return '(Microsoft)';
    }
    if (dot === '1.2.156.10197' || dot.indexOf('1.2.156.10197.') === 0) {
        return '(国密)';
    }
    return '';
}

// ---------- 时间解析：UTCTime / GeneralizedTime → 'YYYY-MM-DD HH:mm:ss UTC' ----------

function asn1FormatTime(content) {
    var s = asn1BytesToLatin1(content).trim();
    if (s.slice(-1) === 'Z') {
        s = s.slice(0, -1); // DER 证书绝大多数以 Z 结尾（UTC）；带 ±hhmm 偏移的走 Hex 预览
    }
    s = s.replace(/\.\d+$/, ''); // GeneralizedTime 小数秒（BER 变体）忽略
    if (!/^\d+$/.test(s)) {
        return null;
    }
    // 去掉 Z 后按长度分派（12 位 UTCTime 含秒 / 10 位无秒变体 / 14 位 GeneralizedTime；
    // GeneralizedTime 无秒变体与 UTCTime 含秒同为 12 位，按证书实际使用惯例优先按 UTCTime 解）
    var y, mo, d, h, mi, sec;
    if (s.length === 12) {
        y = parseInt(s.substr(0, 2), 10);
        y = y >= 50 ? 1900 + y : 2000 + y; // 50 分界世纪
        mo = parseInt(s.substr(2, 2), 10);
        d = parseInt(s.substr(4, 2), 10);
        h = parseInt(s.substr(6, 2), 10);
        mi = parseInt(s.substr(8, 2), 10);
        sec = parseInt(s.substr(10, 2), 10);
    } else if (s.length === 10) {
        y = parseInt(s.substr(0, 2), 10);
        y = y >= 50 ? 1900 + y : 2000 + y;
        mo = parseInt(s.substr(2, 2), 10);
        d = parseInt(s.substr(4, 2), 10);
        h = parseInt(s.substr(6, 2), 10);
        mi = parseInt(s.substr(8, 2), 10);
        sec = 0;
    } else if (s.length === 14) {
        y = parseInt(s.substr(0, 4), 10);
        mo = parseInt(s.substr(4, 2), 10);
        d = parseInt(s.substr(6, 2), 10);
        h = parseInt(s.substr(8, 2), 10);
        mi = parseInt(s.substr(10, 2), 10);
        sec = parseInt(s.substr(12, 2), 10);
    } else {
        return null;
    }
    // 粗略合法性校验，非法按原样（Hex 预览）显示
    if (!(mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h <= 23 && mi <= 59 && sec <= 60)) {
        return null;
    }
    var p2 = function (n) { return (n < 10 ? '0' : '') + n; };
    return y + '-' + p2(mo) + '-' + p2(d) + ' ' + p2(h) + ':' + p2(mi) + ':' + p2(sec) + ' UTC';
}

// ---------- ASN.1 TLV 递归解析（核心） ----------

var ASN1_MAX_DEPTH = 16; // 嵌套深度上限，防异常数据递归爆栈

// 解析 bytes[startOffset, endOffset) 处的一个 TLV，返回节点：
//   { offset, tagBytes, tagFirst, constructed, headerLen, contentLen,
//     contentStart, totalLen, children, embeddedDer, rawBytes }
// 解析越界 / 长度溢出 / 深度超限抛出带字节定位的中文错误
// （错误中的"第 N 字节"为 1 起始序号，与树形左侧 @偏移（0 起始）对应关系为 N = 偏移+1）
function asn1ParseTlv(bytes, startOffset, endOffset, depth) {
    if (depth > ASN1_MAX_DEPTH) {
        throw new Error('第 ' + (startOffset + 1) + ' 字节附近：嵌套超过 ' + ASN1_MAX_DEPTH + ' 层深度上限，已中止解析');
    }
    if (startOffset >= endOffset) {
        throw new Error('第 ' + (startOffset + 1) + ' 字节处：数据不足，无法读取 Tag');
    }

    // --- Tag：首字节（支持多字节 tag：低 5 位全 1 时后续字节高位延续）---
    var pos = startOffset;
    var tagFirst = bytes[pos++];
    var tagBytes = [tagFirst];
    if (tagBytesIsMulti(tagFirst)) {
        var tb;
        do {
            if (pos >= endOffset) {
                throw new Error('第 ' + (pos + 1) + ' 字节处：多字节 Tag 越界');
            }
            tb = bytes[pos++];
            tagBytes.push(tb);
        } while (tb & 0x80);
    }
    var tagLen = pos - startOffset;

    // --- 长度：短格式（<0x80）/ 长格式（0x81/0x82/0x84… 大端）；DER 禁用不定长 0x80 ---
    if (pos >= endOffset) {
        throw new Error('第 ' + (pos + 1) + ' 字节处：缺少长度字段');
    }
    var lenByte = bytes[pos++];
    var contentLen = 0;
    if (lenByte < 0x80) {
        contentLen = lenByte;
    } else if (lenByte === 0x80) {
        throw new Error('第 ' + pos + ' 字节处：不定长格式(0x80)不是合法 DER');
    } else {
        var n = lenByte & 0x7F;
        if (pos + n > endOffset) {
            throw new Error('第 ' + (pos + 1) + ' 字节处长度字段超出数据边界');
        }
        for (var k = 0; k < n; k++) {
            contentLen = contentLen * 256 + bytes[pos + k];
        }
        pos += n;
    }
    var headerLen = pos - startOffset;
    var contentStart = pos;
    if (contentStart + contentLen > endOffset) {
        throw new Error('第 ' + (startOffset + tagLen + 1) + ' 字节附近：长度字段声明 ' + contentLen +
            ' 字节内容，超出数据边界（此处之后仅剩 ' + (endOffset - contentStart) + ' 字节）');
    }
    var totalLen = headerLen + contentLen;

    var node = {
        offset: startOffset,        // 在整个 DER 缓冲中的偏移（0 起始，树形 @N 显示用）
        tagBytes: tagBytes,         // tag 完整字节（正常证书只有 1 字节）
        tagFirst: tagFirst,         // tag 首字节（判类型 / 名称）
        constructed: (tagFirst & 0x20) !== 0, // bit5：构造类型（含上下文类 0xA0-0xFF）
        headerLen: headerLen,       // tag + 长度字段合计字节数
        contentLen: contentLen,
        contentStart: contentStart,
        totalLen: totalLen,
        children: [],               // 构造类型的子节点 / OCTET STRING 展开的内嵌节点
        embeddedDer: false,         // OCTET STRING 内容成功展开为内嵌 DER
        rawBytes: bytes.slice(startOffset, startOffset + totalLen) // 该节点完整字节
    };

    if (node.constructed) {
        // 构造类型：在内容区间内逐个解析子 TLV（上下文类 0xA0-0xFF 同样按此递归）
        var p = contentStart;
        var end = contentStart + contentLen;
        while (p < end) {
            var child = asn1ParseTlv(bytes, p, end, depth + 1);
            node.children.push(child);
            p += child.totalLen;
        }
    } else if (tagFirst === 0x04 && contentLen >= 2 && depth + 1 <= ASN1_MAX_DEPTH) {
        // --- OCTET STRING 智能嵌套：内容恰好能被完整解析为一串 TLV（精确吃满）时展开
        //     （PKCS#8 私钥 / PKCS#7 信封常见）；解析失败按普通数据显示，不报错 ---
        try {
            var inner = [];
            var q = contentStart;
            var innerEnd = contentStart + contentLen;
            while (q < innerEnd) {
                var sub = asn1ParseTlv(bytes, q, innerEnd, depth + 1);
                inner.push(sub);
                q += sub.totalLen;
            }
            node.children = inner;
            node.embeddedDer = true;
        } catch (e) {
            node.children = [];
            node.embeddedDer = false;
        }
    }
    return node;
}

// ---------- 内容预览 ----------

// 节点 → 一行预览文本（按 tag 类型分类；纯函数，不触碰 DOM）
function asn1Preview(tlv) {
    var c = tlv.rawBytes.slice(tlv.headerLen); // 内容字节
    var t = tlv.tagFirst;
    try {
        if (t === 0x05) {
            return ''; // NULL → 空
        }
        if (t === 0x01) {
            return c.length > 0 ? (c[0] !== 0 ? 'TRUE' : 'FALSE') : '';
        }
        if (t === 0x06) {
            var dot = asn1DecodeOid(c);
            if (dot === null) {
                return 'OID 内容异常：' + asn1HexPreview(c, 32);
            }
            var name = asn1OidName(dot);
            if (name === '') {
                return dot;
            }
            return name.charAt(0) === '(' ? dot + ' ' + name : dot + ' (' + name + ')';
        }
        if (t === 0x02 || t === 0x0A) {
            // INTEGER / ENUMERATED：≤8 字节给十进制 + 完整 Hex，超长只显 Hex 截断
            if (c.length === 0) {
                return '';
            }
            if (c.length <= 8 && typeof BigInt === 'function') {
                var v = BigInt(0);
                for (var i = 0; i < c.length; i++) {
                    v = v * BigInt(256) + BigInt(c[i]);
                }
                if (c[0] & 0x80) {
                    v -= BigInt(1) << BigInt(8 * c.length); // 二补码负数
                }
                return v.toString(10) + ' (0x' + asn1BytesToHex(c).toUpperCase() + ')';
            }
            return '0x' + asn1HexPreview(c, 16) + '，共 ' + c.length + ' 字节';
        }
        if (t === 0x03) {
            // BIT STRING：首字节为未用位数
            if (c.length === 0) {
                return '';
            }
            return '未用位 ' + c[0] + '，' + asn1HexPreview(c.slice(1), 16);
        }
        if (t === 0x17 || t === 0x18) {
            var ft = asn1FormatTime(c);
            return ft !== null ? ft : asn1HexPreview(c, 32);
        }
        if (t === 0x0C) {
            var u = asn1DecodeUtf8(c);
            return u !== null ? asn1Truncate(u) : '含非法 UTF-8 序列：' + asn1HexPreview(c, 32);
        }
        if (t === 0x13 || t === 0x14 || t === 0x16 || t === 0x1B) {
            // PrintableString / T61String / IA5String / GeneralString：按 Latin-1 原文
            return asn1Truncate(asn1BytesToLatin1(c));
        }
        if (t === 0x1E) {
            return asn1Truncate(asn1DecodeUtf16be(c));
        }
        if (tlv.embeddedDer) {
            return '[内嵌 DER，' + tlv.contentLen + ' 字节]';
        }
        // OCTET STRING（未展开）/ 其他：hex 前 32 字节 + …（完整 hex 可点击节点复制）
        return asn1HexPreview(c, 32);
    } catch (e) {
        return '';
    }
}

// ---------- 树形渲染 ----------

// 渲染时按行序收集节点引用，供点击复制时按 data-ni 索引取回（事件委托）
var ASN1_NODE_LIST = [];

// 节点 → tag 徽章配色类：SEQUENCE/SET 蓝、OID 绿、字符串青、时间紫、
// 整型/布尔橙、BIT/OCTET STRING/NULL 灰、上下文类紫灰；未分类中性灰
function asn1BadgeClass(node) {
    var t = node.tagFirst;
    if (t === 0x30 || t === 0x31) { return 'asn1-badge-seq'; }
    if (t === 0x06) { return 'asn1-badge-oid'; }
    if (t === 0x0C || t === 0x13 || t === 0x14 || t === 0x16 || t === 0x1B || t === 0x1E) {
        return 'asn1-badge-str'; // UTF8/Printable/T61/IA5/General/BMP 字符串
    }
    if (t === 0x17 || t === 0x18) { return 'asn1-badge-time'; }
    if (t === 0x01 || t === 0x02 || t === 0x0A) { return 'asn1-badge-int'; }
    if (t === 0x03 || t === 0x04 || t === 0x05) { return 'asn1-badge-bin'; }
    if ((t & 0xC0) === 0x80) { return 'asn1-badge-ctx'; }
    return 'asn1-badge-other';
}

// 渲染 TLV 树到容器（全 DOM API + textContent 防注入）：
//   节点行 = 折叠箭头 + tag 徽章（+ [内嵌] 小标记）+ @偏移/长度 + 内容预览；
//   有子节点的行后紧跟 .asn1-children 子树容器（嵌套缩进 + 左侧竖线辅助线，
//   折叠时由 CSS 相邻选择器整体隐藏）；
//   tlv 可传单个根节点或根节点数组（顶层多个并列 TLV 时）
function asn1RenderTree(container, tlv) {
    var roots = Array.isArray(tlv) ? tlv : [tlv];
    ASN1_NODE_LIST = [];
    container.textContent = '';

    // 构建单个节点行（行序注册进 ASN1_NODE_LIST，供点击复制按 data-ni 取回）
    function buildRow(node) {
        var idx = ASN1_NODE_LIST.length;
        ASN1_NODE_LIST.push(node);
        var name = node.tagBytes.length > 1
            ? 'TAG_0x' + asn1BytesToHex(node.tagBytes).toUpperCase() + '…'
            : asn1TagName(node.tagFirst, node.constructed);
        var hasChildren = node.children.length > 0;

        var row = document.createElement('div');
        row.className = 'asn1-node' + (hasChildren ? ' asn1-has-children' : '');
        row.setAttribute('data-ni', String(idx));
        row.title = '点击复制该节点完整 Hex（' + node.totalLen + ' 字节）';

        // 折叠箭头（叶子节点用同宽占位空 span 保持对齐）
        var toggle = document.createElement('span');
        toggle.className = hasChildren ? 'asn1-toggle' : 'asn1-toggle-slot';
        toggle.textContent = hasChildren ? '▾' : '';
        row.appendChild(toggle);

        // tag 徽章（按类型分色）
        var badge = document.createElement('span');
        badge.className = 'asn1-badge ' + asn1BadgeClass(node);
        badge.textContent = name;
        row.appendChild(badge);

        // 内嵌 DER 追加小标记
        if (node.embeddedDer) {
            var emb = document.createElement('span');
            emb.className = 'asn1-badge asn1-badge-emb';
            emb.textContent = '[内嵌]';
            row.appendChild(emb);
        }

        var meta = document.createElement('span');
        meta.className = 'asn1-meta';
        meta.textContent = '@' + node.offset + ' 长' + node.totalLen +
            '(头' + node.headerLen + '+内容' + node.contentLen + ')';
        row.appendChild(meta);

        var preview = document.createElement('span');
        preview.className = 'asn1-preview';
        preview.textContent = asn1Preview(node);
        row.appendChild(preview);

        return row;
    }

    // 递归构建：节点行 + （有子节点时）子树容器
    function buildInto(parent, node) {
        parent.appendChild(buildRow(node));
        if (node.children.length > 0) {
            var kids = document.createElement('div');
            kids.className = 'asn1-children';
            for (var i = 0; i < node.children.length; i++) {
                buildInto(kids, node.children[i]);
            }
            parent.appendChild(kids);
        }
    }

    for (var r = 0; r < roots.length; r++) {
        buildInto(container, roots[r]);
    }
}

// ---------- 页面动作 ----------

// 概要 + 树形统一渲染：ex 为 asn1ExtractDer / asn1ExtractDerBytes 的返回值
// （{ bytes, format, note }），fileName 为文件上传路径的文件名（手动粘贴解析传 ''）；
// 概要行追加容器类型说明（note）与文件名
function asn1ShowResult(ex, fileName) {
    var infoElem = document.getElementById('asn1-info');
    var treeElem = document.getElementById('asn1-tree');
    if (!infoElem || !treeElem) {
        return;
    }
    var bytes = ex.bytes;
    if (bytes.length === 0) {
        throw new Error('解码后数据为空');
    }
    // 顶层可能并列多个 TLV（如拼接的 DER），逐个解析
    var roots = [];
    var p = 0;
    while (p < bytes.length) {
        var node = asn1ParseTlv(bytes, p, bytes.length, 0);
        roots.push(node);
        p += node.totalLen;
    }
    var topNames = roots.map(function (r) {
        return asn1TagName(r.tagFirst, r.constructed);
    });
    if (topNames.length > 3) {
        topNames = topNames.slice(0, 3).concat(['等共 ' + topNames.length + ' 个']);
    }
    infoElem.textContent = '输入格式：' + ex.format +
        '｜DER 共 ' + bytes.length + ' 字节｜顶层：' + topNames.join('、') +
        (ex.note ? '｜' + ex.note : '') +
        (fileName ? '｜文件：' + fileName : '');
    asn1RenderTree(treeElem, roots);
}

// 解析错误统一展示：清空概要行，树容器内渲染错误提示块（DOM API 防注入）
function asn1ShowError(msg) {
    var infoElem = document.getElementById('asn1-info');
    var treeElem = document.getElementById('asn1-tree');
    if (infoElem) { infoElem.textContent = ''; }
    if (!treeElem) {
        return;
    }
    treeElem.textContent = '';
    if (!msg) {
        return;
    }
    var div = document.createElement('div');
    div.className = 'asn1-error';
    div.textContent = '❌ ' + msg;
    treeElem.appendChild(div);
}

// "解析"按钮：识别 textarea 输入（PEM / Base64 / Hex）→ 概要信息 + 树形渲染
// （cert.js 的"用 ASN.1 树查看"也是先填 textarea 再调本函数，路径保持不变）
function asn1Parse() {
    var inputElem = document.getElementById('asn1-input');
    if (!inputElem) {
        return;
    }
    asn1ShowError(''); // 清空上次结果
    if (!inputElem.value.trim()) {
        showNotification('请先输入或上传 PEM / Base64 / Hex 数据');
        return;
    }
    try {
        asn1ShowResult(asn1ExtractDer(inputElem.value), '');
    } catch (e) {
        asn1ShowError(e.message);
        showNotification('解析失败：' + e.message);
    }
}

// "全部折叠" / "全部展开"：遍历树中有子节点的行，统一切换折叠类并同步箭头方向
function asn1SetAllCollapsed(collapsed) {
    var treeElem = document.getElementById('asn1-tree');
    if (!treeElem) {
        return;
    }
    var rows = treeElem.querySelectorAll('.asn1-node.asn1-has-children');
    for (var i = 0; i < rows.length; i++) {
        rows[i].classList.toggle('asn1-collapsed', collapsed);
        var toggle = rows[i].firstElementChild; // 折叠箭头恒为行内第一个子元素
        if (toggle) {
            toggle.textContent = collapsed ? '▸' : '▾';
        }
    }
}

function asn1CollapseAll() {
    asn1SetAllCollapsed(true);
}

function asn1ExpandAll() {
    asn1SetAllCollapsed(false);
}

// "清空"按钮
function asn1Clear() {
    var inputElem = document.getElementById('asn1-input');
    var infoElem = document.getElementById('asn1-info');
    var treeElem = document.getElementById('asn1-tree');
    if (inputElem) { inputElem.value = ''; }
    if (infoElem) { infoElem.textContent = ''; }
    if (treeElem) { treeElem.innerHTML = ''; }
}

// 读取上传文件（上限 2MB）：readAsArrayBuffer 后统一走 asn1ExtractDerBytes
// 识别（PEM 头 / JKS 魔数 / 裸 DER + 容器提示），解析直接用 bytes；
// textarea 仅作展示回填（PEM 填原文，二进制 ≤512KB 填大写 Hex，过大填提示文字）
function asn1ReadFile(file) {
    if (file.size > 2 * 1024 * 1024) {
        showNotification('文件过大（超过 2MB），请粘贴内容代替上传');
        return;
    }
    var reader = new FileReader();
    reader.onload = function () {
        var buf = new Uint8Array(reader.result);
        var inputElem = document.getElementById('asn1-input');
        try {
            var ex = asn1ExtractDerBytes(buf, file.name);
            // textarea 回填（仅展示，解析用 bytes）：
            //   PEM 填原文便于人工核对；二进制 ≤512KB 填大写 Hex；过大不填入避免卡顿
            var head = '';
            for (var i = 0; i < Math.min(buf.length, 64); i++) {
                head += String.fromCharCode(buf[i]);
            }
            if (inputElem) {
                if (head.indexOf('-----BEGIN') >= 0) {
                    // 分块转文本，避免大文件 fromCharCode 参数超限
                    var text = '';
                    for (var j = 0; j < buf.length; j += 4096) {
                        text += String.fromCharCode.apply(null, buf.subarray(j, Math.min(j + 4096, buf.length)));
                    }
                    inputElem.value = text;
                } else if (buf.length <= 512 * 1024) {
                    inputElem.value = asn1BytesToHex(buf).toUpperCase();
                } else {
                    inputElem.value = '（二进制文件 ' + file.name + ' 共 ' + buf.length +
                        ' 字节，内容过大不填入输入框，解析结果见下方树）';
                }
            }
            showNotification('已加载文件：' + file.name + '（' + file.size + ' 字节）');
            asn1ShowResult(ex, file.name);
        } catch (e) {
            asn1ShowError(e.message);
            showNotification('解析失败：' + e.message);
        }
    };
    reader.onerror = function () {
        showNotification('文件读取失败');
    };
    reader.readAsArrayBuffer(file);
}

// ---------- 初始化 ----------

// 绑定拖拽区（点击/拖拽/释放）、文件输入与树形点击复制（事件委托，
// 树形重新渲染后监听依然有效）
function asn1Init() {
    var dropZone = document.getElementById('asn1-drop-zone');
    var fileInput = document.getElementById('asn1-file-input');
    if (dropZone && fileInput) {
        // 点击拖拽区弹出文件选择框
        dropZone.addEventListener('click', function (event) {
            // input.click() 派发的 click 会冒泡回拖拽区，需拦截避免无限递归
            if (event.target === fileInput) {
                return;
            }
            fileInput.click();
        });
        // 拖拽悬停高亮（dragover 必须 preventDefault，否则浏览器直接打开文件）
        dropZone.addEventListener('dragover', function (event) {
            event.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', function (event) {
            event.preventDefault();
            dropZone.classList.remove('dragover');
        });
        dropZone.addEventListener('drop', function (event) {
            event.preventDefault();
            dropZone.classList.remove('dragover');
            var files = event.dataTransfer && event.dataTransfer.files;
            if (files && files.length > 0) {
                asn1ReadFile(files[0]);
            }
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                asn1ReadFile(fileInput.files[0]);
            }
            fileInput.value = ''; // 允许重复选择同一文件
        });
    }

    // 树形点击（事件委托，重渲染后监听依然有效）：
    //   点折叠箭头 → 切换该节点子树显隐；点行其余区域 → 复制该节点完整 Hex（大写）
    var treeElem = document.getElementById('asn1-tree');
    if (treeElem) {
        treeElem.addEventListener('click', function (event) {
            var t = event.target;
            // 1) 折叠箭头：切换子树显隐并翻转箭头方向，不触发复制
            if (t.classList && t.classList.contains('asn1-toggle')) {
                var prow = t.closest ? t.closest('.asn1-node') : null;
                if (prow) {
                    var collapsed = prow.classList.toggle('asn1-collapsed');
                    t.textContent = collapsed ? '▸' : '▾';
                }
                return;
            }
            // 2) 节点行（非箭头区域）：复制该节点完整 Hex
            var row = t.closest ? t.closest('.asn1-node') : null;
            if (!row) {
                return;
            }
            var node = ASN1_NODE_LIST[parseInt(row.getAttribute('data-ni'), 10)];
            if (node) {
                copyTextToClipboard(asn1BytesToHex(node.rawBytes).toUpperCase());
                showNotification('已复制节点 Hex（' + node.rawBytes.length + ' 字节）');
            }
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化；
// 无 document 的环境（Node 打桩测试纯解析函数）直接跳过
if (typeof document === 'undefined') {
    // Node 环境：不初始化页面，仅暴露纯解析函数供测试
} else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', asn1Init);
} else {
    asn1Init();
}

// Node 环境导出纯解析函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        asn1ExtractDer: asn1ExtractDer,
        asn1ExtractDerBytes: asn1ExtractDerBytes,
        asn1ParseTlv: asn1ParseTlv,
        asn1DecodeOid: asn1DecodeOid,
        asn1OidName: asn1OidName,
        asn1TagName: asn1TagName,
        asn1FormatTime: asn1FormatTime,
        asn1Preview: asn1Preview
    };
}
