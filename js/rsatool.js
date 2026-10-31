// ============================================================
// RSA 工具页 —— page-rsa（js/rsatool.js）
// Section 1：RSA 密钥对生成（Web Crypto，PKCS#8/SPKI PEM + 模数展示）
// Section 2：RSA 加解密（RSA-OAEP-SHA256/SHA1 + RSAES-PKCS1-v1_5 手写 BigInt）
// Section 3：RSA 签名验签（RSASSA-PKCS1-v1_5-SHA256/384/512 + RSA-PSS-SHA256）
// Section 4：CSR 生成（PKCS#10，SM2 / RSA 双支持，手写 DER 组装）
// 依赖（须先于本文件加载，Node 打桩时挂到全局）：
//   js/vendor/sm-crypto.js → global.smCrypto（0.3.2 本地化打包）
//   js/gmsm.js             → gmDerTlv / gmDerLen / gmGetRadio / gmUtf8ToBytes /
//                            gmHexToBytes / gmCopyInput / gmShowError / sm2ConvInteger
//   js/asn1.js             → asn1ParseTlv / asn1ExtractDer / asn1DecodeOid
//   js/keytool.js          → ktOidToDerContent / ktParsePrivateKey / ktToPkcs8Core /
//                            kt9PrivToPkcs8Pem / ktBuildPem / ktBytesToHex / ktHexToBytes /
//                            ktBytesToBase64 / ktInputToBytes
//（数组归一化 / TLV 取内容等小工具本地自备 rsaToArray 等，不依赖 keytool.js 未导出的内部函数）
// 纯函数（rsaGenKeyCore / rsaParseSpki / rsaParsePkcs8Priv / rsaPkcs1EncryptCore /
// rsaPkcs1DecryptCore / rsaOaepEncryptCore / rsaOaepDecryptCore / rsaSignCore / rsaVerifyCore /
// csrDnDer / csrBuildCri / csrAssemble / csrBuildSm2Core / csrBuildRsaCore / sm2PubFromPriv /
// csrExtractSm2Priv / rsaSpkiFromParts）不触碰 DOM，可在 Node 中单独加载打桩测试。
//
// ===== Web Crypto key usages 限制（重要坑点，务必照此口径）=====
// generateKey 的 usages 必须与 algorithm 匹配：RSA-OAEP 只接受 encrypt/decrypt，
// RSASSA-PKCS1-v1_5 只接受 sign/verify——想把 ['encrypt','decrypt','sign','verify']
// 合并塞给一次 generateKey 会直接抛 SyntaxError（两个算法名不能同 key usages 生成）。
// 正确做法：按 RSA-OAEP 口径 generateKey 一次（extractable）拿到密钥材料并导出
// pkcs8 / spki；后续签名时把同一份 pkcs8/spki 再 importKey 成 RSASSA-PKCS1-v1_5 /
// RSA-PSS 的 CryptoKey 视图（rsaImportCached 按需+缓存）——密钥材料同一把，
// 用途视图分两份（encrypt/decrypt 一份、sign/verify 一份），即"一把密钥、两份用途"。
//
// ===== RSAES-PKCS1-v1_5 手写实现说明 =====
// 浏览器 Web Crypto 已移除 RSAES-PKCS1-v1_5 的 encrypt/decrypt 支持（Chrome/Firefox
// 均抛 NotSupportedError，规范侧因 Bleichenbacher 攻击历史将其弃用）。本页对该
// legacy 算法以纯 JS BigInt 手写：加密 EM = 00 02 || PS(非零随机,≥8B) || 00 || M，
// c = EM^e mod n；解密走 CRT（dp/dq/qi），校验 00 02 前缀与 00 分隔符后取明文。
// 注意：本实现非常数时间（离线工具场景可接受），新场景请使用 RSA-OAEP。
//
// ===== sm-crypto 0.3.2 doSignature 数组签名坑点（CSR 签名必读）=====
// doSignature 的 msg 按"字符串 = UTF-8 文本"处理（内部 utf8ToHex）——把 CRI 的
// hex 字符串传进去会被当作文本二次编码，签名必错！必须把 CRI DER 字节作为
// 【数组】传入（库对数组按原始字节处理，见 js/gmsm.js 文件头坑点 6）。
// ============================================================

// ---------------- 模块状态 ----------------

// Section 1 生成的密钥对暂存（模块变量，供 Section 2/3 "使用上方生成的密钥"）；
// paste 模式不写这里，直接从 textarea 读 PEM
var RSA_KEY_STATE = {
    bits: 0,          // 模长位数
    pubSpki: null,    // 公钥 SPKI DER（普通数组）
    privPkcs8: null,  // 私钥 PKCS#8 DER（普通数组）
    pubPem: '',
    privPem: ''
};

// importKey 结果缓存：同一段 DER + 同一算法视图只导入一次
//（CryptoKey 可反复使用；缓存键含 DER 的 Hex，切换/重新生成密钥不会串缓存）
var RSA_IMPORT_CACHE = {};

// CSR 的 DN 属性表：key → 页面字段名，oid → 属性 OID，tag → 值的 ASN.1 类型
//   CN/O/OU 用 UTF8String(0x0C)，C 用 PrintableString(0x13)（且限 2 字母），
//   E(emailAddress) 用 IA5String(0x16)——口径与 OpenSSL 默认 DN 编码一致
var CSR_DN_SPECS = [
    { key: 'cn', oid: '2.5.4.3', tag: 0x0C, label: 'CN' },
    { key: 'o', oid: '2.5.4.10', tag: 0x0C, label: 'O' },
    { key: 'ou', oid: '2.5.4.11', tag: 0x0C, label: 'OU' },
    { key: 'c', oid: '2.5.4.6', tag: 0x13, label: 'C' },
    { key: 'e', oid: '1.2.840.113549.1.9.1', tag: 0x16, label: 'E' }
];

// ---------------- 基础小工具（本地自备，避免依赖 keytool.js 未导出的内部函数） ----------------

// Buffer / TypedArray / 普通数组 → 普通数组归一化（gmDerTlv 用 concat 拼装，
// concat 不展开 TypedArray——Buffer 整体会被当成单个元素导致 DER 拼装错误）
function rsaToArray(bytes) {
    return Array.prototype.slice.call(bytes);
}

// 取 TLV 节点的内容字节（tag + 长度字段之后的部分；口径同 keytool.js 的 ktContent）
function rsaContent(node) {
    return rsaToArray(node.rawBytes.slice(node.headerLen));
}

// INTEGER 节点内容 → 非负数值（≤6 字节；空 / 超长 / 负数返回 null；CSR 版本号判断用）
function rsaIntValue(node) {
    var c = rsaContent(node);
    if (c.length === 0 || c.length > 6 || (c[0] & 0x80)) {
        return null;
    }
    var v = 0;
    for (var i = 0; i < c.length; i++) {
        v = v * 256 + c[i];
    }
    return v;
}

// 无符号大整数有效位长（RSA 模长用）：去前导零后按首字节最高位 1 计（口径同 ktIntBitLen）
function rsaIntBitLen(bytes) {
    var i = 0;
    while (i < bytes.length && bytes[i] === 0) {
        i++;
    }
    if (i === bytes.length) {
        return 0;
    }
    var b = bytes[i];
    var first = 8;
    while (!(b & 0x80)) {
        first--;
        b <<= 1;
    }
    return (bytes.length - i - 1) * 8 + first;
}

// ---------------- BigInt 小工具（PKCS#1 v1.5 手写加解密用） ----------------

// 文本 → UTF-8 字节数组（自备，不依赖 gmsm.js 未导出的 gmUtf8ToBytes）
function rsaUtf8ToBytes(text) {
    return Array.prototype.slice.call(new TextEncoder().encode(text));
}

// 大端字节数组 → BigInt
function rsaBytesToBigInt(bytes) {
    var hex = ktBytesToHex(bytes);
    return BigInt(hex === '' ? '0' : '0x' + hex);
}

// BigInt → 定长 len 字节的大端数组（不足前补零；超出按实际长度输出）
function rsaBigIntToFixedBytes(value, len) {
    var hex = value.toString(16);
    if (hex.length % 2 !== 0) {
        hex = '0' + hex; // 补齐整字节
    }
    var pad = '';
    for (var i = 0; i < (len - hex.length / 2) * 2; i++) {
        pad += '0';
    }
    return ktHexToBytes(pad + hex);
}

// 平方-乘法模幂：base^exp mod mod（BigInt，RSA 手写路径共用）
function rsaModPow(base, exp, mod) {
    var result = BigInt(1);
    base = ((base % mod) + mod) % mod;
    var one = BigInt(1), two = BigInt(2);
    while (exp > 0) {
        if (exp & one) {
            result = result * base % mod;
        }
        base = base * base % mod;
        exp = exp >> one;
    }
    return result;
}

// 扩展欧几里得模逆：a^-1 mod m（不存在逆元时抛错；SM2 公钥推导用）
function rsaModInverse(a, m) {
    var t = BigInt(0), newT = BigInt(1);
    var r = m, newR = ((a % m) + m) % m;
    while (newR !== BigInt(0)) {
        var q = r / newR; // BigInt / 为截断除法，即取商
        var tmp = t - q * newT; t = newT; newT = tmp;
        tmp = r - q * newR; r = newR; newR = tmp;
    }
    if (r !== BigInt(1)) {
        throw new Error('模逆不存在（输入与模数不互素）');
    }
    return ((t % m) + m) % m;
}

// ---------------- RSA 公私钥 DER 解析（纯函数） ----------------

// DER INTEGER 内容 → 最小无符号形态（剥符号填充 0x00；至少保留 1 字节）。
// 2048 位模数的最高位为 1，DER 编码会前补 0x00 声明正号（内容 257 字节）——
// 不剥掉会把 k 当成 257 字节，导致手写 PKCS#1 v1_5 的密文长度错一截
function rsaStripIntZeros(bytes) {
    var i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) {
        i++;
    }
    return bytes.slice(i);
}

// SPKI → { n, e, bits }（字节组 + 模长有效位）
// 结构：SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING(00 || RSAPublicKey) }
function rsaParseSpki(spkiBytes) {
    var der = rsaToArray(spkiBytes);
    var root = asn1ParseTlv(der, 0, der.length, 0);
    if (root.tagFirst !== 0x30 || !root.constructed || !root.children || root.children.length < 2) {
        throw new Error('不是合法的公钥 SPKI 结构');
    }
    // 算法段校验：第一个子节点 SEQ 内应含 rsaEncryption OID（宽容：不强校验 params）
    var algKids = root.children[0].children || [];
    if (algKids.length < 1 || algKids[0].tagFirst !== 0x06 ||
        asn1DecodeOid(rsaContent(algKids[0])) !== '1.2.840.113549.1.1.1') {
        throw new Error('公钥算法不是 rsaEncryption（仅支持 RSA 公钥）');
    }
    if (root.children[1].tagFirst !== 0x03) {
        throw new Error('SPKI 第二个子节点应为 BIT STRING');
    }
    // BIT STRING 内容：首字节为未用位数（RSA 恒 0x00），其后为 RSAPublicKey DER
    var bitContent = rsaContent(root.children[1]);
    if (bitContent.length < 4 || bitContent[0] !== 0x00) {
        throw new Error('BIT STRING 内容异常（未用位数非 0 或长度不足）');
    }
    var pubSeq = asn1ParseTlv(bitContent.slice(1), 0, bitContent.length - 1, 0);
    var kids = pubSeq.children || [];
    if (pubSeq.tagFirst !== 0x30 || kids.length < 2 || kids[0].tagFirst !== 0x02 || kids[1].tagFirst !== 0x02) {
        throw new Error('RSAPublicKey 结构异常（应为 SEQUENCE { INTEGER n, INTEGER e }）');
    }
    var n = rsaStripIntZeros(rsaToArray(rsaContent(kids[0])));
    var e = rsaStripIntZeros(rsaToArray(rsaContent(kids[1])));
    return { n: n, e: e, bits: rsaIntBitLen(n) };
}

// 私钥 DER（PKCS#8 或 PKCS#1）→ { n, e, d, p, q, dp, dq, qi, privPkcs8 }
//   PKCS#8：SEQUENCE { INTEGER 0, SEQ{OID rsa, NULL}, OCTET STRING(RSAPrivateKey) }
//   PKCS#1：RSAPrivateKey ::= SEQUENCE { INTEGER 0, n, e, d, p, q, dp, dq, qi }
// privPkcs8 字段恒为 PKCS#8 形态 DER（PKCS#1 输入经 ktToPkcs8Core 包壳，供 importKey 用）
function rsaParsePkcs8Priv(derBytes) {
    var der = rsaToArray(derBytes);
    var info = ktParsePrivateKey(der);
    var isRsa = info.kind === 'pkcs1-rsa' || (info.kind === 'pkcs8' && info.algOid === '1.2.840.113549.1.1.1');
    if (!isRsa) {
        throw new Error('不是 RSA 私钥（识别为 ' + (info.label || info.kind) + '）');
    }
    var inner = der;
    var privPkcs8 = der;
    if (info.kind === 'pkcs8') {
        var root = asn1ParseTlv(der, 0, der.length, 0);
        inner = rsaToArray(rsaContent(root.children[2])); // privateKey OCTET STRING 内容 = RSAPrivateKey
    } else {
        privPkcs8 = ktToPkcs8Core(der).der; // PKCS#1 → PKCS#8（包 rsaEncryption + NULL 壳）
    }
    var seq = asn1ParseTlv(inner, 0, inner.length, 0);
    var kids = seq.children || [];
    if (seq.tagFirst !== 0x30 || kids.length < 9) {
        throw new Error('RSAPrivateKey 结构异常（应含 version 与 n/e/d/p/q/dp/dq/qi 九个字段）');
    }
    var pick = function (idx) { return rsaStripIntZeros(rsaToArray(rsaContent(kids[idx]))); };
    return {
        n: pick(1), e: pick(2), d: pick(3),
        p: pick(4), q: pick(5), dp: pick(6), dq: pick(7), qi: pick(8),
        privPkcs8: privPkcs8
    };
}

// RSA 私钥字段 → SPKI 公钥 DER（paste 模式 CSR / 无公钥场景重组公钥用）
// SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING(00 || SEQUENCE{INT n, INT e}) }
// 整数编码走 sm2ConvInteger（去前导零 / 最高位为 1 补 0x00 的 DER INTEGER 规则，任意长度通用）
function rsaSpkiFromParts(parts) {
    var pubSeq = gmDerTlv(0x30, sm2ConvInteger(parts.n).concat(sm2ConvInteger(parts.e)));
    var algId = gmDerTlv(0x30,
        gmDerTlv(0x06, ktOidToDerContent('1.2.840.113549.1.1.1')).concat(gmDerTlv(0x05, [])));
    return gmDerTlv(0x30, algId.concat(gmDerTlv(0x03, [0x00].concat(pubSeq))));
}

// ---------------- RSAES-PKCS1-v1_5 手写加解密（纯函数，BigInt） ----------------

// PKCS#1 v1.5 加密：EM = 00 02 || PS(非零随机 ≥8B) || 00 || M，c = EM^e mod n
// 明文上限 = 模长字节数 k − 11；PS 用 crypto.getRandomValues 逐字节拒绝零
function rsaPkcs1EncryptCore(nBytes, eBytes, msgBytes) {
    var n = rsaBytesToBigInt(nBytes);
    var e = rsaBytesToBigInt(eBytes);
    var k = nBytes.length;
    if (msgBytes.length > k - 11) {
        throw new Error('RSA-PKCS1-v1_5 明文过长：最多 ' + (k - 11) + ' 字节（模长 ' + k * 8 + ' 位 − 11），当前 ' + msgBytes.length + ' 字节');
    }
    // PS：k − mLen − 3 个非零随机字节（拒绝采样，零字节重取）
    var psLen = k - msgBytes.length - 3;
    var ps = [];
    while (ps.length < psLen) {
        var buf = new Uint8Array(psLen - ps.length);
        crypto.getRandomValues(buf);
        for (var i = 0; i < buf.length; i++) {
            if (buf[i] !== 0) { ps.push(buf[i]); }
        }
    }
    var em = [0x00, 0x02].concat(ps, [0x00], rsaToArray(msgBytes));
    var c = rsaModPow(rsaBytesToBigInt(em), e, n);
    return rsaBigIntToFixedBytes(c, k);
}

// PKCS#1 v1.5 解密：CRT(m = m2 + q·((m1 − m2)·qi mod p))，再校验去填充
//（非常数时间实现，离线工具场景；PS ≥ 8 字节 → 00 分隔符位置 ≥ 10）
function rsaPkcs1DecryptCore(parts, cipherBytes) {
    var cipher = rsaToArray(cipherBytes);
    var k = parts.n.length;
    if (!cipher.length || cipher.length > k) {
        throw new Error('密文长度 ' + cipher.length + ' 字节异常（RSA-' + k * 8 + ' 密文应为 ' + k + ' 字节或更短）');
    }
    var c = rsaBytesToBigInt(cipher);
    var p = rsaBytesToBigInt(parts.p), q = rsaBytesToBigInt(parts.q);
    var dp = rsaBytesToBigInt(parts.dp), dq = rsaBytesToBigInt(parts.dq), qi = rsaBytesToBigInt(parts.qi);
    var m1 = rsaModPow(c, dp, p);
    var m2 = rsaModPow(c, dq, q);
    var h = (((m1 - m2) * qi) % p + p) % p;
    var m = m2 + h * q;
    var em = rsaBigIntToFixedBytes(m, k);
    if (em[0] !== 0x00 || em[1] !== 0x02) {
        throw new Error('PKCS#1 v1.5 解密失败：填充前缀不符（密文与私钥/算法不匹配？）');
    }
    var sep = 2;
    while (sep < em.length && em[sep] !== 0x00) { sep++; }
    if (sep < 10) {
        throw new Error('PKCS#1 v1.5 解密失败：填充段异常（PS 不足 8 字节）');
    }
    return em.slice(sep + 1);
}

// ---------------- Web Crypto 包装（importKey 缓存 + 四个核心 async 纯函数） ----------------

// 缓存键：形态 + 算法视图 + DER 内容 Hex（不同密钥 / 不同算法各占一格）
function rsaImportCached(derBytes, format, alg, usages) {
    var cacheKey = format + '|' + alg.name + '|' + (alg.hash || '') + '|' + (alg.saltLength || '') +
        '|' + ktBytesToHex(derBytes);
    if (RSA_IMPORT_CACHE[cacheKey]) {
        return RSA_IMPORT_CACHE[cacheKey];
    }
    var p = crypto.subtle.importKey(format, new Uint8Array(derBytes), alg, true, usages)
        .then(function (key) {
            RSA_IMPORT_CACHE[cacheKey] = Promise.resolve(key); // 首次成功后固化为已解析 Promise
            return key;
        }, function (err) {
            delete RSA_IMPORT_CACHE[cacheKey]; // 失败不缓存，下次调用可重试
            throw err;
        });
    RSA_IMPORT_CACHE[cacheKey] = p; // 并发去重：同键并发调用共享同一次导入
    return p;
}

// 密钥对生成核心（纯函数口径，不触碰 DOM）：按 RSA-OAEP 口径生成一次密钥材料，
// 导出 pkcs8/spki 与两种 PEM（usages 限制见文件头——签名用途由 importKey 二次成视图）
async function rsaGenKeyCore(modulusBits) {
    var pair = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: modulusBits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['encrypt', 'decrypt']);
    var privPkcs8 = Array.from(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)));
    var pubSpki = Array.from(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)));
    return {
        bits: modulusBits,
        privPkcs8: privPkcs8,
        pubSpki: pubSpki,
        privPem: ktBuildPem('PRIVATE KEY', privPkcs8),
        pubPem: ktBuildPem('PUBLIC KEY', pubSpki)
    };
}

// OAEP 加密核心（Node/浏览器通用；hashName 如 'SHA-256'）
async function rsaOaepEncryptCore(pubSpkiBytes, hashName, msgBytes) {
    var pub = await rsaImportCached(pubSpkiBytes, 'spki', { name: 'RSA-OAEP', hash: hashName }, ['encrypt']);
    var buf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, new Uint8Array(msgBytes));
    return Array.from(new Uint8Array(buf));
}

// OAEP 解密核心
async function rsaOaepDecryptCore(privPkcs8Bytes, hashName, cipherBytes) {
    var priv = await rsaImportCached(privPkcs8Bytes, 'pkcs8', { name: 'RSA-OAEP', hash: hashName }, ['decrypt']);
    try {
        var buf = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, new Uint8Array(cipherBytes));
    } catch (e) {
        throw new Error('解密失败：OAEP 去填充校验未通过（密文与密钥/哈希算法不匹配？）');
    }
    return Array.from(new Uint8Array(buf));
}

// 签名核心（alg 为完整算法对象，RSA-PSS 需含 saltLength）
async function rsaSignCore(privPkcs8Bytes, alg, msgBytes) {
    var key = await rsaImportCached(privPkcs8Bytes, 'pkcs8', alg, ['sign']);
    var buf = await crypto.subtle.sign(alg, key, new Uint8Array(msgBytes));
    return Array.from(new Uint8Array(buf));
}

// 验签核心 → boolean
async function rsaVerifyCore(pubSpkiBytes, alg, msgBytes, sigBytes) {
    var key = await rsaImportCached(pubSpkiBytes, 'spki', alg, ['verify']);
    return crypto.subtle.verify(alg, key, new Uint8Array(sigBytes), new Uint8Array(msgBytes));
}

// ---------------- Section 1：RSA 密钥对生成（页面动作） ----------------

// "生成密钥对"按钮：生成后暂存模块状态并回填两个只读 PEM 框 + 模数信息行
async function rsaGenKey() {
    var infoEl = document.getElementById('rsa-gen-info');
    try {
        var bits = parseInt(gmGetRadio('rsa-modulus') || '2048', 10);
        var r = await rsaGenKeyCore(bits);
        RSA_KEY_STATE = {
            bits: r.bits, pubSpki: r.pubSpki, privPkcs8: r.privPkcs8,
            pubPem: r.pubPem, privPem: r.privPem
        };
        document.getElementById('rsa-gen-priv').value = r.privPem;
        document.getElementById('rsa-gen-pub').value = r.pubPem;

        // 模数与公钥指数展示：n 截断显示（2048 位 = 512 个 Hex 字符，全显太长）
        var parsed = rsaParseSpki(r.pubSpki);
        var nHex = ktBytesToHex(parsed.n).toUpperCase();
        var nBrief = nHex.length > 64 ? nHex.substr(0, 64) + '…' : nHex;
        var eHex = ktBytesToHex(parsed.e).toUpperCase();
        infoEl.className = 'result-area gm-oneline';
        infoEl.textContent = '模长 ' + parsed.bits + ' 位（n ' + parsed.n.length + ' 字节）｜e = 0x' + eHex +
            (eHex === '010001' ? '（65537）' : '') + '｜n（截断）= ' + nBrief;
        showNotification('RSA-' + bits + ' 密钥对生成完成，可直接用于下方加解密与签名');
    } catch (e) {
        gmShowError('rsa-gen-info', e);
    }
}

// ---------------- 密钥来源（Section 2/3 共用） ----------------

// 密钥来源切换：paste 模式显示两个 PEM 粘贴框
function rsaKeySrcChanged() {
    var paste = (gmGetRadio('rsa-key-src') || 'gen') === 'paste';
    document.getElementById('rsa-pub-pem-row').style.display = paste ? '' : 'none';
    document.getElementById('rsa-priv-pem-row').style.display = paste ? '' : 'none';
}

// 取公钥 SPKI DER：gen 模式读暂存，paste 模式解析 rsa-pub-pem（PEM/Base64/Hex 均可）
function rsaResolvePubSpki() {
    if ((gmGetRadio('rsa-key-src') || 'gen') === 'gen') {
        if (!RSA_KEY_STATE.pubSpki) {
            throw new Error('尚未生成密钥对：请先在上方点击"生成密钥对"，或把密钥来源切换为"粘贴 PEM"');
        }
        return RSA_KEY_STATE.pubSpki;
    }
    var el = document.getElementById('rsa-pub-pem');
    if (!el || !el.value.trim()) {
        throw new Error('请在"公钥 PEM"框粘贴公钥（-----BEGIN PUBLIC KEY----- 包装，或 Base64/Hex DER）');
    }
    return Array.from(asn1ExtractDer(el.value).bytes);
}

// 取私钥 PKCS#8 DER：paste 模式容忍 PKCS#1（RSA PRIVATE KEY）输入，自动包壳成 PKCS#8
function rsaResolvePrivPkcs8() {
    if ((gmGetRadio('rsa-key-src') || 'gen') === 'gen') {
        if (!RSA_KEY_STATE.privPkcs8) {
            throw new Error('尚未生成密钥对：请先在上方点击"生成密钥对"，或把密钥来源切换为"粘贴 PEM"');
        }
        return RSA_KEY_STATE.privPkcs8;
    }
    var el = document.getElementById('rsa-priv-pem');
    if (!el || !el.value.trim()) {
        throw new Error('请在"私钥 PEM"框粘贴私钥（-----BEGIN PRIVATE KEY----- / RSA PRIVATE KEY 包装，或 Base64/Hex DER）');
    }
    var der = Array.from(asn1ExtractDer(el.value).bytes);
    return rsaParsePkcs8Priv(der).privPkcs8; // 非 RSA / 不识别的结构在此抛中文错误
}

// ---------------- Section 2：RSA 加解密（页面动作） ----------------

// 算法单选 → 标签
function rsaEncAlgLabel() {
    var v = gmGetRadio('rsa-enc-alg') || 'oaep256';
    if (v === 'oaep1') { return 'RSA-OAEP-SHA1'; }
    if (v === 'pkcs1v5') { return 'RSA-PKCS1-v1_5（legacy）'; }
    return 'RSA-OAEP-SHA256';
}

// "加密"按钮：明文文本 → Base64 密文
async function rsaEncrypt() {
    var resultEl = document.getElementById('rsa-enc-result');
    try {
        var text = document.getElementById('rsa-enc-input').value;
        if (!text) {
            throw new Error('请输入明文文本');
        }
        var algV = gmGetRadio('rsa-enc-alg') || 'oaep256';
        var pubSpki = rsaResolvePubSpki();
        var msg = rsaUtf8ToBytes(text);
        var pub = rsaParseSpki(pubSpki); // 模长预检（Web Crypto 超长报错信息不友好，先行中文提示）

        var cipher;
        if (algV === 'pkcs1v5') {
            // legacy：浏览器 Web Crypto 已移除 RSAES-PKCS1-v1_5，走手写 BigInt 实现
            if (msg.length > pub.n.length - 11) {
                throw new Error('RSA-PKCS1-v1_5 明文过长：最多 ' + (pub.n.length - 11) +
                    ' 字节（模长 ' + pub.bits + ' 位 − 11），当前 ' + msg.length + ' 字节');
            }
            cipher = rsaPkcs1EncryptCore(pub.n, pub.e, msg);
        } else {
            var hash = algV === 'oaep1' ? 'SHA-1' : 'SHA-256';
            var hLen = hash === 'SHA-1' ? 20 : 32;
            var maxLen = pub.n.length - 2 * hLen - 2; // OAEP 上限 = k − 2×hLen − 2
            if (msg.length > maxLen) {
                throw new Error('OAEP 明文过长：最多 ' + maxLen + ' 字节（模长 ' + pub.bits + ' 位 / 哈希 ' +
                    hash + ' 下：模长字节 ' + pub.n.length + ' − 2×' + hLen + ' − 2），当前 ' + msg.length + ' 字节；请减小明文或增大模长');
            }
            cipher = await rsaOaepEncryptCore(pubSpki, hash, msg);
        }
        resultEl.className = 'result-area';
        resultEl.textContent = ktBytesToBase64(cipher);
        showNotification('加密完成（' + rsaEncAlgLabel() + '，' + cipher.length + ' 字节密文，Base64 输出）');
    } catch (e) {
        gmShowError('rsa-enc-result', e);
    }
}

// "解密"按钮：密文（Base64，容忍 Hex）→ 明文（UTF-8 文本，非 UTF-8 数据改显 Hex）
async function rsaDecrypt() {
    var resultEl = document.getElementById('rsa-enc-result');
    try {
        var input = document.getElementById('rsa-enc-input').value;
        if (!input.trim()) {
            throw new Error('请输入密文（Base64；本工具亦容忍 Hex 输入）');
        }
        var algV = gmGetRadio('rsa-enc-alg') || 'oaep256';
        var cipher = ktInputToBytes(input); // Hex/Base64 自动识别
        var privPkcs8 = rsaResolvePrivPkcs8();

        var plain;
        if (algV === 'pkcs1v5') {
            plain = rsaPkcs1DecryptCore(rsaParsePkcs8Priv(privPkcs8), cipher);
        } else {
            var hash = algV === 'oaep1' ? 'SHA-1' : 'SHA-256';
            plain = await rsaOaepDecryptCore(privPkcs8, hash, cipher);
        }

        // 展示口径：能按 UTF-8 无损解码则显文本，否则改显大写 Hex（二进制明文）
        var text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(plain));
        resultEl.className = 'result-area';
        if (/�/.test(text)) {
            resultEl.textContent = '（明文含非 UTF-8 字节，' + plain.length + ' 字节）Hex：\n' +
                ktBytesToHex(plain).toUpperCase();
        } else {
            resultEl.textContent = text;
        }
        showNotification('解密完成（' + rsaEncAlgLabel() + '）');
    } catch (e) {
        gmShowError('rsa-enc-result', e);
    }
}

// "清空"按钮
function rsaEncClear() {
    document.getElementById('rsa-enc-input').value = '';
    document.getElementById('rsa-enc-result').textContent = '';
}

// ---------------- Section 3：RSA 签名 / 验签（页面动作） ----------------

// 签名算法单选 → { alg, label }（RSA-PSS 带 saltLength 32）
function rsaSignAlgConf() {
    var v = gmGetRadio('rsa-sign-alg') || 'pkcs1v5-256';
    if (v === 'pss256') {
        return { alg: { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 }, label: 'RSA-PSS-SHA256（salt 32 字节）' };
    }
    if (v === 'pkcs1v5-384') {
        return { alg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, label: 'RSASSA-PKCS1-v1_5-SHA384' };
    }
    if (v === 'pkcs1v5-512') {
        return { alg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, label: 'RSASSA-PKCS1-v1_5-SHA512' };
    }
    return { alg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, label: 'RSASSA-PKCS1-v1_5-SHA256' };
}

// "签名"按钮：消息文本 → Base64 签名值（回填签名值框，便于直接点"验签"自测）
async function rsaSign() {
    var resultEl = document.getElementById('rsa-sign-result');
    try {
        var msg = document.getElementById('rsa-sign-input').value;
        if (!msg) {
            throw new Error('请输入待签名消息');
        }
        var conf = rsaSignAlgConf();
        var privPkcs8 = rsaResolvePrivPkcs8();
        var sig = await rsaSignCore(privPkcs8, conf.alg, rsaUtf8ToBytes(msg));
        var sigB64 = ktBytesToBase64(sig);
        document.getElementById('rsa-sign-value').value = sigB64;
        resultEl.className = 'result-area gm-oneline';
        resultEl.textContent = '✅ 签名完成（' + conf.label + '，' + sig.length + ' 字节签名，Base64 已填入上方签名值框）';
        showNotification('RSA 签名完成，可直接点击"验签"自测');
    } catch (e) {
        gmShowError('rsa-sign-result', e);
    }
}

// "验签"按钮：签名值（Base64/Hex）✅/❌ 红绿显示
async function rsaVerify() {
    var resultEl = document.getElementById('rsa-sign-result');
    try {
        var msg = document.getElementById('rsa-sign-input').value;
        if (!msg) {
            throw new Error('请输入待验签消息');
        }
        var sigInput = document.getElementById('rsa-sign-value').value;
        if (!sigInput.trim()) {
            throw new Error('请粘贴待验证的签名值（Base64 或 Hex）');
        }
        var conf = rsaSignAlgConf();
        var pubSpki = rsaResolvePubSpki();
        var sig = ktInputToBytes(sigInput);
        var ok = await rsaVerifyCore(pubSpki, conf.alg, rsaUtf8ToBytes(msg), sig);
        resultEl.className = 'result-area gm-oneline ' + (ok ? 'jwt-valid' : 'jwt-invalid');
        resultEl.textContent = ok
            ? '✅ 验签通过（' + conf.label + '）'
            : '❌ 验签失败：签名与消息 / 公钥 / 算法不匹配';
        showNotification(ok ? '验签通过' : '验签失败');
    } catch (e) {
        gmShowError('rsa-sign-result', e);
    }
}

// "清空"按钮
function rsaSignClear() {
    document.getElementById('rsa-sign-input').value = '';
    document.getElementById('rsa-sign-value').value = '';
    document.getElementById('rsa-sign-result').textContent = '';
}

// ============================================================
// Section 4：CSR 生成（PKCS#10）—— 手写 DER 组装（纯函数区）
// ============================================================
// PKCS#10 CertificationRequest 结构（RFC 2986）：
//   CertificationRequest ::= SEQUENCE {
//     certificationRequestInfo  CertificationRequestInfo,  -- 待签名的 CRI（DER 原字节参与签名）
//     signatureAlgorithm        AlgorithmIdentifier,       -- SM2: 1.2.156.10197.1.501 / RSA: sha256WithRSAEncryption
//     signature                 BIT STRING }               -- 内容 = 0x00(未用位数) || 签名值
//   CertificationRequestInfo ::= SEQUENCE {
//     version       INTEGER 0,
//     subject       Name(RDNSequence),        -- SEQUENCE OF RDN；每属性 RDN = SET{ SEQ{OID, 类型值} }
//     subjectPKInfo SubjectPublicKeyInfo,     -- SM2 = SEQ{SEQ{OID ecPublicKey, OID SM2曲线}, BIT STRING}（双 OID 标准形态，GmSSL 兼容）
//                                              -- RSA = Web Crypto 导出的 spki DER 直接使用
//     attributes    [0] IMPLICIT }            -- 空属性 → A0 00（无扩展请求）
//
// DN 值类型（口径同 OpenSSL）：CN/O/OU → UTF8String(0x0C)，C → PrintableString(0x13)（2 字母），
// E(emailAddress 1.2.840.113549.1.9.1) → IA5String(0x16)。
// RDN 顺序按页面字段布局输出：CN → O → OU → C → E（仅编码非空项）。

// ASCII 文本 → 字节（PrintableString / IA5String 用）；含非 ASCII 抛中文错误
function csrAsciiBytes(str, what) {
    var out = [];
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        if (code > 0x7F) {
            throw new Error(what + '含非 ASCII 字符（该字段仅允许英文、数字与符号）');
        }
        out.push(code);
    }
    return out;
}

// DN 对象（cn/o/ou/c/e，空项跳过）→ Name(RDNSequence) DER
function csrDnDer(dn) {
    var rdns = [];
    for (var i = 0; i < CSR_DN_SPECS.length; i++) {
        var spec = CSR_DN_SPECS[i];
        var value = dn[spec.key];
        if (!value) { continue; }
        var content = (spec.tag === 0x0C) ? rsaUtf8ToBytes(value) : csrAsciiBytes(value, spec.label + ' 字段');
        // RDN = SET(0x31){ SEQ(0x30){ OID, 值 } }——一属性一 SET（与 OpenSSL 输出同构）
        rdns.push(gmDerTlv(0x31,
            gmDerTlv(0x30, gmDerTlv(0x06, ktOidToDerContent(spec.oid)).concat(gmDerTlv(spec.tag, content)))));
    }
    if (!rdns.length) {
        throw new Error('DN 至少需要一个属性（CN 必填）');
    }
    return gmDerTlv(0x30, Array.prototype.concat.apply([], rdns));
}

// CRI 组装：SEQ{ INTEGER 0, Name, SPKI(完整 TLV 原样放入), [0]{} }
function csrBuildCri(dn, spkiBytes) {
    return gmDerTlv(0x30, []
        .concat(
            gmDerTlv(0x02, [0]),          // version 0
            csrDnDer(dn),                  // subject Name
            rsaToArray(spkiBytes),          // subjectPKInfo（调用方传入完整 TLV）
            gmDerTlv(0xA0, [])             // attributes [0] IMPLICIT 空属性
        ));
}

// CSR 顶层组装：SEQ{ CRI, AlgorithmIdentifier, BIT STRING(00||签名) }
function csrAssemble(criBytes, algIdBytes, sigBytes) {
    return gmDerTlv(0x30, []
        .concat(rsaToArray(criBytes), rsaToArray(algIdBytes),
            gmDerTlv(0x03, [0x00].concat(rsaToArray(sigBytes)))));
}

// SM2 公钥(130 位 04 开头) → SPKI 双 OID 标准形态 DER：
//   SEQUENCE { SEQUENCE { OID 1.2.840.10045.2.1 ecPublicKey, OID 1.2.156.10197.1.301 SM2 曲线 },
//              BIT STRING( 00 || 04||X||Y ) }
//（国产简化写法是曲线 OID 直接作 algorithm——见 1.key；CSR 采用 ecPublicKey + SM2 双 OID
//  标准形态，GmSSL / OpenSSL 3.x+ / 铜锁均按此口径解析 SM2 公钥）
function csrSm2SpkiDer(pubHex130) {
    var algId = gmDerTlv(0x30,
        gmDerTlv(0x06, ktOidToDerContent('1.2.840.10045.2.1')).concat(
            gmDerTlv(0x06, ktOidToDerContent('1.2.156.10197.1.301'))));
    return gmDerTlv(0x30, algId.concat(gmDerTlv(0x03, [0x00].concat(ktHexToBytes(pubHex130)))));
}

// SM2 CSR 构建核心（纯函数）：dn + 私钥(64 位 Hex) + 公钥(130 位 04 开头) → { csrDer, criDer, sigHex, privPem }
// 签名算法：SM2Sign-with-SM3（OID 1.2.156.10197.1.501，国标 GM/T 0006；GmSSL 同口径），
//           AlgorithmIdentifier 不带参数（国密算法惯例，与 GmSSL 输出一致）
function csrBuildSm2Core(dn, privHex, pubHex130) {
    var priv = String(privHex == null ? '' : privHex).replace(/[\s:,]/g, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(priv)) {
        throw new Error('SM2 私钥必须是 64 位 Hex（32 字节）');
    }
    var pub = String(pubHex130 == null ? '' : pubHex130).replace(/[\s:,]/g, '').toLowerCase();
    if (/^[0-9a-f]{128}$/.test(pub)) {
        pub = '04' + pub; // 128 位裸坐标 → 补未压缩点前缀
    }
    if (!/^04[0-9a-f]{128}$/.test(pub)) {
        throw new Error('SM2 公钥必须是 04 开头的 130 位 Hex（未压缩点）');
    }

    var spki = csrSm2SpkiDer(pub);
    var cri = csrBuildCri(dn, spki);

    // ⚠️ sm-crypto 0.3.2 坑点（见文件头）：doSignature 的 msg 按字符串 = UTF-8 文本处理，
    // 传 CRI 的 hex 字符串会被二次编码、签名必错！必须把 CRI DER 字节作为【数组】传入
    // （库对数组按原始字节处理），{hash:true} 走国标 ZA 预处理（UserId 用库默认
    // '1234567812345678'），der:true 返回 DER 编码签名 hex。
    var criBytes = rsaToArray(cri);
    var sigHex = smCrypto.sm2.doSignature(criBytes, priv, { hash: true, der: true });

    // 回验自检：同口径 doVerifySignature 必须通过（推导公钥/编码错误在此拦截）
    if (!smCrypto.sm2.doVerifySignature(criBytes, sigHex, pub, { hash: true, der: true })) {
        throw new Error('内部错误：SM2 CSR 签名回验未通过，已放弃输出');
    }

    var algId = gmDerTlv(0x30, gmDerTlv(0x06, ktOidToDerContent('1.2.156.10197.1.501')));
    var csrDer = csrAssemble(cri, algId, ktHexToBytes(sigHex));
    return {
        csrDer: csrDer,
        criDer: cri,
        sigHex: sigHex.toUpperCase(),
        // 私钥配套输出：国产 PKCS#8 形态（含 SM2 曲线 OID 与公钥，GmSSL 可直接使用）
        privPem: kt9PrivToPkcs8Pem(priv, pub.substr(2))
    };
}

// RSA CSR 组装核心（纯函数）：签名值由调用方生成（页面走 Web Crypto，Node 打拍走 node:crypto）
// 签名算法固定 sha256WithRSAEncryption（OID 1.2.840.113549.1.1.11 + NULL 参数）
function csrBuildRsaCore(dn, spkiBytes, sigBytes) {
    var cri = csrBuildCri(dn, spkiBytes);
    var algId = gmDerTlv(0x30,
        gmDerTlv(0x06, ktOidToDerContent('1.2.840.113549.1.1.11')).concat(gmDerTlv(0x05, [])));
    return { csrDer: csrAssemble(cri, algId, sigBytes), criDer: cri };
}

// ---------------- SM2 私钥 → 公钥推导（BigInt，雅可比坐标点乘） ----------------

// SM2 私钥(64 位 Hex) → 公钥(130 位 04 开头 Hex)。
// sm-crypto 0.3.2 未导出 getPublicKeyFromPrivateKey（doSignature 内部私有），此处以
// BigInt 雅可比坐标 d·G 自实现（参数与 vendor/sm-crypto.js generateEcparam 同源），
// 用于"粘贴 PKCS#8 私钥生成 CSR"场景（CSR 的 SPKI 需要公钥）。
function sm2PubFromPriv(privHex) {
    var P = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF');
    var A = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'); // = p − 3 ≡ −3
    var B = BigInt('0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93');
    var GX = BigInt('0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7');
    var GY = BigInt('0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0');
    var d = BigInt('0x' + String(privHex).replace(/[\s:,]/g, ''));
    if (d <= BigInt(0)) {
        throw new Error('SM2 私钥值非法');
    }
    var m = function (x) { return ((x % P) + P) % P; }; // BigInt % 可能为负，统一归正
    // 注意：JS 不允许 Number 与 BigInt 混合乘加（4 * BigInt 抛 TypeError），系数一律用 BigInt 常量
    var TWO = BigInt(2), THREE = BigInt(3), FOUR = BigInt(4), EIGHT = BigInt(8);

    // 雅可比加点 (X1,Y1,Z1) + (X2,Y2,Z2)（通用式；一方为无穷远点直接返回另一方）
    var jAdd = function (p1, p2) {
        if (!p1) { return p2; }
        if (!p2) { return p1; }
        var Z1Z1 = m(p1[2] * p1[2]);
        var Z2Z2 = m(p2[2] * p2[2]);
        var U1 = m(p1[0] * Z2Z2);
        var U2 = m(p2[0] * Z1Z1);
        var S1 = m(p1[1] * Z2Z2 * p2[2]);
        var S2 = m(p2[1] * Z1Z1 * p1[2]);
        if (U1 === U2) {
            return (S1 === S2) ? jDouble(p1) : null; // 同 X 异 Y → 无穷远
        }
        var H = m(U2 - U1);
        var R = m(S2 - S1);
        var HH = m(H * H);
        var HHH = m(HH * H);
        var V = m(U1 * HH);
        var X3 = m(R * R - HHH - m(TWO * V));
        var Y3 = m(R * (V - X3) - S1 * HHH);
        var Z3 = m(H * p1[2] * p2[2]);
        return [X3, Y3, Z3];
    };

    // 雅可比倍点（a = −3 简式：M = 3(X−Z²)(X+Z²)，全程免模逆）
    var jDouble = function (pt) {
        if (!pt || pt[1] === BigInt(0)) { return null; }
        var XX = m(pt[0] * pt[0]);
        var YY = m(pt[1] * pt[1]);
        var YYYY = m(YY * YY);
        var ZZ = m(pt[2] * pt[2]);
        var S = m(FOUR * pt[0] * YY);
        var M = m(THREE * (pt[0] - ZZ) * (pt[0] + ZZ)); // a = −3 简式
        var X3 = m(M * M - TWO * S);
        var Y3 = m(M * (S - X3) - EIGHT * YYYY);
        var Z3 = m(TWO * pt[1] * pt[2]);
        return [X3, Y3, Z3];
    };

    // 从最高位起 double-and-add：acc = d·G
    var acc = null;
    var base = [GX, GY, BigInt(1)]; // 仿射 → 雅可比（Z = 1）
    var bits = d.toString(2);
    for (var i = 0; i < bits.length; i++) {
        acc = jDouble(acc);
        if (bits.charAt(i) === '1') {
            acc = jAdd(acc, base);
        }
    }
    if (!acc) {
        throw new Error('SM2 公钥推导得到无穷远点（私钥非法）');
    }

    // 雅可比 → 仿射：x = X/Z²，y = Y/Z³（一次性模逆）
    var zInv = rsaModInverse(acc[2], P);
    var zInv2 = m(zInv * zInv);
    var x = m(acc[0] * zInv2);
    var y = m(acc[1] * zInv2 * zInv);

    // 在曲线上的自检：y² ≡ x³ + ax + b (mod p)
    if (m(y * y) !== m(x * x * x + A * x + B)) {
        throw new Error('SM2 公钥推导结果不在曲线上（内部错误）');
    }

    var pad = function (hex) {
        while (hex.length < 64) { hex = '0' + hex; }
        return hex;
    };
    return '04' + pad(x.toString(16)) + pad(y.toString(16));
}

// 粘贴的私钥 DER → SM2 私钥 Hex（PKCS#8[含国产写法] / SEC1 均支持；曲线非 SM2 时抛错）
function csrExtractSm2Priv(derBytes) {
    var der = rsaToArray(derBytes);
    var info = ktParsePrivateKey(der);
    if (info.kind !== 'pkcs8' && info.kind !== 'sec1-ec') {
        throw new Error('不是可识别的 SM2 私钥（支持 PKCS#8 / SEC1；RSA 私钥请选择 RSA 流程）');
    }
    if (info.curveOid && info.curveOid !== '1.2.156.10197.1.301') {
        throw new Error('私钥曲线不是 SM2（识别为 ' + info.curveOid + '），本工具 CSR 仅支持 SM2');
    }
    var inner = der;
    if (info.kind === 'pkcs8') {
        var root = asn1ParseTlv(der, 0, der.length, 0);
        inner = rsaToArray(rsaContent(root.children[2])); // privateKey OCTET STRING = SEC1
    }
    // SEC1：SEQ{ INTEGER 1(可选), OCTET STRING d, [0]曲线?, [1]公钥? }
    var seq = asn1ParseTlv(inner, 0, inner.length, 0);
    var kids = seq.children || [];
    var dIdx = (kids.length > 0 && kids[0].tagFirst === 0x02) ? 1 : 0;
    if (kids.length <= dIdx || kids[dIdx].tagFirst !== 0x04) {
        throw new Error('SEC1 私钥结构异常（未找到 privateKey OCTET STRING）');
    }
    var d = rsaToArray(rsaContent(kids[dIdx]));
    if (d.length > 32) {
        throw new Error('SM2 私钥长度 ' + d.length + ' 字节异常（应 ≤ 32 字节）');
    }
    while (d.length < 32) { d.unshift(0); } // 去前导零的 DER 整数左补零回 32 字节定长
    return ktBytesToHex(d);
}

// ---------------- Section 4：页面动作 ----------------

// 读取并校验 DN 五字段（CN 必填；C 限 2 字母；E 限 ASCII）
function csrReadDn() {
    var dn = {
        cn: document.getElementById('csr-cn').value.trim(),
        o: document.getElementById('csr-o').value.trim(),
        ou: document.getElementById('csr-ou').value.trim(),
        c: document.getElementById('csr-c').value.trim(),
        e: document.getElementById('csr-e').value.trim()
    };
    if (!dn.cn) {
        throw new Error('CN（通用名）必填，如 example.com 或 姓名');
    }
    if (dn.c && !/^[A-Za-z]{2}$/.test(dn.c)) {
        throw new Error('C（国家代码）必须是 2 个字母（ISO 3166-1，如 CN、US；PrintableString 编码）');
    }
    return dn;
}

// CSR 结构自检（asn1ParseTlv 整体解析 + 四行结构描述 + DN 明细）
function csrSelfCheckLines(csrDer, sigAlgName) {
    var root = asn1ParseTlv(csrDer, 0, csrDer.length, 0);
    var kids = root.children || [];
    if (root.tagFirst !== 0x30 || kids.length !== 3) {
        throw new Error('自检失败：顶层应为 SEQUENCE 且含 3 个子节点（CRI / 签名算法 / 签名值），当前 ' + kids.length);
    }
    var cri = kids[0];
    if (cri.tagFirst !== 0x30 || cri.children.length !== 4 ||
        cri.children[0].tagFirst !== 0x02 || rsaIntValue(cri.children[0]) !== 0) {
        throw new Error('自检失败：CRI 应为 SEQ{ INTEGER 0, Name, SPKI, [0] }');
    }
    if (kids[1].tagFirst !== 0x30 || !kids[1].children.length || kids[2].tagFirst !== 0x03) {
        throw new Error('自检失败：签名算法 / 签名值结构异常');
    }

    // DN 明细：每个 RDN(SET) → SEQ{OID, 值}，按 tag 类型解码值
    var dnKids = cri.children[1].children || [];
    var dnParts = [];
    var tagNames = { 0x0C: 'UTF8String', 0x13: 'PrintableString', 0x16: 'IA5String' };
    var labelByOid = {};
    for (var s = 0; s < CSR_DN_SPECS.length; s++) {
        labelByOid[CSR_DN_SPECS[s].oid] = CSR_DN_SPECS[s].label;
    }
    for (var i = 0; i < dnKids.length; i++) {
        var atv = (dnKids[i].children || [])[0];
        if (!atv || atv.children.length < 2) {
            throw new Error('自检失败：RDN 结构异常');
        }
        var oid = asn1DecodeOid(rsaContent(atv.children[0]));
        var valNode = atv.children[1];
        var content = rsaContent(valNode);
        var text = (valNode.tagFirst === 0x0C)
            ? new TextDecoder('utf-8').decode(new Uint8Array(content))
            : String.fromCharCode.apply(null, content);
        dnParts.push((labelByOid[oid] || oid) + '=' + text +
            '（' + (tagNames[valNode.tagFirst] || '0x' + valNode.tagFirst.toString(16)) + '）');
    }

    return [
        '✅ 结构自检通过（DER 共 ' + csrDer.length + ' 字节，asn1ParseTlv 可整体解析）：',
        '1. CertificationRequestInfo = SEQUENCE { INTEGER 0（版本）, Name（' + dnKids.length + ' 个 RDN）, SubjectPublicKeyInfo（' + cri.children[2].totalLen + ' 字节）, [0] 空属性 }',
        '2. signatureAlgorithm = ' + (sigAlgName || asn1DecodeOid(rsaContent(kids[1].children[0]))),
        '3. signature = BIT STRING（' + (kids[2].contentLen - 1) + ' 字节签名值）',
        '4. DN 明细：' + dnParts.join('，')
    ];
}

// 密钥来源切换：paste 模式显示私钥粘贴框
function csrKeySrcChanged() {
    var paste = (gmGetRadio('csr-key-src') || 'sm2') === 'paste';
    document.getElementById('csr-priv-pem-row').style.display = paste ? '' : 'none';
}

// RSA CSR 的签名 + 组装（页面与 paste 分支共用）：
// 生成 / 导入密钥后对 CRI 做 RSASSA-PKCS1-v1_5-SHA256 签名并回验，再交 csrBuildRsaCore 组装
async function csrRsaBuild(dn, spkiBytes, privPkcs8Bytes) {
    var alg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    var cri = csrBuildCri(dn, spkiBytes);
    var sig = await rsaSignCore(privPkcs8Bytes, alg, rsaToArray(cri));
    var ok = await rsaVerifyCore(spkiBytes, alg, rsaToArray(cri), sig);
    if (!ok) {
        throw new Error('内部错误：RSA CSR 签名回验未通过，已放弃输出');
    }
    return csrBuildRsaCore(dn, spkiBytes, sig);
}

// "生成 CSR"按钮：按密钥来源单选分发
async function csrGen() {
    var checkEl = document.getElementById('csr-check-result');
    try {
        var dn = csrReadDn();
        var src = gmGetRadio('csr-key-src') || 'sm2';
        var csrDer, privPem = '', note;

        if (src === 'sm2') {
            // SM2：现场生成密钥对 → 手写 DER 组装 + doSignature（数组口径，见纯函数区坑点注释）
            var pair = smCrypto.sm2.generateKeyPairHex();
            var r = csrBuildSm2Core(dn, pair.privateKey, pair.publicKey);
            csrDer = r.csrDer;
            privPem = r.privPem;
            note = 'SM2（SM2Sign-with-SM3 签名，UserId 为国标默认 1234567812345678；配套私钥见下方输出）';
        } else if (src === 'rsa') {
            // RSA-2048：Web Crypto 生成（签名用途单算法生成即可，无 usages 合并问题）
            var kp = await crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
                true, ['sign', 'verify']);
            var spki = Array.from(new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey)));
            var pkcs8 = Array.from(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)));
            var built = await csrRsaBuild(dn, spki, pkcs8);
            csrDer = built.csrDer;
            privPem = ktBuildPem('PRIVATE KEY', pkcs8);
            note = 'RSA-2048（sha256WithRSAEncryption 签名，openssl req -verify 可验证；配套私钥见下方输出）';
        } else {
            // paste：粘贴 PKCS#8 私钥（SM2 或 RSA 自动识别）
            var pemEl = document.getElementById('csr-priv-pem');
            if (!pemEl.value.trim()) {
                throw new Error('请粘贴 PKCS#8 私钥 PEM（SM2 或 RSA；RSA 的 PKCS#1 形态亦可）');
            }
            var der = Array.from(asn1ExtractDer(pemEl.value).bytes);
            var info = ktParsePrivateKey(der);
            var isRsa = info.kind === 'pkcs1-rsa' || (info.kind === 'pkcs8' && info.algOid === '1.2.840.113549.1.1.1');
            if (isRsa) {
                var parts = rsaParsePkcs8Priv(der);
                var built2 = await csrRsaBuild(dn, rsaSpkiFromParts(parts), parts.privPkcs8);
                csrDer = built2.csrDer;
                note = '粘贴的 RSA 私钥（公钥由私钥字段 n/e 重组，sha256WithRSAEncryption 签名）';
            } else {
                var privHex = csrExtractSm2Priv(der);
                var pubHex = sm2PubFromPriv(privHex); // 公钥由私钥推导（雅可比点乘）
                var r2 = csrBuildSm2Core(dn, privHex, pubHex);
                csrDer = r2.csrDer;
                note = '粘贴的 SM2 私钥（公钥由私钥推导：' + pubHex.substr(0, 16).toUpperCase() + '…，SM2Sign-with-SM3 签名）';
            }
        }

        document.getElementById('csr-result').value = ktBuildPem('CERTIFICATE REQUEST', csrDer);
        document.getElementById('csr-key-result').value =
            privPem || '（使用您粘贴的私钥签名，私钥不重复输出）';
        checkEl.className = 'result-area';
        checkEl.textContent = csrSelfCheckLines(csrDer).join('\n') + '\n——\n' + note;
        showNotification('CSR 生成完成并通过结构自检');
    } catch (e) {
        gmShowError('csr-check-result', e);
    }
}

// "清空"按钮（DN 保留，只清结果与粘贴框）
function csrClear() {
    document.getElementById('csr-priv-pem').value = '';
    document.getElementById('csr-result').value = '';
    document.getElementById('csr-key-result').value = '';
    document.getElementById('csr-check-result').textContent = '';
}

// Node 环境导出纯函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        rsaGenKeyCore: rsaGenKeyCore,
        rsaParseSpki: rsaParseSpki,
        rsaParsePkcs8Priv: rsaParsePkcs8Priv,
        rsaSpkiFromParts: rsaSpkiFromParts,
        rsaBytesToBigInt: rsaBytesToBigInt,
        rsaBigIntToFixedBytes: rsaBigIntToFixedBytes,
        rsaModPow: rsaModPow,
        rsaStripIntZeros: rsaStripIntZeros,
        rsaPkcs1EncryptCore: rsaPkcs1EncryptCore,
        rsaPkcs1DecryptCore: rsaPkcs1DecryptCore,
        rsaOaepEncryptCore: rsaOaepEncryptCore,
        rsaOaepDecryptCore: rsaOaepDecryptCore,
        rsaSignCore: rsaSignCore,
        rsaVerifyCore: rsaVerifyCore,
        csrDnDer: csrDnDer,
        csrBuildCri: csrBuildCri,
        csrAssemble: csrAssemble,
        csrSm2SpkiDer: csrSm2SpkiDer,
        csrBuildSm2Core: csrBuildSm2Core,
        csrBuildRsaCore: csrBuildRsaCore,
        sm2PubFromPriv: sm2PubFromPriv,
        csrExtractSm2Priv: csrExtractSm2Priv,
        csrSelfCheckLines: csrSelfCheckLines
    };
}
