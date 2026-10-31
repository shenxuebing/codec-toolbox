// ============================================================
// 密钥工具页 —— page-keytool（js/keytool.js）
// Section 1：私钥查看与 PKCS#1 ↔ PKCS#8 互转（RSA / ECC / SM2 通吃）
// Section 2：PKCS#12 / PFX 结构查看（仅结构，不解密）
// Section 3：GM/T 0009 加密密钥对解密（SM2 数字信封，头部两种口径自适应）
// Section 4：GM/T 0009 加密密钥对生成（生成后立即回解自测）
// Section 5：GM/T 0016/0018 密钥（ENVELOPEDKEYBLOB，解析/解密/生成/与 0009 互转）
// 依赖（须先于本文件加载，Node 打桩时挂到全局）：
//   js/asn1.js           → asn1ParseTlv / asn1DecodeOid / asn1OidName / asn1TagName / asn1ExtractDer
//                          （node 对象结构 { tagFirst, constructed, headerLen, contentStart,
//                          contentLen, children, rawBytes }，内容字节 = rawBytes.slice(headerLen)）
//   js/gmsm.js           → gmDerTlv / gmDerLen / sm2ConvDerToParts / sm2ConvJoinBare
//   js/vendor/sm-crypto.js → smCrypto.sm2 / smCrypto.sm4（0.3.2 本地化打包，自动挂 global.smCrypto）
// 纯函数（ktOidToDerContent / ktParsePrivateKey / ktToPkcs8Core / ktToPkcs1Core / ktBuildPem /
// ktP12StructSummary / kt9ParseHeader / kt9DecryptCore / kt9GenCore / kt9PrivToPkcs8Pem /
// kt16ParseCore / kt16DecryptCore / kt16BuildCore / kt16BlobTo0009Core / kt16From0009Core）
// 不触碰 DOM，可在 Node 中单独加载打桩测试（同 gmsm.js 模式）。
// ============================================================

// ---------------- 基础小工具（gmsm.js 未导出的转换函数本地自备，避免 Node 端跨文件接线） ----------------

// 取 TLV 节点的内容字节（tag + 长度字段之后的部分；口径同 js/cert.js 的 certContent）
function ktContent(node) {
    return node.rawBytes.slice(node.headerLen);
}

// Buffer / TypedArray / 普通数组 → 普通数组归一化（gmDerTlv 等用 Array.prototype.concat
// 拼装，concat 不会展开 TypedArray——Buffer 整体会被当成单个元素导致 DER 拼装错误）
function ktToArray(bytes) {
    return Array.prototype.slice.call(bytes);
}

// 字节数组 → 小写 Hex 字符串（无分隔）
function ktBytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
}

// Hex 字符串 → 字节数组（容忍空白与 : , 分隔符，统一小写）；非法抛中文错误
function ktHexToBytes(hex) {
    var cleaned = String(hex == null ? '' : hex).replace(/[\s:,]/g, '').toLowerCase();
    if (cleaned === '') {
        throw new Error('Hex 数据为空');
    }
    if (!/^[0-9a-f]+$/.test(cleaned) || cleaned.length % 2 !== 0) {
        throw new Error('不是合法的 Hex 字符串（长度须为偶数且仅含 0-9 a-f）');
    }
    var out = [];
    for (var i = 0; i < cleaned.length; i += 2) {
        out.push(parseInt(cleaned.substr(i, 2), 16));
    }
    return out;
}

// 字节数组 → Base64（分块拼接避免大数组 fromCharCode 参数超限；btoa 为浏览器/Node 16+ 全局）
function ktBytesToBase64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i += 1024) {
        bin += String.fromCharCode.apply(null, bytes.slice(i, Math.min(i + 1024, bytes.length)));
    }
    return btoa(bin);
}

// 输入自动识别：合法偶数位 Hex 按 Hex 解，否则按 Base64 解（GM/T 0009 密文输入用）
function ktInputToBytes(text) {
    var cleaned = String(text == null ? '' : text).replace(/[\s:,]/g, '');
    if (cleaned === '') {
        throw new Error('输入内容为空');
    }
    if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0) {
        return ktHexToBytes(cleaned);
    }
    // Base64 → 字节：兼容 base64url 变体（-_ → +/），去原填充后按剩余长度统一补齐
    var b64 = cleaned.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    if (!/^[A-Za-z0-9+/]+$/.test(b64) || b64.length % 4 === 1) {
        throw new Error('不是合法的 Hex / Base64 输入');
    }
    var pad = (4 - (b64.length % 4)) % 4;
    for (var p = 0; p < pad; p++) {
        b64 += '=';
    }
    var bin;
    try {
        bin = atob(b64);
    } catch (e) {
        throw new Error('不是合法的 Base64 字符串');
    }
    var out = [];
    for (var i = 0; i < bin.length; i++) {
        out.push(bin.charCodeAt(i));
    }
    return out;
}

// INTEGER 节点内容 → 非负数值（≤6 字节；空 / 超长 / 负数返回 null，不参与版本号判断）
function ktIntValue(node) {
    var c = ktContent(node);
    if (c.length === 0 || c.length > 6 || (c[0] & 0x80)) {
        return null;
    }
    var v = 0;
    for (var i = 0; i < c.length; i++) {
        v = v * 256 + c[i];
    }
    return v;
}

// 无符号大整数有效位长（RSA 模长用）：去前导零后按首字节最高位 1 计（口径同 js/cert.js）
function ktIntBitLen(bytes) {
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

// ---------------- OID 编码与曲线表（Section 1 / Section 3 共用） ----------------

// base-128 变体编码（OID 内容字节用）：低位组在后、非末组最高位置 1
function ktBase128(out, v) {
    var stack = [v & 0x7F];
    v = Math.floor(v / 128);
    while (v > 0) {
        stack.push((v % 128) | 0x80);
        v = Math.floor(v / 128);
    }
    for (var i = stack.length - 1; i >= 0; i--) {
        out.push(stack[i]);
    }
}

// 点分 OID → DER 内容字节（首两节点按 40*a+b 合并）；非法抛中文错误
function ktOidToDerContent(dot) {
    var parts = String(dot == null ? '' : dot).split('.');
    if (parts.length < 2) {
        throw new Error('OID 至少要有两个节点：' + dot);
    }
    var nums = [];
    for (var i = 0; i < parts.length; i++) {
        if (!/^\d+$/.test(parts[i])) {
            throw new Error('OID 含非法节点（' + parts[i] + '）：' + dot);
        }
        nums.push(parseInt(parts[i], 10));
    }
    var out = [];
    ktBase128(out, nums[0] * 40 + nums[1]); // 0.x / 1.x 时 b<40；2.x 分支允许 b 任意大
    for (var j = 2; j < nums.length; j++) {
        ktBase128(out, nums[j]);
    }
    return out;
}

// 常用算法 / 曲线 OID
var KT_OID_RSA = '1.2.840.113549.1.1.1';        // rsaEncryption
var KT_OID_EC_PUB = '1.2.840.10045.2.1';        // ecPublicKey
var KT_OID_SM2_CURVE = '1.2.156.10197.1.301';   // SM2 椭圆曲线（GM/T 0006）

// 曲线 OID → 名称（仅收录确信项；SM2 曲线 OID 亦被国产实现直接用作 PKCS#8 的 algorithm OID）
var KT_CURVE_NAMES = {
    '1.2.156.10197.1.301': 'SM2',
    '1.2.840.10045.3.1.7': 'prime256v1',
    '1.3.132.0.34': 'secp384r1',
    '1.3.132.0.35': 'secp521r1'
};

function ktCurveName(oid) {
    return (oid && KT_CURVE_NAMES.hasOwnProperty(oid)) ? KT_CURVE_NAMES[oid] : null;
}

// 曲线 OID → 展示文本：知名给名称，未知给"其他（点分）"，无 OID 提示到单选指定
function ktCurveDisplay(oid) {
    if (!oid) {
        return '未知（SEC1 无 [0] 曲线段，转 PKCS#8 前请在"曲线"单选中指定）';
    }
    var name = ktCurveName(oid);
    return name ? name + '（' + oid + '）' : '其他（' + oid + '）';
}

// ============================================================
// Section 1：私钥识别 + PKCS#1 ↔ PKCS#8 互转（纯函数区）
// ============================================================

// 私钥 DER 识别（纯函数），返回：
//   { kind: 'pkcs8-encrypted' | 'pkcs8' | 'sec1-ec' | 'pkcs1-rsa',
//     derLen, label, ... 各形态字段 }
// 四种形态的结构判定（口径注释）：
//   1) 加密 PKCS#8（EncryptedPrivateKeyInfo）：SEQ{ SEQ{OID 加密算法, 参数}, OCTET STRING 密文 }
//      —— 首子节点是"含 OID 的 SEQUENCE"而非版本 INTEGER，可与明文 PKCS#8 无歧义区分
//   2) 明文 PKCS#8（PrivateKeyInfo）：SEQ{ INTEGER 0, SEQ{OID alg, params}, OCTET STRING 内层私钥 }
//      —— alg 为 rsaEncryption（params NULL）/ ecPublicKey（params 为曲线 OID）/
//         SM2 曲线 OID 直接作 algorithm（国产写法，实测 1.key 即此形态）
//   3) ECC SEC1（RFC 5915）：SEQ{ INTEGER 1(可选，OpenSSL 均带), OCTET STRING d,
//      [0]{OID 曲线} 可选, [1] BIT STRING 公钥 可选 }
//   4) RSA PKCS#1（RSAPrivateKey）：SEQ{ INTEGER 0(version), INTEGER n, INTEGER e, INTEGER d, ... }
function ktParsePrivateKey(der) {
    if (!der || !der.length) {
        throw new Error('私钥数据为空');
    }
    var root = asn1ParseTlv(der, 0, der.length, 0);
    if (root.tagFirst !== 0x30 || !root.constructed) {
        throw new Error('私钥 DER 顶层应为 SEQUENCE（0x30），当前不是——请确认输入的是私钥');
    }
    var kids = root.children || [];
    if (kids.length < 2) {
        throw new Error('顶层 SEQUENCE 子节点过少（' + kids.length + ' 个），不是支持的私钥形态');
    }
    var info = { kind: null, derLen: der.length, label: '' };

    // ---- 形态 1：加密 PKCS#8（识别后只提示，不做转换）----
    if (kids[0].tagFirst === 0x30 && kids[0].children.length >= 1 &&
        kids[0].children[0].tagFirst === 0x06 && kids[1] && kids[1].tagFirst === 0x04) {
        info.kind = 'pkcs8-encrypted';
        info.label = 'ENCRYPTED PRIVATE KEY';
        info.encOid = asn1DecodeOid(ktContent(kids[0].children[0]));
        return info;
    }

    // ---- 形态 2：明文 PKCS#8 ----
    if (kids[0].tagFirst === 0x02 && ktIntValue(kids[0]) === 0 && kids.length >= 3 &&
        kids[1].tagFirst === 0x30 && kids[1].children.length >= 1 && kids[1].children[0].tagFirst === 0x06 &&
        kids[2].tagFirst === 0x04) {
        info.kind = 'pkcs8';
        info.label = 'PRIVATE KEY';
        info.algOid = asn1DecodeOid(ktContent(kids[1].children[0]));
        // params：rsaEncryption 为 NULL；ecPublicKey 的 params 是曲线 OID
        var paramOid = (kids[1].children.length > 1 && kids[1].children[1].tagFirst === 0x06)
            ? asn1DecodeOid(ktContent(kids[1].children[1]))
            : null;
        if (info.algOid === KT_OID_RSA) {
            info.algName = 'RSA（rsaEncryption）';
        } else if (info.algOid === KT_OID_EC_PUB) {
            info.curveOid = paramOid;
            info.algName = 'ECC（ecPublicKey' +
                (paramOid ? ' + 曲线 ' + (ktCurveName(paramOid) || paramOid) : '') + '）';
        } else if (info.algOid === KT_OID_SM2_CURVE) {
            // 国产写法：SM2 曲线 OID 直接作 algorithm（不走 ecPublicKey 包装），1.key 即此形态
            info.curveOid = info.algOid;
            info.algName = 'SM2（曲线 OID 直接作 algorithm，国产写法）';
        } else {
            info.algName = '未知算法（' + info.algOid + '）';
        }
        // 内层私钥（OCTET STRING 内容）本身是一份独立的 PKCS#1(RSA) / SEC1(ECC) DER，
        // 递归识别取字段摘要（模长 / 曲线 / 公钥有无）；失败不阻断识别
        try {
            var inner = ktParsePrivateKey(ktContent(kids[2]));
            if (inner.modulusBits != null) { info.modulusBits = inner.modulusBits; }
            if (inner.curveOid) { info.curveOid = inner.curveOid; }
            if (inner.hasPub != null) { info.hasPub = inner.hasPub; }
            if (inner.privLen != null) { info.privLen = inner.privLen; }
        } catch (e) { /* 内层非标准结构时仅缺字段摘要，不影响形态识别 */ }
        return info;
    }

    // ---- 形态 3：ECC SEC1（首子节点是 OCTET STRING，或 INTEGER 1 + OCTET STRING）----
    var dIdx = -1;
    if (kids[0].tagFirst === 0x04) {
        dIdx = 0;
    } else if (kids[0].tagFirst === 0x02 && ktIntValue(kids[0]) === 1 && kids[1] && kids[1].tagFirst === 0x04) {
        dIdx = 1; // RFC 5915 的 version(1) 前缀（OpenSSL 生成的 EC PRIVATE KEY 均带）
    }
    if (dIdx >= 0) {
        info.kind = 'sec1-ec';
        info.label = 'EC PRIVATE KEY';
        info.privLen = kids[dIdx].contentLen;
        for (var i = dIdx + 1; i < kids.length; i++) {
            var k = kids[i];
            // [0] IMPLICIT 曲线参数段：内含一个 OID
            if (k.tagFirst === 0xA0 && k.children.length >= 1 && k.children[0].tagFirst === 0x06 && !info.curveOid) {
                info.curveOid = asn1DecodeOid(ktContent(k.children[0]));
            } else if (k.tagFirst === 0xA1 && k.children.length >= 1 && k.children[0].tagFirst === 0x03) {
                // [1] IMPLICIT 公钥段：内含 BIT STRING
                info.hasPub = true;
            }
        }
        return info;
    }

    // ---- 形态 4：RSA PKCS#1（version=0 + 连续 INTEGER n/e/d）----
    if (kids[0].tagFirst === 0x02 && ktIntValue(kids[0]) === 0 && kids.length >= 4 &&
        kids[1].tagFirst === 0x02 && kids[2].tagFirst === 0x02 && kids[3].tagFirst === 0x02) {
        info.kind = 'pkcs1-rsa';
        info.label = 'RSA PRIVATE KEY';
        info.modulusBits = ktIntBitLen(ktContent(kids[1])); // 模长有效位（去前导零后）
        return info;
    }

    throw new Error('无法识别的私钥结构：不是 加密 PKCS#8 / PKCS#8 / RSA PKCS#1 / ECC SEC1 中的任一形态');
}

// PKCS#1(RSA) → PKCS#8：包一层 SEQUENCE{ INTEGER 0, SEQ{OID rsaEncryption, NULL}, OCTET STRING(原 DER) }
// SEC1(EC/SM2) → PKCS#8：SEQUENCE{ INTEGER 0, SEQ{OID ecPublicKey, OID 曲线}, OCTET STRING(原 SEC1 DER) }
//   —— 内层 SEC1 原样搬运不改写；曲线 OID 取 SEC1 的 [0] 段，无 [0] 时用 optCurveOid（页面单选传入）
// 已是 PKCS#8 的输入原样返回；加密 PKCS#8 抛错提示先解密（纯函数）
function ktToPkcs8Core(der, optCurveOid) {
    der = ktToArray(der); // 归一化为普通数组再参与 DER 拼装
    var info = ktParsePrivateKey(der);
    if (info.kind === 'pkcs8-encrypted') {
        throw new Error('加密私钥请先用 OpenSSL 解密（本工具暂不解密 PBES2），例如：openssl pkcs8 -topk8 -inform DER -in enc.key -out plain.key -passin pass:口令');
    }
    if (info.kind === 'pkcs8') {
        return { der: der, label: 'PRIVATE KEY', note: '输入已是 PKCS#8（' + info.algName + '），原样输出' };
    }
    if (info.kind === 'pkcs1-rsa') {
        var algRsa = gmDerTlv(0x30,
            gmDerTlv(0x06, ktOidToDerContent(KT_OID_RSA)).concat(gmDerTlv(0x05, []))); // params = NULL
        var derRsa = gmDerTlv(0x30,
            gmDerTlv(0x02, [0]).concat(algRsa, gmDerTlv(0x04, der)));
        return { der: derRsa, label: 'PRIVATE KEY', note: 'RSA PKCS#1 → PKCS#8（algorithm = rsaEncryption + NULL，内层原样搬运）' };
    }
    // sec1-ec：曲线 OID 优先取 SEC1 自带 [0] 段，其次外部指定（页面"曲线"单选）
    var curveOid = info.curveOid || optCurveOid;
    if (!curveOid) {
        throw new Error('SEC1 私钥未携带曲线 OID（无 [0] 参数段），请在"曲线"单选中指定后再转 PKCS#8');
    }
    var algEc = gmDerTlv(0x30,
        gmDerTlv(0x06, ktOidToDerContent(KT_OID_EC_PUB)).concat(gmDerTlv(0x06, ktOidToDerContent(curveOid))));
    var derEc = gmDerTlv(0x30,
        gmDerTlv(0x02, [0]).concat(algEc, gmDerTlv(0x04, der)));
    return {
        der: derEc, label: 'PRIVATE KEY',
        note: 'ECC SEC1 → PKCS#8（algorithm = ecPublicKey + 曲线 ' + curveOid +
            (ktCurveName(curveOid) ? '（' + ktCurveName(curveOid) + '）' : '') + '，内层 SEC1 原样搬运）'
    };
}

// PKCS#8 → PKCS#1(RSA) / SEC1(EC)：剥壳取 privateKey OCTET STRING 内容（原样，无需改写）
// 已是 PKCS#1 / SEC1 的输入原样返回并给出对应 PEM 标签；加密 PKCS#8 抛错提示先解密（纯函数）
function ktToPkcs1Core(der) {
    der = ktToArray(der); // 归一化为普通数组再参与 DER 拼装
    var info = ktParsePrivateKey(der);
    if (info.kind === 'pkcs8-encrypted') {
        throw new Error('加密私钥请先用 OpenSSL 解密（本工具暂不解密 PBES2），解密后即可转 PKCS#1 / SEC1');
    }
    if (info.kind === 'pkcs1-rsa') {
        return { der: der, label: 'RSA PRIVATE KEY', note: '输入已是 RSA PKCS#1，原样输出' };
    }
    if (info.kind === 'sec1-ec') {
        return {
            der: der, label: 'EC PRIVATE KEY',
            note: '输入已是 ECC SEC1' + (info.curveOid ? '（曲线 ' + ktCurveDisplay(info.curveOid) + '）' : '（无 [0] 曲线段）') + '，原样输出'
        };
    }
    // PKCS#8：重新定位第三个子节点（privateKey OCTET STRING），内容即内层 PKCS#1 / SEC1 DER
    var root = asn1ParseTlv(der, 0, der.length, 0);
    var inner = ktToArray(ktContent(root.children[2]));
    try {
        asn1ParseTlv(inner, 0, inner.length, 0); // 合法性校验：内层必须是完整 DER
    } catch (e) {
        throw new Error('PKCS#8 内层私钥 DER 解析失败：' + e.message);
    }
    var isRsa = info.algOid === KT_OID_RSA;
    var noteTail = '（原样，无需改写）';
    if (!isRsa) {
        // ECC 剥壳的特殊处理：OpenSSL / GmSSL 的 PKCS#8 内层 SEC1 通常不带 [0] 曲线段
        // （曲线放在外层 AlgorithmIdentifier 里），剥壳后作为独立 SEC1 会因无法确定曲线而不可用。
        // 外层曲线 OID 已知且内层缺 [0] 时补写 [0]{OID 曲线}（RFC 5915 字段序：
        // version, privateKey, [0] parameters, [1] publicKey），私钥 d 与公钥段原样保留——
        // 产物与 OpenSSL 直接导出的 EC PRIVATE KEY 逐字节一致；外层也无曲线时才按原样输出
        var innerInfo = ktParsePrivateKey(inner);
        if (innerInfo.kind === 'sec1-ec' && !innerInfo.curveOid && info.curveOid) {
            inner = ktSec1InjectCurve(inner, info.curveOid);
            noteTail = '（补写 [0] 曲线段 ' + info.curveOid + '，私钥与公钥原样保留）';
        }
    }
    return {
        der: inner,
        label: isRsa ? 'RSA PRIVATE KEY' : 'EC PRIVATE KEY',
        note: 'PKCS#8（' + info.algName + '）→ 剥壳取出内层' + (isRsa ? ' PKCS#1' : ' SEC1') + noteTail
    };
}

// SEC1 DER 内注入 [0]{OID 曲线} 段：插在 privateKey OCTET STRING 之后、[1] 公钥段之前
// （RFC 5915 字段序）；其余子节点完整 TLV 原样搬运
function ktSec1InjectCurve(sec1Bytes, curveOid) {
    var root = asn1ParseTlv(sec1Bytes, 0, sec1Bytes.length, 0);
    var kids = root.children;
    var dIdx = (kids[0].tagFirst === 0x04) ? 0 : 1; // OCTET 直接到场，或 INTEGER 1 + OCTET
    var parts = [];
    for (var i = 0; i < kids.length; i++) {
        parts.push(ktToArray(kids[i].rawBytes));
    }
    parts.splice(dIdx + 1, 0, gmDerTlv(0xA0, gmDerTlv(0x06, ktOidToDerContent(curveOid))));
    return gmDerTlv(0x30, Array.prototype.concat.apply([], parts));
}

// DER → PEM（Base64 按 64 字符折行，纯函数）
function ktBuildPem(label, der) {
    var b64 = ktBytesToBase64(der);
    var lines = b64.match(/.{1,64}/g) || [];
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----';
}

// 识别信息 → 展示文本（纯函数；格式类型 / DER 字节数 / 字段摘要三行口径）
function ktFormatKeyInfo(info) {
    var L = [];
    if (info.kind === 'pkcs8-encrypted') {
        L.push('格式：加密 PKCS#8（-----BEGIN ENCRYPTED PRIVATE KEY-----）');
        L.push('加密算法：' + (info.encOid || '未知 OID') +
            (info.encOid === '1.2.840.113549.1.5.13' ? '（PBES2）' : info.encOid === '1.2.840.113549.1.5.12' ? '（PBES1）' : ''));
        L.push('DER：' + info.derLen + ' 字节');
        L.push('⚠️ 加密私钥请先用 OpenSSL 解密（本工具暂不解密 PBES2），本工具不做转换');
        return L.join('\n');
    }
    if (info.kind === 'pkcs1-rsa') {
        L.push('格式：RSA PKCS#1（-----BEGIN RSA PRIVATE KEY-----）');
        L.push('DER：' + info.derLen + ' 字节｜模长：' + info.modulusBits + ' 位');
        return L.join('\n');
    }
    if (info.kind === 'sec1-ec') {
        L.push('格式：ECC SEC1（-----BEGIN EC PRIVATE KEY-----）' +
            (info.curveOid === KT_OID_SM2_CURVE ? '｜SM2 曲线（国产 1.key 的 PKCS#8 实为该结构）' : ''));
        L.push('曲线：' + ktCurveDisplay(info.curveOid));
        L.push('DER：' + info.derLen + ' 字节｜私钥：' + info.privLen + ' 字节｜公钥：' +
            (info.hasPub ? '有（[1] BIT STRING）' : '无'));
        return L.join('\n');
    }
    // pkcs8
    L.push('格式：PKCS#8（-----BEGIN PRIVATE KEY-----）');
    L.push('内部算法：' + info.algName);
    if (info.curveOid) { L.push('曲线：' + ktCurveDisplay(info.curveOid)); }
    if (info.modulusBits != null) { L.push('模长：' + info.modulusBits + ' 位'); }
    if (info.privLen != null) {
        L.push('内层私钥：' + info.privLen + ' 字节｜公钥：' + (info.hasPub ? '有' : '无'));
    }
    L.push('DER：' + info.derLen + ' 字节');
    return L.join('\n');
}

// ---------------- Section 1：页面动作 ----------------

// 读取私钥输入（textarea：PEM / Base64 / Hex → DER 字节，识别逻辑复用 asn1.js）
function ktReadKeyInput() {
    var el = document.getElementById('kt-key-input');
    if (!el || !el.value.trim()) {
        throw new Error('请先粘贴私钥（PEM 或 Base64/Hex DER）');
    }
    return asn1ExtractDer(el.value).bytes;
}

// Section 1 统一错误出口：识别区 + 结果区同时显示，并弹通知
function ktKeyError(e) {
    var msg = e && e.message ? e.message : String(e);
    var infoEl = document.getElementById('kt-key-info');
    if (infoEl) { infoEl.textContent = '❌ ' + msg; }
    var resEl = document.getElementById('kt-key-result');
    if (resEl) { resEl.value = '❌ ' + msg; }
    showNotification(msg);
}

// 取"曲线"单选（value 直接为曲线点分 OID，供 SEC1 无 [0] 段时转 PKCS#8 用）
function ktSelectedCurveOid() {
    var checked = document.querySelector('input[name="kt-ec-curve"]:checked');
    return checked ? checked.value : null;
}

// "查看与识别"按钮
function ktInspect() {
    try {
        var bytes = ktReadKeyInput();
        document.getElementById('kt-key-info').textContent = ktFormatKeyInfo(ktParsePrivateKey(bytes));
        showNotification('识别完成（DER ' + bytes.length + ' 字节）');
    } catch (e) {
        ktKeyError(e);
    }
}

// "→ PKCS#8"按钮
function ktToPkcs8() {
    try {
        var bytes = ktReadKeyInput();
        var r = ktToPkcs8Core(bytes, ktSelectedCurveOid());
        document.getElementById('kt-key-info').textContent = ktFormatKeyInfo(ktParsePrivateKey(bytes));
        document.getElementById('kt-key-result').value = r.note + '\n' + ktBuildPem(r.label, r.der);
        showNotification('已转换为 PKCS#8（DER ' + r.der.length + ' 字节）');
    } catch (e) {
        ktKeyError(e);
    }
}

// "→ PKCS#1"按钮（ECC 输入时产物为 SEC1 / EC PRIVATE KEY）
function ktToPkcs1() {
    try {
        var bytes = ktReadKeyInput();
        var r = ktToPkcs1Core(bytes);
        document.getElementById('kt-key-info').textContent = ktFormatKeyInfo(ktParsePrivateKey(bytes));
        document.getElementById('kt-key-result').value = r.note + '\n' + ktBuildPem(r.label, r.der);
        showNotification('转换完成（' + r.label + '，DER ' + r.der.length + ' 字节）');
    } catch (e) {
        ktKeyError(e);
    }
}

// "清空"按钮
function ktClear() {
    document.getElementById('kt-key-input').value = '';
    document.getElementById('kt-key-info').textContent = '';
    document.getElementById('kt-key-result').value = '';
}

// ============================================================
// Section 2：PKCS#12 / PFX 结构查看（纯函数区）
// ============================================================

// PKCS#7 内容类型 OID → 简名（RFC 2315；PKCS#12 的 authSafe / SafeContents 沿用该分支）
var KT_PKCS7_CONTENT_NAMES = {
    '1.2.840.113549.1.7.1': 'data',
    '1.2.840.113549.1.7.2': 'signedData',
    '1.2.840.113549.1.7.3': 'envelopedData',
    '1.2.840.113549.1.7.4': 'signedAndEnvelopedData',
    '1.2.840.113549.1.7.5': 'digestedData',
    '1.2.840.113549.1.7.6': 'encryptedData'
};

// PKCS#12 结构解析（纯函数），返回：
//   { version, hasMac, contentTypes[], certCount, treeLines[], derLen }
// 结构口径（RFC 7292）：PFX ::= SEQUENCE{ version INTEGER(3), authSafe ContentInfo, macData 可选 }
//   authSafe 的 ContentInfo ::= SEQUENCE{ OID contentType(data), [0]{ OCTET STRING(DER AuthenticatedSafe) } }
//   AuthenticatedSafe ::= SEQUENCE OF ContentInfo（data → 内层 OCTET 为 SafeContents 即 SafeBag 序列；
//   envelopedData/encryptedData → 口令加密部分）。
// 遍历口径：PFX → authSafe → AuthenticatedSafe → SafeContents → SafeBag → CertBag → 证书 已有 10+ 层，
//   而 asn1ParseTlv 单棵解析树有 16 层深度上限（防异常数据递归爆栈），从 PFX 一路解到证书内部会触顶
//   （内嵌展开被静默截断、证书数不到账）。故本遍历器在每个 OCTET STRING 边界重新开根解析（深度清零），
//   每棵树都很浅——既遍历到最底层证书，又不放松对单棵树的异常数据防护。
function ktP12StructSummary(bytes) {
    if (!bytes || !bytes.length) {
        throw new Error('PKCS#12 数据为空');
    }
    var root = asn1ParseTlv(bytes, 0, bytes.length, 0);
    if (root.tagFirst !== 0x30 || !root.constructed) {
        throw new Error('PKCS#12 顶层应为 SEQUENCE（0x30），当前不是');
    }
    var kids = root.children || [];
    if (!kids.length || kids[0].tagFirst !== 0x02) {
        throw new Error('PFX 第一个子节点应为版本 INTEGER，当前结构不是 PKCS#12');
    }
    var version = ktIntValue(kids[0]);
    var hasMac = kids.length > 2 && kids[2].tagFirst === 0x30; // 第三子节点 MacData ::= SEQUENCE（可选）

    var stats = { contentTypes: [], certCount: 0, treeLines: [] };

    // 单个节点 → 展示行（Tag 名 / 长度 / OID 名 / 内容预览复用 asn1Preview），并做概要统计
    function nodeLine(node, depth) {
        var indent = '';
        for (var d = 0; d < depth; d++) { indent += '  '; }
        var line = indent + asn1TagName(node.tagFirst, node.constructed) +
            ' 长' + node.totalLen + ' @' + node.offset;
        if (node.tagFirst === 0x06) {
            var dot = asn1DecodeOid(ktContent(node));
            if (dot) {
                var name = asn1OidName(dot);
                line += ' ' + dot + (name ? '（' + name + '）' : '');
                var shortName = KT_PKCS7_CONTENT_NAMES.hasOwnProperty(dot) ? KT_PKCS7_CONTENT_NAMES[dot] : null;
                if (shortName && stats.contentTypes.indexOf(shortName) < 0) {
                    stats.contentTypes.push(shortName);
                }
            }
        }
        // X.509 证书结构计数：SEQUENCE 恰含 3 子节点（tbsCertificate SEQ / signatureAlgorithm SEQ /
        // signatureValue BIT STRING）。CRL 同形态（SEQ{tbs, sigAlg, BIT}）会被一并计入，
        // 属结构计数口径的已知近似
        if (node.tagFirst === 0x30 && node.children.length === 3 &&
            node.children[0].tagFirst === 0x30 && node.children[0].constructed &&
            node.children[1].tagFirst === 0x30 && node.children[1].constructed &&
            node.children[2].tagFirst === 0x03) {
            stats.certCount++;
            line += ' ← X.509 证书 #' + stats.certCount;
        }
        stats.treeLines.push(line);
    }

    // 递归遍历：构造类型下钻子节点；OCTET STRING 内容恰好为完整 DER 时重新开根（深度清零）下钻
    function walkNode(node, depth) {
        nodeLine(node, depth);
        if (node.constructed) {
            for (var i = 0; i < node.children.length; i++) {
                walkNode(node.children[i], depth + 1);
            }
            return;
        }
        if (node.tagFirst === 0x04 && node.contentLen >= 2) {
            // PKCS#12 的 data 逐层包装（ContentInfo → AuthenticatedSafe → SafeContents → 证书）
            // 全靠 OCTET STRING 内嵌 DER 传递。先试解析整个内容确认是完整 DER，再逐个下钻，
            // 并在该 OCTET 行尾标注 [内嵌 DER]；解析失败按普通数据处理（不报错）
            var inner = ktToArray(ktContent(node));
            var embedded = false;
            try {
                var q = 0;
                while (q < inner.length) {
                    var probe = asn1ParseTlv(inner, q, inner.length, 0);
                    q += probe.totalLen;
                }
                embedded = true; // 完整吃满才是合法内嵌 DER
            } catch (e) { embedded = false; }
            if (embedded) {
                stats.treeLines[stats.treeLines.length - 1] += ' [内嵌 DER]';
                var p = 0;
                while (p < inner.length) {
                    var sub = asn1ParseTlv(inner, p, inner.length, 0); // 深度从 0 重新计
                    walkNode(sub, depth + 1);
                    p += sub.totalLen;
                }
            }
        }
    }
    walkNode(root, 0);

    return {
        version: version,
        hasMac: hasMac,
        contentTypes: stats.contentTypes,
        certCount: stats.certCount,
        treeLines: stats.treeLines,
        derLen: bytes.length
    };
}

// ---------------- Section 2：页面动作 ----------------

// 解析结果渲染（bytes 直接来自文件或文本识别）
function ktP12Show(bytes, fileName) {
    var el = document.getElementById('kt-p12-result');
    var s = ktP12StructSummary(bytes);
    // 口令加密的内容类型（envelopedData 等）单独提示"仅结构查看，不解密"
    var encTypes = [];
    for (var i = 0; i < s.contentTypes.length; i++) {
        if (s.contentTypes[i] !== 'data') { encTypes.push(s.contentTypes[i]); }
    }
    var lines = [
        '概要：版本 ' + (s.version == null ? '—' : s.version) +
        '｜含 MAC：' + (s.hasMac ? '是（macData 段存在，本工具不校验）' : '否') +
        '｜内容类型链：' + (s.contentTypes.length ? s.contentTypes.join(' → ') : '未发现') +
        '｜证书：' + s.certCount + ' 张' +
        '｜DER：' + s.derLen + ' 字节' + (fileName ? '｜文件：' + fileName : ''),
        '—— 结构树（缩进 = 层级；Tag / 长度 / OID 名）——',
        s.treeLines.join('\n')
    ];
    if (encTypes.length) {
        lines.push('——\n⚠️ ' + encTypes.join(' / ') + ' 为口令保护部分：仅结构查看，不解密');
    }
    el.textContent = lines.join('\n');
    showNotification('PKCS#12 结构解析完成（版本 ' + (s.version == null ? '?' : s.version) + '，证书 ' + s.certCount + ' 张）');
}

// "解析结构"按钮：textarea 输入（Base64 / Hex / PEM 自动识别，复用 asn1ExtractDer）
function ktP12Run() {
    try {
        var el = document.getElementById('kt-p12-input');
        if (!el || !el.value.trim()) {
            throw new Error('请先上传 .pfx / .p12 文件，或粘贴 Base64 / Hex 内容');
        }
        var ex = asn1ExtractDer(el.value);
        ktP12Show(ex.bytes, '');
    } catch (e) {
        gmShowError('kt-p12-result', e);
    }
}

// "清空"按钮
function ktP12Clear() {
    document.getElementById('kt-p12-input').value = '';
    document.getElementById('kt-p12-result').textContent = '';
}

// 读取上传的 .pfx / .p12 文件（上限 2MB；≤64KB 回显大写 Hex 到 textarea 便于核对）
function ktP12ReadFile(file) {
    if (file.size > 2 * 1024 * 1024) {
        showNotification('文件过大（超过 2MB），请粘贴 Base64 内容代替上传');
        return;
    }
    var reader = new FileReader();
    reader.onload = function () {
        try {
            var bytes = new Uint8Array(reader.result);
            var inputEl = document.getElementById('kt-p12-input');
            if (inputEl) {
                if (bytes.length <= 64 * 1024) {
                    inputEl.value = ktBytesToHex(bytes).toUpperCase();
                } else {
                    inputEl.value = '（二进制文件 ' + file.name + ' 共 ' + bytes.length +
                        ' 字节，过大不回显，解析结果见下方）';
                }
            }
            ktP12Show(bytes, file.name);
        } catch (e) {
            gmShowError('kt-p12-result', e);
        }
    };
    reader.onerror = function () {
        showNotification('文件读取失败');
    };
    reader.readAsArrayBuffer(file);
}

// ============================================================
// Section 3 / Section 4：GM/T 0009 加密密钥对（纯函数区）
// ============================================================
// GM/T 0009 密钥对保护格式 = SM2 数字信封：SM4 对称密钥加密 SM2 私钥，SM2 公钥加密对称密钥。
// 头部字段存在两种实现口径（标准文本未完全统一，各家设备 / SDK 实现有差异），本工具自适应解析：
//   布局 A（1B/1B/1B）：ver(1B) + alg(1B) + keyLen(1B) + keyCipher + privLen(2B 大端) + privCipher [+ 公钥]
//   布局 B（1B/3B/4B）：ver(1B) + alg(3B) + keyLen(4B 大端) + keyCipher + privLen(4B 大端) + privCipher [+ 公钥]
// 解析顺序：先按 A（更常见的小头部实现），字段越界 / 不合理再按 B；两者都失败报含头部 Hex 的错误。
// 尾部公钥：剩余 64 字节视为公钥（无 04 前缀口径），65 字节且以 04 开头视为带前缀变体。

// 尾部公钥判定：从 offset 到结尾 —— 0 字节 → 无公钥（返回空数组）；64 字节 → 公钥；
// 65 字节且首字节 04 → 04 开头公钥变体；其余长度 → 布局不成立（返回 null）
function kt9TailPub(bytes, offset) {
    var rest = bytes.length - offset;
    if (rest === 0) { return []; }
    if (rest === 64) { return bytes.slice(offset); }
    if (rest === 65 && bytes[offset] === 0x04) { return bytes.slice(offset + 1); }
    return null;
}

// 布局 A 解析：字段越界 / 不合理返回 null（合理下限：SM2 密文 ≥96 字节；SM4 密文为 16 字节整倍数）
function kt9ParseHeaderA(bytes) {
    if (bytes.length < 7) { return null; }
    var keyLen = bytes[2];
    if (keyLen < 96 || 3 + keyLen + 2 > bytes.length) { return null; }
    var p = 3 + keyLen;
    var privLen = (bytes[p] << 8) | bytes[p + 1];
    if (privLen < 16 || privLen % 16 !== 0 || p + 2 + privLen > bytes.length) { return null; }
    var tail = kt9TailPub(bytes, p + 2 + privLen);
    if (tail === null) { return null; }
    return {
        layout: 'A',
        ver: bytes[0],
        algBytes: [bytes[1]],
        keyCipher: bytes.slice(3, 3 + keyLen),
        privCipher: bytes.slice(p + 2, p + 2 + privLen),
        pub: tail
    };
}

// 布局 B 解析：alg 3 字节、keyLen / privLen 4 字节大端（校验规则同布局 A）
function kt9ParseHeaderB(bytes) {
    if (bytes.length < 12) { return null; }
    var keyLen = (((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0);
    if (keyLen < 96 || 8 + keyLen + 4 > bytes.length) { return null; }
    var p = 8 + keyLen;
    var privLen = (((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) >>> 0);
    if (privLen < 16 || privLen % 16 !== 0 || p + 4 + privLen > bytes.length) { return null; }
    var tail = kt9TailPub(bytes, p + 4 + privLen);
    if (tail === null) { return null; }
    return {
        layout: 'B',
        ver: bytes[0],
        algBytes: bytes.slice(1, 4),
        keyCipher: bytes.slice(8, 8 + keyLen),
        privCipher: bytes.slice(p + 4, p + 4 + privLen),
        pub: tail
    };
}

// 头部自适应解析入口（纯函数）：A 失败试 B，都失败抛含头部前 16 字节 Hex 的中文错误
function kt9ParseHeader(bytes) {
    if (!bytes || !bytes.length) {
        throw new Error('密钥对保护数据为空');
    }
    var h = kt9ParseHeaderA(bytes);
    if (h) { return h; }
    h = kt9ParseHeaderB(bytes);
    if (h) { return h; }
    throw new Error('不符合 GM/T 0009 密钥对保护格式（头部 Hex（前 16 字节）：' +
        ktBytesToHex(bytes.slice(0, 16)).toUpperCase() + '）');
}

// SM2 密文形态候选：裸 C1C3C2 / 裸 C1C2C3 / DER（GM/T 0010 SM2Cipher）拼回两种裸排布
// —— DER 分支先经 asn1ParseTlv 取出 x/y/hash/cipher 四段（复用 gmsm.js 的 sm2ConvDerToParts，
//    含坐标去前导零 / 左补零归一化），再拼裸密文交给 doDecrypt
function kt9Sm2CipherVariants(keyCipher) {
    if (!keyCipher || !keyCipher.length) { return []; }
    var hex = ktBytesToHex(keyCipher);
    // 兼容带 04 前缀的裸密文：sm-crypto 要求密文不含 04，去掉后剩余仍 ≥96 字节才视为多余前缀
    if (hex.substr(0, 2) === '04' && hex.length >= 194) {
        hex = hex.substr(2);
    }
    var variants = [
        { hex: hex, mode: 1, fmt: '裸 C1C3C2' },
        { hex: hex, mode: 0, fmt: '裸 C1C2C3' }
    ];
    if (keyCipher[0] === 0x30) {
        try {
            var parts = sm2ConvDerToParts(keyCipher);
            variants.push({ hex: ktBytesToHex(sm2ConvJoinBare(parts, 'c1c3c2')), mode: 1, fmt: 'DER（GM/T 0010）' });
            variants.push({ hex: ktBytesToHex(sm2ConvJoinBare(parts, 'c1c2c3')), mode: 0, fmt: 'DER（GM/T 0010）' });
        } catch (e) { /* 内容不是合法 SM2Cipher DER，跳过 DER 形态 */ }
    }
    return variants;
}

// 数字信封拆解：keyCipher 段按候选形态依次试解，成功返回 { keyHex, fmt }，全失败返回 null。
// 口径说明（sm-crypto 0.3.2 库限制，doDecrypt 只返回 UTF-8 文本、无 output 选项）：
//   - 本工具生成口径：16 字节对称密钥以 32 字符 Hex 文本参与 SM2 加密（全 ASCII，逐字符即字节），
//     解出 32 个 Hex 字符即密钥本体；
//   - 真实设备口径：16 原始字节加密，仅当字节恰好构成合法 UTF-8（如全 ASCII）时能按字符码取回，
//     非 UTF-8 的原始字节会抛 'Malformed UTF-8 data'——此为库限制，见页面提示
function kt9UnwrapKey(h, privHex) {
    var variants = kt9Sm2CipherVariants(h.keyCipher);
    for (var i = 0; i < variants.length; i++) {
        var v = variants[i];
        try {
            var plain = smCrypto.sm2.doDecrypt(v.hex, privHex, v.mode);
            if (plain === '') {
                throw new Error('C3 校验未通过');
            }
            if (/^[0-9a-fA-F]{32}$/.test(plain)) {
                return { keyHex: plain.toLowerCase(), fmt: v.fmt + '，Hex 文本口径' };
            }
            if (plain.length === 16) {
                // 16 个字符的文本：全 ASCII 时字符码即 16 个原始字节
                var bs = [];
                for (var c = 0; c < 16; c++) { bs.push(plain.charCodeAt(c) & 0xFF); }
                return { keyHex: ktBytesToHex(bs), fmt: v.fmt + '，原始字节口径' };
            }
            throw new Error('解出内容为 ' + plain.length + ' 字符文本，不是 16 字节对称密钥');
        } catch (e) { /* 该形态失败，继续尝试下一形态 */ }
    }
    return null;
}

// GM/T 0009 解密核心（纯函数）：envBytes = 保护数据，privHex = 接收方 SM2 私钥（64 位 Hex）
// 返回 { layout, ver, algBytes, keyCipherLen, privCipherLen, pubHex, keyHex, sm2Fmt, privKeyHex, pem }
function kt9DecryptCore(envBytes, privHex) {
    var priv = String(privHex == null ? '' : privHex).replace(/[\s:,]/g, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(priv)) {
        throw new Error('解密用 SM2 私钥必须是 64 位 Hex（接收方私钥）');
    }
    var h = kt9ParseHeader(envBytes);
    var unwrapped = kt9UnwrapKey(h, priv);
    if (!unwrapped && h.layout === 'A') {
        // 头部字段均落在界内但 SM2 解密全形态失败时，可能是布局 B 被误判成 A
        // （两布局的字段恰好都"合理"的小概率情形），强制按 B 再试一次
        var hB = kt9ParseHeaderB(envBytes);
        if (hB) {
            var unwrappedB = kt9UnwrapKey(hB, priv);
            if (unwrappedB) {
                h = hB;
                unwrapped = unwrappedB;
            }
        }
    }
    if (!unwrapped) {
        throw new Error('SM2 解密对称密钥失败（已按 布局 A/B × 裸 C1C3C2 / C1C2C3 / DER 形态全部尝试）：' +
            '请核对接收方 SM2 私钥是否正确；另注 sm-crypto 0.3.2 的 doDecrypt 仅返回 UTF-8 文本，' +
            '设备按 16 原始字节（非 Hex 文本口径）加密的密钥若非合法 UTF-8 则无法还原');
    }
    var keyHex = unwrapped.keyHex;
    // 对称密钥长度校验：SM4-128 应为 16 字节（32 位 Hex）——上面筛选已限定 32 位 Hex，此处显式再校验
    if (!/^[0-9a-f]{32}$/.test(keyHex)) {
        throw new Error('对称密钥应为 16 字节（32 位 Hex），当前值异常');
    }

    // 私钥密文按 SM4-ECB + PKCS7 解密：sm-crypto 的 decrypt 对字符串输入按 Hex 解释（与加密侧不对称），
    // 二进制明文必须 output:'array' 取字节数组（库的字符串输出只会按 UTF-8 解释）；密钥为上一步 16 字节的 Hex
    var privPlain;
    try {
        privPlain = smCrypto.sm4.decrypt(ktBytesToHex(h.privCipher), keyHex, { padding: 'pkcs#5', output: 'array' });
    } catch (e) {
        throw new Error('SM4 解密私钥失败（PKCS7 去填充未通过，对称密钥可能不正确）：' + (e && e.message ? e.message : e));
    }
    if (!privPlain || !privPlain.length) {
        // 库在去填充失败时可能静默返回空数组，需显式判失败
        throw new Error('SM4 解密私钥失败（PKCS7 去填充未通过，对称密钥可能不正确）');
    }
    if (privPlain.length !== 32) {
        throw new Error('解出的私钥为 ' + privPlain.length + ' 字节，GM/T 0009 密钥对保护应内含 32 字节 SM2 私钥');
    }
    var privKeyHex = ktBytesToHex(privPlain);
    var pubHex = h.pub && h.pub.length ? ktBytesToHex(h.pub) : null;

    return {
        layout: h.layout,
        ver: h.ver,
        algBytes: h.algBytes,
        keyCipherLen: h.keyCipher.length,
        privCipherLen: h.privCipher.length,
        pubHex: pubHex,
        keyHex: keyHex,
        sm2Fmt: unwrapped.fmt,
        privKeyHex: privKeyHex,
        pem: kt9PrivToPkcs8Pem(privKeyHex, pubHex)
    };
}

// 32 字节 SM2 私钥 → 国产 PKCS#8 形态 PEM（与 gmsm.js "SM2 私钥转 PKCS#8 PEM" 同构）：
//   SEQUENCE { INTEGER 1, OCTET STRING(32) d, [0]{ OID 1.2.156.10197.1.301 }, [1] BIT STRING 公钥(可选) }
// 注：这是国内厂商（1.key 等）对 PKCS#8 的简化写法（算法段不包 ecPublicKey 包装），GmSSL 可直接读取；
//     SM2 曲线 OID 1.2.156.10197.1.301 的 DER 内容字节 = 2A811CCF5501822D
function kt9PrivToPkcs8Pem(privHex, pubHex) {
    var content = []
        .concat(
            gmDerTlv(0x02, [1]),                                                // INTEGER 1（version）
            gmDerTlv(0x04, ktHexToBytes(privHex)),                              // OCTET STRING(32) 私钥 d
            gmDerTlv(0xA0, gmDerTlv(0x06, ktHexToBytes('2a811ccf5501822d')))    // [0]{ OID SM2 曲线 }
        );
    if (pubHex && /^[0-9a-f]{128}$/.test(pubHex)) {
        // [1] 内包 BIT STRING：内容 = 0x00（未用位数）+ 04 || 公钥 64 字节（pubHex 为剥 04 后的 64 字节）
        content = content.concat(gmDerTlv(0xA1, gmDerTlv(0x03, [0x00].concat(ktHexToBytes('04' + pubHex)))));
    }
    return ktBuildPem('PRIVATE KEY', gmDerTlv(0x30, content));
}

// 16 字节随机 SM4 密钥 → 32 位 Hex（crypto.getRandomValues；Node 19+ 同样可用）
function ktRandomHex32() {
    if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
        throw new Error('当前环境无 crypto.getRandomValues，无法生成随机 SM4 密钥');
    }
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    return ktBytesToHex(Array.prototype.slice.call(b));
}

// GM/T 0009 生成核心（纯函数）：privHex 待保护私钥，pubHex 加密用公钥（130 位 04 开头，兼容 128 位），
// optKeyHex 可注入固定 SM4 密钥（Node 对拍用；省略则随机生成）。
// 流程：SM4-ECB/PKCS7 加密私钥 → SM2(C1C3C2) 加密 SM4 密钥 → 按布局 A 组装 + 尾部公钥 64B（剥 04）
// 返回 { bytes, hexUpper, base64, keyHex, privCipherLen }
function kt9GenCore(privHex, pubHex, optKeyHex) {
    var priv = String(privHex == null ? '' : privHex).replace(/[\s:,]/g, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(priv)) {
        throw new Error('SM2 私钥必须是 64 位 Hex（32 字节）');
    }
    var pub = String(pubHex == null ? '' : pubHex).replace(/[\s:,]/g, '').toLowerCase();
    if (/^[0-9a-f]{128}$/.test(pub)) {
        pub = '04' + pub; // 128 位裸坐标 → 补未压缩点前缀
    }
    if (!/^04[0-9a-f]{128}$/.test(pub)) {
        throw new Error('SM2 公钥必须是 04 开头的 130 位 Hex（未压缩点）');
    }
    var key = optKeyHex
        ? String(optKeyHex).replace(/[\s:,]/g, '').toLowerCase()
        : ktRandomHex32();
    if (!/^[0-9a-f]{32}$/.test(key)) {
        throw new Error('SM4 密钥必须是 32 位 Hex（16 字节）');
    }

    // 私钥按 SM4-ECB + PKCS7 加密：必须传字节数组（库对字符串输入按 UTF-8 文本编码，Hex 串会被二次编码）；
    // 加密的字符串输出恒为 Hex（小写）
    var privCipherHex = smCrypto.sm4.encrypt(ktHexToBytes(priv), key, { padding: 'pkcs#5' });
    var privCipher = ktHexToBytes(privCipherHex);

    // SM2 加密对称密钥：sm-crypto 的 doEncrypt 按字符串 UTF-8 编码明文——此处传密钥的 32 字符 Hex 文本
    // （全 ASCII，逐字符即字节），与 Section 3 解密侧的"Hex 文本口径"配套；cipherMode 1 = C1C3C2（新国标）
    var keyCipher = ktHexToBytes(smCrypto.sm2.doEncrypt(key, pub, 1));
    if (keyCipher.length > 255) {
        throw new Error('SM2 密文 ' + keyCipher.length + ' 字节，超出布局 A 的 1 字节密钥长度字段上限（255）');
    }

    // 按布局 A 组装：01(ver) 01(alg=SM4) <keyLen 1B> <keyCipher> <privLen 2B 大端> <privCipher> + 公钥 64B（剥 04）
    var out = [0x01, 0x01, keyCipher.length]
        .concat(keyCipher,
            [(privCipher.length >> 8) & 0xFF, privCipher.length & 0xFF],
            privCipher,
            ktHexToBytes(pub.substr(2)));
    return {
        bytes: out,
        hexUpper: ktBytesToHex(out).toUpperCase(),
        base64: ktBytesToBase64(out),
        keyHex: key,
        privCipherLen: privCipher.length
    };
}

// ---------------- Section 3：页面动作 ----------------

// 算法标识字段展示：0x01 → 标注 SM4（布局 B 的 3 字节含 0x01 亦按 SM4 口径标注，实现口径不一所致）
function kt9AlgDisplay(algBytes) {
    var hex = ktBytesToHex(algBytes).toUpperCase();
    var isSm4 = false;
    for (var i = 0; i < algBytes.length; i++) {
        if (algBytes[i] === 0x01) { isSm4 = true; }
    }
    return '0x' + hex + (isSm4 ? '（SM4）' : '（未知算法）');
}

// "解密"按钮
function kt9Decrypt() {
    try {
        var inputEl = document.getElementById('kt-9-decrypt-input');
        if (!inputEl || !inputEl.value.trim()) {
            throw new Error('请输入 GM/T 0009 密钥对保护数据（Hex 或 Base64）');
        }
        var env = ktInputToBytes(inputEl.value);
        var r = kt9DecryptCore(env, document.getElementById('kt-9-priv').value);
        var lines = [
            '布局 ' + r.layout + ' 解析成功：',
            '版本：' + r.ver + '（0x' + ('0' + r.ver.toString(16).toUpperCase()).slice(-2) + '）｜算法标识：' + kt9AlgDisplay(r.algBytes),
            '密钥密文：' + r.keyCipherLen + ' 字节（SM2，按「' + r.sm2Fmt + '」解出）｜私钥密文：' + r.privCipherLen + ' 字节（SM4-ECB/PKCS7）',
            '尾部公钥：' + (r.pubHex ? '有' : '无'),
            '——',
            '对称密钥（SM4，16 字节）：' + r.keyHex,
            '解出 SM2 私钥（64 位 Hex）：' + r.privKeyHex
        ];
        if (r.pubHex) {
            lines.push('尾部公钥（64 字节，补 04 前缀）：04' + r.pubHex);
        }
        lines.push('——');
        lines.push('PKCS#8 PEM（国产形态）：');
        lines.push(r.pem);
        document.getElementById('kt-9-result').textContent = lines.join('\n');
        showNotification('GM/T 0009 解密成功（布局 ' + r.layout + '）');
    } catch (e) {
        gmShowError('kt-9-result', e);
    }
}

// ---------------- Section 4：页面动作 ----------------

// "生成 0009 密钥对"按钮：生成后立即用 Section 3 的解密核心回解，逐字节对拍私钥
function kt9Gen() {
    try {
        var privEl = document.getElementById('kt-9-gen-priv');
        var pubEl = document.getElementById('kt-9-gen-pub');
        var priv = String(privEl ? privEl.value : '').replace(/[\s:,]/g, '').toLowerCase();
        var r = kt9GenCore(priv, pubEl ? pubEl.value : '');

        // 自测锚点：本页解密函数回解，私钥应逐字节一致
        var back = kt9DecryptCore(r.bytes, priv);
        var ok = back.privKeyHex === priv;

        var lines = [
            'GM/T 0009 密钥对保护数据（布局 A，' + r.bytes.length + ' 字节）：',
            'Hex（大写）：',
            r.hexUpper,
            '——',
            'Base64：',
            r.base64,
            '——',
            '本次 SM4 对称密钥（16 字节）：' + r.keyHex,
            '自测回解：' + (ok
                ? '✅ 私钥逐字节一致（kt9GenCore → kt9DecryptCore 对拍通过）'
                : '❌ 回解不一致（生成：' + priv + '，回解：' + back.privKeyHex + '）')
        ];
        document.getElementById('kt-9-gen-result').textContent = lines.join('\n');
        showNotification(ok ? '0009 密钥对生成成功，自测回解一致' : '生成完成，但自测回解不一致');
    } catch (e) {
        gmShowError('kt-9-gen-result', e);
    }
}

// "清空"按钮
function kt9GenClear() {
    document.getElementById('kt-9-gen-priv').value = '';
    document.getElementById('kt-9-gen-pub').value = '';
    document.getElementById('kt-9-gen-result').textContent = '';
}

// ============================================================
// Section 5：GM/T 0016/0018 密钥（ENVELOPEDKEYBLOB）（纯函数区 + 页面动作）
// ============================================================
// ENVELOPEDKEYBLOB = GM/T 0016《智能密码钥匙密码应用接口规范》/ GM/T 0018《密码设备应用接口规范》
// 导出的 ECC 密钥对保护结构（SKF_ExportSignPriKey / SDF_ExportSignKey_ECC 输出），
// C 结构体的内存映像（ULONG 一律小端），与 GM/T 0009 数字信封同构：
// SM4 对称密钥加密 SM2 私钥，SM2 公钥加密对称密钥（ECCCipherBlob）。
//
// 字节布局（源自用户提供的 byzk0016.h / byzk0018.h，两标准同构）：
//   偏移   长度   字段（ULONG 一律小端）
//   0      4     Version（版本，通常 1）
//   4      4     ulSymmAlgID（SGD 算法标识）
//   8      4     ulBits（对称密钥位长，通常 128）
//   12     64    cbEncryptedPriKey（SM4 加密的私钥密文，定长 64 字节，不足右补零）
//   76     4     PubKey.BitLen（通常 256）
//   80     64    PubKey.X
//   144    64    PubKey.Y
//   208    64    ECCCipherBlob.X（对称密钥 SM2 密文 C1.x，定长 64）
//   272    64    ECCCipherBlob.Y
//   336    32    ECCCipherBlob.HASH（C3）
//   368    4     ECCCipherBlob.CipherLen（小端）
//   372    变长  ECCCipherBlob.Cipher（对称密钥密文 C2，通常 16 字节 = 128 位密钥）
// 固定头 372 字节 + Cipher 变长；总长校验 ≥ 388。

// SGD 算法标识常量表（名称映射；出处：GM/T 0016/0018 头文件 byzk0016.h / byzk0018.h）
var KT16_SGD_ALGS = {
    0x00000101: 'SGD_SM1_ECB',  0x00000102: 'SGD_SM1_CBC',  0x00000104: 'SGD_SM1_CFB',
    0x00000108: 'SGD_SM1_OFB',  0x00000110: 'SGD_SM1_MAC',  0x00000120: 'SGD_SM1_CTR',
    0x00000201: 'SGD_SSF33_ECB', 0x00000202: 'SGD_SSF33_CBC',
    0x00000204: 'SGD_SSF33_CFB', 0x00000208: 'SGD_SSF33_OFB',
    0x00004001: 'SGD_SM4_ECB',  0x00004002: 'SGD_SM4_CBC',
    0x00004004: 'SGD_SM4_CFB',  0x00004008: 'SGD_SM4_OFB'
};

// 算法 ID → 8 位大写 Hex（展示用）
function kt16AlgIdHex(id) {
    var h = (id >>> 0).toString(16).toUpperCase();
    while (h.length < 8) { h = '0' + h; }
    return h;
}

// 小端读 4 字节 ULONG（手写移位，不依赖 DataView——C 结构体内存映像按小端解释）
function kt16ReadU32Le(bytes, off) {
    return (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 0;
}

// 数值 → 4 字节小端
function kt16U32Le(v) {
    return [v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF];
}

// 定长 64 字节坐标数组取 32 字节有效值（自适应探测）：
//   C 惯例为右对齐——256 位值放数组末尾 32 字节、前 32 字节为 0（本工具生成亦按此口径）；
//   部分厂商左对齐（值在前 32 字节）。探测规则：前 32 字节全零 → 取后 32；否则取前 32。
function kt16Coord32(bytes64) {
    var frontZero = true;
    for (var i = 0; i < 32; i++) {
        if (bytes64[i] !== 0) { frontZero = false; break; }
    }
    return frontZero ? bytes64.slice(32) : bytes64.slice(0, 32);
}

// 32 字节（或更短）坐标 → 定长 64 字节右对齐数组（前补零，C 惯例）
function kt16RightAlign64(bytes) {
    var out = [];
    for (var i = 0; i < 64 - bytes.length; i++) { out.push(0); }
    return out.concat(ktToArray(bytes));
}

// 字节数组左补零到 32 字节（裸密文切分 / 公钥切半时坐标不足定长的防御性归一化）
function kt16LeftPad32(bytes) {
    var out = [];
    for (var i = 0; i < 32 - bytes.length; i++) { out.push(0); }
    return out.concat(ktToArray(bytes));
}

// 全零字节判定（公钥段是否为空的判断用）
function kt16AllZero(bytes) {
    for (var i = 0; i < bytes.length; i++) {
        if (bytes[i] !== 0) { return false; }
    }
    return true;
}

// 功能 1：ENVELOPEDKEYBLOB 解析核心（纯函数）——按字节布局切字段
// 返回 { ver, algId, algIdHex, algName, bits, encPriv, pubBitLen, pubX, pubY,
//        cipherX, cipherY, hash, cipherLen, cipherHex, blobLen, warnings }
// （encPriv / pubX / pubY / cipherX / cipherY / hash / cipherHex 均为小写 Hex 串，坐标为自适应取出的 32 字节有效值）
function kt16ParseCore(bytes) {
    if (!bytes || !bytes.length) {
        throw new Error('ENVELOPEDKEYBLOB 数据为空');
    }
    if (bytes.length < 388) {
        throw new Error('总长 ' + bytes.length + ' 字节，不足 ENVELOPEDKEYBLOB 最小长度 388 字节（固定头 372 + C2 密文至少 16）');
    }
    var cipherLen = kt16ReadU32Le(bytes, 368);
    if (cipherLen === 0) {
        throw new Error('ECCCipherBlob.CipherLen 为 0，不是合法的 ENVELOPEDKEYBLOB');
    }
    var warnings = [];
    if (372 + cipherLen > bytes.length) {
        throw new Error('CipherLen=' + cipherLen + ' 超出实际数据（固定头 372 + CipherLen 需 ≤ 总长 ' + bytes.length + ' 字节）');
    }
    if (372 + cipherLen < bytes.length) {
        // 总长与 CipherLen 不一致：超出部分提示后忽略（部分导出口径会在结构体后追加厂商自定义数据）
        warnings.push('结构体后含多余数据（' + (bytes.length - 372 - cipherLen) + ' 字节，已忽略）');
    }
    var algId = kt16ReadU32Le(bytes, 4);
    var algName = KT16_SGD_ALGS[algId];
    if (algId === 0x00004002) {
        // 信封私钥保护实际都用 ECB（定长 64 字节字段无 IV 位置，CBC 无从谈起）；遇 CBC 标识提示后仍按 ECB 试
        warnings.push('ulSymmAlgID 为 SGD_SM4_CBC：定长 64 字节私钥密文字段无 IV，实际信封保护通常按 ECB 实现，本工具按 SM4-ECB 尝试');
    }
    var pubX64 = bytes.slice(80, 144);
    var pubY64 = bytes.slice(144, 208);
    return {
        ver: kt16ReadU32Le(bytes, 0),
        algId: algId,
        algIdHex: kt16AlgIdHex(algId),
        algName: algName || '未知算法',
        bits: kt16ReadU32Le(bytes, 8),
        encPriv: ktBytesToHex(bytes.slice(12, 76)),
        pubBitLen: kt16ReadU32Le(bytes, 76),
        pubX: ktBytesToHex(kt16Coord32(pubX64)),
        pubY: ktBytesToHex(kt16Coord32(pubY64)),
        cipherX: ktBytesToHex(kt16Coord32(bytes.slice(208, 272))),
        cipherY: ktBytesToHex(kt16Coord32(bytes.slice(272, 336))),
        hash: ktBytesToHex(bytes.slice(336, 368)),
        cipherLen: cipherLen,
        cipherHex: ktBytesToHex(bytes.slice(372, 372 + cipherLen)),
        blobLen: bytes.length,
        warnings: warnings
    };
}

// ECCCipherBlob 拼裸密文解出对称密钥：C1C3C2 优先，失败改试 C1C2C3；
// 解出内容口径与 Section 3 的 kt9UnwrapKey 一致（Hex 文本口径 32 字符 / 原始字节口径 16 字符）
function kt16UnwrapKey(f, privHex) {
    var tries = [
        { hex: f.cipherX + f.cipherY + f.hash + f.cipherHex, mode: 1, fmt: 'C1C3C2' },
        { hex: f.cipherX + f.cipherY + f.cipherHex + f.hash, mode: 0, fmt: 'C1C2C3' }
    ];
    for (var i = 0; i < tries.length; i++) {
        var t = tries[i];
        try {
            var plain = smCrypto.sm2.doDecrypt(t.hex, privHex, t.mode);
            if (plain === '') {
                throw new Error('C3 校验未通过');
            }
            if (/^[0-9a-fA-F]{32}$/.test(plain)) {
                return { keyHex: plain.toLowerCase(), fmt: t.fmt + '，Hex 文本口径' };
            }
            if (plain.length === 16) {
                // 16 个字符的文本：全 ASCII 时字符码即 16 个原始字节
                var bs = [];
                for (var c = 0; c < 16; c++) { bs.push(plain.charCodeAt(c) & 0xFF); }
                return { keyHex: ktBytesToHex(bs), fmt: t.fmt + '，原始字节口径' };
            }
            throw new Error('解出内容为 ' + plain.length + ' 字符文本，不是 16 字节对称密钥');
        } catch (e) {
            // 默认出口失败（16 字节真密钥含非 ASCII 字节时 UTF-8 文本出口必然乱码）：
            // 用 output:'array' 字节出口兜底——真实 SKF/SDF 设备导出的 Blob 走该口径
            try {
                var arr = smCrypto.sm2.doDecrypt(t.hex, privHex, t.mode, { output: 'array' });
                if (arr && arr.length === 16) {
                    return { keyHex: ktBytesToHex(arr), fmt: t.fmt + '，原始字节口径（array 出口）' };
                }
            } catch (e2) { /* array 出口也不可用，继续下一形态 */ }
        }
    }
    return null;
}

// cbEncryptedPriKey（定长 64 字节）SM4-ECB 解密自适应：
//   ① 前 48 字节按 PKCS7（32B 私钥 + 16B 填充 → 48B 密文，本工具生成与多数设备口径，尾部 16 字节为补零）
//   ② 前 32 字节裸解（32B 私钥恰两整块、无填充口径，尾部 32 字节为补零）
//   ③ 全 64 字节按 PKCS7（密文占满定长字段口径）
// 成功判据 = 解出且剥填充后恰 32 字节（sm-crypto 的去填充为盲剥不校验填充字节，长度即主判据）
function kt16Sm4DecryptPriv(encPrivBytes, keyHex) {
    var attempts = [
        { len: 48, padding: 'pkcs#5', label: '前 48 字节 PKCS7' },
        { len: 32, padding: 'none', label: '前 32 字节裸解' },
        { len: 64, padding: 'pkcs#5', label: '全 64 字节 PKCS7' }
    ];
    for (var i = 0; i < attempts.length; i++) {
        var a = attempts[i];
        try {
            var out = smCrypto.sm4.decrypt(ktBytesToHex(encPrivBytes.slice(0, a.len)), keyHex,
                { padding: a.padding, output: 'array' });
            if (out && out.length === 32) {
                return { privHex: ktBytesToHex(out), fmt: a.label };
            }
        } catch (e) { /* 该口径失败，继续 */ }
    }
    throw new Error('SM4-ECB 解密私钥密文失败（已按 前48B-PKCS7 / 前32B-裸解 / 全64B-PKCS7 三口径尝试，' +
        '均未解出 32 字节私钥；对称密钥可能不正确）');
}

// 功能 2：ENVELOPEDKEYBLOB 解密核心（纯函数）：blobBytes = Blob，privHex = 保护公钥对应方 SM2 私钥（64 位 Hex）
// 返回 { fields（kt16ParseCore 结果）, keyHex, sm2Fmt, sm4Fmt, privHex, pubHex, pem }
function kt16DecryptCore(blobBytes, privHex) {
    var priv = String(privHex == null ? '' : privHex).replace(/[\s:,]/g, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(priv)) {
        throw new Error('解密用 SM2 私钥必须是 64 位 Hex（保护公钥对应方私钥）');
    }
    var f = kt16ParseCore(blobBytes);
    var unwrapped = kt16UnwrapKey(f, priv);
    if (!unwrapped) {
        throw new Error('SM2 解密对称密钥失败（已按 C1C3C2 / C1C2C3 两形态尝试）：' +
            '请核对解密用 SM2 私钥是否为 ECCCipherBlob 加密公钥的对应方私钥');
    }
    var keyHex = unwrapped.keyHex;
    if (!/^[0-9a-f]{32}$/.test(keyHex)) {
        throw new Error('对称密钥应为 16 字节（32 位 Hex），当前值异常');
    }
    var privOut = kt16Sm4DecryptPriv(ktHexToBytes(f.encPriv), keyHex);
    // 公钥段：BitLen 为 0 或 X/Y 全零视为无公钥（PEM 不携带 [1] 段）
    var pubHex = (f.pubBitLen === 0 || (kt16AllZero(ktHexToBytes(f.pubX)) && kt16AllZero(ktHexToBytes(f.pubY))))
        ? null : f.pubX + f.pubY;
    return {
        fields: f,
        keyHex: keyHex,
        sm2Fmt: unwrapped.fmt,
        sm4Fmt: privOut.fmt,
        privHex: privOut.privHex,
        pubHex: pubHex,
        pem: kt9PrivToPkcs8Pem(privOut.privHex, pubHex)
    };
}

// 通用组装：字段对象（ver/algId/bits/encPriv 定长 64/pubBitLen/pubX/pubY/c1x/c1y/hash/cipher）→ Blob 字节数组
// 坐标一律右对齐填充进定长 64 字节数组（前 32 字节补零，C 惯例：256 位值放数组末尾）
function kt16AssembleBlob(p) {
    return []
        .concat(kt16U32Le(p.ver), kt16U32Le(p.algId), kt16U32Le(p.bits),
            p.encPriv,
            kt16U32Le(p.pubBitLen), kt16RightAlign64(p.pubX), kt16RightAlign64(p.pubY),
            kt16RightAlign64(p.c1x), kt16RightAlign64(p.c1y), p.hash,
            kt16U32Le(p.cipher.length), p.cipher);
}

// 功能 3：ENVELOPEDKEYBLOB 生成核心（纯函数）：privHex 待保护私钥，pubHex130 加密用公钥（04 开头，兼容 128 位裸坐标）
// 流程：随机 16B SM4 密钥 → SM4-ECB/PKCS7 加密 32B 私钥（48B 密文右补零至 64）→
//       SM2（C1C3C2）加密 SM4 密钥 → 组装 Blob（Version=1、SGD_SM4_ECB、bits=128、坐标右对齐）
// 返回 { bytes, hex（大写）, base64, keyHex }；组装后立即调 kt16DecryptCore 自回环校验私钥一致，不一致直接抛错
function kt16BuildCore(privHex, pubHex) {
    var priv = String(privHex == null ? '' : privHex).replace(/[\s:,]/g, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(priv)) {
        throw new Error('SM2 私钥必须是 64 位 Hex（32 字节）');
    }
    var pub = String(pubHex == null ? '' : pubHex).replace(/[\s:,]/g, '').toLowerCase();
    if (/^[0-9a-f]{128}$/.test(pub)) {
        pub = '04' + pub; // 128 位裸坐标 → 补未压缩点前缀
    }
    if (!/^04[0-9a-f]{128}$/.test(pub)) {
        throw new Error('SM2 公钥必须是 04 开头的 130 位 Hex（未压缩点）');
    }
    var key = ktRandomHex32();

    // SM4-ECB/PKCS7 加密 32B 私钥 → 48B 密文右补零至定长 64（PKCS7 填充字节 ≥1，尾部补零不影响解密侧剥填充）
    var privCipher = ktHexToBytes(smCrypto.sm4.encrypt(ktHexToBytes(priv), key, { padding: 'pkcs#5' }));
    while (privCipher.length < 64) { privCipher.push(0); }

    // SM2（C1C3C2）加密对称密钥：与 0009 生成侧同口径——密钥按 32 字符 Hex 文本加密（全 ASCII，逐字符即字节）
    var keyCipher = ktHexToBytes(smCrypto.sm2.doEncrypt(key, pub, 1));
    if (keyCipher.length < 96) {
        throw new Error('SM2 密文异常（' + keyCipher.length + ' 字节，至少应为 C1 64 + C3 32 = 96 字节）');
    }
    var out = kt16AssembleBlob({
        ver: 1,
        algId: 0x00004001, // SGD_SM4_ECB
        bits: 128,
        encPriv: privCipher,
        pubBitLen: 256,
        pubX: ktHexToBytes(pub.substr(2, 64)),
        pubY: ktHexToBytes(pub.substr(66, 64)),
        c1x: keyCipher.slice(0, 32),
        c1y: keyCipher.slice(32, 64),
        hash: keyCipher.slice(64, 96),
        cipher: keyCipher.slice(96)
    });

    // 自回环校验：立即按解密核心解回，私钥必须逐字节一致（不一致说明组装或口径有误，直接抛错不出数据）
    var back = kt16DecryptCore(out, priv);
    if (back.privHex !== priv) {
        throw new Error('自回环校验失败：解回私钥与输入不一致，已放弃输出');
    }
    return {
        bytes: out,
        hex: ktBytesToHex(out).toUpperCase(),
        base64: ktBytesToBase64(out),
        keyHex: key
    };
}

// 0009 头部解出的对称密钥密文（keyCipher）→ { x, y, hash, cipher } 四段：
// 按裸 C1C3C2 切分（kt9GenCore 及多数设备口径）；容忍 04 前缀；DER（GM/T 0010）形态复用 sm2ConvDerToParts 归一化
function kt16SplitSm2(keyCipher) {
    var bytes = ktToArray(keyCipher);
    if (bytes[0] === 0x30) {
        var p = sm2ConvDerToParts(bytes); // 坐标已归一化为 32 字节
        return { x: p.x, y: p.y, hash: p.hash, cipher: p.cipher, fmt: 'DER（GM/T 0010）' };
    }
    var hex = ktBytesToHex(bytes);
    if (hex.substr(0, 2) === '04' && hex.length >= 194) {
        hex = hex.substr(2); // 去多余 04 前缀（口径同 kt9Sm2CipherVariants）
    }
    bytes = ktHexToBytes(hex);
    if (bytes.length < 96) {
        throw new Error('对称密钥 SM2 密文不足 96 字节（C1 64 + C3 32），当前 ' + bytes.length + ' 字节');
    }
    return {
        x: kt16LeftPad32(bytes.slice(0, 32)),
        y: kt16LeftPad32(bytes.slice(32, 64)),
        hash: bytes.slice(64, 96),
        cipher: bytes.slice(96),
        fmt: '裸 C1C3C2'
    };
}

// cbEncryptedPriKey 定长 64 字节剥尾部补零（PKCS7 填充字节 ≥1，真密文末字节必非零，剥零安全）
function kt16StripTailZero(encPrivBytes) {
    var end = encPrivBytes.length;
    while (end > 0 && encPrivBytes[end - 1] === 0) { end--; }
    var out = encPrivBytes.slice(0, end);
    if (out.length < 16 || out.length % 16 !== 0) {
        throw new Error('私钥密文剥尾部补零后为 ' + out.length + ' 字节，不是 16 字节整倍数（密文可能未按补零口径填充）');
    }
    return out;
}

// 功能 4：Blob → GM/T 0009 信封（纯函数）：
// Blob 字段 → 0009 布局 A：01 01 <keyCipherLen 1B> <对称密钥密文 = C1C3C2 的 x+y+hash+cipher>
//             <privCipherLen 2B 大端> <SM4 密文（剥尾部补零）> + 尾部公钥 64B（公钥段全零则省略）
// 返回 { bytes, hex（大写）, base64, keyCipherLen, privCipherLen }；转换后立即转回 Blob 回环对拍各密文段
function kt16BlobTo0009Core(blobBytes) {
    var f = kt16ParseCore(blobBytes);
    var keyCipher = ktHexToBytes(f.cipherX + f.cipherY + f.hash + f.cipherHex);
    if (keyCipher.length > 255) {
        throw new Error('SM2 密文 ' + keyCipher.length + ' 字节，超出布局 A 的 1 字节密钥长度字段上限（255）');
    }
    var privCipher = kt16StripTailZero(ktHexToBytes(f.encPriv));
    var hasPub = f.pubBitLen !== 0 && !(kt16AllZero(ktHexToBytes(f.pubX)) && kt16AllZero(ktHexToBytes(f.pubY)));
    var out = [0x01, 0x01, keyCipher.length]
        .concat(keyCipher,
            [(privCipher.length >> 8) & 0xFF, privCipher.length & 0xFF],
            privCipher,
            hasPub ? ktHexToBytes(f.pubX + f.pubY) : []);

    // 自回环校验：转回 ENVELOPEDKEYBLOB 后各密文段应逐字节一致（自适应取值 × 右对齐填充为无损互逆）
    var back = kt16ParseCore(kt16From0009Core(out).bytes);
    if (back.cipherX + back.cipherY + back.hash + back.cipherHex !== f.cipherX + f.cipherY + f.hash + f.cipherHex ||
        ktBytesToHex(kt16StripTailZero(ktHexToBytes(back.encPriv))) !== ktBytesToHex(privCipher)) {
        throw new Error('自回环校验失败：转回 ENVELOPEDKEYBLOB 后密文段不一致，已放弃输出');
    }
    return {
        bytes: out,
        hex: ktBytesToHex(out).toUpperCase(),
        base64: ktBytesToBase64(out),
        keyCipherLen: keyCipher.length,
        privCipherLen: privCipher.length
    };
}

// 功能 5：GM/T 0009 信封 → Blob（纯函数）：复用 kt9ParseHeader 解 0009（布局 A/B 自适应），
// 对称密钥密文按裸 C1C3C2 切 x/y/hash/cipher，SM4 密文右补零到定长 64；
// algId = SGD_SM4_ECB，bits = 128（0009 算法为 SM4、密钥恒 16 字节；C2 长度依加密口径
// 而异——Hex 文本口径 32 字节 / 设备原始字节口径 16 字节——不代表密钥位数）
// 返回 { bytes, hex（大写）, base64, sm2Fmt, warnings }
function kt16From0009Core(envBytes) {
    var h = kt9ParseHeader(envBytes);
    var parts = kt16SplitSm2(h.keyCipher);
    if (parts.cipher.length === 0) {
        throw new Error('对称密钥 SM2 密文缺少 C2 段（无法推出密钥位长）');
    }
    var privCipher = ktToArray(h.privCipher);
    if (privCipher.length > 64) {
        throw new Error('SM4 私钥密文 ' + privCipher.length + ' 字节超出 ENVELOPEDKEYBLOB 定长字段（64 字节）');
    }
    while (privCipher.length < 64) { privCipher.push(0); }
    var warnings = [];
    var pubX, pubY, pubBitLen;
    if (h.pub && h.pub.length === 64) {
        pubX = h.pub.slice(0, 32);
        pubY = h.pub.slice(32, 64);
        pubBitLen = 256;
    } else {
        // 0009 数据无尾部公钥：Blob 公钥段置零（解密不依赖公钥段，仅 PEM 不携带公钥）
        pubX = [];
        pubY = [];
        pubBitLen = 0;
        warnings.push('0009 数据无尾部公钥，Blob 公钥段（BitLen/X/Y）已置零');
    }
    var out = kt16AssembleBlob({
        ver: 1,
        algId: 0x00004001, // SGD_SM4_ECB
        bits: 128,          // SM4 密钥位长（恒 128；C2 长度≠密钥长度，见函数头注释）
        encPriv: privCipher,
        pubBitLen: pubBitLen,
        pubX: pubX,
        pubY: pubY,
        c1x: parts.x,
        c1y: parts.y,
        hash: parts.hash,
        cipher: parts.cipher
    });
    return {
        bytes: out,
        hex: ktBytesToHex(out).toUpperCase(),
        base64: ktBytesToBase64(out),
        sm2Fmt: parts.fmt,
        warnings: warnings
    };
}

// ---------------- Section 5：页面动作 ----------------

// 当前操作单选（parse / build / to0009 / from0009）
function kt16Mode() {
    var el = document.querySelector('input[name="kt16-mode"]:checked');
    return el ? el.value : 'parse';
}

// Hex 串截断展示（超长取头尾，标注总字节数）
function kt16HexBrief(hex, head, tail) {
    var s = String(hex);
    head = head || 32;
    tail = tail || 16;
    if (s.length <= head + tail + 6) { return s; }
    return s.substr(0, head) + '…' + s.substr(s.length - tail) + '（共 ' + (s.length / 2) + ' 字节）';
}

// 字段表展示（解析结果的多行文本）
function kt16FieldLines(f) {
    var ZERO64 = '0000000000000000000000000000000000000000000000000000000000000000'; // 32 字节全零 Hex
    var lines = [
        '结构解析（总长 ' + f.blobLen + ' 字节 = 固定头 372 + Cipher ' + f.cipherLen + ' 字节）：',
        'Version：' + f.ver,
        'ulSymmAlgID：' + f.algName + '（0x' + f.algIdHex + '）',
        'ulBits：' + f.bits + '（对称密钥位长）',
        'cbEncryptedPriKey（64 字节，SM4 私钥密文）：' + kt16HexBrief(f.encPriv),
        'PubKey.BitLen：' + f.pubBitLen,
        'PubKey.X（32 字节有效值）：' + (f.pubX === ZERO64 ? '（全零，无公钥）' : kt16HexBrief(f.pubX)),
        'PubKey.Y（32 字节有效值）：' + (f.pubY === ZERO64 ? '（全零，无公钥）' : kt16HexBrief(f.pubY)),
        'ECCCipherBlob.X（C1.x 32 字节）：' + kt16HexBrief(f.cipherX),
        'ECCCipherBlob.Y（C1.y 32 字节）：' + kt16HexBrief(f.cipherY),
        'ECCCipherBlob.HASH（C3，32 字节）：' + kt16HexBrief(f.hash),
        'ECCCipherBlob.CipherLen：' + f.cipherLen + '（C2 对称密钥密文 ' + f.cipherLen + ' 字节）'
    ];
    for (var i = 0; i < f.warnings.length; i++) {
        lines.push('⚠ ' + f.warnings[i]);
    }
    return lines;
}

// "执行"按钮：按操作单选分发到对应核心函数
function kt16Run() {
    try {
        var mode = kt16Mode();
        var inputEl = document.getElementById('kt16-input');
        if (!inputEl.value.trim()) {
            throw new Error(mode === 'build'
                ? '请输入待保护的 SM2 私钥（64 位 Hex）'
                : '请输入 ENVELOPEDKEYBLOB 或 GM/T 0009 密钥对保护数据（Hex 或 Base64）');
        }
        var lines = [];
        if (mode === 'build') {
            var r = kt16BuildCore(inputEl.value, document.getElementById('kt16-pub').value);
            lines = [
                'ENVELOPEDKEYBLOB 生成成功（' + r.bytes.length + ' 字节，已通过自回环校验）：',
                'Hex（大写）：',
                r.hex,
                '——',
                'Base64：',
                r.base64,
                '——',
                '本次 SM4 对称密钥（16 字节）：' + r.keyHex,
                '自回环：✅ kt16DecryptCore 解回私钥逐字节一致'
            ];
        } else if (mode === 'to0009') {
            var r2 = kt16BlobTo0009Core(ktInputToBytes(inputEl.value));
            lines = [
                '已转换为 GM/T 0009 密钥对保护数据（布局 A，' + r2.bytes.length + ' 字节）：',
                'Hex（大写）：',
                r2.hex,
                '——',
                'Base64：',
                r2.base64,
                '——',
                'SM2 密钥密文 ' + r2.keyCipherLen + ' 字节｜SM4 私钥密文 ' + r2.privCipherLen + ' 字节（已剥尾部补零）',
                '自回环：✅ 转回 ENVELOPEDKEYBLOB 后各密文段逐字节一致'
            ];
        } else if (mode === 'from0009') {
            var r3 = kt16From0009Core(ktInputToBytes(inputEl.value));
            lines = [
                '已转换为 ENVELOPEDKEYBLOB（' + r3.bytes.length + ' 字节，对称密钥密文按「' + r3.sm2Fmt + '」切分）：',
                'Hex（大写）：',
                r3.hex,
                '——',
                'Base64：',
                r3.base64
            ];
            for (var w = 0; w < r3.warnings.length; w++) {
                lines.push('⚠ ' + r3.warnings[w]);
            }
        } else { // parse：解析（私钥框非空时一并解密）
            var blob = ktInputToBytes(inputEl.value);
            var f = kt16ParseCore(blob);
            lines = kt16FieldLines(f);
            var privVal = String(document.getElementById('kt16-priv').value || '').replace(/[\s:,]/g, '');
            if (privVal) {
                var d = kt16DecryptCore(blob, privVal);
                lines.push('——');
                lines.push('SM2 解密（' + d.sm2Fmt + '）对称密钥（16 字节）：' + d.keyHex);
                lines.push('SM4 解密（' + d.sm4Fmt + '）私钥（64 位 Hex）：' + d.privHex);
                lines.push(d.pubHex ? '公钥（04 + X + Y）：04' + d.pubHex : '公钥：Blob 内无公钥段（已置零）');
                lines.push('——');
                lines.push('PKCS#8 PEM（国产形态）：');
                lines.push(d.pem);
            } else {
                lines.push('——');
                lines.push('（填写上方「解密用 SM2 私钥」后，执行解析将一并解密出私钥与 PKCS#8 PEM）');
            }
        }
        document.getElementById('kt16-result').textContent = lines.join('\n');
        showNotification('GM/T 0016/0018 密钥：执行成功');
    } catch (e) {
        gmShowError('kt16-result', e);
    }
}

// "清空"按钮
function kt16Clear() {
    document.getElementById('kt16-input').value = '';
    document.getElementById('kt16-pub').value = '';
    document.getElementById('kt16-priv').value = '';
    document.getElementById('kt16-result').textContent = '';
}

// 操作单选切换时更新输入框占位提示（按模式解释输入内容）
function kt16Init() {
    var placeholders = {
        parse: '解析 / 解密：粘贴 ENVELOPEDKEYBLOB（Hex 或 Base64）；填写下方私钥可一并解密...',
        build: '生成：SM2 私钥（64 位 Hex），加密用公钥填下方输入框...',
        to0009: 'Blob → 0009：粘贴 ENVELOPEDKEYBLOB（Hex 或 Base64）...',
        from0009: '0009 → Blob：粘贴 GM/T 0009 密钥对保护数据（Hex 或 Base64）...'
    };
    var radios = document.querySelectorAll('input[name="kt16-mode"]');
    for (var i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', function () {
            var inputEl = document.getElementById('kt16-input');
            if (inputEl) { inputEl.placeholder = placeholders[kt16Mode()] || ''; }
        });
    }
}
// 初始化时机口径同 ktInit（body 尾加载直接执行；提前加载时等 DOM 就绪；Node 无 document 跳过）
if (typeof document === 'undefined') {
    // Node 环境：不初始化页面，仅暴露纯函数供测试
} else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', kt16Init);
} else {
    kt16Init();
}

// ---------------- 初始化 ----------------

// 绑定 PKCS#12 拖拽区（点击 / 拖拽 / 释放），口径同 asn1.js 的 asn1Init
function ktInit() {
    var dropZone = document.getElementById('kt-p12-drop');
    var fileInput = document.getElementById('kt-p12-file');
    if (dropZone && fileInput) {
        dropZone.addEventListener('click', function (event) {
            // input.click() 派发的 click 会冒泡回拖拽区，需拦截避免无限递归
            if (event.target === fileInput) {
                return;
            }
            fileInput.click();
        });
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
                ktP12ReadFile(files[0]);
            }
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                ktP12ReadFile(fileInput.files[0]);
            }
            fileInput.value = ''; // 允许重复选择同一文件
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化；
// 无 document 的环境（Node 打桩测试纯函数）直接跳过
if (typeof document === 'undefined') {
    // Node 环境：不初始化页面，仅暴露纯函数供测试
} else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ktInit);
} else {
    ktInit();
}

// Node 环境导出纯函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ktHexToBytes: ktHexToBytes,
        ktBytesToHex: ktBytesToHex,
        ktBytesToBase64: ktBytesToBase64,
        ktOidToDerContent: ktOidToDerContent,
        ktParsePrivateKey: ktParsePrivateKey,
        ktToPkcs8Core: ktToPkcs8Core,
        ktToPkcs1Core: ktToPkcs1Core,
        ktBuildPem: ktBuildPem,
        ktFormatKeyInfo: ktFormatKeyInfo,
        ktP12StructSummary: ktP12StructSummary,
        kt9ParseHeader: kt9ParseHeader,
        kt9Sm2CipherVariants: kt9Sm2CipherVariants,
        kt9DecryptCore: kt9DecryptCore,
        kt9GenCore: kt9GenCore,
        kt9PrivToPkcs8Pem: kt9PrivToPkcs8Pem,
        kt16ParseCore: kt16ParseCore,
        kt16DecryptCore: kt16DecryptCore,
        kt16BuildCore: kt16BuildCore,
        kt16BlobTo0009Core: kt16BlobTo0009Core,
        kt16From0009Core: kt16From0009Core
    };
}
