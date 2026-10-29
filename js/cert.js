// ============================================================
// X.509 证书查看器 —— page-cert
// 在 js/asn1.js 的 DER TLV 解析之上做 X.509 语义遍历：
//   PEM / Base64 / Hex → 版本 / 序列号 / 签名算法 / DN / 有效期 /
//   公钥（RSA / EC / 国密 SM2）/ 扩展（keyUsage / BC / SAN / EKU）/ 签名值
// 本文件不重复实现 TLV 解析，直接使用 asn1.js 的全局函数：
//   asn1ExtractDer / asn1ParseTlv / asn1DecodeOid / asn1OidName / asn1FormatTime
// 纯解析函数（certParse / certFormatDn / certValidityStatus / certParseSpki /
// certParseExtension）不触碰 DOM，可在 Node 中加载打桩测试（须先加载 asn1.js
// 并把上述函数挂到全局）。国密友好：签名 / 曲线 OID 命中 1.2.156.10197 分支时
// asn1OidName 已自动带"国密/SM2"标注，此处无需额外判断逻辑。
// ============================================================

// ---------- 基础工具（asn1.js 未导出的小函数本地自备，仅限字符串/字节转换） ----------

// 取 TLV 节点的内容字节（tag + 长度字段之后的部分）
function certContent(node) {
    return node.rawBytes.slice(node.headerLen);
}

// 字节数组 → 小写 Hex 字符串（无分隔）
function certBytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
}

// Hex 预览：前 maxBytes 字节大写空格分组，超长追加 …（完整值放 title / ASN.1 页查看）
function certHexPreview(bytes, maxBytes) {
    var n = Math.min(bytes.length, maxBytes);
    var parts = [];
    for (var i = 0; i < n; i++) {
        parts.push((bytes[i] < 16 ? '0' : '') + bytes[i].toString(16).toUpperCase());
    }
    var s = parts.join(' ');
    if (bytes.length > maxBytes) s += ' …';
    return s;
}

// 字节数组 → Latin-1 字符串（每字节一字符，IA5 / PrintableString 等 ASCII 场景）
function certLatin1(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += String.fromCharCode(bytes[i]);
    }
    return out;
}

// UTF-8 手工解码（非法 / 截断序列返回 null，由调用方回退 Hex）
function certUtf8(bytes) {
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
            cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12) | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
            cp -= 0x10000;
            out += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
            i += 4;
            continue;
        } else {
            return null;
        }
        out += String.fromCharCode(cp);
    }
    return out;
}

// UTF-16BE 解码（BMPString 用，落单的尾字节忽略）
function certUtf16be(bytes) {
    var out = '';
    for (var i = 0; i + 1 < bytes.length; i += 2) {
        out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return out;
}

// 无符号大整数（序列号 / RSA 模数指数 / pathLen）：BigInt 环境给十进制，否则返回 null
function certBytesToDecimal(bytes) {
    if (typeof BigInt !== 'function' || bytes.length === 0) {
        return null;
    }
    var v = BigInt(0);
    for (var i = 0; i < bytes.length; i++) {
        v = v * BigInt(256) + BigInt(bytes[i]);
    }
    return v.toString(10);
}

// 整数的有效位长（RSA 模长用）：去前导零后按首字节最高位 1 计
function certIntBitLen(bytes) {
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

// OID → 展示文本：'点分 (名称)'；未知给点分本身；名称为 '(国密)' 类前缀提示时拼接
function certOidText(oid) {
    if (oid === null) {
        return '—';
    }
    var name = asn1OidName(oid);
    if (name === '') {
        return oid;
    }
    return name.charAt(0) === '(' ? oid + ' ' + name : oid + ' (' + name + ')';
}

// ---------- AlgorithmIdentifier 与签名哈希 ----------

// SEQUENCE{OID, params 可选} → { oid, paramOid }；结构异常返回 null（上层显示 —）
function certParseAlgId(algNode) {
    if (!algNode || algNode.tagFirst !== 0x30 || algNode.children.length < 1) {
        return null;
    }
    var oid = asn1DecodeOid(certContent(algNode.children[0]));
    if (oid === null) {
        return null;
    }
    var paramOid = null;
    if (algNode.children.length > 1 && algNode.children[1].tagFirst === 0x06) {
        paramOid = asn1DecodeOid(certContent(algNode.children[1])); // EC 曲线放在 params
    }
    return { oid: oid, paramOid: paramOid };
}

// 签名算法 OID → 哈希名（只收录确信项，未知返回 '—'，绝不编造）
var CERT_SIG_HASH = {
    '1.2.840.113549.1.1.4': 'MD5',
    '1.2.840.113549.1.1.5': 'SHA-1',
    '1.2.840.113549.1.1.11': 'SHA-256',
    '1.2.840.113549.1.1.12': 'SHA-384',
    '1.2.840.113549.1.1.13': 'SHA-512',
    '1.2.840.113549.1.1.14': 'SHA-224',
    '1.2.840.10045.4.1': 'SHA-1',
    '1.2.840.10045.4.3.2': 'SHA-256',
    '1.2.840.10045.4.3.3': 'SHA-384',
    '1.2.840.10045.4.3.4': 'SHA-512',
    '1.2.156.10197.1.501': 'SM3' // SM2-1 with SM3（国密）
};

// ---------- DN（X.500 名称）格式化 ----------

// DN value 按 ASN.1 字符串类型解码：UTF8/Printable/IA5/T61/General/BMP 直取，
// 其余（OCTET STRING 等）回退 Hex 截断
function certDecodeDnValue(valueNode) {
    var c = certContent(valueNode);
    var t = valueNode.tagFirst;
    if (t === 0x0C) {
        var u = certUtf8(c);
        if (u !== null) {
            return u;
        }
    } else if (t === 0x13 || t === 0x14 || t === 0x16 || t === 0x1B) {
        return certLatin1(c);
    } else if (t === 0x1E) {
        return certUtf16be(c);
    }
    return '0x' + certHexPreview(c, 16);
}

// Name ::= SEQUENCE OF RDN，RDN = SET OF SEQUENCE{OID, value}
// 输出 'C=CN, O=XX, CN=YY'：RDN 之间 ", "；多值 RDN（SET 内多项）简化按 "+" 连接
// （RFC 2253 习惯写法）。结构异常返回 null（上层显示 —）
function certFormatDn(nameNode) {
    if (!nameNode || nameNode.tagFirst !== 0x30 || nameNode.children.length === 0) {
        return null;
    }
    var parts = [];
    for (var i = 0; i < nameNode.children.length; i++) {
        var rdn = nameNode.children[i];
        var atvs = rdn.tagFirst === 0x31 ? rdn.children : [rdn]; // 容错：缺 SET 包裹按单值处理
        var vals = [];
        for (var j = 0; j < atvs.length; j++) {
            var atv = atvs[j];
            if (!atv.children || atv.children.length < 2) {
                continue;
            }
            var oid = asn1DecodeOid(certContent(atv.children[0]));
            if (oid === null) {
                continue;
            }
            var label = asn1OidName(oid) || oid; // CN/O/C… 命中表给短名，否则给点分
            vals.push(label + '=' + certDecodeDnValue(atv.children[1]));
        }
        if (vals.length > 0) {
            parts.push(vals.join('+'));
        }
    }
    return parts.length > 0 ? parts.join(', ') : null;
}

// ---------- 有效性结论 ----------

// notBefore/notAfter 为 asn1FormatTime 的 'YYYY-MM-DD HH:mm:ss UTC' 串；
// 解析回 UTC 毫秒与 Date.now() 比较：
//   未生效 → 红 jwt-invalid；有效期内 → 绿 jwt-valid（附剩余天数）；已过期 → 红（附过期天数）
function certValidityStatus(notBeforeStr, notAfterStr) {
    var toMs = function (s) {
        var m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/.exec(String(s || ''));
        return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : null;
    };
    var nb = toMs(notBeforeStr);
    var na = toMs(notAfterStr);
    if (nb === null || na === null) {
        return { state: 'unknown', text: '—', cls: '' };
    }
    var now = Date.now();
    var DAY = 86400000;
    if (now < nb) {
        return { state: 'notyet', text: '未生效（距生效还有 ' + Math.ceil((nb - now) / DAY) + ' 天）', cls: 'jwt-invalid' };
    }
    if (now > na) {
        return { state: 'expired', text: '已过期（已过期 ' + Math.ceil((now - na) / DAY) + ' 天）', cls: 'jwt-invalid' };
    }
    return { state: 'valid', text: '有效期内（剩余 ' + Math.ceil((na - now) / DAY) + ' 天）', cls: 'jwt-valid' };
}

// ---------- 公钥解析（SubjectPublicKeyInfo） ----------

// EC / SM2 公钥点形态说明：65 字节 04 开头为未压缩点，33 字节 02/03 开头为压缩点
function certEcPointText(keyBytes) {
    if (keyBytes.length === 65 && keyBytes[0] === 0x04) {
        return '未压缩点（04 开头，65 字节，' + ((keyBytes.length - 1) / 2 * 8) + ' 位曲线）';
    }
    if (keyBytes.length === 33 && (keyBytes[0] === 0x02 || keyBytes[0] === 0x03)) {
        return '压缩点（' + certHexPreview(keyBytes.slice(0, 1), 1) + ' 开头，33 字节）';
    }
    return keyBytes.length > 0 ? '公钥 ' + keyBytes.length + ' 字节' : '—';
}

// SPKI ::= SEQUENCE{AlgorithmIdentifier, BIT STRING}
// 返回 { algoText, curveText, pointText, keyHex, keyPreview }：
//   RSA → 内层 SEQUENCE{INTEGER n, INTEGER e}，模长 = 有效位长，显示 'RSA (2048 位)'
//   ECDSA → params 为曲线 OID；国密 SM2 → 算法 OID 即 SM2 椭圆曲线（GM/T 0015 写法）
//   其他 → OID 名 + 公钥 Hex 截断
function certParseSpki(spkiNode) {
    var out = { algoText: '—', curveText: '—', pointText: '', keyHex: '', keyPreview: '—' };
    if (!spkiNode || spkiNode.tagFirst !== 0x30 || spkiNode.children.length < 2) {
        return out;
    }
    var alg = certParseAlgId(spkiNode.children[0]);
    var pubNode = spkiNode.children[1];
    if (!alg) {
        return out;
    }
    if (pubNode.tagFirst === 0x03) {
        // BIT STRING：首字节为未用位数（正常为 0），之后才是公钥字节
        var pubContent = certContent(pubNode);
        var keyBytes = pubContent.length > 0 ? pubContent.slice(1) : [];
        out.keyHex = certBytesToHex(keyBytes).toUpperCase();
        out.keyPreview = keyBytes.length > 0 ? certHexPreview(keyBytes, 32) : '—';
        if (alg.oid === '1.2.840.113549.1.1.1') {
            // RSA：BIT STRING 内容为内层 DER SEQUENCE{INTEGER n, INTEGER e}
            out.algoText = certOidText(alg.oid);
            out.curveText = '—';
            try {
                var inner = asn1ParseTlv(keyBytes, 0, keyBytes.length, 0);
                if (inner.tagFirst === 0x30 && inner.children.length >= 2 &&
                    inner.children[0].tagFirst === 0x02 && inner.children[1].tagFirst === 0x02) {
                    var nBytes = certContent(inner.children[0]);
                    var eBytes = certContent(inner.children[1]);
                    var eDec = certBytesToDecimal(eBytes);
                    out.algoText = 'RSA (' + certIntBitLen(nBytes) + ' 位)';
                    out.pointText = '指数 e = ' + (eDec !== null ? eDec : '0x' + certBytesToHex(eBytes).toUpperCase());
                }
            } catch (e) {
                // 内层结构异常：保留 OID 展示，不中断整体
            }
        } else if (alg.oid === '1.2.840.10045.2.1') {
            // ECDSA：算法 OID + params 曲线 OID
            out.algoText = certOidText(alg.oid);
            out.curveText = alg.paramOid ? certOidText(alg.paramOid) : '—';
            out.pointText = certEcPointText(keyBytes);
        } else if (alg.oid === '1.2.156.10197.1.301') {
            // 国密 SM2：SPKI 算法 OID 直接用 SM2 椭圆曲线（params 通常为 NULL）
            out.algoText = certOidText(alg.oid); // 命中即带 'SM2 椭圆曲线' 标注
            out.curveText = out.algoText;
            out.pointText = certEcPointText(keyBytes);
        } else {
            // 其他算法：OID 名 + 公钥 Hex 截断（完整值放 title）
            out.algoText = certOidText(alg.oid);
            out.curveText = alg.paramOid ? certOidText(alg.paramOid) : '—';
            out.pointText = '';
        }
    } else {
        // 公钥不是 BIT STRING（结构异常）：至少给出算法信息
        out.algoText = certOidText(alg.oid);
        out.curveText = alg.paramOid ? certOidText(alg.paramOid) : '—';
    }
    return out;
}

// ---------- 扩展解析 ----------

// keyUsage 位名（BIT STRING 高位在前，bit0 = digitalSignature）
var CERT_KEY_USAGE_NAMES = [
    'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
    'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'
];

// keyUsage (2.5.29.15)：extnValue 内容为 BIT STRING 的 DER → 启用位名列表
// （先解析出 BIT STRING TLV，再按"首字节未用位数 + 高位在前"取位）
function certParseKeyUsage(inner) {
    try {
        var root = asn1ParseTlv(inner, 0, inner.length, 0);
        if (root.tagFirst !== 0x03 || root.contentLen < 2) {
            return null;
        }
        var c = certContent(root); // [未用位数, 数据字节...]
        if (c[0] > 7) {
            return null;
        }
        var usableBits = (c.length - 1) * 8 - c[0]; // 有效位数（去掉尾部未用位）
        var on = [];
        for (var b = 0; b < CERT_KEY_USAGE_NAMES.length && b < usableBits; b++) {
            if (c[1 + (b >> 3)] & (0x80 >> (b & 7))) {
                on.push(CERT_KEY_USAGE_NAMES[b]);
            }
        }
        return on.length > 0 ? on.join('、') : '（无启用位）';
    } catch (e) {
        return null;
    }
}

// basicConstraints (2.5.29.19)：SEQUENCE{BOOLEAN cA 可选, INTEGER pathLen 可选}
function certParseBasicConstraints(inner) {
    try {
        var root = asn1ParseTlv(inner, 0, inner.length, 0);
        if (root.tagFirst !== 0x30) {
            return null;
        }
        var ca = false;
        var pathLen = null;
        for (var i = 0; i < root.children.length; i++) {
            var c = root.children[i];
            if (c.tagFirst === 0x01) {
                var bc = certContent(c);
                ca = bc.length > 0 && bc[0] !== 0;
            } else if (c.tagFirst === 0x02) {
                pathLen = certBytesToDecimal(certContent(c));
            }
        }
        var text = ca ? 'CA:TRUE' : 'CA:FALSE';
        if (ca && pathLen !== null) {
            text += ', pathLen:' + pathLen;
        }
        return text;
    } catch (e) {
        return null;
    }
}

// subjectAltName (2.5.29.17)：GeneralNames 序列逐项列出
// [2] dNSName / [7] iPAddress / [1] email / [6] URI 为 IA5（ASCII），
// [4] 目录名结构复杂，简化显示 Hex；其余上下文 tag 显示序号 + Hex 截断
function certParseSan(inner) {
    try {
        var root = asn1ParseTlv(inner, 0, inner.length, 0);
        if (root.tagFirst !== 0x30) {
            return null;
        }
        var items = [];
        for (var i = 0; i < root.children.length; i++) {
            var g = root.children[i];
            var c = certContent(g);
            var t = g.tagFirst;
            if (t === 0x82) {
                items.push('DNS:' + certLatin1(c));
            } else if (t === 0x81) {
                items.push('email:' + certLatin1(c));
            } else if (t === 0x86) {
                items.push('URI:' + certLatin1(c));
            } else if (t === 0x87) {
                items.push('IP:' + (c.length === 4
                    ? c[0] + '.' + c[1] + '.' + c[2] + '.' + c[3]
                    : certHexPreview(c, 16)));
            } else if (t === 0xA4) {
                items.push('目录名:' + certHexPreview(c, 16));
            } else {
                items.push('[' + (t & 0x1F) + ']:' + certHexPreview(c, 16));
            }
        }
        return items.length > 0 ? items.join('、') : '（空）';
    } catch (e) {
        return null;
    }
}

// extKeyUsage (2.5.29.37)：SEQUENCE OF OID → 用途名列表（serverAuth 等）
function certParseEku(inner) {
    try {
        var root = asn1ParseTlv(inner, 0, inner.length, 0);
        if (root.tagFirst !== 0x30) {
            return null;
        }
        var items = [];
        for (var i = 0; i < root.children.length; i++) {
            if (root.children[i].tagFirst === 0x06) {
                var dot = asn1DecodeOid(certContent(root.children[i]));
                if (dot !== null) {
                    items.push(asn1OidName(dot) || dot);
                }
            }
        }
        return items.length > 0 ? items.join('、') : null;
    } catch (e) {
        return null;
    }
}

// Extension ::= SEQUENCE{OID, BOOLEAN critical 可选默认 false, OCTET STRING extnValue}
// 已知扩展结构化解析，失败 / 未知回退 extnValue 内容 Hex 截断
// （完整 Hex 可点"用 ASN.1 树查看"逐节点核对）
function certParseExtension(extNode) {
    var out = { oid: null, name: '', critical: false, text: '—' };
    if (!extNode || extNode.tagFirst !== 0x30 || extNode.children.length < 2) {
        return out;
    }
    out.oid = asn1DecodeOid(certContent(extNode.children[0]));
    if (out.oid === null) {
        return out;
    }
    out.name = asn1OidName(out.oid) || out.oid;
    var idx = 1;
    var valueNode = extNode.children[idx];
    if (valueNode && valueNode.tagFirst === 0x01) {
        // critical 标记存在才编码（DER 默认省略 false）
        var cc = certContent(valueNode);
        out.critical = cc.length > 0 && cc[0] !== 0;
        idx++;
        valueNode = extNode.children[idx];
    }
    if (!valueNode || valueNode.tagFirst !== 0x04) {
        out.text = 'extnValue 缺失或类型异常';
        return out;
    }
    var inner = certContent(valueNode); // extnValue 原始内容（内嵌 DER）
    if (out.oid === '2.5.29.15') {
        var ku = certParseKeyUsage(inner);
        if (ku !== null) {
            out.text = ku;
            return out;
        }
    } else if (out.oid === '2.5.29.19') {
        var bcText = certParseBasicConstraints(inner);
        if (bcText !== null) {
            out.text = bcText;
            return out;
        }
    } else if (out.oid === '2.5.29.17') {
        var san = certParseSan(inner);
        if (san !== null) {
            out.text = san;
            return out;
        }
    } else if (out.oid === '2.5.29.37') {
        var eku = certParseEku(inner);
        if (eku !== null) {
            out.text = eku;
            return out;
        }
    }
    out.text = 'Hex: ' + certHexPreview(inner, 32);
    return out;
}

// ---------- X.509 结构遍历（核心） ----------

// 证书 DER 字节 → 语义化结果对象。根级结构异常抛中文错误；
// 单个字段缺失 / 异常不中断整体（对应值保持 '—' / null，由渲染层兜底）
function certParse(bytes) {
    var root = asn1ParseTlv(bytes, 0, bytes.length, 0);
    // Certificate ::= SEQUENCE{tbsCertificate, signatureAlgorithm, signatureValue}
    if (root.tagFirst !== 0x30 || root.children.length < 3) {
        throw new Error('不是 X.509 证书结构（顶层应为 SEQUENCE{tbsCertificate, signatureAlgorithm, signatureValue}）');
    }
    var tbs = root.children[0];
    // TBSCertificate 至少 6 个子项（V1：serial/signature/issuer/validity/subject/spki）；
    // 该检查同时排除 PKCS#8 私钥（其首子项是 INTEGER 版本号而非 SEQUENCE）等近似结构
    if (tbs.tagFirst !== 0x30 || tbs.children.length < 6) {
        throw new Error('不是 X.509 证书结构（tbsCertificate 应为至少 6 个字段的 SEQUENCE）');
    }
    var kids = tbs.children;
    var idx = 0;

    // [0] EXPLICIT version（可选，V1 证书省略）：内层 INTEGER 0/1/2 → V1/V2/V3
    var version = 1;
    if (kids[0].tagFirst === 0xA0 && kids[0].children.length > 0 && kids[0].children[0].tagFirst === 0x02) {
        var vc = certContent(kids[0].children[0]);
        var v = 0;
        for (var vi = 0; vi < vc.length; vi++) {
            v = v * 256 + vc[vi];
        }
        version = v + 1;
        idx = 1;
    }

    // 序列号（INTEGER）：十进制 + Hex（长序列号用 BigInt，环境不支持时只显 Hex）
    var serialText = '—';
    if (kids[idx].tagFirst === 0x02) {
        var sc = certContent(kids[idx]);
        if (sc.length > 0) {
            var sHex = certBytesToHex(sc).toUpperCase();
            var sDec = certBytesToDecimal(sc);
            serialText = sDec !== null ? sDec + '（0x' + sHex + '）' : '0x' + sHex;
        }
    }
    idx++;

    // tbs 内签名算法（结构上应与外层 signatureAlgorithm 一致）
    var tbsAlg = certParseAlgId(kids[idx]);
    idx++;

    // issuer / validity / subject
    var issuerDn = certFormatDn(kids[idx]);
    idx++;
    var notBefore = null;
    var notAfter = null;
    if (kids[idx] && kids[idx].children.length >= 2) {
        notBefore = asn1FormatTime(certContent(kids[idx].children[0]));
        notAfter = asn1FormatTime(certContent(kids[idx].children[1]));
    }
    idx++;
    var subjectDn = certFormatDn(kids[idx]);
    idx++;

    // 公钥
    var spki = certParseSpki(kids[idx]);
    idx++;

    // 其余字段：[1]/[2] issuerUniqueID/subjectUniqueID（V2 老字段，忽略）、[3] extensions
    var extensions = [];
    for (; idx < kids.length; idx++) {
        if (kids[idx].tagFirst === 0xA3 && kids[idx].children.length > 0 &&
            kids[idx].children[0].tagFirst === 0x30) {
            var extSeq = kids[idx].children[0]; // Extensions ::= SEQUENCE OF Extension
            for (var ei = 0; ei < extSeq.children.length; ei++) {
                extensions.push(certParseExtension(extSeq.children[ei]));
            }
        }
    }

    // 外层签名算法 + 哈希
    var outerAlg = certParseAlgId(root.children[1]);
    var sigAlgText = outerAlg ? certOidText(outerAlg.oid) : '—';
    var sigHash = outerAlg && CERT_SIG_HASH.hasOwnProperty(outerAlg.oid) ? CERT_SIG_HASH[outerAlg.oid] : '—';

    // 签名值（BIT STRING）：剥首字节未用位数后取 Hex（截断显示，完整放 title）
    var sigValText = '—';
    var sigValHex = '';
    var sigValNode = root.children[2];
    if (sigValNode.tagFirst === 0x03) {
        var svc = certContent(sigValNode);
        var sigBytes = svc.length > 0 ? svc.slice(1) : [];
        if (sigBytes.length > 0) {
            sigValHex = certBytesToHex(sigBytes).toUpperCase();
            sigValText = certHexPreview(sigBytes, 32);
        }
    }

    return {
        derLen: bytes.length,
        version: 'V' + version,
        serialText: serialText,
        sigAlgText: sigAlgText,
        tbsSigAlgText: tbsAlg ? certOidText(tbsAlg.oid) : '—',
        sigHash: sigHash,
        issuerDn: issuerDn,
        notBefore: notBefore,
        notAfter: notAfter,
        validity: certValidityStatus(notBefore, notAfter),
        subjectDn: subjectDn,
        spki: spki,
        extensions: extensions,
        sigValText: sigValText,
        sigValHex: sigValHex
    };
}

// ---------- 渲染（全 DOM API + textContent，防注入） ----------

// 结果区追加一个两列表格块（.query-table），rows 项：{label, value, cls 可选, title 可选}
function certAddTable(container, title, rows) {
    var group = document.createElement('div');
    group.className = 'input-group';
    var label = document.createElement('label');
    label.textContent = title;
    group.appendChild(label);
    var table = document.createElement('table');
    table.className = 'query-table';
    var tbody = document.createElement('tbody');
    for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        var tr = document.createElement('tr');
        var th = document.createElement('th');
        th.textContent = r.label;
        var td = document.createElement('td');
        td.textContent = (r.value === null || r.value === undefined || r.value === '') ? '—' : r.value;
        if (r.cls) {
            td.className = r.cls;
        }
        if (r.title) {
            td.title = r.title; // 完整 Hex 等（悬停查看，不撑破布局）
        }
        tr.appendChild(th);
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    group.appendChild(table);
    container.appendChild(group);
}

// 渲染 certParse 的结果到容器：基本信息 / 颁发者与有效期 / 使用者 / 公钥 / 扩展 / 签名值
function certRender(container, result) {
    container.textContent = '';
    certAddTable(container, '基本信息', [
        { label: '输入格式', value: result.format },
        { label: '版本', value: result.version },
        { label: '序列号', value: result.serialText },
        { label: '签名算法', value: result.sigAlgText },
        { label: '签名哈希', value: result.sigHash },
        { label: 'tbs 签名算法', value: result.tbsSigAlgText },
        { label: 'DER 长度', value: result.derLen + ' 字节' }
    ]);
    certAddTable(container, '颁发者 (Issuer) 与有效期', [
        { label: 'Issuer DN', value: result.issuerDn },
        { label: 'notBefore', value: result.notBefore },
        { label: 'notAfter', value: result.notAfter },
        { label: '有效性', value: result.validity.text, cls: result.validity.cls }
    ]);
    certAddTable(container, '使用者 (Subject)', [
        { label: 'Subject DN', value: result.subjectDn }
    ]);
    certAddTable(container, '公钥信息 (SubjectPublicKeyInfo)', [
        { label: '算法', value: result.spki.algoText },
        { label: '曲线', value: result.spki.curveText },
        { label: '点 / 参数', value: result.spki.pointText },
        { label: '公钥 Hex（截断）', value: result.spki.keyPreview, title: result.spki.keyHex }
    ]);
    var extRows = [];
    for (var i = 0; i < result.extensions.length; i++) {
        var ext = result.extensions[i];
        var extLabel = ext.name + (ext.critical ? '（critical）' : '');
        extRows.push({ label: extLabel, value: ext.text, title: ext.oid });
    }
    if (extRows.length === 0) {
        extRows.push({ label: '扩展', value: '（无扩展项，V1 证书常见）' });
    }
    certAddTable(container, '扩展项 (Extensions，共 ' + result.extensions.length + ' 个)', extRows);
    certAddTable(container, '签名值 (signatureValue)', [
        { label: 'Hex（截断）', value: result.sigValText, title: result.sigValHex }
    ]);
}

// ---------- 页面动作 ----------

// "解析证书"按钮：识别输入 → 结构校验 → 解析 → 渲染；根级异常报错
function certRun() {
    var inputElem = document.getElementById('cert-input');
    var resultElem = document.getElementById('cert-result');
    if (!inputElem || !resultElem) {
        return;
    }
    resultElem.textContent = '';
    if (!inputElem.value.trim()) {
        showNotification('请先输入或上传证书（PEM / Base64 / Hex）');
        return;
    }
    try {
        var ex = asn1ExtractDer(inputElem.value);
        var result = certParse(ex.bytes);
        result.format = ex.format + '｜' + ex.bytes.length + ' 字节 DER';
        certRender(resultElem, result);
        showNotification('证书解析成功（' + result.version + '）');
    } catch (e) {
        var errBox = document.createElement('div');
        errBox.className = 'cert-error';
        errBox.textContent = '❌ ' + e.message;
        resultElem.appendChild(errBox);
        showNotification('解析失败：' + e.message);
    }
}

// "用 ASN.1 树查看"按钮：把当前输入原样带到 ASN.1 页解析（逐节点 / 复制 Hex）
function certOpenInAsn1() {
    var src = document.getElementById('cert-input');
    var dst = document.getElementById('asn1-input');
    if (!src || !dst) {
        return;
    }
    if (!src.value.trim()) {
        showNotification('请先输入证书内容');
        return;
    }
    dst.value = src.value;
    asn1Parse();
    switchPage('page-asn1');
}

// "清空"按钮
function certClear() {
    var inputElem = document.getElementById('cert-input');
    var resultElem = document.getElementById('cert-result');
    if (inputElem) {
        inputElem.value = '';
    }
    if (resultElem) {
        resultElem.textContent = '';
    }
}

// 读取上传文件：有 PEM 头按文本直接用，否则按字节转大写 Hex；填入后自动解析一次
function certReadFile(file) {
    if (file.size > 512 * 1024) {
        showNotification('文件过大（超过 512KB），请粘贴内容代替上传');
        return;
    }
    var reader = new FileReader();
    reader.onload = function () {
        var buf = new Uint8Array(reader.result);
        // 前 64 字节找 PEM 头（PEM 为纯 ASCII，按 Latin-1 逐字节比对即可）
        var head = '';
        for (var i = 0; i < Math.min(buf.length, 64); i++) {
            head += String.fromCharCode(buf[i]);
        }
        var inputElem = document.getElementById('cert-input');
        if (head.indexOf('-----BEGIN') >= 0) {
            // 分块转文本，避免大文件 fromCharCode 参数超限
            var text = '';
            for (var j = 0; j < buf.length; j += 4096) {
                text += String.fromCharCode.apply(null, buf.subarray(j, Math.min(j + 4096, buf.length)));
            }
            inputElem.value = text;
        } else {
            // 二进制 DER：转大写 Hex 填入
            inputElem.value = certBytesToHex(buf).toUpperCase();
        }
        showNotification('已加载文件：' + file.name + '（' + file.size + ' 字节）');
        certRun();
    };
    reader.onerror = function () {
        showNotification('文件读取失败');
    };
    reader.readAsArrayBuffer(file);
}

// ---------- 初始化 ----------

// 绑定拖拽区（点击/拖拽/释放）与文件输入（参考 js/asn1.js 尾部写法）
function certInit() {
    var dropZone = document.getElementById('cert-drop-zone');
    var fileInput = document.getElementById('cert-file-input');
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
                certReadFile(files[0]);
            }
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                certReadFile(fileInput.files[0]);
            }
            fileInput.value = ''; // 允许重复选择同一文件
        });
    }
}

// 本文件在 asn1.js 之后、body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底；无 document 的环境（Node 打桩测试纯解析函数）直接跳过
if (typeof document === 'undefined') {
    // Node 环境：不初始化页面，仅暴露纯解析函数供测试
} else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', certInit);
} else {
    certInit();
}

// Node 环境导出纯解析函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        certParse: certParse,
        certFormatDn: certFormatDn,
        certValidityStatus: certValidityStatus,
        certParseSpki: certParseSpki,
        certParseExtension: certParseExtension
    };
}
