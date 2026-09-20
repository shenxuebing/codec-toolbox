// ============================================================
// 增强版编解码工具 - JWT 工具页（page-jwt）
// 功能：解码（任意算法展示）/ 签发（HS256）/ 验证（HS256）
// 依赖（须先于本文件加载）：
//   js/app.js        → safeAtob / bytesToBinaryString / showNotification
//   js/timestamp.js  → tsFormatLocal / tsRelativeDesc（时间字段人性化显示复用）
// 协议约束（RFC 7515 / RFC 7519）：JWT 由三段组成，以 . 分隔——
//   base64url(header) . base64url(payload) . signature
//   前两段为 base64url 编码的 JSON；第三段是对前两段拼接文本的算法签名。
//   base64url 变体：'+' → '-'、'/' → '_'、省略 '=' 填充。
// ============================================================

// 字节数组 → base64url 字符串（先转标准 base64，再做字符替换并去掉 = 填充）
function jwtBase64UrlEncode(bytes) {
    return btoa(bytesToBinaryString(bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// 判断是否为普通 JSON 对象（排除 null 与数组：JWT 的 header/payload 都必须是对象）
function jwtIsPlainObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// base64url 段 → JSON 对象：复用全局 safeAtob 兼容 base64url 变体，
// base64url 解码失败 / 非法 UTF-8 / 非 JSON 均统一抛出带中文说明的错误
function jwtParseSegmentJson(segment, segmentName) {
    var binary;
    try {
        binary = safeAtob(segment);
    } catch (e) {
        throw new Error(segmentName + ' base64url 解码失败（含非法字符）');
    }
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    // 按 UTF-8 解码为文本（非法字节序列会产生替换符，随后 JSON.parse 会报错）
    var text = new TextDecoder().decode(bytes);
    try {
        return JSON.parse(text);
    } catch (e) {
        throw new Error(segmentName + ' 不是合法的 JSON');
    }
}

// 把 JWT 字符串拆为三段并做基本格式校验，失败抛出明确错误
function jwtSplitParts(input) {
    var parts = input.split('.');
    if (parts.length !== 3) {
        throw new Error('格式错误：JWT 应为三段式（header.payload.signature，以 . 分隔），当前拆分出 ' + parts.length + ' 段');
    }
    if (!parts[0] || !parts[1]) {
        throw new Error('格式错误：header / payload 段不能为空');
    }
    return parts;
}

// 用密钥对文本计算 HMAC-SHA256，返回签名字节数组（签发与验证共用同一实现）
async function jwtHmacSha256(secret, text) {
    var encoder = new TextEncoder();
    // 导入原始字节密钥，仅允许用于签名操作
    var key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    var sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(text));
    return new Uint8Array(sigBuffer);
}

// 向容器追加一行：segments 为 {text, cls} 对象或纯字符串的数组，cls 用于着色
// （用 DOM API 构建而非拼 HTML，天然避免 payload 内容引入的 HTML 注入问题）
function jwtAddLine(container, segments) {
    var line = document.createElement('div');
    line.style.marginBottom = '4px';
    segments.forEach(function (segment) {
        var span = document.createElement('span');
        if (typeof segment === 'string') {
            span.textContent = segment;
        } else {
            span.textContent = segment.text;
            if (segment.cls) {
                span.className = segment.cls;
            }
        }
        line.appendChild(span);
    });
    container.appendChild(line);
}

// 时间字段人性化：遍历 exp / iat / nbf（仅数值型），显示标准时间 + 相对描述；
// exp 已过期红色加粗"已过期 xx"、未过期绿色"有效期内"；nbf 未生效红色、已生效绿色
function jwtRenderTimeInfo(container, payload) {
    container.textContent = '';
    var found = false;
    var fields = [
        { key: 'exp', label: 'exp（过期时间）' },
        { key: 'iat', label: 'iat（签发时间）' },
        { key: 'nbf', label: 'nbf（生效时间）' }
    ];
    fields.forEach(function (field) {
        var value = payload[field.key];
        if (typeof value !== 'number') {
            return;
        }
        found = true;
        var date = new Date(value * 1000);
        var valid = !isNaN(date.getTime());
        var timeText = valid
            ? tsFormatLocal(date) + '（本地）/ ' + date.toISOString()
            : '数值超出可表示的时间范围';
        // 第一行：字段 = 原始值 → 标准时间 · 相对描述
        jwtAddLine(container, [field.label + ' = ' + value + ' → ' + timeText + ' · ' + tsRelativeDesc(value * 1000)]);
        if (!valid) {
            return;
        }
        // 第二行：状态结论（exp / nbf 有明确的生效语义，iat 的相对描述已并入第一行）
        if (field.key === 'exp') {
            if (Date.now() >= date.getTime()) {
                jwtAddLine(container, [{ text: '❌ 已过期（' + tsRelativeDesc(value * 1000) + '）', cls: 'jwt-expired' }]);
            } else {
                jwtAddLine(container, [{ text: '✓ 有效期内（约 ' + tsRelativeDesc(value * 1000) + '过期）', cls: 'jwt-valid' }]);
            }
        } else if (field.key === 'nbf') {
            if (Date.now() < date.getTime()) {
                jwtAddLine(container, [{ text: '⚠️ 尚未生效（约 ' + tsRelativeDesc(value * 1000) + '生效）', cls: 'jwt-expired' }]);
            } else {
                jwtAddLine(container, [{ text: '✓ 已生效（' + tsRelativeDesc(value * 1000) + '）', cls: 'jwt-valid' }]);
            }
        }
    });
    if (!found) {
        container.textContent = 'payload 中未发现数值型的 exp / iat / nbf 字段';
    }
}

// 解码 JWT：任意算法均可展示（解码只按结构呈现，不校验签名）
function jwtDecode() {
    var headerEl = document.getElementById('jwt-header');
    var payloadEl = document.getElementById('jwt-payload');
    var sigEl = document.getElementById('jwt-signature');
    var timeEl = document.getElementById('jwt-time-info');
    headerEl.textContent = payloadEl.textContent = sigEl.textContent = '';
    timeEl.textContent = '';

    var input = document.getElementById('jwt-decode-input').value.trim();
    if (!input) {
        headerEl.textContent = '请输入 JWT';
        return;
    }

    var parts;
    try {
        parts = jwtSplitParts(input);
    } catch (e) {
        headerEl.textContent = '❌ ' + e.message;
        return;
    }

    // header 段：base64url → JSON，并在结果中标注 alg / typ
    var header;
    try {
        header = jwtParseSegmentJson(parts[0], 'header');
        if (!jwtIsPlainObject(header)) {
            throw new Error('header 必须是 JSON 对象');
        }
    } catch (e) {
        headerEl.textContent = '❌ ' + e.message;
        return;
    }
    headerEl.textContent = JSON.stringify(header, null, 2) +
        '\n——\nalg（算法）：' + (header.alg !== undefined ? String(header.alg) : '（未声明）') +
        '\ntyp（类型）：' + (header.typ !== undefined ? String(header.typ) : '（未声明）');

    // payload 段：base64url → JSON
    var payload;
    try {
        payload = jwtParseSegmentJson(parts[1], 'payload');
        if (!jwtIsPlainObject(payload)) {
            throw new Error('payload 必须是 JSON 对象');
        }
    } catch (e) {
        payloadEl.textContent = '❌ ' + e.message;
        return;
    }
    payloadEl.textContent = JSON.stringify(payload, null, 2);

    // signature 段：展示 base64url 原串 + 按字节空格分组的十六进制大写
    if (!parts[2]) {
        sigEl.textContent = '（签名段为空：这是一个未签名的 JWT）';
    } else {
        try {
            var sigBinary = safeAtob(parts[2]);
            var hexParts = [];
            for (var i = 0; i < sigBinary.length; i++) {
                hexParts.push(sigBinary.charCodeAt(i).toString(16).padStart(2, '0'));
            }
            sigEl.textContent = 'Base64URL：' + parts[2] +
                '\nHex：' + hexParts.join(' ').toUpperCase();
        } catch (e) {
            sigEl.textContent = '❌ 签名段 base64url 解码失败';
        }
    }

    // 时间字段人性化说明（依赖 payload 解析成功）
    jwtRenderTimeInfo(timeEl, payload);
}

// 签发 JWT（HS256）：header 固定 {"alg":"HS256","typ":"JWT"}；
// 签名输入为 base64url(headerJSON) + '.' + base64url(payloadJSON) 的 UTF-8 字节，
// 以实际序列化出的文本为准计算签名，保证"签出的就是看到的"
async function jwtSign() {
    var resultEl = document.getElementById('jwt-encode-result');
    resultEl.textContent = '';
    var payloadText = document.getElementById('jwt-payload-input').value.trim();
    var secret = document.getElementById('jwt-secret').value;

    if (!payloadText) {
        resultEl.textContent = '请输入 payload';
        return;
    }
    var payload;
    try {
        payload = JSON.parse(payloadText);
    } catch (e) {
        resultEl.textContent = '❌ payload 不是合法 JSON：' + e.message +
            '\n提示：模板中 iat / exp 已留空，请替换为秒级时间戳数字（如 "iat": 1700000000）';
        return;
    }
    if (!jwtIsPlainObject(payload)) {
        resultEl.textContent = '❌ payload 必须是 JSON 对象（{...}）';
        return;
    }
    if (!secret) {
        resultEl.textContent = '请输入密钥';
        return;
    }

    try {
        var encoder = new TextEncoder();
        var header = { alg: 'HS256', typ: 'JWT' };
        var signingInput = jwtBase64UrlEncode(encoder.encode(JSON.stringify(header))) +
            '.' + jwtBase64UrlEncode(encoder.encode(JSON.stringify(payload)));
        var sigBytes = await jwtHmacSha256(secret, signingInput);
        resultEl.textContent = signingInput + '.' + jwtBase64UrlEncode(sigBytes);
        showNotification('JWT 签发成功');
    } catch (error) {
        resultEl.textContent = '❌ 签发失败：' + error.message;
    }
}

// 验证 JWT（HS256）：用相同密钥对前两段重算签名，与第三段比对；
// 本地工具无时序攻击面，直接字符串比较即可；同时独立给出 exp 检查结论
async function jwtVerify() {
    var resultEl = document.getElementById('jwt-verify-result');
    resultEl.textContent = '';
    var input = document.getElementById('jwt-verify-input').value.trim();
    var secret = document.getElementById('jwt-verify-secret').value;

    if (!input) {
        resultEl.textContent = '请输入 JWT';
        return;
    }
    if (!secret) {
        resultEl.textContent = '请输入密钥';
        return;
    }

    try {
        var parts = jwtSplitParts(input);
        var header = jwtParseSegmentJson(parts[0], 'header');
        if (!jwtIsPlainObject(header)) {
            throw new Error('header 必须是 JSON 对象');
        }
        // 非 HS256 算法提前提醒（仍继续对比，结果大概率不匹配）
        if (header.alg !== undefined && header.alg !== 'HS256') {
            jwtAddLine(resultEl, ['⚠️ 该 JWT 声明 alg = ' + header.alg + '，本工具仅支持 HS256 验证，签名对比可能不匹配']);
        }

        var expected = jwtBase64UrlEncode(await jwtHmacSha256(secret, parts[0] + '.' + parts[1]));
        var match = expected === parts[2];
        jwtAddLine(resultEl, match
            ? [{ text: '✓ 签名验证通过（HS256 / HMAC-SHA256）', cls: 'jwt-valid' }]
            : [{ text: '✗ 签名不匹配（密钥错误或内容被篡改）', cls: 'jwt-invalid' }]);

        // exp 检查：无论签名是否匹配都独立给出结论（仅作信息展示）
        try {
            var payload = jwtParseSegmentJson(parts[1], 'payload');
            if (jwtIsPlainObject(payload) && typeof payload.exp === 'number') {
                var expDate = new Date(payload.exp * 1000);
                if (isNaN(expDate.getTime())) {
                    jwtAddLine(resultEl, ['ℹ️ exp 检查：数值超出可表示的时间范围']);
                } else if (Date.now() >= expDate.getTime()) {
                    jwtAddLine(resultEl, [
                        { text: '✗ 已过期：exp = ' + payload.exp + ' → ' + tsFormatLocal(expDate) + '（本地，' },
                        { text: tsRelativeDesc(payload.exp * 1000) + '已过期', cls: 'jwt-expired' },
                        { text: '）' }
                    ]);
                } else {
                    jwtAddLine(resultEl, [
                        { text: '✓ 有效期内：exp = ' + payload.exp + ' → ' + tsFormatLocal(expDate) + '（本地，' },
                        { text: '约 ' + tsRelativeDesc(payload.exp * 1000) + '过期', cls: 'jwt-valid' },
                        { text: '）' }
                    ]);
                }
            } else {
                jwtAddLine(resultEl, ['ℹ️ payload 未包含数值型 exp 字段，跳过过期检查']);
            }
        } catch (e) {
            jwtAddLine(resultEl, ['ℹ️ payload 解析失败（' + e.message + '），无法检查 exp']);
        }
    } catch (error) {
        resultEl.textContent = '❌ ' + error.message;
    }
}

// 页面初始化：在签发区提示当前秒级时间戳，供用户填写 iat 参考
function jwtInit() {
    var hintEl = document.getElementById('jwt-now-sec-hint');
    if (hintEl) {
        hintEl.textContent = Math.floor(Date.now() / 1000);
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', jwtInit);
} else {
    jwtInit();
}
