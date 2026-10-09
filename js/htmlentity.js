// ============================================================
// 增强版编解码工具 - HTML 实体编解码页（page-htmlentity）
// 功能：转实体（五个保留字 / 全部非 ASCII）与 转字符（浏览器原生解码）
// 依赖（须先于本文件加载）：
//   js/app.js → showNotification / copyToClipboard
// 编码口径：
//   basic = 仅 & < > " ' 五个 HTML/XML 保留字（&amp; &lt; &gt; &quot; &#39;）
//   all   = 五个保留字 + 码位大于 127 的所有字符转 &#xNNNN;（大写十六进制）
// 解码口径：
//   借道 textarea 的 innerHTML——浏览器按 RCDATA 规则解析时
//   会自动解码全部命名实体与十进制/十六进制数字实体，读回 value 即得原文
// ============================================================

// 五个保留字转义（& 必须最先替换：后续替换会引入新的 & 字符——
// 例如 < 转成 &lt; 后若 & 尚未处理，这个新引入的 & 会被再次转义成 &amp;lt;，
// 因此顺序固定为 & → < → > → " → '）
function entityEncodeBasic(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// 全量转义：五个保留字 + 所有非 ASCII 字符（码位 > 127）转 &#xNNNN;
// 逐码位扫描（codePointAt），代理对（emoji 等增补平面字符）按完整
// 码位一次处理、i 前移两个码元，不会拆成两个半码位分别转义
function entityEncodeAll(s) {
    var encoded = entityEncodeBasic(s);
    var out = '';
    var i = 0;
    while (i < encoded.length) {
        var code = encoded.codePointAt(i);
        if (code > 127) {
            out += '&#x' + code.toString(16).toUpperCase() + ';';
        } else {
            out += encoded.charAt(i);
        }
        // 增补平面字符（码位 > 0xFFFF）占 2 个 UTF-16 码元，其余占 1 个
        i += code > 0xFFFF ? 2 : 1;
    }
    return out;
}

// 读取转义范围单选：basic（默认）/ all
function entityGetScope() {
    var el = document.querySelector('input[name="entity-scope"]:checked');
    return el ? el.value : 'basic';
}

// "转实体"按钮：按所选范围转义并写入结果区
function entityEncode() {
    var input = document.getElementById('entity-input');
    var resultEl = document.getElementById('entity-result');
    var text = input.value;
    if (!text) {
        showNotification('请先输入内容');
        return;
    }
    var result = entityGetScope() === 'all' ? entityEncodeAll(text) : entityEncodeBasic(text);
    resultEl.textContent = result;
    showNotification('转实体完成');
}

// "转字符"按钮：利用 textarea 中间层解码
//   原理：把输入串赋给一个游离 textarea 的 innerHTML，浏览器解析
//   RCDATA 文本时会对 &amp; &lt; &#39; &#x6D4B; 这类命名/数字实体
//   自动解码，且不会把 <tag> 当作元素解析（textarea 内容只会被当作
//   文本直到 </textarea>），随后读 el.value 即得到解码后的纯文本
function entityDecode() {
    var input = document.getElementById('entity-input');
    var resultEl = document.getElementById('entity-result');
    var text = input.value;
    if (!text) {
        showNotification('请先输入内容');
        return;
    }
    var el = document.createElement('textarea');
    el.innerHTML = text;
    resultEl.textContent = el.value;
    showNotification('转字符完成');
}

// "清空"按钮：清空输入与结果，焦点回到输入框
function entityClear() {
    var input = document.getElementById('entity-input');
    if (input) { input.value = ''; input.focus(); }
    document.getElementById('entity-result').textContent = '';
}

// Node 环境导出（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        entityEncodeBasic: entityEncodeBasic,
        entityEncodeAll: entityEncodeAll,
        entityEncode: entityEncode,
        entityDecode: entityDecode,
        entityClear: entityClear
    };
}
