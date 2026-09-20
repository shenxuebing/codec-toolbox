// ============================================================
// 增强版编解码工具 - JSON 工具页（page-json）
// 功能：格式化 / 压缩 / 校验 / 转义为字符串字面量 / 去转义
// 依赖（须先于本文件加载）：
//   js/app.js → copyToClipboard（结果区复制按钮使用，onclick 直连）
// 按钮均为内联 onclick 调用，本文件无需 DOM 就绪初始化逻辑
// ============================================================

// 读取所选缩进空格数（2/4/8，作为 JSON.stringify 的第三个参数）
function jsonGetIndent() {
    var checked = document.querySelector('input[name="json-indent"]:checked');
    return checked ? parseInt(checked.value, 10) : 2;
}

// 中文 → \uXXXX 转义（仅基本区汉字 U+4E00-U+9FA5，供"中文转义显示"选项使用）
function jsonEscapeChinese(text) {
    return text.replace(/[\u4e00-\u9fa5]/g, function (c) {
        return '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0');
    });
}

// 解析出错时尝试从错误信息中提取 position（V8 风格 "... at position N"），
// 换算为第几行第几列并返回追加提示；提取不到（如 Firefox 信息已自带行列描述）返回空串
function jsonPositionHint(error, text) {
    var match = /position (\d+)/.exec(error.message);
    if (!match) {
        return '';
    }
    var pos = parseInt(match[1], 10);
    if (isNaN(pos) || pos < 0) {
        return '';
    }
    if (pos > text.length) {
        pos = text.length;
    }
    var line = 1;
    var lineStart = 0;
    for (var i = 0; i < pos; i++) {
        if (text.charCodeAt(i) === 10) {   // '\n'
            line++;
            lineStart = i + 1;
        }
    }
    return '\n（错误位置：约在第 ' + line + ' 行 第 ' + (pos - lineStart + 1) + ' 列）';
}

// 格式化：JSON.parse 校验 → 按所选缩进 stringify；
// 勾选"中文转义"时对结果中的汉字再做 \uXXXX 转义（仅影响显示与复制内容）
function jsonFormat() {
    var resultEl = document.getElementById('json-result');
    var input = document.getElementById('json-input').value;
    if (!input.trim()) {
        resultEl.textContent = '请输入 JSON 文本';
        return;
    }
    var obj;
    try {
        obj = JSON.parse(input);
    } catch (e) {
        resultEl.textContent = '❌ JSON 解析失败：' + e.message + jsonPositionHint(e, input);
        return;
    }
    var output = JSON.stringify(obj, null, jsonGetIndent());
    if (document.getElementById('json-unicode').checked) {
        output = jsonEscapeChinese(output);
    }
    resultEl.textContent = output;
}

// 压缩：parse 后无缩进序列化为单行（parse 本身即是校验，非法输入报错并定位行列）
function jsonMinify() {
    var resultEl = document.getElementById('json-result');
    var input = document.getElementById('json-input').value;
    if (!input.trim()) {
        resultEl.textContent = '请输入 JSON 文本';
        return;
    }
    try {
        resultEl.textContent = JSON.stringify(JSON.parse(input));
    } catch (e) {
        resultEl.textContent = '❌ JSON 解析失败：' + e.message + jsonPositionHint(e, input);
    }
}

// 校验：只报告合法/非法；合法时给出顶层类型（对象/数组）与顶层键/元素数量
function jsonValidate() {
    var resultEl = document.getElementById('json-result');
    var input = document.getElementById('json-input').value;
    if (!input.trim()) {
        resultEl.textContent = '请输入 JSON 文本';
        return;
    }
    var obj;
    try {
        obj = JSON.parse(input);
    } catch (e) {
        resultEl.textContent = '❌ JSON 格式非法：' + e.message + jsonPositionHint(e, input);
        return;
    }
    var desc;
    if (Array.isArray(obj)) {
        desc = '数组，' + obj.length + ' 个顶层元素';
    } else if (obj !== null && typeof obj === 'object') {
        desc = '对象，' + Object.keys(obj).length + ' 个顶层键';
    } else {
        // 顶层是字符串/数字/布尔/null：JSON 同样合法，但无键/元素可数
        desc = '值类型（' + JSON.stringify(obj) + '）';
    }
    resultEl.textContent = '✓ JSON 格式合法（' + desc + '）';
}

// 转义为字符串字面量：把输入整体视为一个字符串，先整体 stringify 再去掉外层引号，
// 内部的引号/换行/反斜杠/控制字符均被转义，得到可直接粘贴进代码的双引号字符串
// （如 {"a":1} → {\"a\":1}）。不做 trim：多行 JSON 中的换行会被转成 \n 保留
function jsonEscape() {
    var resultEl = document.getElementById('json-result');
    var input = document.getElementById('json-input').value;
    if (!input.trim()) {
        resultEl.textContent = '请输入 JSON 文本';
        return;
    }
    resultEl.textContent = JSON.stringify(input).slice(1, -1);
}

// 去转义：把输入视为字符串字面量的内容，包上一层引号后 JSON.parse 还原
// （如 {\"a\":1} → {"a":1}）。先 trim：粘贴内容末尾常带换行，会破坏字符串字面量
function jsonUnescape() {
    var resultEl = document.getElementById('json-result');
    var input = document.getElementById('json-input').value.trim();
    if (!input) {
        resultEl.textContent = '请输入 JSON 文本';
        return;
    }
    try {
        resultEl.textContent = JSON.parse('"' + input + '"');
    } catch (e) {
        resultEl.textContent = '❌ 去转义失败：' + e.message +
            '\n提示：输入应为已转义的字符串字面量内容（如 {\\"a\\":1}），其中的双引号必须写成 \\" ，且不能包含裸换行';
    }
}

// 清空输入与结果
function jsonClear() {
    document.getElementById('json-input').value = '';
    document.getElementById('json-result').textContent = '';
}
