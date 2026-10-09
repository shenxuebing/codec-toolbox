// ============================================================
// 增强版编解码工具 - 文本批量处理页（page-textkit）
// 功能：多行文本按选项链式处理（去首尾空白 / 删空行 / 去重 / 排序 /
//       转小写）+ 处理前后统计（字符 / 行 / 非空行 / UTF-8 字节数）
// 依赖（须先于本文件加载）：
//   js/app.js → showNotification / copyToClipboard
// 处理口径：
//   顺序固定 trim → 删空行 → 去重（Set 保持首次出现）→
//   排序（localeCompare，可选降序）→ 转小写；
//   未勾选任何处理选项时只统计不修改文本（结果 = 原文）
// ============================================================

// 最近一次处理结果（供"下载 .txt"使用）
var textkitLastResult = '';

// 文本 → 逻辑行数组：兼容 CRLF / CR / LF 三种换行风格，
// 行尾若以换行结束则末尾不再多算一个空行（与常见编辑器行数口径一致）
function textkitSplitLines(text) {
    if (text === '') { return []; }
    var lines = text.split(/\r\n|\r|\n/);
    if (lines.length > 1 && lines[lines.length - 1] === '') {
        lines.pop();
    }
    return lines;
}

// 行数组按选项链式处理（顺序固定，见文件头注释）
//   opts: { trim, rmempty, dedupe, sort, desc, lower } 均为布尔
function textkitProcessLines(lines, opts) {
    var out = lines.slice();
    var i;
    if (opts.trim) {
        for (i = 0; i < out.length; i++) { out[i] = out[i].trim(); }
    }
    if (opts.rmempty) {
        out = out.filter(function (line) { return line !== ''; });
    }
    if (opts.dedupe) {
        // Set 按插入顺序遍历，天然保持"首次出现"的先后
        var seen = new Set();
        out = out.filter(function (line) {
            if (seen.has(line)) { return false; }
            seen.add(line);
            return true;
        });
    }
    if (opts.sort) {
        out.sort(function (a, b) { return a.localeCompare(b); });
        if (opts.desc) { out.reverse(); }
    }
    if (opts.lower) {
        for (i = 0; i < out.length; i++) { out[i] = out[i].toLowerCase(); }
    }
    return out;
}

// 文本的 UTF-8 编码字节数（TextEncoder；极老环境兜底用
// unescape(encodeURIComponent()) 经典技巧按字节长度估算）
function textkitByteLength(text) {
    if (typeof TextEncoder !== 'undefined') {
        return new TextEncoder().encode(text).length;
    }
    return unescape(encodeURIComponent(text)).length;
}

// 统计一个文本：字符数（UTF-16 码元）/ 行数 / 非空行数 / UTF-8 字节数
function textkitStatsOf(text) {
    var lines = textkitSplitLines(text);
    var nonEmpty = 0;
    for (var i = 0; i < lines.length; i++) {
        if (lines[i].trim() !== '') { nonEmpty++; }
    }
    return {
        chars: text.length,
        lines: lines.length,
        nonEmpty: nonEmpty,
        bytes: textkitByteLength(text)
    };
}

// 统计对象 → 单行展示文本；统计模式为"行数"时行指标排在首位，
// 为"字符数"（默认）时字符指标排在首位
function textkitFormatStats(stats, mode) {
    if (mode === 'lines') {
        return '行 ' + stats.lines + ' / 非空行 ' + stats.nonEmpty +
            ' / 字符 ' + stats.chars + ' / 字节(UTF-8) ' + stats.bytes;
    }
    return '字符 ' + stats.chars + ' / 行 ' + stats.lines +
        ' / 非空行 ' + stats.nonEmpty + ' / 字节(UTF-8) ' + stats.bytes;
}

// 读取统计模式单选：chars（默认）/ lines
function textkitGetMode() {
    var el = document.querySelector('input[name="textkit-mode"]:checked');
    return el ? el.value : 'chars';
}

// 读取全部处理选项复选框
function textkitGetOptions() {
    return {
        trim: document.getElementById('textkit-trim').checked,
        rmempty: document.getElementById('textkit-rmempty').checked,
        dedupe: document.getElementById('textkit-dedupe').checked,
        sort: document.getElementById('textkit-sort').checked,
        desc: document.getElementById('textkit-sort-desc').checked,
        lower: document.getElementById('textkit-lower').checked
    };
}

// "处理"按钮：统计 → 按需链式处理 → 写结果与统计区（含前后对比）
function textkitRun() {
    var input = document.getElementById('textkit-input');
    var resultEl = document.getElementById('textkit-result');
    var statsEl = document.getElementById('textkit-stats');
    var text = input.value;
    if (!text) {
        showNotification('请先输入内容');
        return;
    }

    var opts = textkitGetOptions();
    var mode = textkitGetMode();
    var before = textkitStatsOf(text);

    var outText = text;
    var anyOption = opts.trim || opts.rmempty || opts.dedupe || opts.sort || opts.lower;
    if (anyOption) {
        outText = textkitProcessLines(textkitSplitLines(text), opts).join('\n');
    } // 未勾选任何处理选项：只统计不修改，结果为原文

    var after = textkitStatsOf(outText);
    textkitLastResult = outText;
    resultEl.textContent = outText === '' ? '（处理后为空文本）' : outText;

    // 统计区：处理前 → 处理后对比；行数减少时额外标注删了几行
    var removed = before.lines - after.lines;
    statsEl.textContent = '处理前：' + textkitFormatStats(before, mode) +
        ' → 处理后：' + textkitFormatStats(after, mode) +
        (removed > 0 ? '（删了 ' + removed + ' 行）' : '（行数未变）');
    showNotification(anyOption ? '处理完成' : '未勾选处理选项，仅统计');
}

// "下载 .txt"按钮：把最近一次处理结果保存为 processed.txt
function textkitDownload() {
    if (!textkitLastResult) {
        showNotification('没有可下载的结果，请先处理');
        return;
    }
    var blob = new Blob([textkitLastResult], { type: 'text/plain;charset=utf-8' });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'processed.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    showNotification('已开始下载 processed.txt');
}

// "清空"按钮：清空输入、统计与结果，焦点回到输入框
function textkitClear() {
    var input = document.getElementById('textkit-input');
    if (input) { input.value = ''; input.focus(); }
    document.getElementById('textkit-result').textContent = '';
    document.getElementById('textkit-stats').textContent = '输入文本并点击"处理"后此处显示统计';
    textkitLastResult = '';
}

// Node 环境导出（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        textkitSplitLines: textkitSplitLines,
        textkitProcessLines: textkitProcessLines,
        textkitStatsOf: textkitStatsOf,
        textkitByteLength: textkitByteLength,
        textkitFormatStats: textkitFormatStats,
        textkitRun: textkitRun,
        textkitDownload: textkitDownload,
        textkitClear: textkitClear
    };
}
