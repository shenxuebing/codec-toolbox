// ============================================================
// 增强版编解码工具 - JSON ↔ CSV 互转页（page-csv）
// 功能：对象数组 → CSV（列并集 + RFC 4180 转义 + BOM 选项）/
//       CSV → JSON（RFC 4180 状态机解析 + 单元格类型推断）
// 依赖（须先于本文件加载）：
//   js/app.js → showNotification / copyToClipboard
// 转义口径（RFC 4180）：
//   单元格含 分隔符 / 双引号 / 换行 时整格用双引号包裹，
//   内部双引号翻倍为 ""；行与行之间用 \r\n 分隔
// ============================================================

// 最近一次转换结果与对应扩展名（供"下载"按钮使用）
var csvLastResult = '';
var csvLastExt = '.csv';

// 分隔符单选的 value 归一化：HTML 属性里写的是字面量 "\t"（反斜杠+t），
// 浏览器不会解释转义序列，这里统一换成真正的制表符
function csvNormalizeSep(v) {
    if (v === '\\t') { return '\t'; }
    return v || ',';
}

// CSV 单元格转义（RFC 4180）：
//   null/undefined → 空串；值含 分隔符、"、\n、\r 之一时
//   整格加双引号包裹，且内部 " 翻倍为 ""；其余原样输出
function csvEscapeCell(v, sep) {
    if (v === null || v === undefined) { return ''; }
    var s = String(v);
    if (s.indexOf('"') !== -1 || s.indexOf(sep) !== -1 ||
        s.indexOf('\n') !== -1 || s.indexOf('\r') !== -1) {
        return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
}

// JSON 对象数组 → CSV 文本
//   obj       解析后的 JSON 值（必须是纯对象数组，否则抛错）
//   sep       分隔符（已归一化的真实字符）
//   hasHeader true 时首行输出键名作为表头
// 返回不含 BOM 的 CSV 字符串（BOM 由 csvConvert 按勾选项追加），
// 行分隔符用 \r\n（RFC 4180 规定 CRLF）
function csvJsonToCsv(obj, sep, hasHeader) {
    if (!Array.isArray(obj)) {
        throw new Error('应为对象数组，如 [{...},{...}]');
    }
    for (var i = 0; i < obj.length; i++) {
        var el = obj[i];
        if (typeof el !== 'object' || el === null || Array.isArray(el)) {
            throw new Error('应为对象数组，如 [{...},{...}]');
        }
    }
    // 列 = 所有元素键的并集，按首次出现顺序排列
    var columns = [];
    var seen = {};
    for (var a = 0; a < obj.length; a++) {
        for (var key in obj[a]) {
            if (Object.prototype.hasOwnProperty.call(obj[a], key) && !seen[key]) {
                seen[key] = true;
                columns.push(key);
            }
        }
    }
    var lines = [];
    if (hasHeader && columns.length > 0) {
        lines.push(columns.map(function (k) { return csvEscapeCell(k, sep); }).join(sep));
    }
    for (var r = 0; r < obj.length; r++) {
        lines.push(columns.map(function (k) {
            var v = obj[r][k];
            // 嵌套对象/数组 JSON.stringify 后作为单元格值（保证可逆、不丢结构）
            if (typeof v === 'object' && v !== null) { v = JSON.stringify(v); }
            return csvEscapeCell(v, sep); // 缺失键 → undefined → 空单元格
        }).join(sep));
    }
    return lines.join('\r\n');
}

// RFC 4180 CSV 解析器：逐字符三态状态机
//   状态1 普通：遇 sep 收格、遇 \r\n/\n/\r 收行、遇起始 " 进入引号内
//   状态2 引号内：sep 与换行都是普通字符，遇 "" 转义为一个 "，
//                遇单个 " 转入"引号后"
//   状态3 引号后：紧接 sep/换行则按普通态收格收行（容忍 "a"x 这类
//                非法尾部字符，直接拼接不报错）
// 返回二维数组：外层为行、内层为该行各单元格字符串
function csvParseCsv(text, sep) {
    // 容错：去掉 Excel 另存 UTF-8 CSV 时常见的文件头 BOM
    text = String(text).replace(/^\uFEFF/, '');
    var rows = [];
    var row = [];
    var cell = '';
    var inQuotes = false;      // 状态2：引号内
    var justClosed = false;    // 状态3：引号刚闭合（用于区分"起始引号"与普通字符）
    var i = 0;
    var len = text.length;
    while (i < len) {
        var ch = text.charAt(i);
        if (inQuotes) {
            if (ch === '"') {
                if (text.charAt(i + 1) === '"') {
                    cell += '"';      // "" 转义为一个双引号
                    i += 2;
                } else {
                    inQuotes = false; // 引号闭合
                    justClosed = true;
                    i += 1;
                }
            } else {
                cell += ch;           // 引号内的 sep/换行都是普通字符
                i += 1;
            }
        } else {
            if (ch === '"' && cell === '' && !justClosed) {
                inQuotes = true;      // 单元格起始引号
                i += 1;
            } else if (ch === sep) {
                row.push(cell);
                cell = '';
                justClosed = false;
                i += 1;
            } else if (ch === '\r' || ch === '\n') {
                if (ch === '\r' && text.charAt(i + 1) === '\n') { i += 1; } // CRLF 合并
                row.push(cell);
                cell = '';
                justClosed = false;
                rows.push(row);
                row = [];
                i += 1;
            } else {
                cell += ch;
                justClosed = false;
                i += 1;
            }
        }
    }
    // 末行无换行结尾时也要收进来（cell 非空或行内已有分隔出的格子）
    if (cell !== '' || row.length > 0) {
        row.push(cell);
        rows.push(row);
    }
    return rows;
}

// 单元格类型推断：
//   true/false → 布尔；无前导零的整数字符串（位数 ≤16，超出会丢精度）→ Number；
//   浮点 → Number；空串 → null；其余保持字符串
//   注意 "007" 这类前导零数字保持字符串——一旦转 Number 前导零即丢失，
//   编号/工号类数据会被破坏格式
function csvInfer(v) {
    if (v === '') { return null; }
    if (v === 'true') { return true; }
    if (v === 'false') { return false; }
    var m;
    if ((m = v.match(/^-?(0|[1-9]\d*)$/)) && m[0].replace('-', '').length <= 16) {
        return Number(v); // 整数（含负号），16 位以内 Number 可精确表示
    }
    if (/^-?(0|[1-9]\d*)\.\d+$/.test(v)) {
        return Number(v); // 常规小数（科学计数法、前导零小数不转，保持原样）
    }
    return v;
}

// CSV 文本 → JSON 对象数组
//   hasHeader true：首行为键名；数据行列数多于表头时多出的列用 col_N 键补，
//                   不足的列按空串取值（经 csvInfer 推断为 null）
//   hasHeader false：所有列依次用 col_1、col_2… 作键
function csvCsvToJson(text, sep, hasHeader) {
    var rows = csvParseCsv(text, sep);
    // 过滤完全空白的行（连续换行/末尾多余空行产生的 [''] 行）
    rows = rows.filter(function (r) {
        return r.some(function (c) { return c !== ''; });
    });
    if (rows.length === 0) { return []; }
    var keys;
    var startRow;
    if (hasHeader) {
        keys = rows[0].slice();
        startRow = 1;
    } else {
        // 无表头：按所有行中的最大列数生成 col_1..col_N 键
        var width = 0;
        for (var w = 0; w < rows.length; w++) {
            if (rows[w].length > width) { width = rows[w].length; }
        }
        keys = [];
        for (var k = 1; k <= width; k++) { keys.push('col_' + k); }
        startRow = 0;
    }
    var result = [];
    for (var r = startRow; r < rows.length; r++) {
        var obj = {};
        for (var c = 0; c < keys.length; c++) {
            // 列不足时按空串取值（推断为 null）
            obj[keys[c]] = csvInfer(c < rows[r].length ? rows[r][c] : '');
        }
        // 列数多于表头：多出的单元格按出现位置补 col_N 键
        for (var c2 = keys.length; c2 < rows[r].length; c2++) {
            obj['col_' + (c2 + 1)] = csvInfer(rows[r][c2]);
        }
        result.push(obj);
    }
    return result;
}

// 读取页面上当前选择的分隔符（找不到单选时回退为逗号）
function csvGetSep() {
    var el = document.querySelector('input[name="csv-sep"]:checked');
    return csvNormalizeSep(el ? el.value : ',');
}

// 读取当前方向：j2c = JSON → CSV，c2j = CSV → JSON
function csvGetMode() {
    var el = document.querySelector('input[name="csv-mode"]:checked');
    return el ? el.value : 'j2c';
}

// "转换"按钮：按方向单选调用对应转换并写结果区
function csvConvert() {
    var input = document.getElementById('csv-input');
    var resultEl = document.getElementById('csv-result');
    var text = input.value.trim();
    if (!text) {
        showNotification('请先输入内容');
        return;
    }
    var mode = csvGetMode();
    var sep = csvGetSep();
    var hasHeader = document.getElementById('csv-header').checked;
    var addBom = document.getElementById('csv-bom').checked;
    try {
        if (mode === 'c2j') {
            var arr = csvCsvToJson(text, sep, hasHeader);
            var jsonText = JSON.stringify(arr, null, 2);
            csvLastResult = jsonText;
            csvLastExt = '.json';
            resultEl.textContent = jsonText;
            showNotification('转换完成：' + arr.length + ' 条记录');
        } else {
            // 先 JSON.parse 校验，语法错误直接给出解析器消息
            var obj;
            try {
                obj = JSON.parse(text);
            } catch (e) {
                resultEl.textContent = '❌ JSON 解析失败：' + e.message;
                showNotification('JSON 解析失败');
                return;
            }
            var csv = csvJsonToCsv(obj, sep, hasHeader);
            // 勾选 BOM 时在结果前加 \uFEFF：Excel 双击打开 UTF-8 CSV
            // 才能把中文识别对，否则默认按 ANSI 解码会乱码
            if (addBom) { csv = '\uFEFF' + csv; }
            csvLastResult = csv;
            csvLastExt = '.csv';
            resultEl.textContent = csv === '' ? '（空数组：无数据行）' : csv;
            if (csv === '') { csvLastResult = ''; }
            showNotification('转换完成：' + obj.length + ' 行');
        }
    } catch (e) {
        resultEl.textContent = '❌ ' + e.message;
        showNotification('转换失败');
    }
}

// "下载"按钮：把最近一次转换结果保存为 converted.csv / converted.json
function csvDownload() {
    if (!csvLastResult) {
        showNotification('没有可下载的结果，请先转换');
        return;
    }
    var mime = csvLastExt === '.json' ? 'application/json' : 'text/csv;charset=utf-8';
    var blob = new Blob([csvLastResult], { type: mime });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'converted' + csvLastExt;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    showNotification('已开始下载 converted' + csvLastExt);
}

// "清空"按钮：清空输入与结果
function csvClear() {
    var input = document.getElementById('csv-input');
    if (input) { input.value = ''; input.focus(); }
    document.getElementById('csv-result').textContent = '';
    csvLastResult = '';
}

// 按方向更新输入框占位提示
function csvUpdatePlaceholder() {
    var input = document.getElementById('csv-input');
    if (!input) { return; }
    if (csvGetMode() === 'c2j') {
        input.placeholder = '输入 CSV 文本，如：\nname,age\n张三,25\n李四,30\n（含逗号/引号/换行的字段请按 RFC 4180 用双引号包裹）';
    } else {
        input.placeholder = '输入 JSON 对象数组，如 [{"name":"张三","age":25},{"name":"李四","age":30,"city":"北京"}]';
    }
}

// 页面初始化：方向单选切换时联动占位提示
function csvInit() {
    var radios = document.querySelectorAll('input[name="csv-mode"]');
    for (var i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', csvUpdatePlaceholder);
    }
    csvUpdatePlaceholder();
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// typeof document 判断用于兜底：Node 环境直接 require 时跳过 DOM 绑定
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', csvInit);
    } else {
        csvInit();
    }
}

// Node 环境导出转换函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测；
// csvConvert 等含 DOM 调用的函数一并导出，打桩 document 后可全流程测试）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        csvJsonToCsv: csvJsonToCsv,
        csvParseCsv: csvParseCsv,
        csvCsvToJson: csvCsvToJson,
        csvEscapeCell: csvEscapeCell,
        csvInfer: csvInfer,
        csvNormalizeSep: csvNormalizeSep,
        csvConvert: csvConvert,
        csvDownload: csvDownload,
        csvClear: csvClear
    };
}
