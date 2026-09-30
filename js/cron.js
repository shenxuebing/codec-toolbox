// ============================================================
// 增强版编解码工具 - Cron 表达式解析页（page-cron）
// 功能：表达式 → 中文描述（cronstrue 中文语言包）/ 五字段取值明细 /
//       未来 5 次执行时间（逐分钟暴力扫描推算）
// 依赖（须先于本文件加载）：
//   js/vendor/cronstrue.min.js → cronstrue.toString(expr, { locale: 'zh_CN' })
//   注意：cronstrue 对非法表达式返回 undefined（不抛错），必须判空
//   js/app.js → showNotification / copyToClipboard
// 语义口径（标准 vixie Cron 规范）：
//   五段依次为 分(0-59) 时(0-23) 日(1-31) 月(1-12) 周(0-7，0/7 均为周日)；
//   日(dom)与周(dow)两个字段"都受限（都非 *）"时为 OR 关系，
//   其一为 * 时为 AND 关系 —— 这是标准 Cron 与常识直觉最大的差异点
// ============================================================

// 五个字段的定义：[中文名, 最小值, 最大值]（周字段上限 7，解析后 7 归一为 0）
var CRON_FIELD_DEFS = [
    ['分钟', 0, 59],
    ['小时', 0, 23],
    ['日', 1, 31],
    ['月', 1, 12],
    ['星期', 0, 7]
];

// 星期 0-6 的中文名（数组下标即星期值，0 = 周日）
var CRON_WEEK_NAMES = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];

// 月份 1-12 的中文名（数组下标即月份值）
var CRON_MONTH_NAMES = ['', '1月', '2月', '3月', '4月', '5月', '6月', '7月', '8月', '9月', '10月', '11月', '12月'];

// 解析单个字段表达式，返回排序去重的取值数组；格式非法或越界时抛错（中文消息）
// 支持：*、*/n（步长）、a-b（范围）、a-b/n、逗号列表 1,15,30、单值；
//       另外兼容 a/n（等同 a-最大值/n，部分 Cron 方言的写法）
function cronParseField(expr, min, max) {
    var result = {};
    var items = String(expr).split(',');
    for (var i = 0; i < items.length; i++) {
        var item = items[i];
        if (item === '' ) {
            throw new Error('存在空的逗号子项');
        }
        var m;
        if (item === '*') {
            // *：全范围
            for (var v = min; v <= max; v++) { result[v] = true; }
        } else if ((m = item.match(/^\*\/(\d+)$/))) {
            // */n：从最小值起每 n 取一个
            var stepAll = parseInt(m[1], 10);
            if (stepAll < 1) { throw new Error('步长必须 ≥ 1'); }
            for (var v2 = min; v2 <= max; v2 += stepAll) { result[v2] = true; }
        } else if ((m = item.match(/^(\d+)-(\d+)(?:\/(\d+))?$/))) {
            // a-b 或 a-b/n：范围（可带步长）
            var lo = parseInt(m[1], 10);
            var hi = parseInt(m[2], 10);
            var step = m[3] ? parseInt(m[3], 10) : 1;
            if (lo > hi) { throw new Error('范围起点 ' + lo + ' 大于终点 ' + hi); }
            if (step < 1) { throw new Error('步长必须 ≥ 1'); }
            if (lo < min || hi > max) {
                throw new Error('值 ' + (lo < min ? lo : hi) + ' 超出范围 ' + min + '-' + max);
            }
            for (var v3 = lo; v3 <= hi; v3 += step) { result[v3] = true; }
        } else if ((m = item.match(/^(\d+)\/(\d+)$/))) {
            // a/n：等同 a-最大值/n（兼容部分方言写法）
            var start = parseInt(m[1], 10);
            var step2 = parseInt(m[2], 10);
            if (start < min || start > max) {
                throw new Error('值 ' + start + ' 超出范围 ' + min + '-' + max);
            }
            if (step2 < 1) { throw new Error('步长必须 ≥ 1'); }
            for (var v4 = start; v4 <= max; v4 += step2) { result[v4] = true; }
        } else if ((m = item.match(/^(\d+)$/))) {
            // 单值
            var val = parseInt(m[1], 10);
            if (val < min || val > max) {
                throw new Error('值 ' + val + ' 超出范围 ' + min + '-' + max);
            }
            result[val] = true;
        } else {
            throw new Error('无法识别的子项 "' + item + '"');
        }
    }
    // 对象键去重后转为升序数组
    var keys = Object.keys(result).map(Number);
    keys.sort(function (a, b) { return a - b; });
    return keys;
}

// 把取值数组转为紧凑区间表示法：连续段写 a-b，其余逗号连接
// 如 [1,2,3,4,5] → "1-5"；[0,15,30,45] → "0,15,30,45"；[1,2,3,10] → "1-3,10"
function cronCompactValues(values) {
    var parts = [];
    var i = 0;
    while (i < values.length) {
        var j = i;
        while (j + 1 < values.length && values[j + 1] === values[j] + 1) { j++; }
        parts.push(i === j ? String(values[i]) : values[i] + '-' + values[j]);
        i = j + 1;
    }
    return parts.join(',');
}

// 字段明细表格单元格用的完整展示文本：
// ≤ 12 个值直接展示紧凑表示法（月/周字段附加中文名注解）；
// > 12 个值展示"共 N 个值" + 前 12 个值的紧凑表示法
function cronFieldCellText(values, nameOf) {
    var head = values.length > 12
        ? '共 ' + values.length + ' 个值：'
        : '';
    var text = head + cronCompactValues(values.slice(0, 12)) + (values.length > 12 ? ' …' : '');
    if (nameOf && values.length <= 12) {
        // 中文名注解：连续段合并为"周一至周五"，单值与断裂处用"、"连接
        var names = [];
        var i = 0;
        while (i < values.length) {
            var j = i;
            while (j + 1 < values.length && values[j + 1] === values[j] + 1) { j++; }
            names.push(i === j ? nameOf(values[i]) : nameOf(values[i]) + '至' + nameOf(values[j]));
            i = j + 1;
        }
        text += '（' + names.join('、') + '）';
    }
    return text;
}

// 本地时间格式化：YYYY-MM-DD HH:mm:ss 星期X
function cronFormatLocal(date) {
    function pad(n) { return (n < 10 ? '0' : '') + n; }
    return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate()) +
        ' ' + pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds()) +
        ' ' + CRON_WEEK_NAMES[date.getDay()];
}

// 推算未来 count 次执行时间：从"当前时间的下一分钟"（秒/毫秒清零）起
// 逐分钟暴力扫描，上限一年（366 天 × 1440 分 = 527040 次迭代；
// 每次迭代仅为 4-5 次数值/Set 成员比较，纯数值运算总耗时 < 1s，可接受）
// fields 结构：{ minute, hour, dom, month, dow }（数组或 Set 均可）+
//   domAll / dowAll（对应字段是否为 *，缺省时按"取值集合是否覆盖全范围"推断）
// 命中条件：分∈分集 && 时∈时集 && 月∈月集 &&
//   （日/周其一为 * 时：日∈日集 && 周∈周集；两者均受限时：日∈日集 || 周∈周集）
function cronNextRuns(fields, count) {
    if (typeof count !== 'number' || count < 1) { count = 5; }

    // 统一转 Set 加速成员判断；并推断缺省的 domAll/dowAll 标志
    function toSet(arr) {
        if (arr instanceof Set) { return arr; }
        var s = new Set();
        for (var i = 0; i < arr.length; i++) { s.add(arr[i]); }
        return s;
    }
    function coversFull(set, lo, hi) {
        for (var v = lo; v <= hi; v++) { if (!set.has(v)) { return false; } }
        return true;
    }
    var minute = toSet(fields.minute);
    var hour = toSet(fields.hour);
    var dom = toSet(fields.dom);
    var month = toSet(fields.month);
    var dow = toSet(fields.dow);
    var domAll = (typeof fields.domAll === 'boolean') ? fields.domAll : coversFull(dom, 1, 31);
    var dowAll = (typeof fields.dowAll === 'boolean') ? fields.dowAll : coversFull(dow, 0, 6);

    // 起点：当前时间 + 1 分钟，秒/毫秒清零（cron 只精确到分钟）
    var cursor = new Date();
    cursor.setSeconds(0, 0);
    cursor.setMinutes(cursor.getMinutes() + 1);

    var runs = [];
    var MAX_ITER = 366 * 24 * 60; // 一年（闰年口径）
    for (var iter = 0; iter < MAX_ITER && runs.length < count; iter++) {
        if (minute.has(cursor.getMinutes()) &&
            hour.has(cursor.getHours()) &&
            month.has(cursor.getMonth() + 1)) {
            var domHit = dom.has(cursor.getDate());
            var dowHit = dow.has(cursor.getDay());
            // 标准 Cron 的日/周语义：其一为 * 时 AND，两者均受限时 OR
            var dayOk = (domAll || dowAll) ? (domHit && dowHit) : (domHit || dowHit);
            if (dayOk) {
                runs.push(new Date(cursor.getTime())); // 复制快照，cursor 还要继续走
            }
        }
        // setMinutes 自动处理进位/月末/闰年等日历规则（且对夏令时安全）
        cursor.setMinutes(cursor.getMinutes() + 1);
    }
    return runs;
}

// 页面主入口：校验 → 中文描述 → 字段明细 → 未来 5 次执行时间
function cronRun() {
    var input = document.getElementById('cron-input');
    var descEl = document.getElementById('cron-desc');
    var fieldsEl = document.getElementById('cron-fields');
    var nextEl = document.getElementById('cron-next');

    // 连续空格合并为一个后再按空格拆分
    var expr = (input && input.value ? input.value : '').trim().replace(/\s+/g, ' ');
    descEl.textContent = '';
    fieldsEl.innerHTML = '';
    nextEl.textContent = '';

    if (!expr) {
        descEl.textContent = '❌ 请输入 Cron 表达式';
        return;
    }

    var parts = expr.split(' ');
    if (parts.length !== 5) {
        descEl.textContent = '❌ 标准 Cron 应为 5 段（分 时 日 月 周），当前 ' + parts.length + ' 段';
        return;
    }

    // 1) 中文描述（cronstrue 对非法表达式返回 undefined，必须判空）
    var desc;
    try {
        desc = (typeof cronstrue !== 'undefined')
            ? cronstrue.toString(expr, { locale: 'zh_CN' })
            : undefined;
    } catch (e) {
        desc = undefined; // 个别病态输入可能抛错，一并按"无法解析"处理
    }
    if (desc === undefined || desc === null || desc === '') {
        descEl.textContent = '❌ 表达式无法解析（字段值超范围或格式非法）';
        return;
    }
    descEl.textContent = '✅ ' + desc;

    // 2) 五个字段逐一解析（周字段先按 0-7 解析，再把 7 归一为 0 = 周日）
    var sets = [];
    for (var i = 0; i < 5; i++) {
        var def = CRON_FIELD_DEFS[i];
        try {
            var values = cronParseField(parts[i], def[1], def[2]);
        } catch (e) {
            descEl.textContent = '❌ ' + def[0] + '字段 "' + parts[i] + '" 非法：' + e.message;
            return;
        }
        if (i === 4) {
            // 星期 0/7 都是周日：7 归一为 0 后重新排序去重
            var norm = {};
            for (var k = 0; k < values.length; k++) { norm[values[k] % 7] = true; }
            values = Object.keys(norm).map(Number).sort(function (a, b) { return a - b; });
        }
        sets.push(values);
    }

    // 字段明细表：字段 / 原始表达式 / 解析后的取值集合
    var rowsHtml = '<thead><tr><th style="width:70px;">字段</th><th style="width:110px;">原始表达式</th><th>解析后的取值集合</th></tr></thead><tbody>';
    for (var r = 0; r < 5; r++) {
        var def2 = CRON_FIELD_DEFS[r];
        var nameOf = null;
        if (r === 3) {
            nameOf = function (v) { return CRON_MONTH_NAMES[v]; }; // 月：1月...12月
        } else if (r === 4) {
            nameOf = function (v) { return CRON_WEEK_NAMES[v]; };  // 周：周日...周六
        }
        rowsHtml += '<tr><th>' + def2[0] + '（' + def2[1] + '-' + def2[2] + '）</th><td>' + parts[r] +
            '</td><td>' + cronFieldCellText(sets[r], nameOf) + '</td></tr>';
    }
    rowsHtml += '</tbody>';
    fieldsEl.innerHTML = rowsHtml;

    // 3) 未来 5 次执行时间（日/周字段是否受限以"原始表达式是否为 *"判断，符合标准规范）
    var runs = cronNextRuns({
        minute: sets[0],
        hour: sets[1],
        dom: sets[2],
        month: sets[3],
        dow: sets[4],
        domAll: parts[2] === '*',
        dowAll: parts[4] === '*'
    }, 5);

    if (runs.length === 0) {
        nextEl.textContent = '❌ 未来一年内无执行时间（检查是否 2 月 30 日这类不存在组合）';
        return;
    }
    var lines = [];
    for (var n = 0; n < runs.length; n++) {
        lines.push((n + 1) + '. ' + cronFormatLocal(runs[n]));
    }
    if (runs.length < 5) {
        lines.push('（一年内仅找到 ' + runs.length + ' 次）');
    }
    nextEl.textContent = lines.join('\n');
}

// 清空输入与三个结果区
function cronClear() {
    var input = document.getElementById('cron-input');
    if (input) { input.value = ''; input.focus(); }
    document.getElementById('cron-desc').textContent = '';
    document.getElementById('cron-fields').innerHTML = '';
    document.getElementById('cron-next').textContent = '';
}

// 页面初始化：输入框回车触发解析
function cronInit() {
    var input = document.getElementById('cron-input');
    if (input) {
        input.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                cronRun();
            }
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', cronInit);
} else {
    cronInit();
}

// Node 环境导出纯解析函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        cronParseField: cronParseField,
        cronNextRuns: cronNextRuns,
        cronCompactValues: cronCompactValues
    };
}
