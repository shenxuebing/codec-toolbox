// ============================================================
// 正则测试器（page-regex）
// - 匹配统计（N 处 / 分组 M 个 / 耗时）+ 高亮预览（mark 标签）
// - 分组捕获明细表（DOM API + textContent，防注入）
// - 替换预览（$1 引用分组，String.replace 原生语义）
// - 常用速查按钮由 REGEX_PRESETS 数据动态生成，避免内联
//   onclick 属性里转义正则串（引号/反斜杠地狱）
// 零依赖，全部计算在本地完成。
// ============================================================

// 常用正则速查数据（按钮文案 + 预置模式；pattern 为正则源码字符串形式）
var REGEX_PRESETS = [
    { name: '邮箱',             pattern: '[\\w.+-]+@[\\w-]+\\.[\\w.]+' },
    { name: '手机号',           pattern: '1[3-9]\\d{9}' },
    { name: 'IPv4',             pattern: '((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)' },
    { name: 'URL',              pattern: 'https?://[^\\s]+' },
    { name: '日期(YYYY-MM-DD)', pattern: '\\d{4}-\\d{2}-\\d{2}' },
    { name: '十六进制颜色',     pattern: '#[0-9a-fA-F]{6}' },
    { name: '中文',             pattern: '[\\u4e00-\\u9fa5]+' }
];

// 自动重跑防抖计时器（模块级，input 停顿 400ms 后触发 regexRun）
var regexDebounceTimer = null;

// HTML 转义：覆盖 & < > " ' 五个字符（纯函数，便于 Node 对拍）
function regexEscapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
}

// 收集勾选的 flags（g 始终保留：未勾 g 时内部自动加 g 用于全量统计）
function regexCollectFlags() {
    var flags = '';
    var list = ['g', 'i', 'm', 's', 'u', 'y'];
    for (var i = 0; i < list.length; i++) {
        var el = document.getElementById('regex-flag-' + list[i]);
        if (el && el.checked) {
            flags += list[i];
        }
    }
    if (flags.indexOf('g') < 0) {
        flags = 'g' + flags; // 自动补 g（调用方负责在 UI 上提示"未开启全局匹配"）
    }
    return flags;
}

// 全量收集匹配（纯函数，便于 Node 对拍）：
// 返回 { ok, error, matches }；matches 为 exec 结果数组（保留 index/groups 原生字段）
function regexCollectMatches(pattern, flags, text) {
    var result = { ok: false, error: '', matches: [] };
    var re;
    try {
        re = new RegExp(pattern, flags);
    } catch (e) {
        // 正则语法错误：把引擎的原始报错透出给调用方展示
        result.error = e && e.message ? e.message : String(e);
        return result;
    }

    var matches = [];
    var guard = 0; // 匹配次数上限保护（正常不会触及，防病态输入拖死页面）
    while (guard++ < 500000) {
        var m = re.exec(text);
        if (m === null) {
            break;
        }
        matches.push(m);
        // 零宽匹配防死循环：零宽匹配成功后 lastIndex 停在 m.index 不前进，
        // 下一轮 exec 会永远命中同一位置；此时强制 lastIndex +1 跳过该字符。
        // （如 (?=a) 对 "ab"：命中位置 0 后跳到 1，再匹配失败，共 1 处）
        if (re.lastIndex === m.index) {
            re.lastIndex = m.index + 1;
        }
    }
    result.ok = true;
    result.matches = matches;
    return result;
}

// 探测捕获组总数（含命名组，纯函数）：
// 在原模式后拼恒真空分支 "|"，对空串 exec 一次，
// m.length - 2 即原模式的组数（-1 是完整匹配 m[0]，-1 是探测用的空捕获组）
function regexCountGroups(pattern, flags) {
    try {
        var probe = new RegExp(pattern + '|()', flags.replace(/[gy]/g, ''));
        var m = probe.exec('');
        return m ? m.length - 2 : 0;
    } catch (e) {
        return 0; // 探测失败（理论不会：主正则已验证合法）按 0 组处理
    }
}

// 生成高亮预览 HTML（纯函数）：非匹配片段转义，匹配片段转义后包 <mark>，
// 零宽匹配给一个带虚线边框的空占位标记（否则不可见）；一次性拼接返回
function regexBuildHighlight(text, matches) {
    var parts = [];
    var pos = 0;
    for (var i = 0; i < matches.length; i++) {
        var m = matches[i];
        if (m.index < pos) {
            continue; // 保险：跳过异常重叠的匹配（正常 exec 循环不会产生）
        }
        parts.push(regexEscapeHtml(text.slice(pos, m.index)));
        if (m[0] === '') {
            parts.push('<mark class="regex-zero"></mark>');
        } else {
            parts.push('<mark>' + regexEscapeHtml(m[0]) + '</mark>');
        }
        pos = m.index + m[0].length;
    }
    parts.push(regexEscapeHtml(text.slice(pos)));
    return parts.join('');
}

// 分组捕获明细表行数上限：超过只渲染前 N 行（表格 DOM 太大会拖垮页面）
var REGEX_GROUPS_MAX_ROWS = 500;

// 渲染分组捕获明细表：DOM API 构建，全部走 textContent（防注入）；
// 无分组显示"该正则无捕获分组"，无匹配显示"无匹配内容"
function regexRenderGroups(container, matches, groupsCount) {
    container.textContent = '';
    if (groupsCount === 0) {
        container.textContent = '该正则无捕获分组';
        return;
    }
    if (matches.length === 0) {
        container.textContent = '无匹配内容';
        return;
    }

    var table = document.createElement('table');
    table.className = 'query-table';

    // 表头：匹配序号 / 组号 / 组名 / 捕获值
    var thead = document.createElement('thead');
    var headRow = document.createElement('tr');
    var heads = ['匹配序号', '组号', '组名', '捕获值'];
    for (var h = 0; h < heads.length; h++) {
        var th = document.createElement('th');
        th.textContent = heads[h];
        headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    var rows = 0;
    var truncated = false;
    for (var i = 0; i < matches.length && !truncated; i++) {
        var m = matches[i];
        // m.groups：命名捕获组的 名字 → 值 映射（无命名组时为 undefined）
        var named = m.groups || {};
        for (var g = 1; g < m.length; g++) {
            if (rows >= REGEX_GROUPS_MAX_ROWS) {
                truncated = true;
                break;
            }
            var tr = document.createElement('tr');

            var tdNo = document.createElement('td');
            tdNo.textContent = String(i + 1);
            tr.appendChild(tdNo);

            var tdG = document.createElement('td');
            tdG.textContent = String(g);
            tr.appendChild(tdG);

            var tdName = document.createElement('td');
            tdName.textContent = named[String(g)] || '-';
            tr.appendChild(tdName);

            var tdVal = document.createElement('td');
            // 未参与本次匹配的组（如 alternation 另一分支）值为 undefined，显示空串
            tdVal.textContent = (m[g] === undefined) ? '' : m[g];
            tr.appendChild(tdVal);

            tbody.appendChild(tr);
            rows++;
        }
    }
    table.appendChild(tbody);
    container.appendChild(table);

    if (truncated) {
        var tip = document.createElement('p');
        tip.className = 'regex-groups-more';
        tip.textContent = '… 匹配 × 分组较多，仅显示前 ' + REGEX_GROUPS_MAX_ROWS + ' 行';
        container.appendChild(tip);
    }
}

// 主入口：执行一次完整匹配并刷新统计 / 高亮 / 分组表 / 替换结果
function regexRun() {
    var patternEl = document.getElementById('regex-pattern');
    var textEl = document.getElementById('regex-text');
    var statsEl = document.getElementById('regex-stats');
    var hlEl = document.getElementById('regex-highlight');
    var groupsEl = document.getElementById('regex-groups');
    var replaceEl = document.getElementById('regex-replace');
    var replaceBlock = document.getElementById('regex-replace-block');
    var replaceResultEl = document.getElementById('regex-replace-result');

    var pattern = patternEl.value;
    var text = textEl.value;

    // 错误提示的红色样式：进入时先摘掉上次的错误态
    statsEl.classList.remove('jwt-invalid');

    if (pattern === '') {
        statsEl.textContent = '请输入正则表达式';
        hlEl.textContent = '';
        groupsEl.textContent = '';
        replaceBlock.style.display = 'none';
        return;
    }

    var userCheckedG = document.getElementById('regex-flag-g').checked;
    var flags = regexCollectFlags();

    // 大文本提示（不阻断，仅提醒性能风险）
    if (text.length > 100 * 1024) {
        showNotification('⚠️ 测试文本超过 100KB，匹配与高亮可能变慢');
    }

    var start = Date.now();
    var r = regexCollectMatches(pattern, flags, text);
    if (!r.ok) {
        statsEl.textContent = '❌ 正则语法错误：' + r.error;
        statsEl.classList.add('jwt-invalid'); // 复用红字样式
        hlEl.textContent = '';
        groupsEl.textContent = '';
        replaceBlock.style.display = 'none';
        return;
    }
    var matches = r.matches;
    var groupsCount = regexCountGroups(pattern, flags);

    // 结果区 1：统计行
    var statsText = '匹配 ' + matches.length + ' 处 / 分组 ' + groupsCount + ' 个 / 耗时 ' + (Date.now() - start) + ' ms';
    if (!userCheckedG) {
        statsText += '（未开启全局匹配，已自动按 g 全量统计）';
    }
    statsEl.textContent = statsText;

    // 结果区 2：高亮预览（片段均已转义，innerHTML 一次性写入；无匹配时显示转义原文）
    hlEl.innerHTML = regexBuildHighlight(text, matches);

    // 结果区 3：分组捕获明细表
    regexRenderGroups(groupsEl, matches, groupsCount);

    // 结果区 4：替换结果（填写了替换字符串才显示；新建同一 RegExp 副本——主循环的 lastIndex 已耗尽）
    if (replaceEl.value !== '') {
        try {
            var reReplace = new RegExp(pattern, flags);
            replaceResultEl.textContent = text.replace(reReplace, replaceEl.value);
            replaceBlock.style.display = '';
        } catch (e) {
            replaceResultEl.textContent = '替换失败：' + (e && e.message ? e.message : String(e));
            replaceBlock.style.display = '';
        }
    } else {
        replaceBlock.style.display = 'none';
    }
}

// 速查按钮回调：填入预置正则并立即执行一次匹配
function regexFill(pattern) {
    document.getElementById('regex-pattern').value = pattern;
    regexRun();
}

// 清空本页全部输入与结果
function regexClear() {
    document.getElementById('regex-pattern').value = '';
    document.getElementById('regex-replace').value = '';
    document.getElementById('regex-text').value = '';
    var statsEl = document.getElementById('regex-stats');
    statsEl.classList.remove('jwt-invalid');
    statsEl.textContent = '已清空';
    document.getElementById('regex-highlight').textContent = '';
    document.getElementById('regex-groups').textContent = '';
    document.getElementById('regex-replace-result').textContent = '';
    document.getElementById('regex-replace-block').style.display = 'none';
}

// 输入自动重跑：400ms 防抖（大文本逐键全量匹配会卡顿，停顿后再跑）
function regexDebouncedRun() {
    if (regexDebounceTimer !== null) {
        clearTimeout(regexDebounceTimer);
    }
    regexDebounceTimer = setTimeout(function () {
        regexDebounceTimer = null;
        regexRun();
    }, 400);
}

// 初始化：生成常用速查按钮 + 绑定输入/flags 变化自动重跑
function regexInit() {
    // 速查按钮：从 REGEX_PRESETS 数据动态生成（闭包捕获各自的 pattern，无内联转义）
    var box = document.getElementById('regex-presets');
    if (box) {
        for (var i = 0; i < REGEX_PRESETS.length; i++) {
            (function (preset) {
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'regex-preset-btn';
                btn.textContent = preset.name;
                btn.addEventListener('click', function () {
                    regexFill(preset.pattern);
                });
                box.appendChild(btn);
            })(REGEX_PRESETS[i]);
        }
    }
    // 文本输入：input 事件防抖重跑
    var ids = ['regex-pattern', 'regex-replace', 'regex-text'];
    for (var j = 0; j < ids.length; j++) {
        var el = document.getElementById(ids[j]);
        if (el) {
            el.addEventListener('input', regexDebouncedRun);
        }
    }
    // flags 复选：change 事件防抖重跑
    var flagList = ['g', 'i', 'm', 's', 'u', 'y'];
    for (var k = 0; k < flagList.length; k++) {
        var flagEl = document.getElementById('regex-flag-' + flagList[k]);
        if (flagEl) {
            flagEl.addEventListener('change', regexDebouncedRun);
        }
    }
}

// 脚本在 body 末尾加载，DOM 已就绪可直接初始化（Node 对拍环境无 document，跳过）
if (typeof document !== 'undefined' && document.getElementById('regex-pattern')) {
    regexInit();
}

// Node 环境导出纯函数（浏览器中 module 未定义自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        REGEX_PRESETS: REGEX_PRESETS,
        regexEscapeHtml: regexEscapeHtml,
        regexCollectMatches: regexCollectMatches,
        regexCountGroups: regexCountGroups,
        regexBuildHighlight: regexBuildHighlight
    };
}
