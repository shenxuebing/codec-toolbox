// ============================================================
// 文本 Diff 对比（page-diff）
// - 左右文本按行做 LCS（最长公共子序列）经典 DP 对齐
// - 统一视图逐行渲染：= 未变（灰白）/ − 删除（红底）/ + 新增（绿底）
// - 选项：忽略行首尾空白 / 忽略大小写（仅作用于比较键，显示仍为原文）
// 零依赖，全部计算在本地完成。
// ============================================================

// 行数上限：超过 2000 行仅对比前 2000 行（DP 矩阵 2001×2001 ≈ 16MB Uint32，可控）
var DIFF_MAX_LINES = 2000;
// DP 单元数上限保护：超过则放弃 LCS，降级为按行号逐行对齐（见 diffComputeOps）
var DIFF_DP_CELL_LIMIT = 5000000;

// 切行：统一换行符（\r\n / \r）为 \n 后按 \n 切分，保留行内容
function diffSplitLines(text) {
    return text.replace(/\r\n?/g, '\n').split('\n');
}

// 生成比较键：按选项对单行做行首尾空白裁剪（\s 含全角空格）/ 小写化（纯函数，便于 Node 对拍）
function diffMakeKey(line, ignoreWs, ignoreCase) {
    var key = ignoreWs ? line.replace(/^\s+|\s+$/g, '') : line;
    if (ignoreCase) {
        key = key.toLowerCase();
    }
    return key;
}

// LCS 对齐（纯函数，便于 Node 对拍）：
// aKeys/bKeys 为两侧行的比较键数组，返回操作序列
// [{type:'equal'|'delete'|'insert', a:左行索引|-1, b:右行索引|-1}]
function diffComputeOps(aKeys, bKeys) {
    var n = aKeys.length;
    var m = bKeys.length;
    var ops = [];
    var i, j;

    // 降级保护：DP 矩阵单元数超上限时放弃 LCS，退化为按行号逐行对齐
    // （键相等记 equal，否则同位置记一删一增；正常 DIFF_MAX_LINES=2000 内不会触发，
    //  仅为将来调大行数上限或异常输入兜底）
    if ((n + 1) * (m + 1) > DIFF_DP_CELL_LIMIT) {
        var same = Math.min(n, m);
        for (var x = 0; x < same; x++) {
            if (aKeys[x] === bKeys[x]) {
                ops.push({ type: 'equal', a: x, b: x });
            } else {
                ops.push({ type: 'delete', a: x, b: -1 });
                ops.push({ type: 'insert', a: -1, b: x });
            }
        }
        for (var y = same; y < n; y++) {
            ops.push({ type: 'delete', a: y, b: -1 });
        }
        for (var z = same; z < m; z++) {
            ops.push({ type: 'insert', a: -1, b: z });
        }
        return ops;
    }

    // 经典 DP：dp[i*(m+1)+j] = aKeys[i..] 与 bKeys[j..] 的 LCS 长度（自后向前填表）。
    // 用 Uint32Array 一维数组按行寻址，比二维数组省内存且访问更快
    var dp = new Uint32Array((n + 1) * (m + 1));
    for (i = n - 1; i >= 0; i--) {
        var rowBase = i * (m + 1);
        var nextBase = rowBase + (m + 1);
        for (j = m - 1; j >= 0; j--) {
            dp[rowBase + j] = (aKeys[i] === bKeys[j])
                ? dp[nextBase + j + 1] + 1
                : Math.max(dp[nextBase + j], dp[rowBase + j + 1]);
        }
    }

    // 回溯（正向走表）：行相等记 equal；不等时朝 DP 值更大的一侧推进，
    // 左侧推进记 delete、右侧推进记 insert；尾部剩余行补 delete/insert
    i = 0;
    j = 0;
    while (i < n && j < m) {
        if (aKeys[i] === bKeys[j]) {
            ops.push({ type: 'equal', a: i, b: j });
            i++;
            j++;
        } else if (dp[(i + 1) * (m + 1) + j] >= dp[i * (m + 1) + j + 1]) {
            ops.push({ type: 'delete', a: i, b: -1 });
            i++;
        } else {
            ops.push({ type: 'insert', a: -1, b: j });
            j++;
        }
    }
    while (i < n) {
        ops.push({ type: 'delete', a: i, b: -1 });
        i++;
    }
    while (j < m) {
        ops.push({ type: 'insert', a: -1, b: j });
        j++;
    }
    return ops;
}

// 渲染统一视图：DOM API 逐行构建（textContent，防注入），
// 每行 = 左行号 | 右行号 | 符号（=/−/+）| 行内容；文档片段一次性挂载
function diffRender(container, ops, leftLines, rightLines) {
    container.textContent = '';
    if (ops.length === 0) {
        container.textContent = '两侧行数均为 0';
        return;
    }
    var frag = document.createDocumentFragment();
    for (var i = 0; i < ops.length; i++) {
        var op = ops[i];

        var row = document.createElement('div');
        row.className = 'diff-line ' + (op.type === 'equal' ? 'diff-eq' : op.type === 'delete' ? 'diff-del' : 'diff-add');

        var lnum = document.createElement('span');
        lnum.className = 'diff-lnum';
        lnum.textContent = op.a >= 0 ? String(op.a + 1) : '';

        var rnum = document.createElement('span');
        rnum.className = 'diff-rnum';
        rnum.textContent = op.b >= 0 ? String(op.b + 1) : '';

        var sym = document.createElement('span');
        sym.className = 'diff-sym';
        sym.textContent = op.type === 'equal' ? '=' : (op.type === 'delete' ? '−' : '+');

        var content = document.createElement('span');
        content.className = 'diff-content';
        // delete/equal 显示左原文，insert 显示右原文
        content.textContent = (op.type === 'insert') ? rightLines[op.b] : leftLines[op.a];

        row.appendChild(lnum);
        row.appendChild(rnum);
        row.appendChild(sym);
        row.appendChild(content);
        frag.appendChild(row);
    }
    container.appendChild(frag);
}

// 主入口：切行 → 生成比较键 → LCS 对齐 → 统计 + 渲染
function diffRun() {
    var leftEl = document.getElementById('diff-left');
    var rightEl = document.getElementById('diff-right');
    var statsEl = document.getElementById('diff-stats');
    var resultEl = document.getElementById('diff-result');
    var ignoreWs = document.getElementById('diff-ignore-ws').checked;
    var ignoreCase = document.getElementById('diff-ignore-case').checked;

    var start = Date.now();
    var leftLines = diffSplitLines(leftEl.value);
    var rightLines = diffSplitLines(rightEl.value);

    // 行数上限：超过 2000 行仅对比前 2000 行
    if (leftLines.length > DIFF_MAX_LINES || rightLines.length > DIFF_MAX_LINES) {
        showNotification('行数超 ' + DIFF_MAX_LINES + '，仅对比前 ' + DIFF_MAX_LINES + ' 行');
        leftLines = leftLines.slice(0, DIFF_MAX_LINES);
        rightLines = rightLines.slice(0, DIFF_MAX_LINES);
    }

    // 比较键：忽略空白/大小写只影响比较，渲染仍用原文
    var leftKeys = [];
    var rightKeys = [];
    var k;
    for (k = 0; k < leftLines.length; k++) {
        leftKeys.push(diffMakeKey(leftLines[k], ignoreWs, ignoreCase));
    }
    for (k = 0; k < rightLines.length; k++) {
        rightKeys.push(diffMakeKey(rightLines[k], ignoreWs, ignoreCase));
    }

    // LCS 对齐
    var ops = diffComputeOps(leftKeys, rightKeys);

    // 统计新增 / 删除 / 相同行数
    var added = 0;
    var removed = 0;
    var same = 0;
    for (var i = 0; i < ops.length; i++) {
        if (ops[i].type === 'equal') {
            same++;
        } else if (ops[i].type === 'delete') {
            removed++;
        } else {
            added++;
        }
    }
    statsEl.textContent = '新增 ' + added + ' 行 / 删除 ' + removed + ' 行 / 相同 ' + same + ' 行 / 耗时 ' + (Date.now() - start) + ' ms';

    // 统一视图渲染
    diffRender(resultEl, ops, leftLines, rightLines);
}

// 交换左右两个文本框的内容（便于反向查看差异）
function diffSwap() {
    var leftEl = document.getElementById('diff-left');
    var rightEl = document.getElementById('diff-right');
    var tmp = leftEl.value;
    leftEl.value = rightEl.value;
    rightEl.value = tmp;
    showNotification('已交换左右文本');
}

// 清空本页全部输入与结果
function diffClear() {
    document.getElementById('diff-left').value = '';
    document.getElementById('diff-right').value = '';
    document.getElementById('diff-ignore-ws').checked = false;
    document.getElementById('diff-ignore-case').checked = false;
    document.getElementById('diff-stats').textContent = '已清空';
    document.getElementById('diff-result').textContent = '';
}

// Node 环境导出纯函数（浏览器中 module 未定义自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        DIFF_MAX_LINES: DIFF_MAX_LINES,
        diffSplitLines: diffSplitLines,
        diffMakeKey: diffMakeKey,
        diffComputeOps: diffComputeOps
    };
}
