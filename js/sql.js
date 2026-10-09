// ========== SQL 格式化页（page-sql） ==========
// 基于本地化 sql-formatter 库（全局 sqlFormatter，离线可用）：
// 方言 / 缩进 / 关键字大小写可选；输入防抖 600ms 自动格式化；另附"压缩为一行"。

var sqlDebounceTimer = null; // 输入防抖定时器句柄

// 读取页面三组单选并组装 sqlFormatter.format 的配置对象
function sqlBuildConfig() {
    var dialect = document.querySelector('input[name="sql-dialect"]:checked');
    var indent = document.querySelector('input[name="sql-indent"]:checked');
    var kase = document.querySelector('input[name="sql-case"]:checked');
    var indentVal = indent ? indent.value : '2';
    return {
        language: dialect ? dialect.value : 'sql',
        // Tab 模式由 useTabs 控制，tabWidth 仅作占位（实际缩进宽度为一个 \t）
        tabWidth: indentVal === 'tab' ? 2 : parseInt(indentVal, 10),
        useTabs: indentVal === 'tab',
        keywordCase: kase ? kase.value : 'upper'
    };
}

// 格式化：空输入提示；库对极端输入可能抛错，捕获后显示错误信息
function sqlFormatRun() {
    var input = document.getElementById('sql-input').value;
    if (!input.trim()) {
        showNotification('请输入 SQL 语句');
        return;
    }
    var result = document.getElementById('sql-result');
    try {
        result.textContent = sqlFormatter.format(input, sqlBuildConfig());
    } catch (e) {
        result.textContent = '❌ ' + (e && e.message ? e.message : e);
    }
}

// 压缩为一行：仅把连续空白（含换行/制表符）合并为单个空格并去首尾空白，不改动 SQL 语义
function sqlMinify() {
    var input = document.getElementById('sql-input').value;
    if (!input.trim()) {
        showNotification('请输入 SQL 语句');
        return;
    }
    document.getElementById('sql-result').textContent = input.replace(/\s+/g, ' ').trim();
}

// 清空输入与结果，并取消未触发的防抖定时器
function sqlClear() {
    if (sqlDebounceTimer) {
        clearTimeout(sqlDebounceTimer);
        sqlDebounceTimer = null;
    }
    document.getElementById('sql-input').value = '';
    document.getElementById('sql-result').textContent = '';
}

// ---------- 初始化 ----------

// 输入防抖 600ms 自动格式化；切换任一选项时若已有输入立即按新配置重排
function sqlInit() {
    var input = document.getElementById('sql-input');
    if (input) {
        input.addEventListener('input', function () {
            if (sqlDebounceTimer) {
                clearTimeout(sqlDebounceTimer);
            }
            sqlDebounceTimer = setTimeout(function () {
                sqlDebounceTimer = null;
                if (input.value.trim()) {
                    sqlFormatRun();
                }
            }, 600);
        });
    }
    var radios = document.querySelectorAll('input[name="sql-dialect"], input[name="sql-indent"], input[name="sql-case"]');
    for (var i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', function () {
            if (document.getElementById('sql-input').value.trim()) {
                sqlFormatRun();
            }
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', sqlInit);
} else {
    sqlInit();
}
