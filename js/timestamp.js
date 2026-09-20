// ============================================================
// 增强版编解码工具 - 时间戳转换页（page-timestamp）
// 功能：当前时间戳实时显示（秒/毫秒）、时间戳 → 日期、日期 → 时间戳
// 依赖全局函数（js/app.js 提供，须先于本文件加载）：
//   copyToClipboard(id)  复制指定元素的文本
// 本文件在 body 尾加载，执行时页面元素已就绪，可直接初始化
// ============================================================

// 星期中文映射：Date.getDay() 返回 0~6，0 表示周日
var TS_WEEK_NAMES = ['日', '一', '二', '三', '四', '五', '六'];

// 数字两位补零（月/日/时/分/秒通用）
function tsPad2(num) {
    return num < 10 ? '0' + num : '' + num;
}

// Date → "YYYY-MM-DD HH:mm:ss"（按浏览器本地时区，使用 get* 系列方法）
function tsFormatLocal(date) {
    return date.getFullYear() + '-' + tsPad2(date.getMonth() + 1) + '-' + tsPad2(date.getDate()) +
        ' ' + tsPad2(date.getHours()) + ':' + tsPad2(date.getMinutes()) + ':' + tsPad2(date.getSeconds());
}

// Date → "YYYY-MM-DD HH:mm:ss"（按 UTC，使用 getUTC* 系列方法）
function tsFormatUtc(date) {
    return date.getUTCFullYear() + '-' + tsPad2(date.getUTCMonth() + 1) + '-' + tsPad2(date.getUTCDate()) +
        ' ' + tsPad2(date.getUTCHours()) + ':' + tsPad2(date.getUTCMinutes()) + ':' + tsPad2(date.getUTCSeconds());
}

// 相对时间描述：目标时间相对"现在"的人类可读表达（如 "3 天前" / "5 小时后"）
function tsRelativeDesc(targetMs) {
    var diffMs = targetMs - Date.now();
    var absSec = Math.abs(diffMs) / 1000;
    if (absSec < 1) {
        return '刚刚';
    }
    // 秒 → 分 → 时 → 天 → 月 → 年 逐级换算（月按 30 天、年按 365 天近似，保留 1 位小数）
    var text;
    if (absSec < 60) {
        text = Math.floor(absSec) + ' 秒';
    } else if (absSec < 3600) {
        text = Math.floor(absSec / 60) + ' 分钟';
    } else if (absSec < 86400) {
        text = Math.floor(absSec / 3600) + ' 小时';
    } else if (absSec < 86400 * 30) {
        text = Math.floor(absSec / 86400) + ' 天';
    } else if (absSec < 86400 * 365) {
        text = (absSec / (86400 * 30)).toFixed(1) + ' 个月';
    } else {
        text = (absSec / (86400 * 365)).toFixed(1) + ' 年';
    }
    return text + (diffMs >= 0 ? '后' : '前');
}

// 刷新"当前时间戳"两个显示框（由 setInterval 每秒调用一次）
function tsUpdateNow() {
    var now = Date.now();
    document.getElementById('ts-now-sec').textContent = Math.floor(now / 1000);
    document.getElementById('ts-now-ms').textContent = now;
}

// 页面初始化：启动每秒刷新；日期选择器默认填入当前本地时间
function tsInit() {
    tsUpdateNow();
    setInterval(tsUpdateNow, 1000);
    // datetime-local 控件要求 "YYYY-MM-DDTHH:mm:ss" 格式（不带时区，按本地时区解释）
    var now = new Date();
    document.getElementById('ts-datetime').value =
        now.getFullYear() + '-' + tsPad2(now.getMonth() + 1) + '-' + tsPad2(now.getDate()) +
        'T' + tsPad2(now.getHours()) + ':' + tsPad2(now.getMinutes()) + ':' + tsPad2(now.getSeconds());
}

// 时间戳 → 日期：按位数自动识别秒级（≤10 位）/ 毫秒级（≥11 位）
function tsConvertToDate() {
    var resultEl = document.getElementById('ts-to-date-result');
    var input = document.getElementById('ts-input').value.trim();
    if (!input) {
        resultEl.textContent = '请输入时间戳';
        return;
    }
    if (!/^\d+$/.test(input)) {
        resultEl.textContent = '❌ 无效输入：时间戳必须为纯数字（不允许负号、小数点或其他字符）';
        return;
    }
    if (input.length < 9 || input.length > 16) {
        resultEl.textContent = '❌ 无效输入：位数应为 9 ~ 16 位（常见为 10 位秒级 / 13 位毫秒级），当前为 ' + input.length + ' 位';
        return;
    }
    var isSeconds = input.length <= 10;
    var ms = isSeconds ? Number(input) * 1000 : Number(input);
    var date = new Date(ms);
    if (isNaN(date.getTime())) {
        resultEl.textContent = '❌ 无效输入：数值超出 JavaScript 可表示的时间范围';
        return;
    }
    resultEl.textContent =
        '识别类型：' + (isSeconds ? '秒级时间戳' : '毫秒级时间戳') + '\n' +
        '本地时间：' + tsFormatLocal(date) + ' 星期' + TS_WEEK_NAMES[date.getDay()] + '\n' +
        'UTC 时间：' + tsFormatUtc(date) + ' UTC\n' +
        'ISO 8601：' + date.toISOString() + '\n' +
        '相对描述：' + tsRelativeDesc(ms);
}

// "现在"按钮：向输入框填入当前秒级时间戳（不自动转换，便于在此基础上修改）
function tsSetNow() {
    document.getElementById('ts-input').value = Math.floor(Date.now() / 1000);
}

// 清空：输入框与结果区一并复位
function tsClear() {
    document.getElementById('ts-input').value = '';
    document.getElementById('ts-to-date-result').textContent = '';
}

// 日期 → 时间戳：datetime-local 的值（如 2024-01-01T12:00:00）不含时区信息，
// Date 构造函数按浏览器本地时区解析，正好符合"本地时间换时间戳"的需求
function tsConvertToTimestamp() {
    var secEl = document.getElementById('ts-out-sec');
    var msEl = document.getElementById('ts-out-ms');
    var value = document.getElementById('ts-datetime').value;
    if (!value) {
        secEl.textContent = msEl.textContent = '请先选择日期时间';
        return;
    }
    var date = new Date(value);
    if (isNaN(date.getTime())) {
        secEl.textContent = msEl.textContent = '❌ 日期无效';
        return;
    }
    secEl.textContent = Math.floor(date.getTime() / 1000);
    msEl.textContent = date.getTime();
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', tsInit);
} else {
    tsInit();
}
