// ============================================================
// 增强版编解码工具 - 年龄计算页（page-age）
// 功能：输入出生日期与基准日期，计算：
//   周岁（按日历逐月借位，非除法近似）/ 总生存天数·小时·分钟 /
//   下次生日（闰年 2/29 生日按 3/1 修正）/ 生肖 / 星座 / 出生当天星期几
// 依赖（须先于本文件加载）：
//   js/app.js → showNotification
// 计算口径：
//   日期一律取本地时区当天 00:00，避免 new Date('YYYY-MM-DD')
//   按 UTC 解析产生的时区偏移；总生存为两个 00:00 之间的整时段
// ============================================================

// 十二生肖（下标 = (年份 - 1900) % 12，1900 年为鼠年）
var AGE_ZODIAC = ['鼠', '牛', '虎', '兔', '龙', '蛇', '马', '羊', '猴', '鸡', '狗', '猪'];

// 星座边界表：[起始月, 起始日, 名称]，1.1-1.19 归摩羯（表中 12.22 起的摩羯座跨年）
var AGE_CONSTELLATIONS = [
    [1, 20, '水瓶座'], [2, 19, '双鱼座'], [3, 21, '白羊座'], [4, 20, '金牛座'],
    [5, 21, '双子座'], [6, 22, '巨蟹座'], [7, 23, '狮子座'], [8, 23, '处女座'],
    [9, 23, '天秤座'], [10, 24, '天蝎座'], [11, 23, '射手座'], [12, 22, '摩羯座']
];

// 星期名称（下标 = Date.getDay()，0 = 星期日）
var AGE_WEEKDAYS = ['日', '一', '二', '三', '四', '五', '六'];

// ---------- 纯计算函数（不触碰 DOM，便于自测） ----------

// 解析 "YYYY-MM-DD" 为 {y, m, d}（m/d 为 1 起始），格式不符返回 null
function ageParseDateStr(str) {
    var match = /^(\d{4})-(\d{2})-(\d{2})$/.exec((str || '').trim());
    if (!match) return null;
    return { y: parseInt(match[1], 10), m: parseInt(match[2], 10), d: parseInt(match[3], 10) };
}

// 校验 {y,m,d} 是真实存在的日历日期（如 2025-02-30 滚动到 3 月即非法）
function ageIsValidDate(p) {
    var date = new Date(p.y, p.m - 1, p.d);
    return date.getFullYear() === p.y && date.getMonth() === p.m - 1 && date.getDate() === p.d;
}

// 是否闰年（能被 400 整除，或能被 4 整除且不能被 100 整除）
function ageIsLeap(year) {
    return (year % 400 === 0) || (year % 4 === 0 && year % 100 !== 0);
}

// 生肖：(年份 - 1900) % 12，负数先修正（年份早于 1900 时 % 结果可能为负）
function ageGetZodiac(year) {
    var index = (year - 1900) % 12;
    if (index < 0) {
        index += 12;
    }
    return AGE_ZODIAC[index];
}

// 星座：从最后一个边界向前找第一个"起始月日 <= 出生日期"的星座，
// 1.1-1.19 早于所有起始日，落到兜底摩羯座（12.22 起跨年）
function ageGetConstellation(month, day) {
    for (var i = AGE_CONSTELLATIONS.length - 1; i >= 0; i--) {
        var range = AGE_CONSTELLATIONS[i];
        if (month > range[0] || (month === range[0] && day >= range[1])) {
            return range[2];
        }
    }
    return '摩羯座';
}

// 某年份内生日的实际日期：闰年 2/29 生日在平年按 3/1 计算（返回是否修正标记）
function ageBirthdayInYear(birthM, birthD, year) {
    if (birthM === 2 && birthD === 29 && !ageIsLeap(year)) {
        return { m: 3, d: 1, corrected: true };
    }
    return { m: birthM, d: birthD, corrected: false };
}

// 周岁：按日历逐月借位（日不够借上个月实际天数，月不够借一年 12 个月），
// 生日当天月/天自然为 0
function ageGetExactAge(birth, target) {
    var years = target.y - birth.y;
    var months = target.m - birth.m;
    var days = target.d - birth.d;
    if (days < 0) {
        // 借位天数 = 目标日期上一个月的实际天数：new Date(y, m, 0) 为 m 月最后一天
        // （m 为 1 起始月份，-1 后正好是 JS 的 0 起始下个月，day 0 回退到上月末）
        months -= 1;
        days += new Date(target.y, target.m - 1, 0).getDate();
    }
    if (months < 0) {
        years -= 1;
        months += 12;
    }
    return { years: years, months: months, days: days };
}

// 下次生日：先看基准年内的生日（含闰年修正）是否已过，
// 已过则取下一年；返回生日日期、距今天数与修正标记
function ageGetNextBirthday(birth, target) {
    var thisYear = ageBirthdayInYear(birth.m, birth.d, target.y);
    var thisDate = new Date(target.y, thisYear.m - 1, thisYear.d);
    var targetDate = new Date(target.y, target.m - 1, target.d);

    var nextYear, nextInfo;
    if (thisDate.getTime() < targetDate.getTime()) {
        // 今年生日（修正后）已过 → 取下一年
        nextYear = target.y + 1;
        nextInfo = ageBirthdayInYear(birth.m, birth.d, nextYear);
    } else {
        // 今年生日还未过或就是今天
        nextYear = target.y;
        nextInfo = thisYear;
    }
    var nextDate = new Date(nextYear, nextInfo.m - 1, nextInfo.d);
    var daysLeft = Math.round((nextDate.getTime() - targetDate.getTime()) / 86400000);
    var isToday = daysLeft === 0;
    return { date: nextDate, daysLeft: daysLeft, corrected: nextInfo.corrected, isToday: isToday };
}

// 补零格式化 "YYYY-MM-DD"
function ageFormatDate(y, m, d) {
    return y + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
}

// 组装多行结果文本（纯函数：入参为已校验的 {y,m,d} 结构）
function ageBuildResult(birth, target) {
    var lines = [];

    // 1. 周岁（日历借位）
    var age = ageGetExactAge(birth, target);
    lines.push('周岁：' + age.years + ' 岁 ' + age.months + ' 个月 ' + age.days + ' 天');

    // 2. 总生存：出生当天 00:00 至基准日 00:00 的整天/时/分钟（三个数字行）
    var birthTime = new Date(birth.y, birth.m - 1, birth.d).getTime();
    var targetTime = new Date(target.y, target.m - 1, target.d).getTime();
    var diff = targetTime - birthTime;
    var totalDays = Math.round(diff / 86400000);
    var totalHours = Math.round(diff / 3600000);
    var totalMinutes = Math.round(diff / 60000);
    lines.push('总生存：' + totalDays.toLocaleString() + ' 天');
    lines.push('总生存：' + totalHours.toLocaleString() + ' 小时');
    lines.push('总生存：' + totalMinutes.toLocaleString() + ' 分钟');

    // 3. 下次生日（闰年 2/29 生日按 3/1 修正）
    var next = ageGetNextBirthday(birth, target);
    if (next.isToday) {
        lines.push('下次生日：今天正是生日 🎉（星期' + AGE_WEEKDAYS[next.date.getDay()] + '）');
    } else {
        var weekday = AGE_WEEKDAYS[next.date.getDay()];
        var line = '下次生日：' + ageFormatDate(next.date.getFullYear(), next.date.getMonth() + 1, next.date.getDate()) +
            '（星期' + weekday + '），距今 ' + next.daysLeft + ' 天';
        if (next.corrected) {
            line += '（闰年修正：2/29 生日按 3/1 计算）';
        }
        lines.push(line);
    }

    // 4. 生肖 & 5. 星座
    lines.push('生肖：' + ageGetZodiac(birth.y));
    lines.push('星座：' + ageGetConstellation(birth.m, birth.d));

    // 6. 出生当天星期几
    var birthWeekday = new Date(birth.y, birth.m - 1, birth.d).getDay();
    lines.push('出生当天：星期' + AGE_WEEKDAYS[birthWeekday]);

    return lines.join('\n');
}

// ---------- 页面交互 ----------

// "现在"按钮：重置基准日期为今天
function ageSetNow() {
    var now = new Date();
    document.getElementById('age-target').value =
        ageFormatDate(now.getFullYear(), now.getMonth() + 1, now.getDate());
}

// "计算年龄"按钮：读取并校验两个日期，合法则输出多行结果
function ageCalculate() {
    var resultEl = document.getElementById('age-result');
    var birth = ageParseDateStr(document.getElementById('age-birth').value);
    var targetStr = document.getElementById('age-target').value;
    // 基准日期留空 = 今天
    var target = targetStr ? ageParseDateStr(targetStr) : ageParseDateStr(ageTodayStr());

    // 校验：出生日期为空 / 非法
    if (!birth || !ageIsValidDate(birth)) {
        resultEl.textContent = '❌ 请输入有效的出生日期';
        showNotification('请输入出生日期');
        return;
    }
    if (!target || !ageIsValidDate(target)) {
        resultEl.textContent = '❌ 基准日期无效';
        showNotification('基准日期无效');
        return;
    }
    // 校验：出生日期晚于基准日期
    if (new Date(birth.y, birth.m - 1, birth.d).getTime() > new Date(target.y, target.m - 1, target.d).getTime()) {
        resultEl.textContent = '❌ 出生日期不能晚于基准日期';
        showNotification('出生日期不能晚于基准日期');
        return;
    }

    resultEl.textContent = ageBuildResult(birth, target);
}

// 今天的 "YYYY-MM-DD" 字符串（本地时区）
function ageTodayStr() {
    var now = new Date();
    return ageFormatDate(now.getFullYear(), now.getMonth() + 1, now.getDate());
}

// ---------- 初始化 ----------

// 基准日期默认填今天，并绑定回车快捷计算
function ageInit() {
    ageSetNow();
    var birthInput = document.getElementById('age-birth');
    var targetInput = document.getElementById('age-target');
    if (birthInput) {
        birthInput.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') ageCalculate();
        });
    }
    if (targetInput) {
        targetInput.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') ageCalculate();
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ageInit);
} else {
    ageInit();
}
