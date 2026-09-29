// ============================================================
// 增强版编解码工具 - 年龄计算页（page-age）
// 功能：输入出生日期与基准日期，计算：
//   周岁（按日历逐月借位，非除法近似）/ 总生存天数·小时·分钟 /
//   下次生日（闰年 2/29 生日按 3/1 修正）/ 生肖 / 星座 / 出生当天星期几 /
//   农历生日与下次农历生日（内嵌 1900-2100 农历数据表，无外部依赖）
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

    // 3.5 农历生日与下次农历生日（内嵌 1900-2100 农历数据表换算）
    // 出生日期超出换算范围：提示一句并跳过两段；仅查找失败（基准日越过 2100）则静默跳过，
    // 两种情况均不中断其余输出
    var lunarNext = ageGetNextLunarBirthday(birth, target);
    if (lunarNext && lunarNext.outOfRange) {
        lines.push('农历信息：出生日期超出农历换算支持范围（1900-2100）');
    } else if (lunarNext) {
        var bl = lunarNext.birthLunar;
        lines.push('农历生日：' + ageLunarYearCn(bl.year) + '年' + ageLunarDateCn(bl) +
            '（农历 ' + bl.year + '-' + (bl.isLeapMonth ? '闰' : '') + bl.month + '-' + bl.day + '）');

        var nextLunarDate = ageSolarToLunar(lunarNext.date);
        var lunarLine = '下次农历生日：' + ageFormatDate(lunarNext.date.getFullYear(), lunarNext.date.getMonth() + 1, lunarNext.date.getDate()) +
            ' 星期' + AGE_WEEKDAYS[lunarNext.date.getDay()] +
            '（农历' + (nextLunarDate.isLeapMonth ? '闰' : '') +
            AGE_LUNAR_MONTHS[nextLunarDate.month] + '月' +
            AGE_LUNAR_DAYS[nextLunarDate.day] + '），距今 ' + lunarNext.daysLeft + ' 天';
        if (lunarNext.notes.length > 0) {
            lunarLine += '（' + lunarNext.notes.join('；') + '）';
        }
        lines.push(lunarLine);
    }

    // 4. 生肖 & 5. 星座
    lines.push('生肖：' + ageGetZodiac(birth.y));
    lines.push('星座：' + ageGetConstellation(birth.m, birth.d));

    // 6. 出生当天星期几
    var birthWeekday = new Date(birth.y, birth.m - 1, birth.d).getDay();
    lines.push('出生当天：星期' + AGE_WEEKDAYS[birthWeekday]);

    return lines.join('\n');
}

// ---------- 农历换算（1900-2100） ----------
// 数据口径：经典 lunarInfo 压缩数据表（公开的经典农历算法数据，逐值照抄标准版本，
// 共 201 年），每年一个数，各 bit 位含义：
//   bit0-3   闰月月份（0 = 当年无闰月）
//   bit4-15  农历 1-12 月大小月（1 = 大月 30 天，0 = 小月 29 天），月份 m 对应 bit(16-m)
//   bit16    闰月大小（1 = 闰大月 30 天，0 = 闰小月 29 天）
// 纪元基准：公历 1900-01-31 = 农历 1900 年正月初一；
// 支持范围 1900-2100，超出返回 null，由调用方提示"出生日期超出农历换算支持范围（1900-2100）"
var AGE_LUNAR_INFO = [
    0x04bd8, 0x04ae0, 0x0a570, 0x054d5, 0x0d260, 0x0d950, 0x16554, 0x056a0, 0x09ad0, 0x055d2, // 1900-1909
    0x04ae0, 0x0a5b6, 0x0a4d0, 0x0d250, 0x1d255, 0x0b540, 0x0d6a0, 0x0ada2, 0x095b0, 0x14977, // 1910-1919
    0x04970, 0x0a4b0, 0x0b4b5, 0x06a50, 0x06d40, 0x1ab54, 0x02b60, 0x09570, 0x052f2, 0x04970, // 1920-1929
    0x06566, 0x0d4a0, 0x0ea50, 0x06e95, 0x05ad0, 0x02b60, 0x186e3, 0x092e0, 0x1c8d7, 0x0c950, // 1930-1939
    0x0d4a0, 0x1d8a6, 0x0b550, 0x056a0, 0x1a5b4, 0x025d0, 0x092d0, 0x0d2b2, 0x0a950, 0x0b557, // 1940-1949
    0x06ca0, 0x0b550, 0x15355, 0x04da0, 0x0a5b0, 0x14573, 0x052b0, 0x0a9a8, 0x0e950, 0x06aa0, // 1950-1959
    0x0aea6, 0x0ab50, 0x04b60, 0x0aae4, 0x0a570, 0x05260, 0x0f263, 0x0d950, 0x05b57, 0x056a0, // 1960-1969
    0x096d0, 0x04dd5, 0x04ad0, 0x0a4d0, 0x0d4d4, 0x0d250, 0x0d558, 0x0b540, 0x0b6a0, 0x195a6, // 1970-1979
    0x095b0, 0x049b0, 0x0a974, 0x0a4b0, 0x0b27a, 0x06a50, 0x06d40, 0x0af46, 0x0ab60, 0x09570, // 1980-1989
    0x04af5, 0x04970, 0x064b0, 0x074a3, 0x0ea50, 0x06b58, 0x05ac0, 0x0ab60, 0x096d5, 0x092e0, // 1990-1999
    0x0c960, 0x0d954, 0x0d4a0, 0x0da50, 0x07552, 0x056a0, 0x0abb7, 0x025d0, 0x092d0, 0x0cab5, // 2000-2009
    0x0a950, 0x0b4a0, 0x0baa4, 0x0ad50, 0x055d9, 0x04ba0, 0x0a5b0, 0x15176, 0x052b0, 0x0a930, // 2010-2019
    0x07954, 0x06aa0, 0x0ad50, 0x05b52, 0x04b60, 0x0a6e6, 0x0a4e0, 0x0d260, 0x0ea65, 0x0d530, // 2020-2029
    0x05aa0, 0x076a3, 0x096d0, 0x04afb, 0x04ad0, 0x0a4d0, 0x1d0b6, 0x0d250, 0x0d520, 0x0dd45, // 2030-2039
    0x0b5a0, 0x056d0, 0x055b2, 0x049b0, 0x0a577, 0x0a4b0, 0x0aa50, 0x1b255, 0x06d20, 0x0ada0, // 2040-2049
    0x14b63, 0x09370, 0x049f8, 0x04970, 0x064b0, 0x168a6, 0x0ea50, 0x06b20, 0x1a6c4, 0x0aae0, // 2050-2059
    0x092e0, 0x0d2e3, 0x0c960, 0x0d557, 0x0d4a0, 0x0da50, 0x05d55, 0x056a0, 0x0a6d0, 0x055d4, // 2060-2069
    0x052d0, 0x0a9b8, 0x0a950, 0x0b4a0, 0x0b6a6, 0x0ad50, 0x055a0, 0x0aba4, 0x0a5b0, 0x052b0, // 2070-2079
    0x0b273, 0x06930, 0x07337, 0x06aa0, 0x0ad50, 0x14b55, 0x04b60, 0x0a570, 0x054e4, 0x0d160, // 2080-2089
    0x0e968, 0x0d520, 0x0daa0, 0x16aa6, 0x056d0, 0x04ae0, 0x0a9d4, 0x0a4d0, 0x0d150, 0x0f252, // 2090-2099
    0x0d520 // 2100
];

// 农历换算支持的年份边界（y <= 2100 可用）
var AGE_LUNAR_MAX_YEAR = 2100;

// 农历 1900 年正月初一对应的公历日期（换算基准）
var AGE_LUNAR_EPOCH = new Date(1900, 0, 31);

// 农历月份名（下标 1-12 对应正月到腊月）
var AGE_LUNAR_MONTHS = ['', '正', '二', '三', '四', '五', '六', '七', '八', '九', '十', '冬', '腊'];

// 农历日名（初一到三十）
var AGE_LUNAR_DAYS = ['', '初一', '初二', '初三', '初四', '初五', '初六', '初七', '初八', '初九', '初十',
    '十一', '十二', '十三', '十四', '十五', '十六', '十七', '十八', '十九', '二十',
    '廿一', '廿二', '廿三', '廿四', '廿五', '廿六', '廿七', '廿八', '廿九', '三十'];

// 某农历年闰哪个月（0 = 无闰月）
function ageLunarLeapMonth(year) {
    return AGE_LUNAR_INFO[year - 1900] & 0xf;
}

// 某农历年闰月的天数（29 或 30；无闰月返回 0）
function ageLunarLeapDays(year) {
    if (ageLunarLeapMonth(year) === 0) return 0;
    return (AGE_LUNAR_INFO[year - 1900] & 0x10000) ? 30 : 29;
}

// 某农历年普通月（1-12）的天数（29 或 30）
function ageLunarMonthDays(year, month) {
    return (AGE_LUNAR_INFO[year - 1900] & (0x10000 >> month)) ? 30 : 29;
}

// 某农历年总天数（12 个普通月 + 可能的闰月）
function ageLunarYearDays(year) {
    var sum = 348;   // 12 个月 × 29 天小月基准
    for (var i = 0x8000; i > 0x8; i >>= 1) {
        if (AGE_LUNAR_INFO[year - 1900] & i) sum++;
    }
    return sum + ageLunarLeapDays(year);
}

// 构建某农历年的月序列：[{month, isLeap, days}]，闰月排在同名普通月之后；
// 下次农历生日查找需按"顺序"定位月份，序列化后线性扫描最不易错
function ageLunarMonthList(year) {
    var list = [];
    var leap = ageLunarLeapMonth(year);
    for (var m = 1; m <= 12; m++) {
        list.push({ month: m, isLeap: false, days: ageLunarMonthDays(year, m) });
        if (leap === m) {
            list.push({ month: m, isLeap: true, days: ageLunarLeapDays(year) });
        }
    }
    return list;
}

// 公历 → 农历：返回 {year, month, day, isLeapMonth}；超范围返回 null
// 入参为本地时区 00:00 的 Date
function ageSolarToLunar(date) {
    var offset = Math.round((date.getTime() - AGE_LUNAR_EPOCH.getTime()) / 86400000);
    if (offset < 0) return null;
    var year = 1900;
    while (year <= AGE_LUNAR_MAX_YEAR) {
        var yearDays = ageLunarYearDays(year);
        if (offset < yearDays) break;
        offset -= yearDays;
        year++;
    }
    if (year > AGE_LUNAR_MAX_YEAR) return null;
    var months = ageLunarMonthList(year);
    var idx = 0;
    while (idx < months.length) {
        if (offset < months[idx].days) break;
        offset -= months[idx].days;
        idx++;
    }
    var m = months[idx] || months[months.length - 1];
    return { year: year, month: m.month, day: offset + 1, isLeapMonth: m.isLeap };
}

// 农历 → 公历：年/月(1-12)/日/是否闰月 → 该农历日 00:00 的 Date；
// 年份超范围 / 该年无此闰月 / 日越界（如三十遇小月）返回 null
function ageLunarToSolar(year, month, day, isLeap) {
    if (year < 1900 || year > AGE_LUNAR_MAX_YEAR) return null;
    if (month < 1 || month > 12) return null;
    var days = 0;
    for (var y = 1900; y < year; y++) days += ageLunarYearDays(y);
    var months = ageLunarMonthList(year);
    for (var i = 0; i < months.length; i++) {
        var m = months[i];
        if (m.month === month && m.isLeap === !!isLeap) {
            if (day < 1 || day > m.days) return null;
            return new Date(1900, 0, 31 + days + dayOffset(months, i) + day - 1);
        }
    }
    return null;   // 该年不存在此闰月
}

// 月序列中第 idx 个月之前累计的天数
function dayOffset(months, idx) {
    var sum = 0;
    for (var i = 0; i < idx; i++) sum += months[i].days;
    return sum;
}

// 公历数字年份 → 中文数字年（2000 → 二〇〇〇）
function ageLunarYearCn(year) {
    var digits = '〇一二三四五六七八九';
    var s = String(year);
    var out = '';
    for (var i = 0; i < s.length; i++) out += digits[parseInt(s[i], 10)];
    return out;
}

// 农历日期 → 中文串（正月初一 / 闰六月十五）
function ageLunarDateCn(lunar) {
    return (lunar.isLeapMonth ? '闰' : '') + AGE_LUNAR_MONTHS[lunar.month] + '月' + AGE_LUNAR_DAYS[lunar.day];
}

// 下次农历生日：从基准日 target 起找出生农历月日对应的下一个公历日期。
// 规则：出生在普通月 → 恒取普通月（即使该年有闰同名月也不跟，且不注明）；
//       出生在闰月 → 优先取该年闰月（基准年/下一年有则用），无闰同名月则取普通月并注明；
//       候选日期早于/等于基准日（已过，含当天）→ 顺延下一年，腊月生日跨年由此天然覆盖；
//       出生日为三十而当年该月只有廿九 → 取当月最后一天并注明。
// 返回 {date, daysLeft, notes, birthLunar}；
// 出生日期超范围返回 {outOfRange: true}；基准日越过 2100 查找失败返回 null
function ageGetNextLunarBirthday(birth, target) {
    var birthDate = new Date(birth.y, birth.m - 1, birth.d);
    var birthLunar = ageSolarToLunar(birthDate);
    if (!birthLunar) {
        return { outOfRange: true };
    }
    var targetDate = new Date(target.y, target.m - 1, target.d);
    var lm = birthLunar.month;
    var ld = birthLunar.day;

    for (var ly = Math.max(target.y, 1900); ly <= Math.min(target.y + 1, AGE_LUNAR_MAX_YEAR); ly++) {
        var notes = [];
        // 确定取闰月还是普通月
        var useLeap = false;
        if (birthLunar.isLeapMonth) {
            if (ageLunarLeapMonth(ly) === lm) {
                useLeap = true;
            } else {
                notes.push('今年无闰' + AGE_LUNAR_MONTHS[lm] + '月，按普通' + AGE_LUNAR_MONTHS[lm] + '月计');
            }
        }
        var day = ld;
        var monthDaysActual = useLeap ? ageLunarLeapDays(ly) : ageLunarMonthDays(ly, lm);
        if (day > monthDaysActual) {
            day = monthDaysActual;   // 出生三十遇小月：按当月最后一天
            notes.push('该年' + (useLeap ? '闰' : '') + AGE_LUNAR_MONTHS[lm] + '月无三十，按' + AGE_LUNAR_DAYS[day] + '计');
        }
        var solar = ageLunarToSolar(ly, lm, day, useLeap);
        if (!solar) continue;   // 理论不达（闰月判断已前置），防御性跳过
        if (solar.getTime() > targetDate.getTime()) {
            var daysLeft = Math.round((solar.getTime() - targetDate.getTime()) / 86400000);
            return { date: solar, daysLeft: daysLeft, notes: notes, birthLunar: birthLunar };
        }
    }
    return null;   // 基准日临近/越过 2100，查找不到
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

// Node 环境导出纯计算函数（浏览器中 module 未定义，此块自动跳过，便于锚点对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ageSolarToLunar: ageSolarToLunar,
        ageLunarToSolar: ageLunarToSolar,
        ageLunarLeapMonth: ageLunarLeapMonth,
        ageGetNextLunarBirthday: ageGetNextLunarBirthday,
        ageBuildResult: ageBuildResult
    };
}
