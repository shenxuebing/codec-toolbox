// ============================================================
// 进制转换（page-radix）
// 2 / 8 / 10 / 16 / 36 / 62 进制任意长度大整数互转，基于 BigInt：
//   - 2/8/10/16 直接用 BigInt(带前缀字符串) 解析 + toString(n) 输出
//   - 36/62 内置 BigInt 不支持，自实现逐字符累乘解析与除基取余输出
//   - 36 进制数字字符为 0-9a-z（解析时大小写不敏感，同 parseInt 习惯）
//   - 62 进制数字字符为 0-9a-zA-Z（大小写敏感：a=10...z=35，A=36...Z=61）
// ============================================================

// 36 / 62 进制的数字字符表（自实现解析与格式化共用）
var RADIX_DIGITS_36 = '0123456789abcdefghijklmnopqrstuvwxyz';
var RADIX_DIGITS_62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

// 输出行：进制 → 结果框 id（2/8/16 输出带 0b/0o/0x 前缀，便于直接粘贴回输入框往返）
var RADIX_BASES = [2, 8, 10, 16, 36, 62];

// 读取当前选中的输入进制（默认 10）
function radixGetBase() {
    var radios = document.getElementsByName('radix-base');
    for (var i = 0; i < radios.length; i++) {
        if (radios[i].checked) {
            return parseInt(radios[i].value, 10);
        }
    }
    return 10;
}

// 取指定进制输入应使用的数字字符表
function radixDigitTable(base) {
    if (base === 36) { return RADIX_DIGITS_36; }
    if (base === 62) { return RADIX_DIGITS_62; }
    if (base === 2) { return '01'; }
    if (base === 8) { return '01234567'; }
    if (base === 16) { return '0123456789abcdefABCDEF'; }
    return '0123456789'; // 10 进制
}

// 清空全部 6 个结果行
function radixClearOutputs() {
    for (var i = 0; i < RADIX_BASES.length; i++) {
        document.getElementById('radix-out-' + RADIX_BASES[i]).value = '';
    }
}

// 转换失败提示：结果行清空后在 10 进制行显示错误，并弹通知
function radixShowError(message) {
    radixClearOutputs();
    document.getElementById('radix-out-10').value = '❌ ' + message;
    showNotification(message);
}

// 自实现：36/62 进制字符串 → BigInt（逐字符按位累乘累加）
// 入参须为纯数字字符（不含符号），字符表由 table 提供
function radixParseBig(str, base, table) {
    var value = 0n;
    var bigBase = BigInt(base);
    for (var i = 0; i < str.length; i++) {
        var digit = table.indexOf(str[i]);
        if (digit < 0 || digit >= base) {
            return null; // 调用方已提前校验，此处兜底
        }
        value = value * bigBase + BigInt(digit);
    }
    return value;
}

// 自实现：BigInt → 36/62 进制字符串（除基取余，余数循环到为 0）
// 入参须为非负 BigInt
function radixFormatBig(value, base, table) {
    if (value === 0n) {
        return '0';
    }
    var bigBase = BigInt(base);
    var digits = '';
    while (value > 0n) {
        digits = table[Number(value % bigBase)] + digits; // 余数即最低位，逆序拼接
        value = value / bigBase;
    }
    return digits;
}

// 主入口：读取输入与所选进制，校验后转成 BigInt，再输出全部 6 种进制
function radixConvert() {
    var input = document.getElementById('radix-input');

    // 预处理：去前后空白与千分位逗号
    var text = input.value.replace(/,/g, '').trim();
    if (!text) {
        radixShowError('请输入数值');
        return;
    }

    var base = radixGetBase();

    // offset：已从开头剥离的字符数（负号 + 前缀），用于把错误位置换算回原始输入的下标
    var offset = 0;

    // 提取负号（只允许出现在首位，且后面必须还有数字）
    var negative = false;
    if (text.charAt(0) === '-') {
        negative = true;
        text = text.slice(1);
        offset = 1;
        if (!text) {
            radixShowError('“-”后没有任何数字');
            return;
        }
    } else if (text.indexOf('-') >= 0) {
        // 负号出现在中间：定位给用户看
        var midPos = text.indexOf('-');
        radixShowError('第 ' + (midPos + 1) + ' 个字符 “-” 不是合法的 ' + base + ' 进制数字（负号只能放在开头）');
        return;
    }

    // 前缀剥离：输入带 0b/0o/0x 前缀且与所选进制一致时去掉（大小写均可）
    var prefixes = { 2: '0b', 8: '0o', 16: '0x' };
    if (prefixes[base] && text.length >= 2) {
        var head = text.slice(0, 2).toLowerCase();
        if (head === prefixes[base]) {
            text = text.slice(2);
            offset += 2;
            if (!text) {
                radixShowError('前缀 “' + prefixes[base] + '”后没有任何数字');
                return;
            }
        }
    }

    // 字符集校验：找到第一个非法字符并报出位置（36 进制大小写不敏感，先转小写）
    var checkText = (base === 36) ? text.toLowerCase() : text;
    var table = radixDigitTable(base);
    for (var i = 0; i < checkText.length; i++) {
        var ch = checkText.charAt(i);
        var valid = false;
        for (var j = 0; j < table.length; j++) {
            if (table.charAt(j) === ch) { valid = true; break; }
        }
        if (!valid) {
            radixShowError('第 ' + (offset + i + 1) + ' 个字符 “' + ch + '” 不是合法的 ' + base + ' 进制数字');
            return;
        }
    }

    // 解析为 BigInt
    var value;
    if (base === 36) {
        value = radixParseBig(checkText, 36, RADIX_DIGITS_36);
    } else if (base === 62) {
        value = radixParseBig(text, 62, RADIX_DIGITS_62);
    } else {
        // 2/8/10/16：交给 BigInt 原生解析（带标准前缀）
        var literal = text;
        if (base === 2) { literal = '0b' + text; }
        else if (base === 8) { literal = '0o' + text; }
        else if (base === 16) { literal = '0x' + text; }
        try {
            value = BigInt(literal);
        } catch (e) {
            radixShowError('无法解析为 ' + base + ' 进制整数');
            return;
        }
    }
    if (value === null) {
        radixShowError('无法解析为 ' + base + ' 进制整数');
        return;
    }
    if (negative) {
        value = -value;
    }

    // 逐行输出：绝对值格式化后补负号；2/8/16 加 0b/0o/0x 前缀
    // （16 进制按大写 Hex 输出，与本工具哈希/国密页的展示习惯一致；解析时大小写均可）
    var isNeg = value < 0n;
    var abs = isNeg ? -value : value;
    var outputs = {
        2: '0b' + abs.toString(2),
        8: '0o' + abs.toString(8),
        10: abs.toString(10),
        16: '0x' + abs.toString(16).toUpperCase(),
        36: radixFormatBig(abs, 36, RADIX_DIGITS_36),
        62: radixFormatBig(abs, 62, RADIX_DIGITS_62)
    };
    for (var k = 0; k < RADIX_BASES.length; k++) {
        var b = RADIX_BASES[k];
        document.getElementById('radix-out-' + b).value = (isNeg ? '-' : '') + outputs[b];
    }
}

// 清空：输入框与全部结果行
function radixClear() {
    document.getElementById('radix-input').value = '';
    radixClearOutputs();
}

// 页面初始化：输入框回车直接触发转换
function radixInit() {
    var input = document.getElementById('radix-input');
    if (input && typeof input.addEventListener === 'function') {
        input.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                radixConvert();
            }
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', radixInit);
} else {
    radixInit();
}

// Node 环境导出纯转换函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        radixParseBig: radixParseBig,
        radixFormatBig: radixFormatBig,
        radixDigitTable: radixDigitTable
    };
}
