// ============================================================
// 密码生成器（page-passgen）
// - 可勾选字符集（大写/小写/数字/符号），可选排除易混淆字符
// - 可选"保证每类至少 1 个"：先每类各取 1 个，再从全池补齐，最后 Fisher-Yates 洗牌
// - 随机数全部来自 crypto.getRandomValues（Uint32Array），
//   取字符采用拒绝采样（rejection sampling）：丢弃落在非完整区间
//   [k*max, 2^32) 的样本后再取模，避免模偏差（modulo bias）
// - 强度评估口径：信息熵估算 = 长度 × log2(字符池大小)，
//   仅作相对参考，不代表对字典攻击/撞库等现实威胁的抵抗力
// 离线可用，无任何外部依赖。
// ============================================================

// 各类字符集常量
var PASSGEN_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
var PASSGEN_LOWER = 'abcdefghijklmnopqrstuvwxyz';
var PASSGEN_DIGIT = '0123456789';
var PASSGEN_SYMBOL = '!@#$%^&*()';
// 易混淆字符：数字 0/1、大写 O/I、小写 l
var PASSGEN_AMBIGUOUS = '0O1lI';

// 从一类字符集中剔除易混淆字符
function passgenStripAmbiguous(chars) {
    var out = '';
    for (var i = 0; i < chars.length; i++) {
        if (PASSGEN_AMBIGUOUS.indexOf(chars[i]) < 0) {
            out += chars[i];
        }
    }
    return out;
}

// 按选项构建字符集：
// opts = { upper, lower, digit, symbol, noAmbiguous }（布尔值）
// 返回 { classes: [每类字符集...], pool: 拼接后的全池 }；全不勾选时 pool 为空串
function passgenBuildSets(opts) {
    var defs = [
        { name: '大写', chars: PASSGEN_UPPER, on: opts.upper },
        { name: '小写', chars: PASSGEN_LOWER, on: opts.lower },
        { name: '数字', chars: PASSGEN_DIGIT, on: opts.digit },
        { name: '符号', chars: PASSGEN_SYMBOL, on: opts.symbol }
    ];
    var classes = [];
    for (var i = 0; i < defs.length; i++) {
        if (!defs[i].on) {
            continue;
        }
        classes.push(opts.noAmbiguous ? passgenStripAmbiguous(defs[i].chars) : defs[i].chars);
    }
    return { classes: classes, pool: classes.join('') };
}

// 拒绝采样取 [0, max) 的均匀随机整数：
// 2^32 内 max 的最大整数倍为 limit，样本 ≥ limit 时丢弃重取，
// 使每个取值概率严格相等，避免直接取模带来的模偏差
function passgenRandomIndex(max) {
    var limit = Math.floor(4294967296 / max) * max;
    var buf = new Uint32Array(1);
    while (true) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) {
            return buf[0] % max;
        }
    }
}

// 生成一个密码：
// ensureEach 为真时，先从每个选中类各取 1 个字符占据前 k 位，
// 其余位从全池随机取，最后 Fisher-Yates 洗牌（随机数同样来自 getRandomValues）
function passgenGenerateOne(length, classes, pool, ensureEach) {
    var chars = [];
    var start = 0;
    if (ensureEach) {
        for (var i = 0; i < classes.length; i++) {
            chars.push(classes[i].charAt(passgenRandomIndex(classes[i].length)));
        }
        start = classes.length;
    }
    for (var j = start; j < length; j++) {
        chars.push(pool.charAt(passgenRandomIndex(pool.length)));
    }
    // Fisher-Yates 洗牌：打散"前 k 位固定为各类首字符"的可预测痕迹
    for (var k = chars.length - 1; k > 0; k--) {
        var r = passgenRandomIndex(k + 1);
        var tmp = chars[k];
        chars[k] = chars[r];
        chars[r] = tmp;
    }
    return chars.join('');
}

// 强度评估（信息熵估算口径）：
// 熵 = 长度 × log2(字符池大小)
// <40 非常弱、<60 弱、<80 中等、<100 强、≥100 非常强
function passgenStrength(len, poolSize) {
    var entropy = len * Math.log(poolSize) / Math.LN2;
    var level;
    if (entropy < 40) {
        level = '非常弱';
    } else if (entropy < 60) {
        level = '弱';
    } else if (entropy < 80) {
        level = '中等';
    } else if (entropy < 100) {
        level = '强';
    } else {
        level = '非常强';
    }
    return { entropy: entropy, level: level };
}

// 主入口：按选项批量生成密码并逐行输出
function passgenRun() {
    // 读取字符集与附加选项
    var opts = {
        upper: document.getElementById('passgen-upper').checked,
        lower: document.getElementById('passgen-lower').checked,
        digit: document.getElementById('passgen-digit').checked,
        symbol: document.getElementById('passgen-symbol').checked,
        noAmbiguous: document.getElementById('passgen-no-ambiguous').checked
    };
    var sets = passgenBuildSets(opts);
    if (!sets.pool) {
        showNotification('请至少选择一个字符类型');
        return;
    }

    // 长度校验（滑块本身限定 4-128，此处防御性再校验）
    var length = Number(document.getElementById('passgen-length').value);
    if (!Number.isInteger(length) || length < 4 || length > 128) {
        showNotification('密码长度必须在 4-128 之间');
        return;
    }

    // 数量校验（1-100 的整数）
    var count = Number(document.getElementById('passgen-count').value);
    if (!Number.isInteger(count) || count < 1 || count > 100) {
        showNotification('生成数量必须是 1-100 之间的整数');
        return;
    }

    var ensureEach = document.getElementById('passgen-ensure-each').checked;
    if (ensureEach && length < sets.classes.length) {
        showNotification('密码长度过短，无法保证每类至少 1 个字符');
        return;
    }

    // 批量生成并逐行渲染：每个密码一行（只读框 + 独立复制按钮，与工具箱结果行同款式）
    // 数量为 1 时体验最简：一行一密码，行尾"复制"即取即用
    var container = document.getElementById('passgen-result');
    container.innerHTML = '';
    for (var i = 0; i < count; i++) {
        var pwd = passgenGenerateOne(length, sets.classes, sets.pool, ensureEach);
        var row = document.createElement('div');
        row.className = 'gm-key-row';
        row.style.marginBottom = '6px';
        var input = document.createElement('input');
        input.type = 'text';
        input.readOnly = true;
        input.value = pwd;
        // 等宽字体便于辨认易混淆字符；与工具箱单行结果观感一致
        input.style.cssText = 'flex:1;padding:10px;border:2px solid #e9ecef;border-radius:6px;font-size:14px;font-family:Consolas,monospace;letter-spacing:1px;box-sizing:border-box;';
        input.id = 'passgen-row-' + i;
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-secondary';
        btn.textContent = '复制';
        btn.onclick = (function (id) {
            return function () {
                var el = document.getElementById(id);
                el.select && el.select();
                copyTextToClipboard(el.value);
            };
        })(input.id);
        row.appendChild(input);
        row.appendChild(btn);
        container.appendChild(row);
    }

    // 强度标签：按首个密码的长度与实际字符池评估
    var names = [];
    if (opts.upper) { names.push('大写'); }
    if (opts.lower) { names.push('小写'); }
    if (opts.digit) { names.push('数字'); }
    if (opts.symbol) { names.push('符号'); }
    var st = passgenStrength(length, sets.pool.length);
    var el = document.getElementById('passgen-strength');
    // 非常弱/弱 → 红（jwt-invalid）；中等 → 黄（内联色）；强/非常强 → 绿（jwt-valid）
    if (st.level === '强' || st.level === '非常强') {
        el.className = 'result-area gm-oneline jwt-valid';
        el.style.color = '';
    } else if (st.level === '中等') {
        el.className = 'result-area gm-oneline';
        el.style.color = '#e6a700';
    } else {
        el.className = 'result-area gm-oneline jwt-invalid';
        el.style.color = '';
    }
    el.style.fontWeight = 'bold';
    el.textContent = '密码强度（首个）：' + st.level +
        '｜字符集：' + names.join('+') + '（' + sets.pool.length + ' 字符' +
        (opts.noAmbiguous ? '，已排除易混淆' : '') + '）' +
        '｜熵 ≈ ' + st.entropy.toFixed(1) + ' bit（' + length + ' × log2(' + sets.pool.length + ')）';

    showNotification('已生成 ' + count + ' 个密码');
}

// 清空结果区与强度标签
function passgenClear() {
    document.getElementById('passgen-result').innerHTML = '';
    var el = document.getElementById('passgen-strength');
    el.textContent = '';
    el.className = 'result-area gm-oneline';
    el.style.color = '';
}

// 初始化：长度滑块 input 事件实时更新数值显示
function passgenInit() {
    var slider = document.getElementById('passgen-length');
    var display = document.getElementById('passgen-len-value');
    var update = function () {
        display.textContent = slider.value;
    };
    slider.addEventListener('input', update);
    update();
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化；
// typeof 守卫使 Node 环境 require 本文件做对拍自测时不触碰 DOM
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', passgenInit);
    } else {
        passgenInit();
    }
}

// Node 环境导出纯生成/计算函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        passgenBuildSets: passgenBuildSets,
        passgenRandomIndex: passgenRandomIndex,
        passgenGenerateOne: passgenGenerateOne,
        passgenStrength: passgenStrength,
        PASSGEN_UPPER: PASSGEN_UPPER,
        PASSGEN_LOWER: PASSGEN_LOWER,
        PASSGEN_DIGIT: PASSGEN_DIGIT,
        PASSGEN_SYMBOL: PASSGEN_SYMBOL,
        PASSGEN_AMBIGUOUS: PASSGEN_AMBIGUOUS
    };
}
