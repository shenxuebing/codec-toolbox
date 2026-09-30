// ============================================================
// IP 子网计算器（page-ipcalc）
// - 输入 IPv4 + 前缀，支持三种形态：CIDR（a.b.c.d/nn）、
//   IP + 点分掩码（斜杠或空格分隔）、纯 IP（默认 /32）
// - 纯位运算：地址与掩码均转 32 位无符号整数（>>> 0），
//   network = ip & mask，broadcast = network | 反掩码
// - /31 与 /32 采用特殊口径（RFC 3021）：
//   /31 点对点链路无网络/广播地址，两端均计为可用主机（2 个）；
//   /32 单主机路由，网络 = 广播 = 主机自身（1 个）。
// 零依赖，全部计算在本地完成。
// ============================================================

// 提示行默认文案（清空后恢复）
var IPCALC_HINT_DEFAULT = '💡 支持 CIDR（192.168.1.36/26）、IP + 点分掩码（192.168.1.36 255.255.255.192）与纯 IP（默认 /32）三种输入形态。';

// 结果表 10 个只读字段 id（清空 / 报错时统一处理）
var IPCALC_OUT_IDS = [
    'ipcalc-out-network', 'ipcalc-out-broadcast', 'ipcalc-out-mask', 'ipcalc-out-wildcard',
    'ipcalc-out-first', 'ipcalc-out-last', 'ipcalc-out-count', 'ipcalc-out-prefix',
    'ipcalc-out-type', 'ipcalc-out-binary'
];

// 点分十进制 IPv4 → 32 位无符号整数；段数 / 每段取值不合法时抛错并指明第几段
function ipcalcParseIp(str, label) {
    var parts = String(str).split('.');
    if (parts.length !== 4) {
        throw new Error(label + '「' + str + '」必须是四段点分十进制（a.b.c.d）');
    }
    var value = 0;
    for (var i = 0; i < 4; i++) {
        var seg = parts[i];
        // 纯数字 1-3 位（容忍前导零，按十进制解析）
        if (!/^\d{1,3}$/.test(seg)) {
            throw new Error(label + '第 ' + (i + 1) + ' 段「' + seg + '」不是 0-255 的数字');
        }
        var num = parseInt(seg, 10);
        if (num > 255) {
            throw new Error(label + '第 ' + (i + 1) + ' 段「' + num + '」越界（应在 0-255）');
        }
        value = ((value << 8) | num) >>> 0;
    }
    return value;
}

// 点分掩码 → 前缀长度；掩码二进制必须形如 1*0*（高位连续 1 接连续 0）
function ipcalcMaskToPrefix(maskStr) {
    var mask = ipcalcParseIp(maskStr, '掩码');
    // 反掩码（wildcard）须为 2^n - 1（低位连续 1）：wild & (wild + 1) === 0 即通过
    // 例：255.0.255.0 → 反掩码 0.255.0.255，与自身 +1 相与非 0 → 非连续，报错
    var wild = (~mask) >>> 0;
    if ((wild & (wild + 1)) !== 0) {
        throw new Error('掩码 ' + maskStr + ' 不是连续的（二进制须为连续 1 接连续 0，如 255.255.255.192）');
    }
    // 连续 1 的个数即前缀长度（掩码全 0 → /0，全 1 → /32）
    var prefix = 0;
    var m = mask;
    while (m !== 0) {
        prefix += m & 1;
        m >>>= 1;
    }
    return prefix;
}

// 解析用户输入（返回 { ip: 32 位无符号整数, prefix: 前缀长度 }，失败抛错）：
// 1. CIDR：a.b.c.d/nn（nn 0-32）
// 2. IP + 空格或斜杠 + 点分掩码（掩码需通过连续性校验后转前缀）
// 3. 纯 IP：默认 /32（单主机）
function ipcalcParse(input) {
    var text = String(input == null ? '' : input).trim();
    if (!text) {
        throw new Error('请先输入 IP / CIDR');
    }
    // 以首个 '/' 或连续空白为界拆成两段
    var m = text.match(/^([^\/\s]+)(?:[\/\s]+(.*))?$/);
    if (!m) {
        throw new Error('无法识别输入「' + text + '」');
    }
    var ip = ipcalcParseIp(m[1], 'IP ');
    var maskPart = (m[2] || '').trim();
    if (!maskPart) {
        return { ip: ip, prefix: 32 }; // 纯 IP：默认 /32
    }
    if (/[\/\s]/.test(maskPart)) {
        throw new Error('第二段「' + maskPart + '」无法识别（应为前缀长度或点分掩码）');
    }
    // 纯数字按前缀长度处理（斜杠与空格分隔符同规则），否则按点分掩码
    if (/^\d+$/.test(maskPart)) {
        var prefix = parseInt(maskPart, 10);
        if (prefix > 32) {
            throw new Error('前缀长度 /' + prefix + ' 越界（应在 0-32）');
        }
        return { ip: ip, prefix: prefix };
    }
    return { ip: ip, prefix: ipcalcMaskToPrefix(maskPart) };
}

// 地址类型判定（按输入 IP 本身，从特殊到一般逐级匹配）
function ipcalcType(ip) {
    if (ip === 0xFFFFFFFF) return '受限广播';
    var b1 = ip >>> 24;                        // 首字节
    if (b1 === 0) return '本网络（保留）';      // 0.0.0.0/8
    if (b1 === 10) return 'A 类私有';           // 10/8
    if (b1 === 127) return '环回';              // 127/8
    if ((ip >>> 16) === 0xA9FE) return '链路本地'; // 169.254/16
    if ((ip >>> 20) === 0xAC1) return 'B 类私有';  // 172.16/12（172.16-172.31）
    if ((ip >>> 16) === 0xC0A8) return 'C 类私有'; // 192.168/16
    if ((ip >>> 28) === 0xE) return '组播（D 类）'; // 224/4
    if ((ip >>> 28) === 0xF) return '保留（E 类）'; // 240/4
    return '公网';
}

// 32 位无符号整数 → 点分十进制
function ipcalcIntToStr(n) {
    n = n >>> 0;
    return ((n >>> 24) & 255) + '.' + ((n >>> 16) & 255) + '.' + ((n >>> 8) & 255) + '.' + (n & 255);
}

// 32 位无符号整数 → 二进制表示（每字节 8 位补零，空格分组）
function ipcalcToBinary(n) {
    n = n >>> 0;
    var bytes = [];
    for (var i = 3; i >= 0; i--) {
        bytes.push(('00000000' + ((n >>> (i * 8)) & 255).toString(2)).slice(-8));
    }
    return bytes.join(' ');
}

// 千分位：62 → 62，16777214 → 16,777,214（手写避免 toLocaleString 的环境差异）
function ipcalcThousands(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// 核心计算：传入无符号整数 IP 与前缀长度，返回全部展示字段（纯函数，便于 Node 对拍）
function ipcalcCompute(ip, prefix) {
    ip = ip >>> 0;
    // 前缀全 1 左移 (32-prefix) 位得掩码；prefix=0 时 JS 位移量按 5 位截断（<<32 等于 <<0），需特判为 0
    var mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    var wild = (~mask) >>> 0;
    var network = (ip & mask) >>> 0;
    var broadcast = (network | wild) >>> 0;

    // 可用主机口径：
    // - /31（RFC 3021）：点对点链路不设网络/广播地址，两个地址均为可用主机
    // - /32：单主机路由，网络 = 广播 = 主机自身，可用 1 个
    // - 其余（含 /0）：first = 网络 + 1，last = 广播 - 1，count = 总地址数 - 2
    //   /0 时 2^32 - 2 = 4294967294，仍在 Number 安全整数范围内
    var first, last, count;
    if (prefix >= 31) {
        first = network;
        last = broadcast;
        count = prefix === 31 ? 2 : 1;
    } else {
        first = (network + 1) >>> 0;
        last = (broadcast - 1) >>> 0;
        count = Math.pow(2, 32 - prefix) - 2;
    }
    return {
        ip: ip,
        prefix: prefix,
        mask: mask,
        wildcard: wild,
        network: network,
        broadcast: broadcast,
        first: first,
        last: last,
        count: count,
        total: Math.pow(2, 32 - prefix), // 网段总地址数（含网络/广播）
        type: ipcalcType(ip),
        binary: ipcalcToBinary(ip)
    };
}

// ---------------- 页面交互 ----------------

// 写提示行：isError 时红色显示 ❌ 原因，否则恢复默认灰色
function ipcalcSetHint(text, isError) {
    var el = document.getElementById('ipcalc-extra');
    el.textContent = text;
    el.style.color = isError ? '#dc3545' : '';
}

// 仅清空 10 个输出字段（不动输入框与提示行）
function ipcalcClearOutputs() {
    for (var i = 0; i < IPCALC_OUT_IDS.length; i++) {
        document.getElementById(IPCALC_OUT_IDS[i]).value = '';
    }
}

// 主入口：解析输入 → 计算 → 回填 10 个只读字段；失败清空字段并在提示行显示 ❌ 原因
function ipcalcRun() {
    try {
        var parsed = ipcalcParse(document.getElementById('ipcalc-input').value);
        var r = ipcalcCompute(parsed.ip, parsed.prefix);
        document.getElementById('ipcalc-out-network').value = ipcalcIntToStr(r.network);
        document.getElementById('ipcalc-out-broadcast').value = ipcalcIntToStr(r.broadcast);
        document.getElementById('ipcalc-out-mask').value = ipcalcIntToStr(r.mask);
        document.getElementById('ipcalc-out-wildcard').value = ipcalcIntToStr(r.wildcard);
        document.getElementById('ipcalc-out-first').value = ipcalcIntToStr(r.first);
        document.getElementById('ipcalc-out-last').value = ipcalcIntToStr(r.last);
        document.getElementById('ipcalc-out-count').value = ipcalcThousands(r.count);
        document.getElementById('ipcalc-out-prefix').value = '/' + r.prefix;
        document.getElementById('ipcalc-out-type').value = r.type;
        document.getElementById('ipcalc-out-binary').value = r.binary;
        // 提示行：该前缀下每网段总地址数、可用主机数与本网段跨度（如 /26 每段 64 个地址可用 62）
        ipcalcSetHint('💡 /' + r.prefix + '：每网段共 ' + ipcalcThousands(r.total) + ' 个地址，可用主机 ' +
            ipcalcThousands(r.count) + ' 个；本段跨度 ' + ipcalcIntToStr(r.network) + ' ~ ' + ipcalcIntToStr(r.broadcast) + '。', false);
    } catch (e) {
        ipcalcClearOutputs();
        ipcalcSetHint('❌ ' + e.message, true);
        showNotification(e.message);
    }
}

// 示例：填入经典 /26 向量并立即计算
function ipcalcExample() {
    document.getElementById('ipcalc-input').value = '192.168.1.36/26';
    ipcalcRun();
}

// 清空本页输入、结果与提示
function ipcalcClear() {
    document.getElementById('ipcalc-input').value = '';
    ipcalcClearOutputs();
    ipcalcSetHint(IPCALC_HINT_DEFAULT, false);
}

// 页面初始化：输入框回车直接计算
function ipcalcInit() {
    var input = document.getElementById('ipcalc-input');
    if (input) {
        input.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                ipcalcRun();
            }
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ipcalcInit);
} else {
    ipcalcInit();
}

// Node 环境导出纯函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ipcalcParse: ipcalcParse,
        ipcalcParseIp: ipcalcParseIp,
        ipcalcMaskToPrefix: ipcalcMaskToPrefix,
        ipcalcCompute: ipcalcCompute,
        ipcalcType: ipcalcType,
        ipcalcIntToStr: ipcalcIntToStr,
        ipcalcToBinary: ipcalcToBinary,
        ipcalcThousands: ipcalcThousands
    };
}
