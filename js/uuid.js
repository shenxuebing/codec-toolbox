// ============================================================
// UUID 生成器（page-uuid）
// - v4：纯随机（crypto.getRandomValues 16 字节，置 version/variant 位）
// - v7：按 RFC 9562 布局，前 48 位为毫秒时间戳（大端），
//   时间上整体递增，适合做数据库主键 / 排序键；
//   同一毫秒内多次生成天然有序（时间戳相同），但随机部分仍随机，
//   不保证严格单调（RFC 允许 rand_a 做单调计数器，此处采用全随机实现）
// 随机数全部来自浏览器密码学随机源 crypto.getRandomValues，离线可用。
// ============================================================

// 读取一组同名单选框中选中项的 value
function uuidGetRadio(name) {
    var radios = document.getElementsByName(name);
    for (var i = 0; i < radios.length; i++) {
        if (radios[i].checked) {
            return radios[i].value;
        }
    }
    return '';
}

// 16 字节 → 标准 8-4-4-4-12 连字符格式字符串，再按选项转大写/去连字符
function uuidFormatBytes(bytes, upper, noHyphen) {
    var hex = [];
    for (var i = 0; i < 16; i++) {
        var s = bytes[i].toString(16);
        if (s.length < 2) {
            s = '0' + s; // 每字节固定两位小写 hex
        }
        hex.push(s);
    }
    var str = hex.slice(0, 4).join('') + '-' + hex.slice(4, 6).join('') + '-' +
        hex.slice(6, 8).join('') + '-' + hex.slice(8, 10).join('') + '-' +
        hex.slice(10, 16).join('');
    if (noHyphen) {
        str = str.replace(/-/g, '');
    }
    if (upper) {
        str = str.toUpperCase();
    }
    return str;
}

// 生成一个 v4（随机）UUID 的 16 字节：
// 先取 16 个密码学随机字节，再置 version(0100) 与 variant(10) 位
function uuidV4Bytes() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // 第 7 字节高 4 位 = 0100（version 4）
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // 第 9 字节高 2 位 = 10（variant 1，即首 hex 为 8/9/a/b）
    return bytes;
}

// 生成一个 v7（时间戳有序）UUID 的 16 字节，按 RFC 9562 布局：
//   unix_ts_ms 48 位（字节 0-5，大端毫秒时间戳）
//   ver 4 位 = 0111（字节 6 高 4 位）+ rand_a 12 位（字节 6 低 4 位 + 字节 7）
//   var 2 位 = 10（字节 8 高 2 位）+ rand_b 62 位（字节 8 低 6 位 + 字节 9-15）
// 随机段(rand_a/rand_b)取自同一个随机缓冲区，仅覆写时间戳与版本位
function uuidV7Bytes() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    // 48 位毫秒时间戳大端写入字节 0-5（掩码防溢出）
    var ts = BigInt(Date.now()) & 0xffffffffffffn;
    bytes[0] = Number((ts >> 40n) & 0xffn);
    bytes[1] = Number((ts >> 32n) & 0xffn);
    bytes[2] = Number((ts >> 24n) & 0xffn);
    bytes[3] = Number((ts >> 16n) & 0xffn);
    bytes[4] = Number((ts >> 8n) & 0xffn);
    bytes[5] = Number(ts & 0xffn);
    bytes[6] = (bytes[6] & 0x0f) | 0x70; // 高 4 位 = 0111（version 7），低 4 位归 rand_a
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // 高 2 位 = 10（variant 1）
    return bytes;
}

// 主入口：按选项批量生成并逐行输出
function uuidGenerate() {
    // 数量校验（1-1000 的整数；用 Number + isInteger 拦下小数与非法串）
    var count = Number(document.getElementById('uuid-count').value);
    if (!Number.isInteger(count) || count < 1 || count > 1000) {
        showNotification('数量必须是 1-1000 之间的整数');
        return;
    }

    var version = uuidGetRadio('uuid-version');           // v4 / v7
    var upper = uuidGetRadio('uuid-case') === 'upper';    // 小写 / 大写
    var noHyphen = document.getElementById('uuid-hyphen').checked; // 去连字符

    var lines = [];
    for (var i = 0; i < count; i++) {
        var bytes = (version === 'v7') ? uuidV7Bytes() : uuidV4Bytes();
        lines.push(uuidFormatBytes(bytes, upper, noHyphen));
    }
    document.getElementById('uuid-result').textContent = lines.join('\n');
    showNotification('已生成 ' + count + ' 个');
}

// 清空结果区
function uuidClear() {
    document.getElementById('uuid-result').textContent = '';
}

// Node 环境导出纯生成函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        uuidV4Bytes: uuidV4Bytes,
        uuidV7Bytes: uuidV7Bytes,
        uuidFormatBytes: uuidFormatBytes
    };
}
