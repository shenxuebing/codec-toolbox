// ============================================================
// 增强版编解码工具 - ASCII 码表页（page-ascii）
// 功能：0-255 码位对照表（标准区/扩展区/全部切换）+ 搜索过滤 + 点击行复制
// 依赖（须先于本文件加载）：
//   js/app.js → copyTextToClipboard（内部已带复制成功的通知提示）
// 数据口径：
//   0-31 与 127 为控制字符（英文缩写 + 中文名）；32 为空格（SP）；
//   128-159 在 ISO-8859-1 中为 C1 控制符，Windows-1252 将其重排为常用符号，
//     此区间做简单处理：字符列按 Unicode 码位原样显示（多为不可见控制符），
//     名称列标注 CP1252 对应符号，不追求完整名称表；
//   160-255 为 Latin-1 补充区：标点/符号给出常用名称，字母区间概括标注
// ============================================================

// 0-31 控制字符表：[英文缩写, 中文名称]，数组下标即码位
var ASCII_CTRL = [
    ['NUL', '空字符'], ['SOH', '标题开始'], ['STX', '正文开始'], ['ETX', '正文结束'],
    ['EOT', '传输结束'], ['ENQ', '询问'], ['ACK', '确认'], ['BEL', '响铃'],
    ['BS', '退格'], ['HT', '水平制表'], ['LF', '换行'], ['VT', '垂直制表'],
    ['FF', '换页'], ['CR', '回车'], ['SO', '移出'], ['SI', '移入'],
    ['DLE', '数据链路转义'], ['DC1', '设备控制1'], ['DC2', '设备控制2'], ['DC3', '设备控制3'],
    ['DC4', '设备控制4'], ['NAK', '否认'], ['SYN', '同步空闲'], ['ETB', '传输块结束'],
    ['CAN', '取消'], ['EM', '介质结束'], ['SUB', '替换'], ['ESC', '转义'],
    ['FS', '文件分隔符'], ['GS', '组分隔符'], ['RS', '记录分隔符'], ['US', '单元分隔符']
];

// 160-191 及 215/247 的 Latin-1 常用名称（其余 192-255 概括为字母区间）
var ASCII_LATIN1_NAMES = {
    160: 'NBSP 不换行空格', 161: '¡ 反向感叹号', 162: '¢ 分币符号', 163: '£ 英镑符号',
    164: '¤ 货币符号', 165: '¥ 日元/人民币符号', 166: '¦ 断竖线', 167: '§ 章节号',
    168: '¨ 分音符', 169: '© 版权符号', 170: 'ª 阴性序数符', 171: '« 左双书名号',
    172: '¬ 逻辑非', 173: 'SHY 软连字符', 174: '® 注册商标', 175: '¯ 长音符号',
    176: '° 度', 177: '± 正负号', 178: '² 平方', 179: '³ 立方',
    180: '´ 尖音符', 181: 'µ 微符号', 182: '¶ 段落符', 183: '· 间隔点',
    184: '¸ 软音符', 185: '¹ 一次方', 186: 'º 阳性序数符', 187: '» 右双书名号',
    188: '¼ 四分之一', 189: '½ 二分之一', 190: '¾ 四分之三', 191: '¿ 反向问号',
    215: '× 乘号', 247: '÷ 除号'
};

// 128-159 的 Windows-1252 重排符号（格式"符号 描述"；129/141/143/144/157 未定义，不列）
var ASCII_CP1252 = {
    128: '€ 欧元符号', 130: '‚ 单低引号', 131: 'ƒ 函数符', 132: '„ 双低引号',
    133: '… 省略号', 134: '† 剑号', 135: '‡ 双剑号', 136: 'ˆ 抑音符',
    137: '‰ 千分号', 138: 'Š S带抑音符', 139: '‹ 左单书名号', 140: 'Œ OE连字',
    142: 'Ž Z带抑音符', 145: '‘ 左单引号', 146: '’ 右单引号', 147: '“ 左双引号',
    148: '” 右双引号', 149: '• 实心圆点', 150: '– 短破折号', 151: '— 长破折号',
    152: '˜ 小波浪号', 153: '™ 商标', 154: 'š s带抑音符', 155: '› 右单书名号',
    156: 'œ oe连字', 158: 'ž z带抑音符', 159: 'Ÿ Y带分音符'
};

// 获取单个码位的完整展示信息（渲染 / 搜索 / 复制三处共用同一份数据）
function asciiGetInfo(code) {
    var ch = String.fromCharCode(code);
    var info = {
        code: code,
        hex: code.toString(16).toUpperCase().padStart(2, '0'),
        oct: code.toString(8),
        ch: ch,
        display: ch,   // 字符列展示文本
        label: ch,     // 点击复制时括号内的"字符"部分
        name: '',      // 名称/说明列
        isCtrl: false  // 是否控制字符行（浅灰底色）
    };
    if (code < 32) {
        info.display = info.label = ASCII_CTRL[code][0];
        info.name = ASCII_CTRL[code][1];
        info.isCtrl = true;
    } else if (code === 32) {
        info.display = info.label = 'SP';
        info.name = '空格';
    } else if (code === 127) {
        info.display = info.label = 'DEL';
        info.name = '删除';
        info.isCtrl = true;
    } else if (code < 128) {
        if (code >= 48 && code <= 57) {
            info.name = '数字';
        } else if (code >= 65 && code <= 90) {
            info.name = '大写字母';
        } else if (code >= 97 && code <= 122) {
            info.name = '小写字母';
        } else {
            info.name = '可打印符号';
        }
    } else if (code < 160) {
        // C1 控制区：名称列标注 CP1252 重排符号，无对应符号的给出 Unicode 码位
        info.isCtrl = true;
        var cp1252 = ASCII_CP1252[code];
        if (cp1252) {
            info.label = cp1252.split(' ')[0];
            info.name = 'CP1252 重排：' + cp1252;
        } else {
            info.label = 'U+00' + info.hex;
            info.name = 'C1 控制字符（CP1252 未定义）';
        }
    } else {
        info.name = ASCII_LATIN1_NAMES[code] || 'Latin-1 补充区（带变音符的拉丁字母）';
    }
    return info;
}

// 单元格文本 HTML 转义：可打印字符中含 & < > 三个 HTML 保留字符
function asciiEscapeHtml(text) {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// 生成单行 HTML：data-dec 供事件委托定位行；控制字符行加 ascii-ctrl-row 底色类
function asciiBuildRowHtml(info) {
    var charClass = (info.isCtrl || info.code === 32) ? 'ascii-abbr' : 'ascii-char';
    return '<tr data-dec="' + info.code + '"' + (info.isCtrl ? ' class="ascii-ctrl-row"' : '') + '>' +
        '<td>' + info.code + '</td>' +
        '<td>0x' + info.hex + '</td>' +
        '<td>' + info.oct + '</td>' +
        '<td><span class="' + charClass + '">' + asciiEscapeHtml(info.display) + '</span></td>' +
        '<td>' + asciiEscapeHtml(info.name) + '</td>' +
        '</tr>';
}

// 判断码位是否匹配搜索词：拼出"十进制 0xNN NN 八进制 字符 缩写 名称"的
// 检索串后做子串匹配（大小写不敏感），支持 A、65、0x41、DEL、空格 等多种写法
function asciiInfoMatches(info, term) {
    var haystack = (info.code + ' 0x' + info.hex + ' ' + info.hex + ' ' + info.oct + ' ' +
        info.ch + ' ' + info.display + ' ' + info.label + ' ' + info.name).toLowerCase();
    return haystack.indexOf(term) !== -1;
}

// 读取当前所选码位范围：std=标准区(0-127) / ext=扩展区(128-255) / all=全部(0-255)
function asciiGetRange() {
    var checked = document.querySelector('input[name="ascii-range"]:checked');
    return checked ? checked.value : 'std';
}

// 渲染码表：按所选范围生成 + 按搜索词过滤；全部行先字符串拼接、
// 最后一次性 innerHTML 写入（256 行也只触发一次解析重排，避免逐行 append 卡顿）
function asciiRender() {
    var container = document.getElementById('ascii-table-container');
    if (!container) {
        return;
    }
    var range = asciiGetRange();
    var term = document.getElementById('ascii-search').value.trim().toLowerCase();
    var start = range === 'ext' ? 128 : 0;
    var end = range === 'std' ? 127 : 255;

    var rows = [];
    for (var code = start; code <= end; code++) {
        var info = asciiGetInfo(code);
        if (term && !asciiInfoMatches(info, term)) {
            continue;
        }
        rows.push(asciiBuildRowHtml(info));
    }

    var body = rows.length > 0
        ? rows.join('')
        : '<tr><td colspan="5" class="ascii-empty">无匹配项</td></tr>';
    container.innerHTML =
        '<table class="ascii-table">' +
        '<thead><tr><th>十进制</th><th>十六进制</th><th>八进制</th><th>字符</th><th>名称 / 说明</th></tr></thead>' +
        '<tbody>' + body + '</tbody>' +
        '</table>';
}

// 搜索输入事件入口：渲染函数内部会读取当前搜索词，与切换范围共用同一条渲染路径，
// 因此切换范围后搜索过滤仍然保持生效
function asciiSearch() {
    asciiRender();
}

// 点击行复制：复制 "0xNN (字符)" 复合文本（copyTextToClipboard 内部自带成功通知）
function asciiCopyRow(code) {
    var info = asciiGetInfo(code);
    copyTextToClipboard('0x' + info.hex + ' (' + info.label + ')');
}

// 页面初始化：绑定搜索输入 / 范围切换事件，码表点击用事件委托实现
// （innerHTML 重渲染后监听依然有效），最后完成首次渲染
function asciiInit() {
    var searchInput = document.getElementById('ascii-search');
    if (searchInput) {
        searchInput.addEventListener('input', asciiSearch);
    }
    var radios = document.getElementsByName('ascii-range');
    for (var i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', asciiRender);
    }
    var container = document.getElementById('ascii-table-container');
    if (container) {
        container.addEventListener('click', function (event) {
            var row = event.target.closest ? event.target.closest('tr[data-dec]') : null;
            if (row) {
                asciiCopyRow(parseInt(row.getAttribute('data-dec'), 10));
            }
        });
    }
    asciiRender();
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', asciiInit);
} else {
    asciiInit();
}
