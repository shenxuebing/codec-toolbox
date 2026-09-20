// ============================================================
// 增强版编解码工具 - 主逻辑（多文件版）
// 自 .materials/main-logic.js 迁移全部原有函数，另新增：
//   switchPage()      侧边栏页面切换（替代旧版 switchTab）
//   parseUrlQuery()   URL 查询参数解析表格（URL 工具页增强）
// 依赖（须先于本文件加载）：
//   js/vendor/crypto-js.js  → 全局 CryptoJS
//   js/vendor/gbk.js        → 全局 gbk（gbk.encode / gbk.decode）
//   js/vendor/sm3.js        → 全局 window.sm3Hash
// ============================================================

// 工具函数
function showNotification(message) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.classList.add('show');
    setTimeout(() => {
        notification.classList.remove('show');
    }, 2000);
}

// 字节数组 → 二进制字符串（每字节对应一个字符码，供 btoa 使用）
// 分块拼接：大数组直接展开为 fromCharCode 的参数会超过函数参数数量上限，
// 触发 "Maximum call stack size exceeded"，每块 0x8000 字节可安全规避
function bytesToBinaryString(bytes) {
    const CHUNK_SIZE = 0x8000;
    let result = '';
    for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
        const chunk = bytes.subarray ? bytes.subarray(i, i + CHUNK_SIZE) : bytes.slice(i, i + CHUNK_SIZE);
        result += String.fromCharCode.apply(null, chunk);
    }
    return result;
}

// 兼容 Base64URL 的安全 atob：
// Base64URL 变体（JWT、密钥交换等密码学场景常见）使用 '-'/'_' 替代 '+'/'/' 且省略 '=' 填充，
// 直接 atob 会抛异常，此处先做字符替换、去空白并按需补齐填充
function safeAtob(input) {
    let str = input.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    const pad = str.length % 4;
    if (pad === 2) {
        str += '==';
    } else if (pad === 3) {
        str += '=';
    }
    return atob(str);
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;
    if (text && text !== '-' && text !== '') {
        copyTextToClipboard(text);
    }
}

function copyHash(hashType) {
    const element = document.getElementById(hashType + '-result');
    if (!element) return;
    const text = element.textContent;
    if (text && text !== '-') {
        copyTextToClipboard(text);
    }
}

function copySpecific(hashType, format) {
    const id = hashType + '-' + format;
    const el = document.getElementById(id);
    if (!el) return;
    const text = el.textContent;
    if (text && text !== '-') {
        copyTextToClipboard(text);
    }
}

function copyTextToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('已复制到剪贴板');
        }).catch(err => {
            console.error('复制失败:', err);
            fallbackCopyTextToClipboard(text);
        });
    } else {
        fallbackCopyTextToClipboard(text);
    }
}

function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.top = '0';
    textArea.style.left = '0';
    textArea.style.position = 'fixed';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showNotification('已复制到剪贴板');
        } else {
            showNotification('复制失败，请手动复制');
        }
    } catch (err) {
        showNotification('复制失败，请手动复制');
    }
    document.body.removeChild(textArea);
}

// ===================== 侧边栏页面切换 =====================
// 旧版 switchTab 已删除：多文件版改为侧边栏 + 多页面结构，
// 切换时同步更新所有 .page 的显示与所有 .menu-item 的高亮
function switchPage(pageId) {
    const pages = document.getElementsByClassName('page');
    for (let i = 0; i < pages.length; i++) {
        pages[i].classList.toggle('active', pages[i].id === pageId);
    }
    const menuItems = document.getElementsByClassName('menu-item');
    for (let i = 0; i < menuItems.length; i++) {
        menuItems[i].classList.toggle('active', menuItems[i].getAttribute('data-page') === pageId);
    }
}

// 侧边栏菜单绑定（DOM 加载完成后绑定，确保元素已就绪）
document.addEventListener('DOMContentLoaded', function() {
    const menuItems = document.querySelectorAll('.menu-item[data-page]');
    for (let i = 0; i < menuItems.length; i++) {
        menuItems[i].addEventListener('click', function() {
            switchPage(this.getAttribute('data-page'));
        });
    }
});

// 编码转换函数
function hexToBase64() {
    const input = document.getElementById('hex-input').value.trim();
    if (!input) {
        document.getElementById('hex-result').textContent = '请输入Hex内容';
        return;
    }
    try {
        const cleanHex = input.replace(/\s/g, '');
        if (!/^[0-9a-fA-F]+$/.test(cleanHex)) {
            throw new Error('无效的Hex格式');
        }
        const paddedHex = cleanHex.length % 2 === 0 ? cleanHex : '0' + cleanHex;
        const bytes = new Uint8Array(paddedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const binary = bytesToBinaryString(bytes);
        const base64 = btoa(binary);
        document.getElementById('hex-result').textContent = base64;
    } catch (error) {
        document.getElementById('hex-result').textContent = '转换失败: ' + error.message;
    }
}

function base64ToHex() {
    const input = document.getElementById('hex-input').value.trim();
    if (!input) {
        document.getElementById('hex-result').textContent = '请输入Base64内容';
        return;
    }
    try {
        const binary = safeAtob(input);
        const hex = Array.from(binary).map(char =>
            char.charCodeAt(0).toString(16).padStart(2, '0')
        ).join('');
        document.getElementById('hex-result').textContent = hex.toUpperCase();
    } catch (error) {
        document.getElementById('hex-result').textContent = '转换失败: ' + error.message;
    }
}

function autoDetectAndConvert() {
    const input = document.getElementById('hex-input').value.trim();
    if (!input) {
        document.getElementById('hex-result').textContent = '请输入内容';
        return;
    }

    if (/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
        try {
            safeAtob(input);
            base64ToHex();
            return;
        } catch (e) {
        }
    }

    if (/^[0-9a-fA-F\s]+$/.test(input)) {
        hexToBase64();
        return;
    }

    document.getElementById('hex-result').textContent = '无法识别输入格式';
}

function clearHexArea() {
    document.getElementById('hex-input').value = '';
    document.getElementById('hex-result').textContent = '';
}

// 字符串编码转换函数
function getSelectedEncoding(prefix = '') {
    const encoding = document.querySelector('input[name="' + prefix + 'encoding"]:checked').value;
    return encoding;
}

// 最近一次 Hex/Base64 → 字符串 解码得到的原始字节缓存
// 业务原因：二进制数据（密钥/密文等）强转文本会产生 U+FFFD，字节不可逆丢失，
// "保存原始字节(.bin)"按钮依赖此缓存将未损坏的原始字节无损写回文件
let lastDecodedBytes = null;   // 解码得到的原始字节（Uint8Array）
let lastDecodedSource = null;  // 来源标识：'hex' 或 'base64'

// 显示/隐藏二进制警告（badCount 为结果中 U+FFFD 替换符的数量，大于 0 时显示）
function updateBinaryWarn(badCount) {
    const warnDiv = document.getElementById('binary-warn');
    if (!warnDiv) return;
    if (badCount > 0) {
        warnDiv.textContent = '⚠️ 检测到 ' + badCount + ' 个无法解码的字节（显示为 �）：该数据很可能是二进制（密钥/密文/证书等），不是文本。转字符串和"保存到文件"都会损坏数据，请改用"保存原始字节(.bin)"或 Hex/Base64 格式。';
        warnDiv.style.display = 'block';
    } else {
        warnDiv.textContent = '';
        warnDiv.style.display = 'none';
    }
}

function stringToHex() {
    const input = document.getElementById('string-input').value;
    if (!input) {
        document.getElementById('string-result').textContent = '请输入字符串';
        updateBinaryWarn(0);
        return;
    }
    try {
        // 正向编码不产生"解码字节"语义，清空缓存并隐藏警告，防止旧状态残留被误存
        lastDecodedBytes = null;
        lastDecodedSource = null;
        updateBinaryWarn(0);
        const encoding = getSelectedEncoding();
        let bytes;
        if (encoding === 'utf8') {
            const encoder = new TextEncoder();
            bytes = encoder.encode(input);
        } else {
            bytes = utf8ToGbkBytes(input);
        }
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        document.getElementById('string-result').textContent = hex.toUpperCase();
    } catch (error) {
        lastDecodedBytes = null;
        lastDecodedSource = null;
        updateBinaryWarn(0);
        document.getElementById('string-result').textContent = '转换失败: ' + error.message;
    }
}

function stringToBase64() {
    const input = document.getElementById('string-input').value;
    if (!input) {
        document.getElementById('string-result').textContent = '请输入字符串';
        updateBinaryWarn(0);
        return;
    }
    try {
        // 正向编码不产生"解码字节"语义，清空缓存并隐藏警告，防止旧状态残留被误存
        lastDecodedBytes = null;
        lastDecodedSource = null;
        updateBinaryWarn(0);
        const encoding = getSelectedEncoding();
        let binary;
        if (encoding === 'utf8') {
            // unescape 是已废弃 API，改用 TextEncoder + 分块拼接
            binary = bytesToBinaryString(new TextEncoder().encode(input));
        } else {
            const bytes = utf8ToGbkBytes(input);
            binary = bytesToBinaryString(bytes);
        }
        const base64 = btoa(binary);
        document.getElementById('string-result').textContent = base64;
    } catch (error) {
        lastDecodedBytes = null;
        lastDecodedSource = null;
        updateBinaryWarn(0);
        document.getElementById('string-result').textContent = '转换失败: ' + error.message;
    }
}

function hexToString() {
    const input = document.getElementById('string-input').value.trim();
    if (!input) {
        document.getElementById('string-result').textContent = '请输入Hex内容';
        updateBinaryWarn(0);
        return;
    }
    try {
        const encoding = getSelectedEncoding();
        const cleanHex = input.replace(/\s/g, '');
        if (!/^[0-9a-fA-F]+$/.test(cleanHex)) {
            throw new Error('无效的Hex格式');
        }
        const paddedHex = cleanHex.length % 2 === 0 ? cleanHex : '0' + cleanHex;
        const bytes = new Uint8Array(paddedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        let result;
        if (encoding === 'utf8') {
            const decoder = new TextDecoder();
            result = decoder.decode(bytes);
            // 出现 U+FFFD 替换符说明原始字节不是合法 UTF-8 文本，二进制数据强转文本会不可逆丢失字节，需提示用户
            const badCount = (result.match(/�/g) || []).length;
            updateBinaryWarn(badCount);
        } else {
            result = gbkBytesToUtf8(bytes);
            // GBK 解码不产生 U+FFFD，无法据此判断是否二进制，仅确保警告不残留
            updateBinaryWarn(0);
        }
        // 缓存解码前的原始字节，供"保存原始字节(.bin)"无损保存
        lastDecodedBytes = bytes;
        lastDecodedSource = 'hex';
        document.getElementById('string-result').textContent = result;
    } catch (error) {
        // 转换失败时清空缓存，避免保存到与当前结果不符的旧字节
        lastDecodedBytes = null;
        lastDecodedSource = null;
        updateBinaryWarn(0);
        document.getElementById('string-result').textContent = '转换失败: ' + error.message;
    }
}

function base64ToString() {
    const input = document.getElementById('string-input').value.trim();
    if (!input) {
        document.getElementById('string-result').textContent = '请输入Base64内容';
        updateBinaryWarn(0);
        return;
    }
    try {
        const encoding = getSelectedEncoding();
        const binary = safeAtob(input);
        const bytes = new Uint8Array([...binary].map(char => char.charCodeAt(0)));

        let result;
        if (encoding === 'utf8') {
            const decoder = new TextDecoder();
            result = decoder.decode(bytes);
            // 出现 U+FFFD 替换符说明原始字节不是合法 UTF-8 文本，二进制数据强转文本会不可逆丢失字节，需提示用户
            const badCount = (result.match(/�/g) || []).length;
            updateBinaryWarn(badCount);
        } else {
            result = gbkBytesToUtf8(bytes);
            // GBK 解码不产生 U+FFFD，无法据此判断是否二进制，仅确保警告不残留
            updateBinaryWarn(0);
        }
        // 缓存解码前的原始字节，供"保存原始字节(.bin)"无损保存
        lastDecodedBytes = bytes;
        lastDecodedSource = 'base64';
        document.getElementById('string-result').textContent = result;
    } catch (error) {
        // 转换失败时清空缓存，避免保存到与当前结果不符的旧字节
        lastDecodedBytes = null;
        lastDecodedSource = null;
        updateBinaryWarn(0);
        document.getElementById('string-result').textContent = '转换失败: ' + error.message;
    }
}

// GBK编码支持函数（使用 vendor/gbk.js，支持完整的23940个GBK字符）
function utf8ToGbkBytes(str) {
    // 检查GBK库是否加载
    if (typeof gbk === 'undefined' || !gbk.encode) {
        console.error('⚠️ GBK库未加载，降级到UTF-8编码');
        return new TextEncoder().encode(str);
    }

    try {
        // 使用 gbk.encode 将字符串转换为GBK字节数组
        return gbk.encode(str);
    } catch (error) {
        console.error('GBK编码失败:', error);
        // 降级到UTF-8
        return new TextEncoder().encode(str);
    }
}

function gbkBytesToUtf8(bytes) {
    // 检查GBK库是否加载
    if (typeof gbk === 'undefined' || !gbk.decode) {
        console.error('⚠️ GBK库未加载，降级到UTF-8解码');
        return new TextDecoder().decode(bytes);
    }

    try {
        // 使用 gbk.decode 将GBK字节数组转换为字符串
        return gbk.decode(bytes);
    } catch (error) {
        console.error('GBK解码失败:', error);
        // 降级到UTF-8
        return new TextDecoder().decode(bytes);
    }
}

// 文件保存功能
function saveStringResultToFile() {
    const result = document.getElementById('string-result').textContent;
    if (!result || result === '' || result.includes('转换失败') || result.includes('请输入')) {
        showNotification('没有有效的结果可以保存');
        return;
    }

    try {
        const input = document.getElementById('string-input').value.trim();
        let filename = 'converted_result.txt';
        if (input.length > 0 && input.length <= 10) {
            filename = `converted_${input.replace(/[^\w\u4e00-\u9fa5]/g, '_')}.txt`;
        }

        const blob = new Blob([result], { type: 'text/plain;charset=utf-8' });

        if (window.showSaveFilePicker) {
            window.showSaveFilePicker({
                suggestedName: filename,
                types: [{
                    description: 'Text files',
                    accept: { 'text/plain': ['.txt'] }
                }]
            }).then(fileHandle => {
                return fileHandle.createWritable();
            }).then(writable => {
                return writable.write(blob).then(() => writable.close());
            }).then(() => {
                showNotification('文件已保存');
            }).catch(err => {
                console.error('保存文件失败:', err);
                showNotification('保存失败，请手动复制结果');
            });
        } else {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            showNotification('文件已保存到本地');
        }
    } catch (error) {
        console.error('保存文件失败:', error);
        showNotification('保存失败，请手动复制结果');
    }
}

// 保存最近一次 Hex/Base64 → 字符串 解码得到的原始字节为 .bin 文件
// 业务原因：二进制数据（密钥/密文等）经 TextDecoder 强转文本已产生 U+FFFD 损坏，
// "保存到文件"存下的是损坏文本，只有缓存的原始字节才能无损还原
function saveDecodedBytesToFile() {
    if (!lastDecodedBytes || lastDecodedBytes.length === 0) {
        showNotification('没有可保存的解码字节，请先执行 Hex → 字符串 或 Base64 → 字符串');
        return;
    }

    try {
        const byteCount = lastDecodedBytes.length;
        const blob = new Blob([lastDecodedBytes], { type: 'application/octet-stream' });
        const filename = 'decoded_bytes.bin';

        if (window.showSaveFilePicker) {
            window.showSaveFilePicker({
                suggestedName: filename,
                types: [{
                    description: 'Binary files',
                    accept: { 'application/octet-stream': ['.bin'] }
                }]
            }).then(fileHandle => {
                return fileHandle.createWritable();
            }).then(writable => {
                return writable.write(blob).then(() => writable.close());
            }).then(() => {
                showNotification('文件已保存（' + byteCount + ' 字节）');
            }).catch(err => {
                console.error('保存文件失败:', err);
                showNotification('保存失败，请重试');
            });
        } else {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            showNotification('文件已保存到本地（' + byteCount + ' 字节）');
        }
    } catch (error) {
        console.error('保存文件失败:', error);
        showNotification('保存失败，请重试');
    }
}

// ===================== URL/Unicode/随机字节 =====================
// URL 编解码、Unicode 转义、随机字节生成已从旧版第三个页签拆分为三个独立页面，
// 输入/结果/复制组件与 id 全部沿用，主逻辑无需感知页面划分

// 读取 URL 编码模式（component=encodeURIComponent 参数模式 / uri=encodeURI 整URL模式）
// 业务原因：两种模式保留字符集不同——处理查询参数值必须用参数模式，
// 否则 ?&#= 等分隔符会被原样保留带来歧义；处理完整 URL 则需要整URL模式保留结构
function getUrlMode() {
    const checked = document.querySelector('input[name="url-mode"]:checked');
    return checked ? checked.value : 'component';
}

// URL 编码：按所选模式编码后写入结果区
function urlEncode() {
    const input = document.getElementById('url-input').value;
    if (!input) {
        document.getElementById('url-result').textContent = '请输入内容';
        return;
    }
    try {
        const result = getUrlMode() === 'uri' ? encodeURI(input) : encodeURIComponent(input);
        document.getElementById('url-result').textContent = result;
        // 输入含 ? 时自动解析查询参数，方便核对键值对
        if (input.indexOf('?') !== -1) {
            parseUrlQuery();
        }
    } catch (error) {
        document.getElementById('url-result').textContent = '编码失败: ' + error.message;
    }
}

// URL 解码：非法 % 序列（如 %GG 或被截断的 %E4）会抛 URIError，捕获后给出友好提示
function urlDecode() {
    const input = document.getElementById('url-input').value;
    if (!input) {
        document.getElementById('url-result').textContent = '请输入内容';
        return;
    }
    try {
        const result = getUrlMode() === 'uri' ? decodeURI(input) : decodeURIComponent(input);
        document.getElementById('url-result').textContent = result;
        // 输入含 ? 时自动解析查询参数，方便核对键值对
        if (input.indexOf('?') !== -1) {
            parseUrlQuery();
        }
    } catch (error) {
        document.getElementById('url-result').textContent = '解码失败: ' + error.message;
    }
}

// URL 参数解析（URL 工具页新增）：截取输入中首个 ? 之后的查询串，
// 按 & 与 = 拆分为表格渲染到 url-query-result，
// 三列分别为：参数名（解码后）/ 解码后值 / 原始键值对，便于对照编码前后的差异
function parseUrlQuery() {
    const container = document.getElementById('url-query-result');
    if (!container) return;
    const input = document.getElementById('url-input').value.trim();

    let query = '';
    const qIndex = input.indexOf('?');
    if (qIndex !== -1) {
        query = input.slice(qIndex + 1);
        // 锚点（# 之后的内容）不属于查询串，需剔除
        const hashIndex = query.indexOf('#');
        if (hashIndex !== -1) {
            query = query.slice(0, hashIndex);
        }
    }

    const pairs = query.split('&').filter(pair => pair.length > 0);
    if (!query || pairs.length === 0) {
        container.textContent = 'URL 中未找到查询参数';
        return;
    }

    // 用 DOM API 构建表格，避免手工拼 HTML 引入转义/注入问题
    container.innerHTML = '';

    const table = document.createElement('table');
    table.className = 'query-table';

    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    ['参数名', '解码后值', '原始值'].forEach(title => {
        const th = document.createElement('th');
        th.textContent = title;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    pairs.forEach(pair => {
        // 仅按第一个 = 拆分：参数值本身可能再包含 =（如 Base64 填充）
        const eqIndex = pair.indexOf('=');
        const rawName = eqIndex === -1 ? pair : pair.slice(0, eqIndex);
        const rawValue = eqIndex === -1 ? '' : pair.slice(eqIndex + 1);

        const row = document.createElement('tr');

        const nameCell = document.createElement('td');
        nameCell.textContent = safeDecodeQueryComponent(rawName);
        row.appendChild(nameCell);

        const valueCell = document.createElement('td');
        // 只有键没有值的参数（flag 型，如 ?debug）解码后值标记为"（无值）"
        valueCell.textContent = eqIndex === -1 ? '（无值）' : safeDecodeQueryComponent(rawValue);
        row.appendChild(valueCell);

        const rawCell = document.createElement('td');
        rawCell.textContent = pair;
        row.appendChild(rawCell);

        tbody.appendChild(row);
    });
    table.appendChild(tbody);

    container.appendChild(table);
}

// 解码单个查询组件：非法 % 序列（如 %GG）解码会抛 URIError，失败时回退显示原文
function safeDecodeQueryComponent(str) {
    try {
        return decodeURIComponent(str.replace(/\+/g, '%20'));
    } catch (e) {
        return str;
    }
}

// 字符串 → \uXXXX：逐个 UTF-16 码单元转为 4 位十六进制小写（不足 4 位补零）
// ASCII 可见字符也统一转换，牺牲少量可读性换取规则简单一致，便于程序间比对；
// 码单元级转换使 emoji 等增补平面字符输出为两个连续的代理对，天然可被下方解码函数还原
function stringToUnicode() {
    const input = document.getElementById('unicode-input').value;
    if (!input) {
        document.getElementById('unicode-result').textContent = '请输入内容';
        return;
    }
    let result = '';
    for (let i = 0; i < input.length; i++) {
        result += '\\u' + input.charCodeAt(i).toString(16).padStart(4, '0');
    }
    document.getElementById('unicode-result').textContent = result;
}

// \uXXXX → 字符串：正则匹配 4 位十六进制转义逐个还原
function unicodeToString() {
    const input = document.getElementById('unicode-input').value;
    if (!input) {
        document.getElementById('unicode-result').textContent = '请输入内容';
        return;
    }
    // 完全没有匹配时明确提示，避免原样输出让用户误以为转换未生效
    if (!/\\u[0-9a-fA-F]{4}/.test(input)) {
        document.getElementById('unicode-result').textContent = '未找到 \\uXXXX 转义序列';
        return;
    }
    const result = input.replace(/\\u[0-9a-fA-F]{4}/g, match => String.fromCharCode(parseInt(match.slice(2), 16)));
    document.getElementById('unicode-result').textContent = result;
}

// 随机字节生成：生成密钥/盐/IV 等场景使用，底层走 Web Crypto 保证密码学安全
function generateRandomBytes() {
    const lengthInput = document.getElementById('random-length').value;
    const length = parseInt(lengthInput, 10);
    // 空/非数字/非正数/超上限均视为非法：上限 1MB 防止误填大数值导致页面卡死
    if (!lengthInput || isNaN(length) || length <= 0 || length > 1048576) {
        showNotification('请输入 1 ~ 1048576 之间的字节长度');
        return;
    }
    const bytes = new Uint8Array(length);
    // crypto.getRandomValues 单次调用上限 65536 字节，超过时必须分批循环填充
    const MAX_BATCH = 65536;
    for (let offset = 0; offset < length; offset += MAX_BATCH) {
        crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + MAX_BATCH, length)));
    }
    // 同时输出 Hex（大写）与 Base64 两种最常用格式，配合复制按钮按需取用
    const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const base64 = btoa(bytesToBinaryString(bytes));
    document.getElementById('random-result').textContent = 'Hex: ' + hex + '\nBase64: ' + base64;
    showNotification('已生成 ' + length + ' 字节');
}

// 清空 URL/Unicode/随机字节三个页面的全部输入与结果；随机长度恢复默认值 32
// （三个页面已拆分但清空按钮沿用旧函数，所引用的 id 均仍存在，行为与旧版一致）
function clearUrlUnicodeArea() {
    document.getElementById('url-input').value = '';
    document.getElementById('unicode-input').value = '';
    document.getElementById('random-length').value = '32';
    document.getElementById('url-result').textContent = '';
    document.getElementById('unicode-result').textContent = '';
    document.getElementById('random-result').textContent = '';
}

// ===================== 文件工具功能 =====================
// 全局状态：当前选中的文件 + 最近一次文件转换的完整结果
// 业务原因：大文件转换结果可达数百万字符，界面只展示前 10 万字符，
// 完整结果必须单独缓存，"下载完整结果"才有数据可下
let selectedFile = null;
let fileConvertFullResult = '';
// 记录当前转换结果的格式（'base64' 或 'hex'），下载时据此决定文件扩展名
let fileConvertFormat = 'base64';

// 将字节数格式化为人类可读的大小（自动选择 B/KB/MB/GB 单位）
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let index = 0;
    let size = bytes;
    while (size >= 1024 && index < units.length - 1) {
        size /= 1024;
        index++;
    }
    // B 取整数，其余单位保留 2 位小数
    return (index === 0 ? size : size.toFixed(2)) + ' ' + units[index];
}

// 处理文件选择（点击选择和拖拽两种方式均走此入口）
function handleFileSelect(file) {
    if (!file) return;
    selectedFile = file;
    // 大于 50MB 的文件读取与哈希计算耗时明显，提前在信息区提示用户
    const sizeTip = file.size > 50 * 1024 * 1024 ? '（文件较大，计算可能需要数秒）' : '';
    document.getElementById('file-info').textContent =
        '文件名: ' + file.name + ' | 大小: ' + formatFileSize(file.size) +
        ' | 类型: ' + (file.type || '未知') + sizeTip;
    // 切换文件后旧哈希与转换结果已失效，全部重置避免误读
    setAllFileHashResults('-');
    document.getElementById('file-convert-result').textContent = '';
    fileConvertFullResult = '';
}

// 批量设置 10 个文件哈希结果框的占位文本（计算中/失败/重置）
function setAllFileHashResults(value) {
    const ids = ['file-md5-hex','file-md5-base64','file-sha1-hex','file-sha1-base64','file-sha256-hex','file-sha256-base64','file-sha512-hex','file-sha512-base64','file-sm3-hex','file-sm3-base64'];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    });
}

// 读取文件为 ArrayBuffer：Promise 封装 FileReader，便于 async/await 串联
function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error || new Error('文件读取失败'));
        reader.readAsArrayBuffer(file);
    });
}

// 对完整文件字节计算五种哈希（与文本页面对相同字节计算走同一套算法，结果天然一致）
async function calculateFileHashes() {
    if (!selectedFile) {
        showNotification('请先选择文件');
        return;
    }
    setAllFileHashResults('计算中...');
    try {
        const buffer = await readFileAsArrayBuffer(selectedFile);
        const data = new Uint8Array(buffer);

        // MD5 使用 CryptoJS（同步，字节包装为 WordArray，与文本页面同一代码路径）
        const md5Word = CryptoJS.MD5(CryptoJS.lib.WordArray.create(data));

        // SHA 系列使用 Web Crypto
        const [sha1Buf, sha256Buf, sha512Buf] = await Promise.all([
            window.crypto.subtle.digest('SHA-1', data),
            window.crypto.subtle.digest('SHA-256', data),
            window.crypto.subtle.digest('SHA-512', data)
        ]);

        const sha1Out = formatHashOutputs(sha1Buf);
        const sha256Out = formatHashOutputs(sha256Buf);
        const sha512Out = formatHashOutputs(sha512Buf);

        // SM3 内嵌实现返回 hex，再转 Base64
        const sm3Hex = window.sm3Hash(data);
        const sm3Bytes = [];
        for (let i = 0; i < sm3Hex.length; i += 2) sm3Bytes.push(parseInt(sm3Hex.substr(i, 2), 16));
        const sm3Base64 = btoa(bytesToBinaryString(sm3Bytes));

        // 填充到页面（分别写入 hex 与 base64 到两个框）
        document.getElementById('file-md5-hex').textContent = md5Word.toString(CryptoJS.enc.Hex);
        document.getElementById('file-md5-base64').textContent = md5Word.toString(CryptoJS.enc.Base64);

        document.getElementById('file-sha1-hex').textContent = sha1Out.hex;
        document.getElementById('file-sha1-base64').textContent = sha1Out.base64;

        document.getElementById('file-sha256-hex').textContent = sha256Out.hex;
        document.getElementById('file-sha256-base64').textContent = sha256Out.base64;

        document.getElementById('file-sha512-hex').textContent = sha512Out.hex;
        document.getElementById('file-sha512-base64').textContent = sha512Out.base64;

        document.getElementById('file-sm3-hex').textContent = sm3Hex;
        document.getElementById('file-sm3-base64').textContent = sm3Base64;

    } catch (error) {
        console.error('文件哈希计算错误:', error);
        setAllFileHashResults('计算失败: ' + error.message);
    }
}

// 展示文件转换结果：超过 10 万字符只在界面显示前 10 万字符并追加截断说明，
// 完整内容仍保留在 fileConvertFullResult 供下载
function displayFileConvertResult(text) {
    const MAX_DISPLAY = 100000;
    const el = document.getElementById('file-convert-result');
    if (text.length > MAX_DISPLAY) {
        el.textContent = text.slice(0, MAX_DISPLAY) + '\n...(结果过大已截断显示，请点击"下载完整结果"获取全部)';
    } else {
        el.textContent = text;
    }
}

// 文件 → Base64：整个文件字节编码为 Base64（Data URI、文件传输场景常用）
async function convertFileToBase64() {
    if (!selectedFile) {
        showNotification('请先选择文件');
        return;
    }
    try {
        document.getElementById('file-convert-result').textContent = '转换中...';
        const buffer = await readFileAsArrayBuffer(selectedFile);
        // bytesToBinaryString 内部分块拼接，避免大文件一次性展开爆栈
        const base64 = btoa(bytesToBinaryString(new Uint8Array(buffer)));
        fileConvertFormat = 'base64';
        fileConvertFullResult = base64;
        displayFileConvertResult(base64);
    } catch (error) {
        console.error('文件转Base64失败:', error);
        fileConvertFullResult = '';
        document.getElementById('file-convert-result').textContent = '转换失败: ' + error.message;
    }
}

// 文件 → Hex（大写）：分块拼接控制内存峰值，大文件逐字节 map+join 会产生超大临时数组
async function convertFileToHex() {
    if (!selectedFile) {
        showNotification('请先选择文件');
        return;
    }
    try {
        document.getElementById('file-convert-result').textContent = '转换中...';
        const buffer = await readFileAsArrayBuffer(selectedFile);
        const bytes = new Uint8Array(buffer);
        let hex = '';
        const CHUNK_SIZE = 0x8000;
        for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
            let part = '';
            const end = Math.min(i + CHUNK_SIZE, bytes.length);
            for (let j = i; j < end; j++) {
                part += bytes[j].toString(16).padStart(2, '0');
            }
            hex += part.toUpperCase();
        }
        fileConvertFormat = 'hex';
        fileConvertFullResult = hex;
        displayFileConvertResult(hex);
    } catch (error) {
        console.error('文件转Hex失败:', error);
        fileConvertFullResult = '';
        document.getElementById('file-convert-result').textContent = '转换失败: ' + error.message;
    }
}

// 下载完整的转换结果（界面截断时获取全部内容的唯一途径）
function downloadFileConvertResult() {
    if (!fileConvertFullResult) {
        showNotification('没有可下载的结果，请先执行 文件 → Base64 或 文件 → Hex');
        return;
    }
    try {
        // 按当前格式决定扩展名：文件名.base64.txt / 文件名.hex.txt
        const ext = fileConvertFormat === 'hex' ? '.hex.txt' : '.base64.txt';
        const filename = (selectedFile ? selectedFile.name : 'file') + ext;
        const blob = new Blob([fileConvertFullResult], { type: 'text/plain;charset=utf-8' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        showNotification('完整结果已开始下载');
    } catch (error) {
        console.error('下载结果失败:', error);
        showNotification('下载失败，请重试');
    }
}

// 清空文件工具区域：释放文件引用并复位所有展示
function clearFileArea() {
    selectedFile = null;
    fileConvertFullResult = '';
    document.getElementById('file-input').value = '';
    document.getElementById('file-info').textContent = '';
    document.getElementById('file-convert-result').textContent = '';
    setAllFileHashResults('-');
}

// 文件工具事件绑定（DOM 加载完成后绑定，确保元素已就绪）
document.addEventListener('DOMContentLoaded', function() {
    const dropZone = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');

    // 点击拖拽区弹出文件选择框
    dropZone.addEventListener('click', function(event) {
        // input.click() 派发的 click 事件会冒泡回拖拽区，
        // 不拦截会再次触发本处理器造成无限递归
        if (event.target === fileInput) return;
        fileInput.click();
    });

    // 拖拽悬停高亮（dragover 必须 preventDefault，否则浏览器直接打开文件）
    dropZone.addEventListener('dragover', function(event) {
        event.preventDefault();
        dropZone.classList.add('dragover');
    });

    // 拖拽离开时取消高亮
    dropZone.addEventListener('dragleave', function(event) {
        event.preventDefault();
        dropZone.classList.remove('dragover');
    });

    // 释放文件完成选择
    dropZone.addEventListener('drop', function(event) {
        event.preventDefault();
        dropZone.classList.remove('dragover');
        const files = event.dataTransfer && event.dataTransfer.files;
        if (files && files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    // 点击方式选择文件
    fileInput.addEventListener('change', function() {
        if (fileInput.files && fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });
});

// 哈希计算函数
function getSelectedHashEncoding() {
    return document.querySelector('input[name="hash-encoding"]:checked').value;
}

function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function formatHashOutputs(hashBuffer) {
    return {
        hex: arrayBufferToHex(hashBuffer),
        base64: arrayBufferToBase64(hashBuffer)
    };
}

// 获取选择的输入格式
function getSelectedHashInputFormat() {
    const radios = document.getElementsByName('hash-input-format');
    for (let radio of radios) {
        if (radio.checked) return radio.value;
    }
    return 'text'; // 默认文本
}

async function calculateAllHashes() {
    const input = document.getElementById('hash-input').value;
    if (!input) {
        setAllHashResults('请输入内容');
        return;
    }

    const inputFormat = getSelectedHashInputFormat();
    const encoding = getSelectedHashEncoding();
    let data;

    try {
        // 根据输入格式解析数据
        if (inputFormat === 'hex') {
            // Hex格式：去除空格和非十六进制字符，然后转换
            const hexStr = input.replace(/[^0-9A-Fa-f]/g, '');
            if (hexStr.length % 2 !== 0) {
                setAllHashResults('Hex格式错误：长度必须是偶数');
                return;
            }
            const bytes = [];
            for (let i = 0; i < hexStr.length; i += 2) {
                bytes.push(parseInt(hexStr.substr(i, 2), 16));
            }
            data = new Uint8Array(bytes);

        } else if (inputFormat === 'base64') {
            // Base64格式：使用atob解码
            try {
                const binaryString = safeAtob(input);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                data = bytes;
            } catch (e) {
                setAllHashResults('Base64格式错误');
                return;
            }

        } else {
            // 文本格式：根据编码（UTF-8或GBK）转换
            if (encoding === 'utf8') {
                const encoder = new TextEncoder();
                data = encoder.encode(input);
            } else {
                data = utf8ToGbkBytes(input);
            }
        }

        // 显示计算中占位
        setAllHashResults('计算中...');

        // MD5 使用 CryptoJS（同步）
        const md5Word = CryptoJS.MD5(CryptoJS.lib.WordArray.create(data));
        const md5Hex = md5Word.toString(CryptoJS.enc.Hex);
        const md5Base64 = md5Word.toString(CryptoJS.enc.Base64);

        // SHA 系列使用 Web Crypto
        const [sha1Buf, sha256Buf, sha512Buf] = await Promise.all([
            window.crypto.subtle.digest('SHA-1', data),
            window.crypto.subtle.digest('SHA-256', data),
            window.crypto.subtle.digest('SHA-512', data)
        ]);

        const sha1Out = formatHashOutputs(sha1Buf);
        const sha256Out = formatHashOutputs(sha256Buf);
        const sha512Out = formatHashOutputs(sha512Buf);

        // SM3（vendor 实现，返回 hex）
        const sm3Hex = window.sm3Hash(data);
        // hex -> base64
        const sm3Bytes = [];
        for (let i = 0; i < sm3Hex.length; i += 2) sm3Bytes.push(parseInt(sm3Hex.substr(i, 2), 16));
        const sm3Base64 = btoa(bytesToBinaryString(sm3Bytes));

        // 填充到页面（分别写入 hex 与 base64 到两个框）
        document.getElementById('md5-hex').textContent = md5Hex;
        document.getElementById('md5-base64').textContent = md5Base64;

        document.getElementById('sha1-hex').textContent = sha1Out.hex;
        document.getElementById('sha1-base64').textContent = sha1Out.base64;

        document.getElementById('sha256-hex').textContent = sha256Out.hex;
        document.getElementById('sha256-base64').textContent = sha256Out.base64;

        document.getElementById('sha512-hex').textContent = sha512Out.hex;
        document.getElementById('sha512-base64').textContent = sha512Out.base64;

        document.getElementById('sm3-hex').textContent = sm3Hex;
        document.getElementById('sm3-base64').textContent = sm3Base64;

    } catch (error) {
        console.error('哈希计算错误:', error);
        setAllHashResults('计算失败: ' + error.message);
    }
}

// 保留兼容函数（如需单项调用）
function calculateMD5Both(data) {
    try {
        const wordArray = CryptoJS.lib.WordArray.create(data);
        const hashObj = CryptoJS.MD5(wordArray);
        return {
            hex: hashObj.toString(CryptoJS.enc.Hex),
            base64: hashObj.toString(CryptoJS.enc.Base64)
        };
    } catch (error) {
        console.error('MD5 calculation failed:', error);
        return {hex: 'MD5计算失败', base64: 'MD5计算失败'};
    }
}

function setAllHashResults(value) {
    const ids = ['md5-hex','md5-base64','sha1-hex','sha1-base64','sha256-hex','sha256-base64','sha512-hex','sha512-base64','sm3-hex','sm3-base64'];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    });
}

function clearHashArea() {
    document.getElementById('hash-input').value = '';
    setAllHashResults('-');
}

// 切换哈希输入格式时的处理
function toggleHashEncodingSelector() {
    const inputFormat = getSelectedHashInputFormat();
    const encodingSelector = document.getElementById('hash-text-encoding-selector');

    // 当输入格式为Hex或Base64时，隐藏文本编码选择器
    if (inputFormat === 'hex' || inputFormat === 'base64') {
        encodingSelector.style.display = 'none';
    } else {
        encodingSelector.style.display = 'flex';
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    if (!window.crypto || !window.crypto.subtle) {
        alert('您的浏览器不支持Web Crypto API，某些功能可能无法正常工作');
    }

    // 检测并测试GBK编码库
    if (typeof gbk === 'undefined' || !gbk.encode) {
        console.error('❌ GBK库未加载，GBK编码功能将降级为UTF-8');
        setTimeout(() => {
            showNotification('警告：GBK编码库未加载');
        }, 1000);
    } else {
        // 测试GBK编码功能
        try {
            const testStr = '中国人';
            const gbkBytes = utf8ToGbkBytes(testStr);
            const hexStr = Array.from(gbkBytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');

            console.log('=== GBK编码测试 ===');
            console.log('✓ 编码测试:', testStr, '→', hexStr);
            console.log('  预期编码: "中"=D6 D0, "国"=B9 FA, "人"=C8 CB');

            // 测试解码
            const decoded = gbkBytesToUtf8(gbkBytes);
            console.log('✓ 解码测试:', hexStr, '→', decoded);

            if (decoded === testStr && hexStr === 'D6 D0 B9 FA C8 CB') {
                console.log('🎉 GBK编解码测试全部通过！(支持23940个GBK字符)');
                showNotification('✓ GBK编码已就绪 (完整支持)');
            } else {
                console.warn('⚠️ GBK测试失败:', '期望"' + testStr + '"，得到"' + decoded + '"');
                showNotification('⚠️ GBK编码可能有问题');
            }
        } catch (e) {
            console.error('❌ GBK编码测试失败:', e);
            showNotification('GBK编码测试失败');
        }
    }

    setAllHashResults('-');

    // 为哈希输入格式选择器添加事件监听
    const hashInputFormatRadios = document.getElementsByName('hash-input-format');
    for (let radio of hashInputFormatRadios) {
        radio.addEventListener('change', toggleHashEncodingSelector);
    }

    // 初始化显示状态
    toggleHashEncodingSelector();
});
