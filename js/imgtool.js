// ============================================================
// 增强版编解码工具 - 图片 Base64 页（page-image）
// 功能：
//   1. 图片 → Base64：拖拽/点击选择图片，预览并按
//      Data URI / 纯 Base64 两种格式输出，附 CSS/HTML 用法示例
//   2. Base64 → 图片：粘贴/输入 Base64 或 Data URI，
//      预览（宽高/大小/格式）并按 mime 扩展名下载
// 依赖（须先于本文件加载）：
//   js/app.js → showNotification / copyTextToClipboard /
//               safeAtob / bytesToBinaryString
// 说明：超长结果（>10 万字符）界面截断显示，完整内容缓存在
//       全局变量中供"复制完整结果"使用（与文件工具页同模式）
// ============================================================

// ---------- 全局状态 ----------
// 当前选中的图片文件 + FileReader 读出的完整 Data URI + 当前模式完整结果
var imgSelectedFile = null;   // 图片 → Base64：当前选中的文件
var imgDataUri = '';          // 图片 → Base64：readAsDataURL 读出的完整 Data URI
var imgMime = 'image/png';    // 图片 → Base64：图片 MIME 类型
var imgFullBase64 = '';       // 图片 → Base64：当前模式下未截断的完整结果（供复制）
// Base64 → 图片：最近一次预览成功的解析结果（供下载按钮使用）
var imgB64DataUri = '';       // 预览图片的 Data URI
var imgB64Bytes = null;       // 解码出的原始字节（Uint8Array）
var imgB64Mime = 'image/png'; // 解析出的 MIME 类型

// 结果区最大显示字符数：超过则截断显示（与文件工具页的 10 万上限一致）
var IMG_MAX_DISPLAY = 100000;

// ---------- 通用小工具 ----------

// 字节数格式化为人类可读大小（B/KB/MB/GB，与文件工具页 formatFileSize 同风格）
function imgFormatSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB'];
    var index = 0;
    var size = bytes;
    while (size >= 1024 && index < units.length - 1) {
        size /= 1024;
        index++;
    }
    return (index === 0 ? size : size.toFixed(2)) + ' ' + units[index];
}

// MIME → 界面格式名称（PNG/JPEG/GIF/WebP/SVG）
function imgMimeLabel(mime) {
    var labels = {
        'image/png': 'PNG',
        'image/jpeg': 'JPEG',
        'image/gif': 'GIF',
        'image/webp': 'WebP',
        'image/svg+xml': 'SVG'
    };
    return labels[mime] || mime;
}

// MIME → 下载文件扩展名（png/jpeg/gif/webp/svg）
function imgExtFromMime(mime) {
    var exts = {
        'image/png': 'png',
        'image/jpeg': 'jpeg',
        'image/gif': 'gif',
        'image/webp': 'webp',
        'image/svg+xml': 'svg'
    };
    return exts[mime] || 'png';
}

// 从解码字节中嗅探真实图片类型（纯 Base64 输入没有 mime 前缀时使用）
// 返回 mime 字符串，无法识别时返回 null
function imgSniffMime(bytes) {
    if (bytes.length < 4) return null;
    // PNG: 89 50 4E 47
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'image/png';
    // JPEG: FF D8 FF
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'image/jpeg';
    // GIF: "GIF8"
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return 'image/gif';
    // WebP: "RIFF"...."WEBP"
    if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
        bytes.length > 12 && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'image/webp';
    // SVG（文本以 < 开头，如 <svg / <?xml）
    if (bytes[0] === 0x3C) return 'image/svg+xml';
    return null;
}

// 从 Data URI 中提取字节（safeAtob 已内置去空白与 Base64URL 兼容）
function imgBytesFromDataUri(dataUri) {
    var commaIdx = dataUri.indexOf(',');
    var payload = commaIdx === -1 ? dataUri : dataUri.slice(commaIdx + 1);
    var binary = safeAtob(payload);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// 截断长文本用于示例代码展示（超出部分以 ... 代替）
function imgTruncateForHint(text, max) {
    return text.length > max ? text.slice(0, max) + '...' : text;
}

// ---------- Section 1：图片 → Base64 ----------

// 读取当前输出格式单选（data-uri = 含前缀 / raw = 纯 Base64）
function imgGetMode() {
    var checked = document.querySelector('input[name="img-b64-mode"]:checked');
    return checked ? checked.value : 'data-uri';
}

// 处理图片文件选择（点击选择和拖拽两种方式均走此入口）：
// 校验类型 → 显示文件信息 → readAsDataURL → 预览 + 自动转换
function imgHandleFile(file) {
    if (!file) return;
    // 文件工具页的 accept 已限定 image/*，此处再兜底校验类型
    if (file.type && file.type.indexOf('image/') !== 0) {
        showNotification('请选择图片文件（PNG/JPEG/GIF/WebP/SVG 等）');
        return;
    }
    imgSelectedFile = file;
    // 先展示文件名/大小/类型信息
    document.getElementById('img-info').textContent =
        '文件名: ' + file.name + ' | 大小: ' + imgFormatSize(file.size) +
        ' | 类型: ' + (file.type || '未知');
    // 切换文件后旧结果已失效，先复位
    imgDataUri = '';
    imgFullBase64 = '';
    document.getElementById('img-b64-result').textContent = '读取中...';

    var reader = new FileReader();
    reader.onload = function (e) {
        imgDataUri = e.target.result;
        // readAsDataURL 的前缀自带 mime；文件无类型时从 Data URI 头部兜底解析
        imgMime = file.type || (imgDataUri.slice(0, 30).match(/^data:([^;,]+)/) || [])[1] || 'image/png';
        imgUpdatePreview(imgDataUri);
        imgConvertToBase64();
    };
    reader.onerror = function () {
        imgDataUri = '';
        imgFullBase64 = '';
        document.getElementById('img-b64-result').textContent = '读取文件失败';
        showNotification('读取文件失败');
    };
    reader.readAsDataURL(file);
}

// 更新 Section 1 预览：用独立 Image 对象 onload 取 naturalWidth/Height，
// 再把 Data URI 赋给页面上的预览 <img>（预览图与宽高测量互不影响）
function imgUpdatePreview(dataUri) {
    var preview = document.getElementById('img-preview');
    var dimension = document.getElementById('img-dimension');
    if (!preview || !dimension) return;
    preview.src = dataUri;
    preview.style.display = '';
    dimension.textContent = '尺寸测量中...';
    var probe = new Image();
    probe.onload = function () {
        dimension.textContent = '宽 × 高：' + probe.naturalWidth + ' × ' + probe.naturalHeight + ' 像素';
    };
    probe.onerror = function () {
        dimension.textContent = '图片预览加载失败';
    };
    probe.src = dataUri;
}

// 按当前模式渲染 Base64 结果（文件读取完成或切换模式时调用）：
// 完整结果缓存到 imgFullBase64，界面超过 10 万字符截断显示
function imgConvertToBase64() {
    var el = document.getElementById('img-b64-result');
    if (!imgDataUri) {
        el.textContent = '请先选择图片';
        return;
    }
    var mode = imgGetMode();
    // raw 模式去掉 "data:image/xxx;base64," 前缀，只留 Base64 本体
    var full = mode === 'raw' ? imgDataUri.slice(imgDataUri.indexOf(',') + 1) : imgDataUri;
    imgFullBase64 = full;
    if (full.length > IMG_MAX_DISPLAY) {
        el.textContent = full.slice(0, IMG_MAX_DISPLAY) +
            '\n...(结果过大已截断显示，请点击"复制完整结果"获取全部 ' + full.length + ' 字符)';
    } else {
        el.textContent = full;
    }
    imgUpdateCssHint(mode);
}

// 根据所选模式生成 CSS / HTML 用法示例（长串截断为可读形式）
function imgUpdateCssHint(mode) {
    var hint = document.getElementById('img-css-hint');
    if (!hint) return;
    if (!imgDataUri) {
        hint.textContent = '选择图片并转换后，此处按所选格式显示可直接复制使用的示例代码';
        return;
    }
    if (mode === 'data-uri') {
        // Data URI 可直接用于 CSS 背景
        hint.textContent =
            '/* CSS 背景用法（结果已含前缀，可直接拼接） */\n' +
            'background-image: url("' + imgTruncateForHint(imgDataUri, 80) + '");';
    } else {
        // 纯 Base64 需自行补上 data 前缀才能作为图片地址使用
        var raw = imgDataUri.slice(imgDataUri.indexOf(',') + 1);
        hint.textContent =
            '<!-- HTML 用法（纯 Base64 需补 data 前缀） -->\n' +
            '<img src="data:' + imgMime + ';base64,' + imgTruncateForHint(raw, 60) + '">';
    }
}

// "复制完整结果"按钮：复制未截断的全文（与界面截断显示互补）
function imgCopyFullResult() {
    if (!imgFullBase64) {
        showNotification('没有可复制的结果，请先选择图片');
        return;
    }
    copyTextToClipboard(imgFullBase64);
}

// ---------- Section 2：Base64 → 图片 ----------

// 解析输入文本（纯 Base64 / Data URI 两种形式）：
// 返回 { mime, bytes, dataUri }；解析失败抛出异常，由调用方统一提示
function imgParseBase64Input(text) {
    var input = text.trim();
    if (!input) {
        throw new Error('empty');
    }

    // 形式一：Data URI（data:image/png;base64,xxxx 或内联 SVG 等非 base64 形式）
    if (input.slice(0, 5).toLowerCase() === 'data:') {
        var commaIdx = input.indexOf(',');
        if (commaIdx === -1) {
            throw new Error('invalid');
        }
        var header = input.slice(5, commaIdx);
        // 头部形如 image/png、image/png;base64、image/svg+xml;charset=utf-8
        var mime = (header.split(';')[0] || '').trim().toLowerCase();
        if (mime.indexOf('image/') !== 0) {
            throw new Error('not image');
        }
        var payload = input.slice(commaIdx + 1).trim();
        if (header.toLowerCase().indexOf('base64') !== -1) {
            // base64 形式：先做字符集校验（空串或含非法字符直接判无效），
            // 再解码为字节（safeAtob 内部已去空白），并按字节嗅探校正 mime
            var cleanPayload = payload.replace(/\s/g, '');
            if (!cleanPayload || !/^[A-Za-z0-9+/=]+$/.test(cleanPayload)) {
                throw new Error('invalid');
            }
            var binary = safeAtob(cleanPayload);
            var bytes = new Uint8Array(binary.length);
            for (var i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            var sniffed = imgSniffMime(bytes);
            if (sniffed && sniffed !== mime) {
                mime = sniffed;
            }
            return { mime: mime, bytes: bytes, dataUri: 'data:' + mime + ';base64,' + payload.replace(/\s/g, '') };
        }
        // 非 base64 的 Data URI（如 url 编码的内联 SVG）：解码文本后按 UTF-8 字节透传
        var svgText;
        try {
            svgText = decodeURIComponent(payload);
        } catch (e) {
            svgText = payload;
        }
        var textBytes = new TextEncoder().encode(svgText);
        return { mime: mime, bytes: textBytes, dataUri: input };
    }

    // 形式二：纯 Base64 字符串 → 先做字符集校验再解码，按魔数嗅探类型（默认 image/png）
    var cleanRaw = input.replace(/\s/g, '');
    if (!cleanRaw || !/^[A-Za-z0-9+/=]+$/.test(cleanRaw)) {
        throw new Error('invalid');
    }
    var rawBinary = safeAtob(cleanRaw);
    var rawBytes = new Uint8Array(rawBinary.length);
    for (var j = 0; j < rawBinary.length; j++) {
        rawBytes[j] = rawBinary.charCodeAt(j);
    }
    var rawMime = imgSniffMime(rawBytes) || 'image/png';
    return { mime: rawMime, bytes: rawBytes, dataUri: 'data:' + rawMime + ';base64,' + input.replace(/\s/g, '') };
}

// "预览图片"按钮：解析输入 → 构造 Data URI 赋给预览 <img>，
// onload 后显示宽高；解析失败或渲染失败统一提示
function imgPreviewFromBase64() {
    var inputEl = document.getElementById('img-b64-input');
    var preview = document.getElementById('img-b64-preview');
    var dimension = document.getElementById('img-b64-dimension');
    var text = inputEl.value;

    // 每次预览先复位旧状态，防止下载到与当前输入不符的旧图
    imgB64DataUri = '';
    imgB64Bytes = null;
    imgB64Mime = 'image/png';
    preview.style.display = 'none';
    preview.removeAttribute('src');

    if (!text.trim()) {
        dimension.textContent = '';
        showNotification('请先输入 Base64 或 Data URI 内容');
        return;
    }

    var parsed;
    try {
        parsed = imgParseBase64Input(text);
    } catch (e) {
        dimension.textContent = '❌ Base64 无效或不是受支持的图片格式';
        showNotification('Base64 无效或不是受支持的图片格式');
        return;
    }

    imgB64DataUri = parsed.dataUri;
    imgB64Bytes = parsed.bytes;
    imgB64Mime = parsed.mime;

    // 先渲染失败占位，onload 成功后覆盖为尺寸信息
    dimension.textContent = '解析成功：' + imgMimeLabel(parsed.mime) + ' / ' + imgFormatSize(parsed.bytes.length) + '，加载预览中...';

    var probe = new Image();
    probe.onload = function () {
        preview.src = parsed.dataUri;
        preview.style.display = '';
        dimension.textContent = '宽 × 高：' + probe.naturalWidth + ' × ' + probe.naturalHeight +
            ' 像素 | 大小：' + imgFormatSize(parsed.bytes.length) +
            ' | 格式：' + imgMimeLabel(parsed.mime);
    };
    probe.onerror = function () {
        // 解码成功但浏览器无法渲染（字节不是有效图片）
        imgB64DataUri = '';
        imgB64Bytes = null;
        dimension.textContent = '❌ Base64 无效或不是受支持的图片格式';
        showNotification('Base64 无效或不是受支持的图片格式');
    };
    probe.src = parsed.dataUri;
}

// 页面级粘贴处理：剪贴板是图片文件时读取并直接预览（同时填入输入框），
// 是文本且焦点不在输入类元素上时填入 Base64 输入框；仅在图片页激活时生效
function imgOnPaste(event) {
    var page = document.getElementById('page-image');
    if (!page || !page.classList.contains('active')) return;
    var clipboard = event.clipboardData;
    if (!clipboard) return;

    // 1) 优先检查剪贴板中的图片文件（截图 Ctrl+V 场景）
    var items = clipboard.items || [];
    for (var i = 0; i < items.length; i++) {
        if (items[i].kind === 'file' && items[i].type.indexOf('image/') === 0) {
            var file = items[i].getAsFile();
            if (file) {
                event.preventDefault();
                imgLoadPastedImage(file);
            }
            return;
        }
    }

    // 2) 文本：焦点已在输入框/文本域内时保持默认粘贴行为，否则填入 Base64 输入框
    var text = clipboard.getData('text');
    if (text) {
        var tag = event.target && event.target.tagName;
        if (tag === 'TEXTAREA' || tag === 'INPUT') return;
        event.preventDefault();
        document.getElementById('img-b64-input').value = text;
        showNotification('已填入 Base64 输入框');
    }
}

// 读取粘贴的图片文件：转 Data URI 后直接预览（Section 2 流程），
// 并回填输入框，便于后续复制/下载
function imgLoadPastedImage(file) {
    var reader = new FileReader();
    reader.onload = function (e) {
        var dataUri = e.target.result;
        document.getElementById('img-b64-input').value = dataUri;
        imgB64DataUri = dataUri;
        imgB64Mime = file.type || (imgSniffMime(imgBytesFromDataUri(dataUri)) || 'image/png');
        imgB64Bytes = imgBytesFromDataUri(dataUri);

        var preview = document.getElementById('img-b64-preview');
        var dimension = document.getElementById('img-b64-dimension');
        preview.src = dataUri;
        preview.style.display = '';
        var probe = new Image();
        probe.onload = function () {
            dimension.textContent = '宽 × 高：' + probe.naturalWidth + ' × ' + probe.naturalHeight +
                ' 像素 | 大小：' + imgFormatSize(file.size) +
                ' | 格式：' + imgMimeLabel(imgB64Mime);
        };
        probe.onerror = function () {
            dimension.textContent = '❌ 剪贴板图片加载失败';
        };
        probe.src = dataUri;
        showNotification('已从剪贴板粘贴图片并预览');
    };
    reader.onerror = function () {
        showNotification('读取剪贴板图片失败');
    };
    reader.readAsDataURL(file);
}

// "下载图片"按钮：按最近一次预览成功的字节构造 Blob 下载，
// 文件名 image.<mime 对应扩展名>（png/jpeg/gif/webp/svg）
function imgDownloadImage() {
    if (!imgB64Bytes || !imgB64DataUri) {
        showNotification('请先预览出有效图片再下载');
        return;
    }
    try {
        var blob = new Blob([imgB64Bytes], { type: imgB64Mime });
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'image.' + imgExtFromMime(imgB64Mime);
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        showNotification('图片已开始下载（' + imgMimeLabel(imgB64Mime) + '）');
    } catch (error) {
        console.error('下载图片失败:', error);
        showNotification('下载失败，请重试');
    }
}

// "清空"按钮：复位 Section 2 的输入、预览与下载缓存
function imgClear() {
    imgB64DataUri = '';
    imgB64Bytes = null;
    imgB64Mime = 'image/png';
    document.getElementById('img-b64-input').value = '';
    var preview = document.getElementById('img-b64-preview');
    preview.style.display = 'none';
    preview.removeAttribute('src');
    document.getElementById('img-b64-dimension').textContent = '';
}

// ---------- 初始化 ----------

// 绑定拖拽区（点击/拖拽/释放）、文件输入、输出格式切换与页面级粘贴事件
// （参照 app.js 文件工具页的绑定写法，事件全部收在本模块内，不依赖 app.js）
function imgInit() {
    var dropZone = document.getElementById('img-drop-zone');
    var fileInput = document.getElementById('img-file-input');
    if (dropZone && fileInput) {
        // 点击拖拽区弹出文件选择框
        dropZone.addEventListener('click', function (event) {
            // input.click() 派发的 click 会冒泡回拖拽区，需拦截避免无限递归
            if (event.target === fileInput) return;
            fileInput.click();
        });
        // 拖拽悬停高亮（dragover 必须 preventDefault，否则浏览器直接打开文件）
        dropZone.addEventListener('dragover', function (event) {
            event.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', function (event) {
            event.preventDefault();
            dropZone.classList.remove('dragover');
        });
        dropZone.addEventListener('drop', function (event) {
            event.preventDefault();
            dropZone.classList.remove('dragover');
            var files = event.dataTransfer && event.dataTransfer.files;
            if (files && files.length > 0) {
                imgHandleFile(files[0]);
            }
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                imgHandleFile(fileInput.files[0]);
            }
        });
    }

    // 切换输出格式时若有已读取的图片，立即按新模式重渲染（无需重新读文件）
    var radios = document.getElementsByName('img-b64-mode');
    for (var i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', function () {
            if (imgDataUri) {
                imgConvertToBase64();
            } else {
                imgUpdateCssHint(imgGetMode());
            }
        });
    }

    // 页面级粘贴：绑定在 document 上，内部判断仅图片页激活时生效
    document.addEventListener('paste', imgOnPaste);
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', imgInit);
} else {
    imgInit();
}
