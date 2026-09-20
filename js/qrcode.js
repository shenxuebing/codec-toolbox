// ============================================================
// 增强版编解码工具 - 二维码工具页（page-qrcode）
// 功能：
//   1. 生成二维码：文本 → 二维码 SVG（qrcode-generator 库），
//      可下载 PNG（SVG → canvas → toBlob）与 SVG
//   2. 识别二维码：选择/拖拽/粘贴图片 → jsQR 像素级解析出文本，
//      内容为 URL 时额外给出可点击链接
// 依赖（须先于本文件加载）：
//   js/vendor/qrcode-generator.min.js → 全局 qrcode(typeNumber, ecc)
//   js/vendor/jsqr.min.js            → 全局 jsQR(rgba, w, h)
//   js/app.js                        → showNotification / copyToClipboard
// 安全说明：createSvgTag 输出为库生成的固定结构（用户原文只编码
//   进模块矩阵，不会以文本形式出现在 SVG 里），可安全 innerHTML 注入；
//   识别结果一律用 textContent / DOM API 呈现，禁止 innerHTML 拼接
// ============================================================

// ---------- 全局状态 ----------

var qrSvgString = '';      // 最近一次生成的 SVG 字符串（供下载 PNG/SVG 复用）
var qrSelectedFile = null; // 识别区当前选中的图片文件
var qrRecognizedText = ''; // 最近一次识别出的文本（供复制）

// 关键修正：qrcode-generator 默认的 stringToBytes 按 charCodeAt 截低 8 位
// 编码（"测" → 单字节 0x4B），中文会生成乱码二维码；必须切到内置的
// UTF-8 编码器（"测" → E6 B5 8B），扫描端才能正确解出中文
if (typeof qrcode === 'function' && qrcode.stringToBytesFuncs && qrcode.stringToBytesFuncs['UTF-8']) {
    qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'];
}

// ---------- Section 1：生成二维码 ----------

// 读取尺寸单选（128/256/384，返回数值）
function qrGetSize() {
    var checked = document.querySelector('input[name="qr-size"]:checked');
    return checked ? parseInt(checked.value, 10) : 256;
}

// 读取纠错级别单选（L/M/Q/H）
function qrGetEcc() {
    var checked = document.querySelector('input[name="qr-ecc"]:checked');
    return checked ? checked.value : 'M';
}

// 内部辅助：把生成的 SVG 注入显示容器并输出信息行
// （innerHTML 仅接收 createSvgTag 的输出，见文件头安全说明）
function qrRenderSvg(svg, moduleCount, charCount) {
    document.getElementById('qr-code-display').innerHTML = svg;
    // 版本号与模块数的关系：moduleCount = 17 + 4 × 版本
    var version = (moduleCount - 17) / 4;
    document.getElementById('qr-info').textContent =
        '模块数：' + moduleCount + ' × ' + moduleCount +
        ' ｜ 版本：' + version +
        ' ｜ 字符数：' + charCount +
        ' ｜ 纠错级别：' + qrGetEcc();
    document.getElementById('qr-info').style.display = 'block';
}

// "生成二维码"按钮：读取文本与选项，qrcode(0, ecc) 自动适配版本号
function qrGenerate() {
    var text = document.getElementById('qr-text-input').value;
    if (!text) {
        showNotification('请输入要生成二维码的内容');
        return;
    }
    try {
        var size = qrGetSize();
        var qr = qrcode(0, qrGetEcc());
        qr.addData(text);
        qr.make();
        var moduleCount = qr.getModuleCount();
        // cellSize 取整后实际输出尺寸可能略小于所选 px（floor 舍去零头），
        // 保证模块边界对齐像素格，避免锯齿；下限 1 防止大版本小尺寸时取 0
        var cellSize = Math.max(1, Math.floor(size / moduleCount));
        var svg = qr.createSvgTag({ cellSize: cellSize, margin: 2 });
        qrSvgString = svg;
        qrRenderSvg(svg, moduleCount, text.length);
    } catch (error) {
        // typeNumber 0（自动）也有容量上限：内容超出时库直接抛异常
        qrSvgString = '';
        document.getElementById('qr-code-display').textContent = '生成失败';
        document.getElementById('qr-info').style.display = 'none';
        showNotification('内容过长，请减少字符数或降低纠错级别');
    }
}

// "清空"按钮（生成区）：复位输入、二维码显示与下载缓存
function qrClear() {
    qrSvgString = '';
    document.getElementById('qr-text-input').value = '';
    document.getElementById('qr-code-display').textContent = '点击"生成二维码"后此处显示二维码';
    document.getElementById('qr-info').textContent = '';
    document.getElementById('qr-info').style.display = 'none';
}

// 通用下载：把 Blob 存为文件（临时 <a download> 点击后移除）
function qrDownloadBlob(blob, filename) {
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// "下载 PNG"按钮：SVG 以 blob URL 加载进 Image → 画到 canvas →
// toBlob 导出 PNG（尺寸取所选 px，白底填充避免透明底在深色环境难辨）
function qrDownloadPng() {
    if (!qrSvgString) {
        showNotification('请先生成二维码');
        return;
    }
    var size = qrGetSize();
    var svgBlob = new Blob([qrSvgString], { type: 'image/svg+xml;charset=utf-8' });
    var url = window.URL.createObjectURL(svgBlob);
    var img = new Image();
    img.onload = function () {
        var canvas = document.createElement('canvas');
        canvas.width = size;
        canvas.height = size;
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, size, size);
        ctx.drawImage(img, 0, 0, size, size);
        window.URL.revokeObjectURL(url);
        try {
            canvas.toBlob(function (blob) {
                if (!blob) {
                    // toBlob 回调拿不到 Blob（个别浏览器/隐身模式）：降级下载 SVG
                    showNotification('PNG 导出失败，已改为下载 SVG，或右键二维码图片另存为');
                    qrDownloadSvg();
                    return;
                }
                qrDownloadBlob(blob, 'qrcode-' + size + 'px.png');
                showNotification('PNG 已开始下载（' + size + '×' + size + '）');
            }, 'image/png');
        } catch (error) {
            // file:// 等场景下 canvas 可能被判污染（SecurityError）：
            // 降级为直接下载 SVG，并提示可右键二维码图片另存为
            console.error('PNG 导出失败:', error);
            showNotification('PNG 导出失败（浏览器安全限制），已改为下载 SVG，或右键二维码图片另存为');
            qrDownloadSvg();
        }
    };
    img.onerror = function () {
        window.URL.revokeObjectURL(url);
        showNotification('PNG 导出失败，已改为下载 SVG，或右键二维码图片另存为');
        qrDownloadSvg();
    };
    img.src = url;
}

// "下载 SVG"按钮：直接把 SVG 字符串存为 .svg 文件
// （前置 <?xml?> 声明可提高部分看图软件的兼容性）
function qrDownloadSvg() {
    if (!qrSvgString) {
        showNotification('请先生成二维码');
        return;
    }
    try {
        var blob = new Blob(['<?xml version="1.0" encoding="UTF-8"?>\n' + qrSvgString],
            { type: 'image/svg+xml;charset=utf-8' });
        qrDownloadBlob(blob, 'qrcode.svg');
        showNotification('SVG 已开始下载');
    } catch (error) {
        console.error('下载 SVG 失败:', error);
        showNotification('下载失败，请重试');
    }
}

// ---------- Section 2：识别二维码 ----------

// 处理图片文件选择（点击/拖拽/粘贴三种方式均走此入口）：
// 校验类型 → 预览 → 缓存文件供"识别二维码"按钮使用
function qrHandleFile(file) {
    if (!file) return;
    if (file.type && file.type.indexOf('image/') !== 0) {
        showNotification('请选择图片文件（PNG/JPEG 等）');
        return;
    }
    qrSelectedFile = file;
    // 切换图片后旧识别结果已失效，先复位
    qrRecognizedText = '';
    document.getElementById('qr-recognize-result').textContent = '';
    document.getElementById('qr-recognize-link').style.display = 'none';

    var reader = new FileReader();
    reader.onload = function (e) {
        var preview = document.getElementById('qr-image-preview');
        preview.src = e.target.result;
        preview.style.display = 'inline-block';
    };
    reader.onerror = function () {
        showNotification('读取图片失败');
    };
    reader.readAsDataURL(file);
}

// 内部辅助：把图片画到离屏 canvas 并调 jsQR 识别
// jsQR 需要 RGBA 像素数据（Uint8ClampedArray），过小的二维码图
// 放大后会提高识别率——小于 100px 的图按 4 倍最近邻放大重绘再试一次
function qrDecodeFromImage(img) {
    var w = img.naturalWidth;
    var h = img.naturalHeight;
    var canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    var ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, w, h);
    var imageData = ctx.getImageData(0, 0, w, h);
    var result = jsQR(imageData.data, w, h);
    if (result && result.data) return result.data;

    // 第一次失败且图片偏小：4 倍放大重绘再识别一次
    // （最近邻缩放保留模块边缘的锐利度，比默认的双线性模糊更适合 jsQR）
    if (w < 100 || h < 100) {
        var sw = w * 4;
        var sh = h * 4;
        canvas.width = sw;
        canvas.height = sh;
        var sctx = canvas.getContext('2d');
        sctx.imageSmoothingEnabled = false;
        sctx.drawImage(img, 0, 0, sw, sh);
        var scaled = sctx.getImageData(0, 0, sw, sh);
        result = jsQR(scaled.data, sw, sh);
        if (result && result.data) return result.data;
    }
    return null;
}

// "识别二维码"按钮：FileReader → Image → 离屏 canvas → jsQR
function qrRecognize() {
    if (!qrSelectedFile) {
        showNotification('请先选择或粘贴二维码图片');
        return;
    }
    var resultEl = document.getElementById('qr-recognize-result');
    var linkBox = document.getElementById('qr-recognize-link');
    resultEl.textContent = '识别中...';
    linkBox.style.display = 'none';

    var reader = new FileReader();
    reader.onload = function (e) {
        var img = new Image();
        img.onload = function () {
            try {
                // data: URL 加载的图片不会污染 canvas，getImageData 在
                // file:// 下同样可用（识别路径不依赖 toBlob，无跨域限制）
                var text = qrDecodeFromImage(img);
                if (text === null || text === '') {
                    qrRecognizedText = '';
                    resultEl.textContent =
                        '未识别到二维码：请确保图片清晰、二维码完整且占比足够大';
                    showNotification('未识别到二维码');
                    return;
                }
                qrRecognizedText = text;
                // 识别结果一律 textContent 呈现，杜绝原文被当 HTML 执行
                resultEl.textContent = text;
                // 内容是 URL 时额外给出可点击链接：DOM API 构建属性，防注入
                if (/^https?:\/\//i.test(text)) {
                    linkBox.textContent = '链接：';
                    var a = document.createElement('a');
                    a.href = text;
                    a.target = '_blank';
                    a.rel = 'noopener noreferrer';
                    a.textContent = text;
                    linkBox.appendChild(a);
                    linkBox.style.display = 'block';
                }
            } catch (error) {
                console.error('识别二维码失败:', error);
                qrRecognizedText = '';
                resultEl.textContent = '识别过程出错：' + (error.message || '请重试');
            }
        };
        img.onerror = function () {
            resultEl.textContent = '图片加载失败，请确认是有效的图片文件';
        };
        img.src = e.target.result;
    };
    reader.onerror = function () {
        resultEl.textContent = '读取图片失败';
    };
    reader.readAsDataURL(qrSelectedFile);
}

// "清空"按钮（识别区）：复位文件、预览与识别结果
function qrClearRecognize() {
    qrSelectedFile = null;
    qrRecognizedText = '';
    var preview = document.getElementById('qr-image-preview');
    preview.style.display = 'none';
    preview.removeAttribute('src');
    document.getElementById('qr-file-input').value = '';
    document.getElementById('qr-recognize-result').textContent = '';
    document.getElementById('qr-recognize-link').style.display = 'none';
}

// ---------- 初始化 ----------

// 页面级粘贴处理：仅二维码页激活时生效，剪贴板含图片项时
// 取出文件走 qrHandleFile（与拖拽/点击选择同一条路径）
function qrOnPaste(event) {
    var page = document.getElementById('page-qrcode');
    if (!page || !page.classList.contains('active')) return;
    var clipboard = event.clipboardData;
    if (!clipboard) return;
    var items = clipboard.items || [];
    for (var i = 0; i < items.length; i++) {
        if (items[i].kind === 'file' && items[i].type.indexOf('image/') === 0) {
            var file = items[i].getAsFile();
            if (file) {
                event.preventDefault();
                qrHandleFile(file);
            }
            return;
        }
    }
}

// 绑定拖拽区（点击/拖拽/释放）、文件输入、输入框 Ctrl+Enter 快捷生成
// 与页面级粘贴事件（写法参照 js/imgtool.js 的绑定模式）
function qrInit() {
    var dropZone = document.getElementById('qr-drop-zone');
    var fileInput = document.getElementById('qr-file-input');
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
                qrHandleFile(files[0]);
            }
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                qrHandleFile(fileInput.files[0]);
            }
        });
    }

    // 输入框内 Ctrl+Enter 快捷生成（Enter 本身留给换行）
    var textInput = document.getElementById('qr-text-input');
    if (textInput) {
        textInput.addEventListener('keydown', function (event) {
            if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
                event.preventDefault();
                qrGenerate();
            }
        });
    }

    document.addEventListener('paste', qrOnPaste);
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', qrInit);
} else {
    qrInit();
}
