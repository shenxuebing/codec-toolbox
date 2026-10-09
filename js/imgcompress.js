// ========== 图片压缩页（page-imgcompress） ==========
// canvas 离屏重绘实现纯本地压缩：支持转 JPEG / WebP（质量可调）与 PNG（无损），
// 可按最长边等比缩小；全程在浏览器本地完成，不上传任何数据。

var imgcFile = null;        // 当前已选择的原始文件对象（取名称与原大小用）
var imgcImage = null;       // 已加载完成的 Image 对象（压缩时作为绘制源）
var imgcOrigWidth = 0;      // 原图宽（Image.onload 取 naturalWidth）
var imgcOrigHeight = 0;     // 原图高（naturalHeight）
var imgcResultBlob = null;  // 压缩结果 Blob（下载用）
var imgcResultUrl = '';     // 结果 Blob 的 objectURL（预览用，更换/清空时释放）
var imgcResultExt = 'jpg';  // 当前结果文件扩展名（按实际输出 MIME 决定）

// ---------- 文件选择与原图预览 ----------

// 处理选中的图片文件：FileReader 读为 Data URL → Image 加载成功后记录宽高并预览
function imgcHandleFile(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onerror = function () {
        showNotification('❌ 文件读取失败');
    };
    reader.onload = function (e) {
        var img = new Image();
        img.onload = function () {
            // 记录原图信息，供压缩绘制与压缩率计算使用
            imgcFile = file;
            imgcImage = img;
            imgcOrigWidth = img.naturalWidth;
            imgcOrigHeight = img.naturalHeight;
            var preview = document.getElementById('imgc-preview');
            preview.src = e.target.result;
            preview.style.display = '';
            document.getElementById('imgc-orig-info').textContent =
                '名称：' + file.name + '　|　大小：' + formatFileSize(file.size) +
                '　|　宽 × 高：' + imgcOrigWidth + ' × ' + imgcOrigHeight + ' 像素';
        };
        img.onerror = function () {
            showNotification('❌ 图片加载失败，请确认选择的是有效图片文件');
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// ---------- 压缩 ----------

// 读目标格式单选的当前值（无选中时兜底 JPEG）
function imgcGetFormat() {
    var checked = document.querySelector('input[name="imgc-format"]:checked');
    return checked ? checked.value : 'image/jpeg';
}

// Data URL → Blob（toBlob 不可用时的降级转换路径）
function imgcDataUrlToBlob(dataUrl) {
    var parts = dataUrl.split(',');
    var mime = (parts[0].match(/data:(.*?)(;|$)/) || [])[1] || 'image/png';
    var bin = atob(parts[1]);
    var len = bin.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = bin.charCodeAt(i);
    }
    return new Blob([bytes], { type: mime });
}

// 主压缩流程：canvas 重绘 + toBlob 生成结果，填充预览与统计信息
function imgcCompress() {
    if (!imgcImage) {
        showNotification('请先选择图片');
        return;
    }
    var format = imgcGetFormat();
    // 质量滑块 10-100 → 0.1-1.0；PNG 为无损编码，质量参数对其不生效（传入也会被忽略）
    var quality = parseInt(document.getElementById('imgc-quality').value, 10) / 100;
    var maxSide = parseInt(document.getElementById('imgc-maxside').value, 10);
    if (isNaN(maxSide) || maxSide < 0) maxSide = 0;

    // 最长边缩放：仅在 maxSide>0 且最长边超限时按比例缩小；宽高取整，避免分数尺寸导致绘制模糊
    var newW = imgcOrigWidth;
    var newH = imgcOrigHeight;
    var longest = Math.max(newW, newH);
    if (maxSide > 0 && longest > maxSide) {
        var scale = maxSide / longest;
        newW = Math.max(1, Math.round(newW * scale));
        newH = Math.max(1, Math.round(newH * scale));
    }

    var canvas = document.createElement('canvas');
    canvas.width = newW;
    canvas.height = newH;
    var ctx = canvas.getContext('2d');
    // JPEG 无透明通道：先铺白底，避免透明 PNG 转 JPEG 后透明区域变黑
    if (format === 'image/jpeg') {
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, newW, newH);
    }
    ctx.drawImage(imgcImage, 0, 0, newW, newH);

    var onBlob = function (blob) {
        // toBlob 回调可能拿到 null（格式不支持等）；老浏览器无 toBlob —— 均降级用 dataURL 方式生成
        if (!blob) {
            try {
                blob = imgcDataUrlToBlob(canvas.toDataURL(format, quality));
                showNotification('⚠️ 当前浏览器 canvas.toBlob 不可用，已降级使用 dataURL 方式');
            } catch (e) {
                showNotification('❌ 压缩失败：' + (e && e.message ? e.message : e));
                return;
            }
        }
        var actualType = blob.type || format;
        // 个别浏览器不支持 WebP 编码时会静默回退成 PNG，此处提示真实输出格式
        if (format === 'image/webp' && actualType !== 'image/webp') {
            showNotification('⚠️ 当前浏览器不支持 WebP 输出，已按 ' + actualType + ' 输出');
        }
        imgcResultExt = actualType === 'image/webp' ? 'webp'
            : actualType === 'image/png' ? 'png'
            : actualType === 'image/jpeg' ? 'jpg' : 'img';
        imgcShowResult(blob, newW, newH);
    };

    if (typeof canvas.toBlob === 'function') {
        // png 忽略质量参数（无损），jpeg/webp 传 quality
        canvas.toBlob(onBlob, format, format === 'image/png' ? undefined : quality);
    } else {
        onBlob(null);
    }
}

// 填充结果区：预览图 + 新大小/新宽高/压缩率（变小绿、变大红）
function imgcShowResult(blob, newW, newH) {
    // 释放上一个 objectURL，避免内存泄漏
    if (imgcResultUrl) {
        URL.revokeObjectURL(imgcResultUrl);
    }
    imgcResultBlob = blob;
    imgcResultUrl = URL.createObjectURL(blob);

    var preview = document.getElementById('imgc-result-preview');
    preview.src = imgcResultUrl;
    preview.style.display = '';

    // 压缩率 = (1 - 新/旧) × 100%，带正负号；变大时为负
    var origSize = imgcFile ? imgcFile.size : 0;
    var rate = origSize > 0 ? (1 - blob.size / origSize) * 100 : 0;
    var sign = rate >= 0 ? '+' : '';   // 负数 toFixed 自带负号
    var rateCls = rate >= 0 ? 'jwt-valid' : 'jwt-invalid';
    var rateText = sign + rate.toFixed(1) + '%';
    document.getElementById('imgc-result-info').innerHTML =
        '新大小：' + formatFileSize(blob.size) +
        '（原 ' + formatFileSize(origSize) + '）<br>' +
        '新宽 × 高：' + newW + ' × ' + newH + ' 像素（原 ' + imgcOrigWidth + ' × ' + imgcOrigHeight + '）<br>' +
        '压缩率：<span class="' + rateCls + '">' + rateText + '</span>';
}

// ---------- 下载与清空 ----------

// 下载压缩结果：文件名 = 原名去扩展名 + _compressed.实际格式扩展名
function imgcDownload() {
    if (!imgcResultBlob) {
        showNotification('请先点击"压缩"生成结果');
        return;
    }
    var baseName = imgcFile ? imgcFile.name.replace(/\.[^.]+$/, '') : 'image';
    var a = document.createElement('a');
    a.href = imgcResultUrl;
    a.download = baseName + '_compressed.' + imgcResultExt;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// 清空：释放资源并复位预览/信息（格式/质量/缩放选项保留，方便连续处理）
function imgcClear() {
    if (imgcResultUrl) {
        URL.revokeObjectURL(imgcResultUrl);
    }
    imgcFile = null;
    imgcImage = null;
    imgcOrigWidth = 0;
    imgcOrigHeight = 0;
    imgcResultBlob = null;
    imgcResultUrl = '';
    imgcResultExt = 'jpg';
    var fileInput = document.getElementById('imgc-file-input');
    if (fileInput) fileInput.value = '';
    var preview = document.getElementById('imgc-preview');
    preview.removeAttribute('src');
    preview.style.display = 'none';
    document.getElementById('imgc-orig-info').textContent = '选择图片后此处显示名称、大小与宽高';
    var resultPreview = document.getElementById('imgc-result-preview');
    resultPreview.removeAttribute('src');
    resultPreview.style.display = 'none';
    document.getElementById('imgc-result-info').textContent = '点击"压缩"后此处显示新大小、新宽高与压缩率';
}

// ---------- 初始化 ----------

// 绑定拖拽区（点击/拖拽/释放）、文件输入与质量滑块显示（参照 js/imgtool.js 的绑定写法）
function imgcInit() {
    var dropZone = document.getElementById('imgc-drop-zone');
    var fileInput = document.getElementById('imgc-file-input');
    if (dropZone && fileInput) {
        // 点击拖拽区弹出文件选择框（拦截 input 冒泡回来的 click，避免无限递归）
        dropZone.addEventListener('click', function (event) {
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
                imgcHandleFile(files[0]);
            }
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                imgcHandleFile(fileInput.files[0]);
            }
        });
    }

    // 质量滑块拖动时同步数值显示（PNG 恒无损，滑块对其不生效，见页面注释说明）
    var quality = document.getElementById('imgc-quality');
    if (quality) {
        quality.addEventListener('input', function () {
            document.getElementById('imgc-quality-value').textContent = quality.value + '%';
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', imgcInit);
} else {
    imgcInit();
}
