// ========== PDF 工具页（page-pdf） ==========
// 三个本地化 vendor 库协作，全程浏览器本地处理（file:// 直接可用）：
//   pdfjsLib（js/vendor/pdfjs.min.js）——解析 / 渲染 / 文本提取
//   PDFLib  （js/vendor/pdf-lib.min.js）——页面级编辑（旋转/删页/提取/合并/裁剪/盖白）
//   fflate  （js/vendor/fflate.umd.js）——ZIP 打包（转图片、逐页拆分）
// 全页 6 个 Section 共享第 1 节选中的同一个文件（字节缓存在 PDF_STATE）。

// 文件大小上限（浏览器端 ArrayBuffer 处理 50MB 以内较稳妥）
var PDF_MAX_SIZE = 50 * 1024 * 1024;
// 单次"转图片"页数上限（防止一次渲染几十上百页 canvas 导致内存暴涨）
var PDF2IMG_MAX_PAGES = 50;

// 模块状态：bytes 为原始字节；两个文档对象惰性加载（首次使用时初始化，重选文件时重置）
// 注意：pdfjsDoc 缓存的是"只读"用途（渲染/文本）；pdf-lib 的页面编辑操作每次都从
// bytes 重新 load（避免在已改动的文档上累积误操作），故 pdfLibDoc 仅用于第 1 节读首页尺寸
var PDF_STATE = {
    bytes: null,     // Uint8Array：已选 PDF 的完整字节
    name: 'file.pdf',
    size: 0,
    pdfjsDoc: null,  // pdfjs PDFDocumentProxy（惰性）
    pdfLibDoc: null  // pdf-lib PDFDocument（惰性，只读用途）
};

// 第 2 节转图片结果（zip 打包与逐页下载用）
var PDF2IMG_STATE = { items: [], urls: [] };
// 第 3 节提取的纯文本（复制 / 下载 .txt / 伪 .doc 导出共用）
var PDF_TEXT_RESULT = '';

// ---------------- 通用小工具 ----------------

// 单选组当前值（无选中返回 ''，由调用方兜底）
function pdfRadio(name) {
    var el = document.querySelector('input[name="' + name + '"]:checked');
    return el ? el.value : '';
}

// 页范围解析：'1-3,5' → [1,2,3,5]；空/全空白 → 全部页 1..maxPage；
// 越界自动裁剪（maxPage=10 时 '2-100' → 2..10）；格式非法（如 'abc'）抛错。
// 容错：连续逗号、倒写区间（5-2）、重复页码；返回升序去重的 1 起始页码数组。
function pdfParseRange(str, maxPage) {
    if (typeof maxPage !== 'number' || maxPage < 1 || Math.floor(maxPage) !== maxPage) {
        throw new Error('maxPage 必须为正整数');
    }
    var s = String(str == null ? '' : str).trim();
    var out = [];
    var i, k;
    if (s === '') {
        for (i = 1; i <= maxPage; i++) out.push(i);
        return out;
    }
    var parts = s.split(',');
    for (var p = 0; p < parts.length; p++) {
        var seg = parts[p].trim();
        if (seg === '') continue; // 容错：首尾/连续逗号
        var a, b;
        var m = seg.match(/^(\d+)\s*-\s*(\d+)$/);
        if (m) {
            a = parseInt(m[1], 10);
            b = parseInt(m[2], 10);
        } else if (/^\d+$/.test(seg)) {
            a = b = parseInt(seg, 10);
        } else {
            throw new Error('页范围格式错误："' + seg + '"（示例：1-3,5）');
        }
        if (a > b) { var t = a; a = b; b = t; } // 倒写区间容错（5-2 → 2-5）
        if (a < 1) a = 1;             // 越界下裁剪
        if (b > maxPage) b = maxPage; // 越界上裁剪
        for (k = a; k <= b; k++) out.push(k);
    }
    if (out.length === 0) {
        throw new Error('页范围内没有有效页码（文档共 ' + maxPage + ' 页）');
    }
    out.sort(function (x, y) { return x - y; });
    var dedup = [];
    for (i = 0; i < out.length; i++) {
        if (dedup.length === 0 || dedup[dedup.length - 1] !== out[i]) dedup.push(out[i]);
    }
    return dedup;
}

// 下载文件名 = 已选文件去扩展名 + 后缀 + .pdf（如 report_页面操作.pdf）
function pdfBuildDocName(suffix) {
    var base = PDF_STATE.name.replace(/\.[^.]*$/, '') || 'pdf';
    return base + suffix + '.pdf';
}

// HTML 转义（伪 .doc / 结果区拼接时防注入）
function pdfEscapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Blob 下载（a.download + objectURL，用后即弃）
function pdfDownloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // 异步释放，避免个别浏览器在 click 事件内即回收导致下载失败
    setTimeout(function () { URL.revokeObjectURL(url); }, 3000);
}

// 统一错误出口：通知 + 控制台留痕（结果区文本由各调用方自行补充）
function pdfShowError(where, err) {
    var msg = pdfIsPasswordError(err) ? 'PDF 已加密，本工具暂不支持口令 PDF'
        : (err && err.message ? err.message : String(err));
    showNotification('❌ ' + msg);
    console.error('[pdftool] ' + where + ' 失败：', err);
}

// pdfjs 遇到口令 PDF 抛 PasswordException（name 属性判定，兼容压缩版无 instanceof）
function pdfIsPasswordError(err) {
    return !!err && (err.name === 'PasswordException' ||
        (typeof pdfjsLib !== 'undefined' && err instanceof pdfjsLib.PasswordException));
}

// 顺序执行异步任务（浏览器渲染/保存需逐页排队，避免并发撑爆内存）；
// fn(item, index) —— 回调同时拿到 0 起始序号（进度显示用）
function pdfSequence(items, fn) {
    var results = [];
    var chain = Promise.resolve();
    items.forEach(function (item, idx) {
        chain = chain.then(function () {
            return Promise.resolve(fn(item, idx)).then(function (r) { results.push(r); });
        });
    });
    return chain.then(function () { return results; });
}

// canvas → Blob（toBlob 不可用时降级 dataURL 手工转）
function pdfCanvasToBlob(canvas, mime) {
    return new Promise(function (resolve, reject) {
        if (typeof canvas.toBlob === 'function') {
            canvas.toBlob(function (blob) {
                if (blob) resolve(blob);
                else reject(new Error('canvas 导出 ' + mime + ' 失败'));
            }, mime, mime === 'image/jpeg' ? 0.92 : undefined);
            return;
        }
        try {
            var parts = canvas.toDataURL(mime).split(',');
            var bin = atob(parts[1]);
            var arr = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
            resolve(new Blob([arr], { type: mime }));
        } catch (e) {
            reject(e);
        }
    });
}

// Blob → Uint8Array（zipSync 需要；优先 Blob.arrayBuffer，老浏览器降级 FileReader）
function pdfBlobToBytes(blob) {
    if (typeof blob.arrayBuffer === 'function') {
        return blob.arrayBuffer().then(function (buf) { return new Uint8Array(buf); });
    }
    return new Promise(function (resolve, reject) {
        var r = new FileReader();
        r.onload = function (e) { resolve(new Uint8Array(e.target.result)); };
        r.onerror = function () { reject(new Error('Blob 读取失败')); };
        r.readAsArrayBuffer(blob);
    });
}

// File → Uint8Array（带 50MB 上限校验，读取失败给出文件名）
function pdfReadFileBytes(file) {
    return new Promise(function (resolve, reject) {
        if (file.size > PDF_MAX_SIZE) {
            reject(new Error('文件 ' + file.name + ' 超过 50MB 上限'));
            return;
        }
        var r = new FileReader();
        r.onload = function (e) { resolve(new Uint8Array(e.target.result)); };
        r.onerror = function () { reject(new Error('文件 ' + file.name + ' 读取失败')); };
        r.readAsArrayBuffer(file);
    });
}

// 各操作节的前置校验：未选文件时提示并返回 false
function pdfEnsureFile() {
    if (!PDF_STATE.bytes) {
        showNotification('请先在本页第 1 节选择 PDF 文件');
        return false;
    }
    return true;
}

// 数字输入框取值（非法/负数按 NaN 处理，由调用方校验）
function pdfNum(id) {
    return parseFloat(document.getElementById(id).value);
}

// ---------------- 惰性文档加载 ----------------

// pdfjs 文档（只读缓存）。注意：pdfjs 会"转移"传入缓冲区的所有权（原视图被 detach），
// 因此必须传 bytes.slice() 副本，保住 PDF_STATE.bytes 供 pdf-lib 等其他功能复用
function pdfGetJsDoc() {
    if (PDF_STATE.pdfjsDoc) return Promise.resolve(PDF_STATE.pdfjsDoc);
    return pdfjsLib.getDocument({ data: PDF_STATE.bytes.slice() }).promise.then(function (doc) {
        PDF_STATE.pdfjsDoc = doc;
        return doc;
    });
}

// pdf-lib 文档（只读缓存，仅第 1 节取首页尺寸用）。
// ignoreEncryption：允许载入加密 PDF 的结构，但不会解密内容——对其做页面编辑
// 得到的输出可能不完整/异常，第 4/6 节执行时会另行提示
function pdfGetLibDoc() {
    if (PDF_STATE.pdfLibDoc) return Promise.resolve(PDF_STATE.pdfLibDoc);
    return PDFLib.PDFDocument.load(PDF_STATE.bytes, { ignoreEncryption: true }).then(function (doc) {
        PDF_STATE.pdfLibDoc = doc;
        return doc;
    });
}

// ---------------- 文件选择与状态重置 ----------------

// 释放并复位全部共享状态（更换文件时调用）
function pdfResetState() {
    if (PDF_STATE.pdfjsDoc) {
        try { PDF_STATE.pdfjsDoc.destroy(); } catch (e) { /* 忽略销毁异常 */ }
    }
    PDF_STATE.bytes = null;
    PDF_STATE.pdfjsDoc = null;
    PDF_STATE.pdfLibDoc = null;
    PDF_STATE.name = 'file.pdf';
    PDF_STATE.size = 0;
    PDF_TEXT_RESULT = '';
    pdf2imgClearResults();
    var textResult = document.getElementById('pdf-text-result');
    if (textResult) textResult.textContent = '';
}

// 处理拖拽/点击选中的 PDF 文件：读字节 → 复位状态 → 解析信息与缩略图
function pdfHandleFile(file) {
    if (!file) return;
    pdfReadFileBytes(file).then(function (bytes) {
        pdfResetState();
        PDF_STATE.bytes = bytes;
        PDF_STATE.name = file.name || 'file.pdf';
        PDF_STATE.size = file.size;
        pdfLoadInfo();
    }).catch(function (err) {
        pdfShowError('读取文件', err);
    });
}

// ---------------- Section 1：信息与预览 ----------------

// 解析并展示：页数 / 是否加密 / 元数据（Title/Author/Producer/CreationDate）/
// 首页尺寸（pdf-lib，pt）+ 前 3 页缩略图（canvas 渲染）
function pdfLoadInfo() {
    var infoEl = document.getElementById('pdf-info');
    var thumbsEl = document.getElementById('pdf-thumbs');
    infoEl.textContent = '⏳ 解析中…';
    thumbsEl.innerHTML = '';

    pdfGetJsDoc().then(function (doc) {
        return doc.getMetadata().then(function (md) {
            return { doc: doc, info: md.info || {} };
        });
    }).then(function (r) {
        var lines = [];
        lines.push('文件：' + PDF_STATE.name + '（' + formatFileSize(PDF_STATE.size) + '）');
        lines.push('页数：' + r.doc.numPages +
            '　|　加密：' + (r.info.IsEncrypted ? '是（空口令已解开）' : '否'));
        // 元数据字段可能不存在或为空串，逐个判空展示
        var metaFields = [
            ['标题', r.info.Title], ['作者', r.info.Author],
            ['生成器', r.info.Producer], ['创建时间', r.info.CreationDate]
        ];
        var metaParts = [];
        metaFields.forEach(function (f) {
            if (f[1]) metaParts.push(f[0] + '：' + f[1]);
        });
        if (metaParts.length > 0) lines.push(metaParts.join('　|　'));
        infoEl.textContent = lines.join('\n');

        // 首页尺寸走 pdf-lib（与第 4/6 节同一坐标体系，pt）
        return pdfGetLibDoc().then(function (libDoc) {
            var size = libDoc.getPage(0).getSize();
            infoEl.textContent += '\n首页尺寸：' + Math.round(size.width) + ' × ' +
                Math.round(size.height) + ' pt（1 pt = 1/72 英寸）';
        }).catch(function () {
            infoEl.textContent += '\n首页尺寸：读取失败（文件可能已加密）';
        });
        // 缩略图渲染不阻塞信息展示
        var total = Math.min(3, r.doc.numPages);
        var pages = [];
        for (var i = 1; i <= total; i++) pages.push(i);
        return pdfSequence(pages, function (no) {
            return pdfRenderThumb(r.doc, no).then(function (canvas) {
                var item = document.createElement('div');
                item.className = 'pdf-thumb-item';
                var label = document.createElement('div');
                label.className = 'pdf-thumb-label';
                label.textContent = '第 ' + no + ' 页';
                item.appendChild(canvas);
                item.appendChild(label);
                thumbsEl.appendChild(item);
            });
        });
    }).catch(function (err) {
        if (pdfIsPasswordError(err)) {
            infoEl.textContent = '❌ PDF 已加密，本工具暂不支持口令 PDF';
        } else {
            infoEl.textContent = '❌ 解析失败：' + (err && err.message ? err.message : err);
        }
        pdfShowError('解析 PDF', err);
    });
}

// 渲染单页缩略图（宽度归一到 150px 的 canvas，高度按页面比例）
function pdfRenderThumb(doc, pageNo) {
    return doc.getPage(pageNo).then(function (page) {
        var vp1 = page.getViewport({ scale: 1 });
        var vp = page.getViewport({ scale: 150 / vp1.width });
        var canvas = document.createElement('canvas');
        canvas.width = Math.floor(vp.width);
        canvas.height = Math.floor(vp.height);
        return page.render({
            canvasContext: canvas.getContext('2d'),
            viewport: vp
        }).promise.then(function () { return canvas; });
    });
}

// ---------------- Section 2：PDF 转图片 ----------------

// 清空转图片结果（释放全部 objectURL）
function pdf2imgClearResults() {
    PDF2IMG_STATE.urls.forEach(function (u) { URL.revokeObjectURL(u); });
    PDF2IMG_STATE.items = [];
    PDF2IMG_STATE.urls = [];
    var el = document.getElementById('pdf2img-result');
    if (el) el.innerHTML = '';
    var prog = document.getElementById('pdf2img-progress');
    if (prog) prog.textContent = '';
}

// 主流程：pdfjs 逐页 render（scale = DPI/72）→ toBlob → 逐页下载按钮 + 待打包列表
function pdf2imgRun() {
    if (!pdfEnsureFile()) return;
    var rangeStr = document.getElementById('pdf2img-range').value;
    var dpi = parseInt(pdfRadio('pdf2img-dpi'), 10) || 96;
    var mime = pdfRadio('pdf2img-format') || 'image/jpeg';
    var ext = mime === 'image/png' ? 'png' : 'jpg';
    var progressEl = document.getElementById('pdf2img-progress');
    pdf2imgClearResults();

    pdfGetJsDoc().then(function (doc) {
        var pages = pdfParseRange(rangeStr, doc.numPages); // 非法格式在此抛错
        if (pages.length > PDF2IMG_MAX_PAGES) {
            throw new Error('单次最多转换 ' + PDF2IMG_MAX_PAGES +
                ' 页（本次 ' + pages.length + ' 页），请用页范围分批');
        }
        var scale = dpi / 72; // PDF 用户空间单位 72pt/英寸
        var base = PDF_STATE.name.replace(/\.[^.]*$/, '') || 'pdf';
        return pdfSequence(pages, function (no, idx) {
            progressEl.textContent = '⏳ 渲染中：第 ' + (idx + 1) + '/' + pages.length + ' 页（' + dpi + ' DPI）';
            return doc.getPage(no).then(function (page) {
                var vp = page.getViewport({ scale: scale });
                var canvas = document.createElement('canvas');
                canvas.width = Math.floor(vp.width);
                canvas.height = Math.floor(vp.height);
                return page.render({
                    canvasContext: canvas.getContext('2d'),
                    viewport: vp
                }).promise.then(function () {
                    return pdfCanvasToBlob(canvas, mime);
                }).then(function (blob) {
                    var name = base + '_' + no + '.' + ext;
                    PDF2IMG_STATE.items.push({ name: name, blob: blob });
                    pdf2imgAppendRow(name, blob, no);
                });
            });
        }).then(function () {
            progressEl.textContent = '✅ 转换完成：共 ' + PDF2IMG_STATE.items.length +
                ' 页（' + dpi + ' DPI，' + ext.toUpperCase() + '）';
        });
    }).catch(function (err) {
        progressEl.textContent = '❌ ' + (pdfIsPasswordError(err)
            ? 'PDF 已加密，本工具暂不支持口令 PDF'
            : (err && err.message ? err.message : err));
        pdfShowError('PDF 转图片', err);
    });
}

// 结果区追加一行："第 N 页 + 下载"（DOM API 构建，不拼 HTML）
function pdf2imgAppendRow(name, blob, pageNo) {
    var box = document.getElementById('pdf2img-result');
    var row = document.createElement('div');
    row.className = 'pdf-img-item';
    var label = document.createElement('span');
    label.textContent = '第 ' + pageNo + ' 页';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary';
    btn.textContent = '下载';
    var url = URL.createObjectURL(blob);
    PDF2IMG_STATE.urls.push(url);
    btn.addEventListener('click', function () {
        var a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    });
    row.appendChild(label);
    row.appendChild(btn);
    box.appendChild(row);
}

// 全部转出的图片打包 ZIP（fflate zipSync，文件名 = 原名_页码.ext）
function pdf2imgDownloadZip() {
    if (PDF2IMG_STATE.items.length === 0) {
        showNotification('请先点击"转图片"生成结果');
        return;
    }
    var entries = {};
    pdfSequence(PDF2IMG_STATE.items, function (item) {
        return pdfBlobToBytes(item.blob).then(function (bytes) {
            entries[item.name] = bytes;
        });
    }).then(function () {
        var zipped = fflate.zipSync(entries);
        var base = PDF_STATE.name.replace(/\.[^.]*$/, '') || 'pdf';
        pdfDownloadBlob(new Blob([zipped], { type: 'application/zip' }), base + '_images.zip');
    }).catch(function (err) {
        pdfShowError('打包 ZIP', err);
    });
}

// ---------------- Section 3：提取文本 ----------------

// 逐页 getTextContent 拼接：【第 N 页】+ 该页文本（hasEOL 处补换行）
function pdfTextRun() {
    if (!pdfEnsureFile()) return;
    var resultEl = document.getElementById('pdf-text-result');
    resultEl.textContent = '⏳ 提取中…';
    pdfGetJsDoc().then(function (doc) {
        var pages = [];
        for (var i = 1; i <= doc.numPages; i++) pages.push(i);
        return pdfSequence(pages, function (no) {
            return doc.getPage(no).then(function (page) {
                return page.getTextContent();
            }).then(function (tc) {
                var text = '';
                (tc.items || []).forEach(function (it) {
                    text += it.str;
                    if (it.hasEOL) text += '\n';
                });
                text = text.replace(/\n{3,}/g, '\n\n').trim();
                return '【第 ' + no + ' 页】\n' + (text || '（本页无文字层）');
            });
        });
    }).then(function (lines) {
        PDF_TEXT_RESULT = lines.join('\n\n');
        resultEl.textContent = PDF_TEXT_RESULT || '（未提取到任何文本）';
    }).catch(function (err) {
        resultEl.textContent = '❌ ' + (pdfIsPasswordError(err)
            ? 'PDF 已加密，本工具暂不支持口令 PDF'
            : (err && err.message ? err.message : err));
        pdfShowError('提取文本', err);
    });
}

// 下载 .txt（UTF-8 带 BOM，记事本/Excel 直接识别编码）
function pdfTextDownload() {
    if (!PDF_TEXT_RESULT) {
        showNotification('请先点击"提取文本"');
        return;
    }
    var base = PDF_STATE.name.replace(/\.[^.]*$/, '') || 'pdf';
    // 前置 （BOM 字符）让记事本/Excel 按 UTF-8 识别
    pdfDownloadBlob(new Blob(['\ufeff' + PDF_TEXT_RESULT], { type: 'text/plain;charset=utf-8' }),
        base + '_文本.txt');
}

// 导出 Word（.doc）——注意：这是"伪 doc"：MIME 为 application/msword 的 HTML 包装，
// Word/WPS 可直接打开编辑，但它不是真正的 OLE2/OOXML .doc 格式，仅作轻量导出通道；
// 换行用 <pre> 保留、<br> 兜底，正文经 HTML 转义防注入
function pdfTextToWord() {
    if (!PDF_TEXT_RESULT) {
        showNotification('请先点击"提取文本"');
        return;
    }
    var html = '<html xmlns:o="urn:schemas-microsoft-com:office:office" ' +
        'xmlns:w="urn:schemas-microsoft-com:office:word">' +
        '<head><meta charset="utf-8"><title>' + pdfEscapeHtml(PDF_STATE.name) + '</title></head>' +
        '<body><pre>' + pdfEscapeHtml(PDF_TEXT_RESULT) + '</pre></body></html>';
    var base = PDF_STATE.name.replace(/\.[^.]*$/, '') || 'pdf';
    // 前置 （BOM 字符）让 Word 按 UTF-8 识别中文
    pdfDownloadBlob(new Blob(['\ufeff' + html], { type: 'application/msword' }), base + '_文本.doc');
}

// ---------------- Section 4：页面操作（pdf-lib，纯函数可对拍） ----------------

// 对给定字节执行页面操作，返回操作后 save() 的新字节（不改 PDF_STATE）。
// op：rotate90/rotate180/rotate270（全部页累加旋转）/ remove（删指定页）/
//     extract（提取指定页为新文档）/ reverse（全部页倒序）
// rangeStr：'1-3,5' 语法，remove/extract 必填，rotate/reverse 忽略（留空即可）
function pdfApplyPageOp(bytes, op, rangeStr) {
    return PDFLib.PDFDocument.load(bytes, { ignoreEncryption: true }).then(function (pdfDoc) {
        var total = pdfDoc.getPageCount();
        var angle = op === 'rotate90' ? 90 : op === 'rotate180' ? 180 : op === 'rotate270' ? 270 : 0;
        if (angle) {
            // setRotation 是"绝对角度"：在原角度基础上累加后对 360 取模
            for (var i = 0; i < total; i++) {
                var page = pdfDoc.getPage(i);
                page.setRotation(PDFLib.degrees((page.getRotation().angle + angle) % 360));
            }
            return pdfDoc.save();
        }
        if (op === 'reverse') {
            // 倒序：新文档按倒序逐页 copy（copyPages 保内容流，比交换页树节点直观可靠）
            var order = [];
            for (var j = total - 1; j >= 0; j--) order.push(j);
            return pdfCopyToNew(pdfDoc, order);
        }
        if (op === 'remove' || op === 'extract') {
            var pageNos = pdfParseRange(rangeStr, total); // 1 起始
            var indices = pageNos.map(function (n) { return n - 1; }); // → 0 起始索引
            if (op === 'remove') {
                if (indices.length >= total) {
                    throw new Error('删除后至少保留 1 页（共 ' + total + ' 页，不能全删）');
                }
                // 必须从大索引往小删，否则前面的删除会使后面的索引位移
                indices.sort(function (a, b) { return b - a; });
                indices.forEach(function (idx) { pdfDoc.removePage(idx); });
                return pdfDoc.save();
            }
            return pdfCopyToNew(pdfDoc, indices);
        }
        throw new Error('未知操作：' + op);
    });
}

// 从 src 按 0 起始索引列表复制页到新文档并 save（extract/reverse 共用）
function pdfCopyToNew(srcDoc, indices) {
    return PDFLib.PDFDocument.create().then(function (outDoc) {
        return outDoc.copyPages(srcDoc, indices).then(function (copied) {
            copied.forEach(function (p) { outDoc.addPage(p); });
            return outDoc.save();
        });
    });
}

// "执行并下载"入口：读取单选与页范围 → pdfApplyPageOp → 下载
function pdfPageRun() {
    if (!pdfEnsureFile()) return;
    var op = pdfRadio('pdfpage-op') || 'rotate90';
    var rangeStr = document.getElementById('pdfpage-range').value;
    if ((op === 'remove' || op === 'extract') && !rangeStr.trim()) {
        showNotification('该操作需要填写页范围（如 1-3,5）');
        return;
    }
    try {
        pdfApplyPageOp(PDF_STATE.bytes, op, rangeStr).then(function (outBytes) {
            if (PDF_STATE.pdfLibDoc && PDF_STATE.pdfLibDoc.isEncrypted) {
                // ignoreEncryption 只是允许解析：加密文档的内容并未解密，输出可能异常
                showNotification('⚠️ 源文件已加密，输出结果可能不完整，请注意检查');
            }
            pdfDownloadBlob(new Blob([outBytes], { type: 'application/pdf' }),
                pdfBuildDocName('_页面操作'));
        }).catch(function (err) {
            pdfShowError('页面操作', err);
        });
    } catch (e) {
        pdfShowError('页面操作', e);
    }
}

// ---------------- Section 5：合并 / 拆分 ----------------

// 合并多份字节（顺序即传入顺序）→ 新文档字节（纯函数可对拍）
function pdfMergeBytes(list) {
    return PDFLib.PDFDocument.create().then(function (outDoc) {
        return pdfSequence(list, function (item) {
            return PDFLib.PDFDocument.load(item.bytes, { ignoreEncryption: true })
                .then(function (src) {
                    var indices = [];
                    for (var i = 0; i < src.getPageCount(); i++) indices.push(i);
                    return outDoc.copyPages(src, indices);
                })
                .then(function (copied) {
                    copied.forEach(function (p) { outDoc.addPage(p); });
                });
        }).then(function () {
            return outDoc.save();
        });
    });
}

// 合并入口：按 input files 的选择顺序读取 → pdfMergeBytes → merged.pdf
function pdfMergeRun() {
    var input = document.getElementById('pdfmerge-files');
    var files = input && input.files ? Array.prototype.slice.call(input.files) : [];
    if (files.length < 2) {
        showNotification('请至少选择 2 个 PDF 文件（按选择顺序合并）');
        return;
    }
    pdfSequence(files, function (f) {
        return pdfReadFileBytes(f);
    }).then(function (bytesList) {
        return pdfMergeBytes(bytesList.map(function (b, i) {
            return { name: files[i].name, bytes: b };
        }));
    }).then(function (outBytes) {
        pdfDownloadBlob(new Blob([outBytes], { type: 'application/pdf' }), 'merged.pdf');
    }).catch(function (err) {
        pdfShowError('合并 PDF', err);
    });
}

// 每页拆分为单独的单页 PDF，打包 ZIP 下载（文件名 = 原名_p页码.pdf）
function pdfSplitEach() {
    if (!pdfEnsureFile()) return;
    PDFLib.PDFDocument.load(PDF_STATE.bytes, { ignoreEncryption: true }).then(function (src) {
        var total = src.getPageCount();
        var base = PDF_STATE.name.replace(/\.[^.]*$/, '') || 'pdf';
        var entries = {};
        var indices = [];
        for (var i = 0; i < total; i++) indices.push(i);
        return pdfSequence(indices, function (idx) {
            return pdfCopyToNew(src, [idx]).then(function (onePageBytes) {
                entries[base + '_p' + (idx + 1) + '.pdf'] = onePageBytes;
            });
        }).then(function () {
            var zipped = fflate.zipSync(entries);
            pdfDownloadBlob(new Blob([zipped], { type: 'application/zip' }), base + '_拆分.zip');
        });
    }).catch(function (err) {
        pdfShowError('逐页拆分', err);
    });
}

// ---------------- Section 6：去水印（安全途径，纯函数可对拍） ----------------

// ① 裁剪页边：对每页设置 CropBox（x=左, y=下，宽高 = 原尺寸减四边）。
// 说明：只是视觉裁剪（显示/打印按 CropBox），原内容字节仍保留在文件中；
// 坐标为 PDF 用户空间（原点在左下角），不随页面 /Rotate 旋转交换
function pdfApplyCrop(bytes, top, bottom, left, right) {
    return PDFLib.PDFDocument.load(bytes, { ignoreEncryption: true }).then(function (pdfDoc) {
        var pages = pdfDoc.getPages();
        for (var i = 0; i < pages.length; i++) {
            var mb = pages[i].getMediaBox(); // 一般原点为 0,0，非零时按其偏移计算
            var w = mb.width - left - right;
            var h = mb.height - top - bottom;
            if (w <= 0 || h <= 0) {
                throw new Error('第 ' + (i + 1) + ' 页裁剪后宽/高非正（' +
                    Math.round(w) + '×' + Math.round(h) + '），请减小四边裁剪量');
            }
            pages[i].setCropBox(mb.x + left, mb.y + bottom, w, h);
        }
        return pdfDoc.save();
    });
}

// ② 盖白矩形：对指定页在 (x,y) 位置画 width×height 的纯白矩形。
// 诚实说明局限：矩形追加在该页内容流末尾，只能盖住"绘制次序在其之前"的内容；
// 若正文/水印绘制在其之后（或以平铺图案、注解层呈现），盖白会把正文一起挡住或水印仍在上层，
// 仅适合"水印位于固定矩形区域且其上层无正文"的场景
function pdfApplyCover(bytes, rangeStr, x, y, width, height) {
    return PDFLib.PDFDocument.load(bytes, { ignoreEncryption: true }).then(function (pdfDoc) {
        var pageNos = pdfParseRange(rangeStr, pdfDoc.getPageCount());
        pageNos.forEach(function (n) {
            pdfDoc.getPage(n - 1).drawRectangle({
                x: x, y: y, width: width, height: height,
                color: PDFLib.rgb(1, 1, 1)
            });
        });
        return pdfDoc.save();
    });
}

// 裁剪入口：四边读取 + 校验（非负、不全为 0）
function pdfCropRun() {
    if (!pdfEnsureFile()) return;
    var t = pdfNum('pdfcrop-t'), b = pdfNum('pdfcrop-b');
    var l = pdfNum('pdfcrop-l'), r = pdfNum('pdfcrop-r');
    var edges = [t, b, l, r];
    if (edges.some(function (v) { return isNaN(v) || v < 0; })) {
        showNotification('四边裁剪量必须为不小于 0 的数字');
        return;
    }
    if (t + b + l + r === 0) {
        showNotification('四边均为 0，无需裁剪');
        return;
    }
    pdfApplyCrop(PDF_STATE.bytes, t, b, l, r).then(function (outBytes) {
        pdfDownloadBlob(new Blob([outBytes], { type: 'application/pdf' }), pdfBuildDocName('_裁剪'));
    }).catch(function (err) {
        pdfShowError('裁剪页边', err);
    });
}

// 盖白入口：坐标/宽高读取 + 校验（宽高必须为正）
function pdfCoverRun() {
    if (!pdfEnsureFile()) return;
    var x = pdfNum('pdfcover-x'), y = pdfNum('pdfcover-y');
    var w = pdfNum('pdfcover-w'), h = pdfNum('pdfcover-h');
    if ([x, y, w, h].some(function (v) { return isNaN(v); })) {
        showNotification('X / Y / 宽 / 高必须为数字');
        return;
    }
    if (w <= 0 || h <= 0) {
        showNotification('宽和高必须大于 0');
        return;
    }
    var rangeStr = document.getElementById('pdfcover-range').value;
    pdfApplyCover(PDF_STATE.bytes, rangeStr, x, y, w, h).then(function (outBytes) {
        pdfDownloadBlob(new Blob([outBytes], { type: 'application/pdf' }), pdfBuildDocName('_盖白'));
    }).catch(function (err) {
        pdfShowError('盖白矩形', err);
    });
}

// ---------------- 初始化 ----------------

// 绑定拖拽/点击选择区 + 设置 pdfjs worker
function pdfInit() {
    // workerSrc 指向本地化的 worker 脚本：相对路径（相对 index.html，file:// 协议可用），
    // 不需要（也不能）用 <script> 引入 worker 文件本身；
    // 个别浏览器禁止 file:// 下创建 Worker 时，pdfjs 会自动降级为主线程解析（fake worker），
    // 功能不受影响、仅速度略降
    if (typeof pdfjsLib !== 'undefined' && pdfjsLib.GlobalWorkerOptions) {
        pdfjsLib.GlobalWorkerOptions.workerSrc = 'js/vendor/pdfjs-worker.min.js';
    }

    // 拖拽/点击二合一选择区（写法同 imgcompress/imgtool 页）
    var dropZone = document.getElementById('pdf-drop');
    var fileInput = document.getElementById('pdf-file');
    if (dropZone && fileInput) {
        dropZone.addEventListener('click', function (event) {
            if (event.target === fileInput) return; // 拦截 input 冒泡，避免无限递归
            fileInput.click();
        });
        dropZone.addEventListener('dragover', function (event) {
            event.preventDefault(); // 必须 preventDefault，否则浏览器直接打开文件
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
            if (files && files.length > 0) pdfHandleFile(files[0]);
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                pdfHandleFile(fileInput.files[0]);
                fileInput.value = ''; // 允许连续选择同一文件也能触发 change
            }
        });
    }
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', pdfInit);
    } else {
        pdfInit();
    }
}

// Node 环境导出（浏览器中 module 未定义，此块自动跳过，便于对拍自测）：
// pdfParseRange/pdfBuildDocName 为纯函数；pdfApply* 系列仅依赖全局 PDFLib，
// Node 下先 require vendor/pdf-lib.min.js 挂到全局即可全流程对拍
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        pdfParseRange: pdfParseRange,
        pdfBuildDocName: pdfBuildDocName,
        pdfEscapeHtml: pdfEscapeHtml,
        pdfSequence: pdfSequence,
        pdfApplyPageOp: pdfApplyPageOp,
        pdfApplyCrop: pdfApplyCrop,
        pdfApplyCover: pdfApplyCover,
        pdfMergeBytes: pdfMergeBytes
    };
}

// ---------------- Section 7：图片转 PDF（追加于上述既有代码之后，不改任何旧逻辑） ----------------
// 多张图片按列表顺序逐张成页合入一个新 PDF 文档（pdf-lib embedJpg/embedPng）。
// 本节全部逻辑依赖 DOM/Image/canvas（无纯函数可拆），与第 1 节共享文件无关（独立列表独立状态）。

// 已选图片列表（数组顺序即页序）：{ file: File, url: 缩略图 objectURL, type: MIME, name: 文件名 }
// url 在移除单项 / 清空列表时须 URL.revokeObjectURL 释放
var PDF_IMG_FILES = [];

// 追加图片到列表（不清空已有，支持分批添加）：
// 过滤非图片（MIME 非 image/* 的跳过；MIME 为空的宽容放行，交给后续魔数分型/解码阶段报错）
function pdfImgAddFiles(fileList) {
    var files = fileList && fileList.length ? Array.prototype.slice.call(fileList) : [];
    var added = 0, skipped = 0;
    files.forEach(function (f) {
        if (f.type && f.type.indexOf('image/') !== 0) { skipped++; return; }
        if (f.size > PDF_MAX_SIZE) {
            showNotification('已跳过 ' + f.name + '：超过 50MB 上限');
            return;
        }
        // 缩略图 objectURL：列表展示与后续 canvas 重绘共用同一 URL，避免重复创建
        PDF_IMG_FILES.push({ file: f, url: URL.createObjectURL(f), type: f.type || '', name: f.name || 'image' });
        added++;
    });
    if (skipped > 0) showNotification('已跳过 ' + skipped + ' 个非图片文件');
    if (added > 0) showNotification('已添加 ' + added + ' 张图片（当前共 ' + PDF_IMG_FILES.length + ' 张）');
    pdfImgRenderList();
}

// 渲染已选列表：每行 = 缩略图(40px 高) + 序号/名称/大小 + 上移/下移/移除（DOM API 构建，不拼 HTML）
function pdfImgRenderList() {
    var box = document.getElementById('pdfimg-list');
    if (!box) return;
    box.innerHTML = '';
    if (PDF_IMG_FILES.length === 0) {
        box.textContent = '（尚未选择图片，可点击上方选区或拖拽分批添加）';
        box.style.cssText = 'font-size:12px;color:#6c757d;padding:4px 0;';
        return;
    }
    box.style.cssText = '';
    PDF_IMG_FILES.forEach(function (item, idx) {
        var row = document.createElement('div');
        row.className = 'pdfimg-row';

        // 缩略图：直接引用 item.url（objectURL），高度由 CSS 固定 40px、宽度等比
        var thumb = document.createElement('img');
        thumb.src = item.url;
        thumb.alt = item.name;

        // 名称 + 大小（flex:1 占满剩余宽度，超长省略）
        var meta = document.createElement('span');
        meta.className = 'pdfimg-meta';
        meta.textContent = (idx + 1) + '. ' + item.name + '（' + formatFileSize(item.file.size) + '）';
        meta.title = item.name; // 悬停看全名

        // 上移/下移：交换数组相邻元素后整体重渲染（首位/末位禁用）
        var up = document.createElement('button');
        up.type = 'button';
        up.className = 'btn btn-secondary';
        up.textContent = '↑';
        up.title = '上移（提前一页）';
        if (idx === 0) up.disabled = true;
        up.addEventListener('click', function () {
            var t = PDF_IMG_FILES[idx - 1];
            PDF_IMG_FILES[idx - 1] = PDF_IMG_FILES[idx];
            PDF_IMG_FILES[idx] = t;
            pdfImgRenderList();
        });

        var down = document.createElement('button');
        down.type = 'button';
        down.className = 'btn btn-secondary';
        down.textContent = '↓';
        down.title = '下移（推后一页）';
        if (idx === PDF_IMG_FILES.length - 1) down.disabled = true;
        down.addEventListener('click', function () {
            var t = PDF_IMG_FILES[idx + 1];
            PDF_IMG_FILES[idx + 1] = PDF_IMG_FILES[idx];
            PDF_IMG_FILES[idx] = t;
            pdfImgRenderList();
        });

        // 移除：释放该行 objectURL 后从数组删除
        var del = document.createElement('button');
        del.type = 'button';
        del.className = 'btn btn-secondary';
        del.textContent = '✕';
        del.title = '移除';
        del.addEventListener('click', function () {
            URL.revokeObjectURL(item.url);
            PDF_IMG_FILES.splice(idx, 1);
            pdfImgRenderList();
        });

        row.appendChild(thumb);
        row.appendChild(meta);
        row.appendChild(up);
        row.appendChild(down);
        row.appendChild(del);
        box.appendChild(row);
    });
}

// 单图 → 嵌入对象。分型逻辑（pdf-lib 仅支持 JPG/PNG 两种字节流直嵌）：
//   ① JPEG（魔数 FF D8）→ embedJpg(原字节)：零重编码、零损耗；
//   ② PNG（魔数 89 50 4E 47）→ embedPng(原字节)：同上；
//   ③ 其他格式（BMP/GIF/WebP/SVG…pdf-lib 不认识）→ Image 加载 → 离屏 canvas 重绘 →
//      canvas.toBlob('image/png') 归一为 PNG 字节再 embedPng。
//   说明：MIME type 可能为空或不准（拖拽场景），故按文件头魔数分型而非 type 字段；
//   canvas 重绘路径上 drawImage 会自动应用浏览器默认的 image-orientation（即 EXIF 方向），
//   归一化产物以"浏览器渲染方向"为准；直嵌路径不解析 EXIF（PDF 阅读器普遍忽略 EXIF 方向标记）。
function pdfImgEmbedOne(pdfDoc, item) {
    return pdfReadFileBytes(item.file).then(function (bytes) {
        // 魔数嗅探：JPEG = FF D8，PNG = 89 50 4E 47（'‰PNG'）
        var isJpg = bytes.length > 2 && bytes[0] === 0xFF && bytes[1] === 0xD8;
        var isPng = bytes.length > 4 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47;
        if (isJpg) return pdfDoc.embedJpg(bytes);
        if (isPng) return pdfDoc.embedPng(bytes);

        // 其他格式归一化：objectURL → Image → canvas（naturalWidth/Height 为浏览器
        // 解码后的尺寸，已含 EXIF 方向矫正）→ PNG Blob → 字节 → embedPng
        return new Promise(function (resolve, reject) {
            var img = new Image();
            img.onload = function () { resolve(img); };
            img.onerror = function () {
                reject(new Error('浏览器无法解码该图片（' + item.name + '），请先转为 JPG/PNG'));
            };
            img.src = item.url; // 复用缩略图的 objectURL（File 的 blob URL，Image 可直接加载）
        }).then(function (img) {
            if (!img.naturalWidth || !img.naturalHeight) {
                throw new Error(item.name + ' 无固有尺寸（如未设 width/height 的 SVG），无法转换');
            }
            // GIF 动图在此只取第一帧；BMP/WebP 等经 canvas 像素级重绘
            var canvas = document.createElement('canvas');
            canvas.width = img.naturalWidth;
            canvas.height = img.naturalHeight;
            canvas.getContext('2d').drawImage(img, 0, 0);
            // 复用第 2 节的 canvas→Blob 工具（PNG 无质量参数）
            return pdfCanvasToBlob(canvas, 'image/png');
        }).then(function (blob) {
            return pdfBlobToBytes(blob); // Blob → Uint8Array（embedPng 需要）
        }).then(function (pngBytes) {
            return pdfDoc.embedPng(pngBytes);
        });
    });
}

// A4 纵向尺寸（pt）：210mm × 297mm = 595.28 × 841.89
var PDFIMG_A4_W = 595.28;
var PDFIMG_A4_H = 841.89;

// 主流程：逐张嵌入 → 按"页面尺寸"选项建页排版 → save → 下载 images.pdf
function pdfImgToPdf() {
    var resultEl = document.getElementById('pdfimg-result');
    if (PDF_IMG_FILES.length === 0) {
        showNotification('请先选择至少 1 张图片');
        return;
    }
    var pageSize = pdfRadio('pdfimg-pagesize') || 'fit';
    var margin = pdfNum('pdfimg-margin');
    if (isNaN(margin) || margin < 0 || margin > 100) {
        showNotification('边距必须为 0～100 之间的数字（pt）');
        return;
    }

    var total = PDF_IMG_FILES.length;
    resultEl.textContent = '⏳ 处理中…';
    PDFLib.PDFDocument.create().then(function (pdfDoc) {
        return pdfSequence(PDF_IMG_FILES, function (item, idx) {
            resultEl.textContent = '⏳ 处理中：第 ' + (idx + 1) + '/' + total + ' 张（' + item.name + '）';
            return pdfImgEmbedOne(pdfDoc, item).catch(function (err) {
                // 单张失败带上文件名重抛，中断整体（避免静默缺页）
                throw new Error('第 ' + (idx + 1) + ' 张（' + item.name + '）处理失败：' +
                    (err && err.message ? err.message : err));
            }).then(function (emb) {
                // emb.width/height = 嵌入图像的固有像素尺寸（直嵌=原图像素；归一化=canvas 尺寸）
                var iw = emb.width, ih = emb.height;
                if (pageSize === 'a4') {
                    // A4 纵向：等比缩放放入 (页宽-2m)×(页高-2m) 内容框（小图不放大，scale 上限 1），
                    // 水平垂直居中；坐标原点在页面左下角
                    var availW = PDFIMG_A4_W - 2 * margin;
                    var availH = PDFIMG_A4_H - 2 * margin;
                    if (availW <= 0 || availH <= 0) {
                        throw new Error('边距过大：A4 内容区已无剩余空间（边距 ' + margin + ' pt）');
                    }
                    var scale = Math.min(availW / iw, availH / ih, 1);
                    var dw = iw * scale, dh = ih * scale;
                    var page = pdfDoc.addPage([PDFIMG_A4_W, PDFIMG_A4_H]);
                    page.drawImage(emb, {
                        x: (PDFIMG_A4_W - dw) / 2,
                        y: (PDFIMG_A4_H - dh) / 2,
                        width: dw,
                        height: dh
                    });
                } else {
                    // 按图片尺寸：页面 = 图片像素尺寸（1px = 1pt），整页铺满无边距
                    var page2 = pdfDoc.addPage([iw, ih]);
                    page2.drawImage(emb, { x: 0, y: 0, width: iw, height: ih });
                }
            });
        }).then(function () {
            return pdfDoc.save();
        });
    }).then(function (outBytes) {
        var blob = new Blob([outBytes], { type: 'application/pdf' });
        // a.download 下载（pdfDownloadBlob 内部即 gmCopyInput 式 a.download + objectURL）
        pdfDownloadBlob(blob, 'images.pdf');
        // 每张图恰好一页（GIF 取首帧也不多页），页数 = 图片张数
        resultEl.textContent = '✅ ' + total + ' 张图片 → ' + total + ' 页 PDF，大小 ' + formatFileSize(blob.size);
        showNotification('✅ 已生成 images.pdf（' + total + ' 页）');
    }).catch(function (err) {
        resultEl.textContent = '❌ ' + (err && err.message ? err.message : err);
        pdfShowError('图片转 PDF', err);
    });
}

// 清空列表：逐个释放 objectURL → 清数组 → 清文件输入 → 复位结果区
function pdfImgClear() {
    PDF_IMG_FILES.forEach(function (item) { URL.revokeObjectURL(item.url); });
    PDF_IMG_FILES = [];
    var input = document.getElementById('pdfimg-files');
    if (input) input.value = ''; // 允许再次选择同一批文件仍触发 change
    var resultEl = document.getElementById('pdfimg-result');
    if (resultEl) resultEl.textContent = '选择图片并点击"生成 PDF"后此处显示结果';
    pdfImgRenderList();
    showNotification('已清空图片列表');
}

// 绑定 Section 7 拖拽/点击选区（写法同第 1 节 pdf-drop，multiple 多选；独立绑定，不改 pdfInit）
function pdfImgInit() {
    var dropZone = document.getElementById('pdfimg-drop');
    var fileInput = document.getElementById('pdfimg-files');
    if (!dropZone || !fileInput) return;
    dropZone.addEventListener('click', function (event) {
        if (event.target === fileInput) return; // 拦截 input 冒泡，避免无限递归
        fileInput.click();
    });
    dropZone.addEventListener('dragover', function (event) {
        event.preventDefault(); // 必须 preventDefault，否则浏览器直接打开文件
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
        if (files && files.length > 0) pdfImgAddFiles(files);
    });
    fileInput.addEventListener('change', function () {
        if (fileInput.files && fileInput.files.length > 0) {
            pdfImgAddFiles(fileInput.files);
            fileInput.value = ''; // 允许连续选择同一批文件也能触发 change
        }
    });
}

// Section 7 自己的 readyState 绑定（追加块独立于文件头部的 pdfInit 绑定，互不影响）
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', pdfImgInit);
    } else {
        pdfImgInit();
    }
}
