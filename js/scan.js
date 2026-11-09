// ========== 文档扫描页（page-scan） ==========
// 仿手机"文档扫描"App：投影法自动检测文档边界（自适应白底/黑底）→ 角点透视矫正
// （自实现高斯消元求单应矩阵，双线性插值）→ 扫描增强（白底拉伸 / Otsu 二值化）。
// 纯函数只依赖 {data,width,height} 形态（data 需支持下标访问，如 Uint8ClampedArray），
// 便于 Node 环境对拍；全程浏览器本地完成，零依赖、不上传。

// ---------- 页面状态 ----------

var scanLoaded = false;       // 是否已加载图片（工作画布就绪）
var scanCtx = null;           // #scan-canvas 的 2d 上下文（工作分辨率）
var scanW = 0;                // 工作画布宽（大图已等比缩小，角点坐标系即此分辨率）
var scanH = 0;                // 工作画布高
var scanFileName = '';        // 原始文件名（下载时取主名拼 _scanned）
var scanOrigW = 0;            // 原图宽（未缩小，用于信息展示）
var scanOrigH = 0;            // 原图高
var scanCorners = null;       // 当前角点 {tl:{x,y}, tr, br, bl}（图像坐标系，可为小数）
var scanDragging = null;      // 正在拖拽的角点名（null = 未拖拽）
var scanResultBlob = null;    // 生成结果 Blob（下载用）
var scanResultUrl = '';       // 结果 objectURL（预览用，更换时释放）
var scanResultExt = 'jpg';    // 结果扩展名（按实际输出 MIME 决定）

// ============================================================
// 核心纯函数（module.exports 供 Node 对拍，均不做 DOM/canvas API 调用）
// ============================================================

// 灰度化：ITU-R BT.601 加权 0.299R + 0.587G + 0.114B，返回长度 w*h 的 Float32Array
function scanToGray(imageData) {
    var d = imageData.data;
    var n = imageData.width * imageData.height;
    var gray = new Float32Array(n);
    for (var i = 0, p = 0; i < n; i++, p += 4) {
        gray[i] = 0.299 * d[p] + 0.587 * d[p + 1] + 0.114 * d[p + 2];
    }
    return gray;
}

// 大津阈值（Otsu）：类间方差最大的灰度划分。
// 返回口径：取最优划分下"两类均值的中点"——双峰中间为空谷时（如黑白各半），
// 常规实现会取到首个最大值 t=0 偏向黑峰，取中点则落在谷中心，更符合"阈值在中间"的直觉。
// 全图同一灰度（无有效二分）时返回该灰度本身，保证不产生 NaN。
function scanOtsuThreshold(gray) {
    var hist = new Array(256);
    var i, t, v;
    for (i = 0; i < 256; i++) hist[i] = 0;
    var total = gray.length;
    for (i = 0; i < total; i++) {
        v = gray[i];
        // 浮点灰度四舍五入入桶（超出 [0,255] 的异常值截断）
        t = v <= 0 ? 0 : v >= 255 ? 255 : Math.round(v);
        hist[t]++;
    }
    var sumAll = 0;
    for (i = 0; i < 256; i++) sumAll += i * hist[i];

    var wB = 0, sumB = 0;
    var bestSigma = -1, bestMu0 = 0, bestMu1 = 0, found = false;
    // 遍历阈值 t：[0..t] 为前类，(t..255] 为后类；wB=0 / wF=0 的退化划分跳过
    for (t = 0; t < 255; t++) {
        wB += hist[t];
        if (wB === 0) continue;
        if (wB >= total) break;
        sumB += t * hist[t];
        var muB = sumB / wB;
        var muF = (sumAll - sumB) / (total - wB);
        var sigma = wB * (total - wB) * (muB - muF) * (muB - muF); // 类间方差（省略公共因子 1/total²）
        if (sigma > bestSigma) {
            bestSigma = sigma;
            bestMu0 = muB;
            bestMu1 = muF;
            found = true;
        }
    }
    if (!found) {
        // 全图纯色（如全白/全黑）：返回该灰度值
        for (t = 0; t < 256; t++) {
            if (hist[t] > 0) return t;
        }
        return 127; // 空数组兜底
    }
    return Math.round((bestMu0 + bestMu1) / 2);
}

// 自动边界检测：Otsu 二值化 + 行/列投影法。
// 自适应说明：常规"白底暗文档"场景前景 = 灰度 < otsu；但拍摄"黑底白文档"（如深色桌面
// 上的白纸）时前景定义需反转。这里统计四边 8% 边缘带的平均灰度判断背景明暗：
// 边缘平均 < 128 视为暗背景 → 前景 = 灰度 > otsu（亮文档），否则前景 = 灰度 < otsu（暗文档）。
// 返回 {tl,tr,br,bl} 四角；全图无前景（纯色图）时返回图片四角，由调用方提示。
function scanDetectBounds(gray, w, h) {
    var imgCorners = {
        tl: { x: 0, y: 0 }, tr: { x: w, y: 0 },
        br: { x: w, y: h }, bl: { x: 0, y: h }
    };
    var otsu = scanOtsuThreshold(gray);

    // 8% 边缘带平均灰度（取短边的 8% 作为带宽）
    var m = Math.max(1, Math.round(Math.min(w, h) * 0.08));
    var borderSum = 0, borderCnt = 0;
    var x, y;
    for (y = 0; y < h; y++) {
        var rowTop = y < m, rowBot = y >= h - m;
        for (x = 0; x < w; x++) {
            if (rowTop || rowBot || x < m || x >= w - m) {
                borderSum += gray[y * w + x];
                borderCnt++;
            }
        }
    }
    var darkBg = borderCnt > 0 && borderSum / borderCnt < 128;
    // 前前景判定闭包：darkBg 时亮为文档，否则暗为文档（见函数头自适应说明）
    function isFg(v) { return darkBg ? v > otsu : v < otsu; }

    // 行/列投影：逐行/逐列统计前景像素数
    var rowHist = new Array(h);
    var colHist = new Array(w);
    for (y = 0; y < h; y++) rowHist[y] = 0;
    for (x = 0; x < w; x++) colHist[x] = 0;
    var idx = 0;
    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++, idx++) {
            if (isFg(gray[idx])) {
                rowHist[y]++;
                colHist[x]++;
            }
        }
    }
    var maxRow = 0, maxCol = 0;
    for (y = 0; y < h; y++) if (rowHist[y] > maxRow) maxRow = rowHist[y];
    for (x = 0; x < w; x++) if (colHist[x] > maxCol) maxCol = colHist[x];
    if (maxRow <= 0 || maxCol <= 0) return imgCorners; // 纯色图：无前景

    // 投影阈值取各自最大值的 15%（抗噪：零星噪点不会撑开边界）
    var rowT = maxRow * 0.15, colT = maxCol * 0.15;
    var top = -1, bottom = -1, left = -1, right = -1;
    for (y = 0; y < h; y++) {
        if (rowHist[y] > rowT) { top = y; break; }
    }
    for (y = h - 1; y >= 0; y--) {
        if (rowHist[y] > rowT) { bottom = y; break; }
    }
    for (x = 0; x < w; x++) {
        if (colHist[x] > colT) { left = x; break; }
    }
    for (x = w - 1; x >= 0; x--) {
        if (colHist[x] > colT) { right = x; break; }
    }
    // 上面的 break 保证四个值必然被赋值；防御性兜底
    if (top < 0 || bottom < 0 || left < 0 || right < 0) return imgCorners;

    var corners = {
        tl: { x: left, y: top }, tr: { x: right, y: top },
        br: { x: right, y: bottom }, bl: { x: left, y: bottom }
    };

    // ---- 精化（加分项）：投影得到的是正包围矩形，对倾斜文档四角会偏保守。
    // 在矩形四角 ±8% 窗口内按"角点方向极值"微调（评分统一按"越小越优"：
    // tl 取 x+y 最小；tr 要 x 最大 y 最小即 y−x 最小；br 要 x+y 最大即 −(x+y) 最小；
    // bl 要 y 最大 x 最小即 x−y 最小）；窗口内无前景则保留矩形角。
    var rw = Math.max(1, Math.round(w * 0.08));
    var rh = Math.max(1, Math.round(h * 0.08));
    function refine(name, cx, cy, score) {
        var x0 = Math.max(0, cx - rw), x1 = Math.min(w - 1, cx + rw);
        var y0 = Math.max(0, cy - rh), y1 = Math.min(h - 1, cy + rh);
        var best = null, bestS = Infinity;
        for (var yy = y0; yy <= y1; yy++) {
            for (var xx = x0; xx <= x1; xx++) {
                if (!isFg(gray[yy * w + xx])) continue;
                var s = score(xx, yy);
                if (s < bestS) { bestS = s; best = { x: xx, y: yy }; }
            }
        }
        if (best) corners[name] = best;
    }
    refine('tl', left, top, function (xx, yy) { return xx + yy; });
    refine('tr', right, top, function (xx, yy) { return yy - xx; });
    refine('br', right, bottom, function (xx, yy) { return -(xx + yy); });
    refine('bl', left, bottom, function (xx, yy) { return xx - yy; });

    return corners;
}

// ---------- V2 边界检测：连通域 + 凸包 + 最大面积四边形 ----------
// 相比 V1（行列投影只能得到正置矩形），V2 通过"最大文档连通域 → 凸包 → 最大
// 面积四边形"找出倾斜文档的真实四角，支持任意旋转/透视角度的文档，
// 与手机扫描 App 的检测思路一致。

// V2 主入口：灰度图 → 候选四角（tl/tr/br/bl）；失败返回 null（由调用方降级 V1）
function scanDetectBoundsV2(gray, w, h) {
    // 检测在缩小的分辨率上做（性能：连通域 BFS 与凸包的输入量级受控），
    // 结果按比例映射回原分辨率
    var DS = 4;
    if (Math.max(w, h) / DS < 80) { DS = 1; }   // 小图不缩小
    var dw = Math.max(1, Math.floor(w / DS));
    var dh = Math.max(1, Math.floor(h / DS));

    // 1. 二值化（复用 Otsu + 边缘带极性自适应，与 V1 同口径）
    var otsu = scanOtsuThreshold(gray);
    var m = Math.max(1, Math.round(Math.min(w, h) * 0.08));
    var borderSum = 0, borderCnt = 0, x, y;
    for (y = 0; y < h; y++) {
        var rowTop = y < m, rowBot = y >= h - m;
        for (x = 0; x < w; x++) {
            if (rowTop || rowBot || x < m || x >= w - m) { borderSum += gray[y * w + x]; borderCnt++; }
        }
    }
    var darkBg = borderCnt > 0 && borderSum / borderCnt < 128;

    // 2. 缩小分辨率上的前景图（前景=文档）
    var fg = new Uint8Array(dw * dh);
    for (y = 0; y < dh; y++) {
        var sy = Math.min(h - 1, Math.floor((y + 0.5) * DS));
        for (x = 0; x < dw; x++) {
            var sx = Math.min(w - 1, Math.floor((x + 0.5) * DS));
            var v = gray[sy * w + sx];
            fg[y * dw + x] = (darkBg ? v > otsu : v < otsu) ? 1 : 0;
        }
    }

    // 3. 连通域标记（4 连通 BFS），取像素数最大的组件为文档主体。
    //    背景通常也是一大块连通域——但极性自适应后背景为"非前景"不参与标记，
    //    只有真正的文档（及文档上的贴纸等小块）会成为前景组件
    var label = new Int32Array(dw * dh);          // 0 = 未访问
    var compSizes = [0];                          // 下标 i 对应 label 值 i+1
    var queue = new Int32Array(dw * dh);
    var bestLabel = 0, bestSize = 0, curLabel = 0;
    for (var p0 = 0; p0 < fg.length; p0++) {
        if (fg[p0] && label[p0] === 0) {
            curLabel++;
            var qh = 0, qt = 0;
            queue[qt++] = p0;
            label[p0] = curLabel;
            var size = 0;
            while (qh < qt) {
                var cur = queue[qh++];
                size++;
                var cx = cur % dw, cy = (cur / dw) | 0;
                // 4 连通邻居
                if (cx > 0 && fg[cur - 1] && label[cur - 1] === 0) { label[cur - 1] = curLabel; queue[qt++] = cur - 1; }
                if (cx < dw - 1 && fg[cur + 1] && label[cur + 1] === 0) { label[cur + 1] = curLabel; queue[qt++] = cur + 1; }
                if (cy > 0 && fg[cur - dw] && label[cur - dw] === 0) { label[cur - dw] = curLabel; queue[qt++] = cur - dw; }
                if (cy < dh - 1 && fg[cur + dw] && label[cur + dw] === 0) { label[cur + dw] = curLabel; queue[qt++] = cur + dw; }
            }
            compSizes.push(size);
            if (size > bestSize) { bestSize = size; bestLabel = curLabel; }
        }
    }
    // 文档组件必须占画面一定比例（太小说明没拍到文档或纯噪声）
    if (bestSize < dw * dh * 0.05) { return null; }

    // 4. 收集文档组件的边界点（组件中至少一个邻居为背景/出界的像素），
    //    边界点数量远小于组件全部像素，凸包输入量级可控
    var boundary = [];
    for (y = 0; y < dh; y++) {
        for (x = 0; x < dw; x++) {
            var p = y * dw + x;
            if (label[p] !== bestLabel) { continue; }
            var isB = false;
            if (x === 0 || x === dw - 1 || y === 0 || y === dh - 1) { isB = true; }
            else if (!fg[p - 1] || !fg[p + 1] || !fg[p - dw] || !fg[p + dw]) { isB = true; }
            if (isB) { boundary.push({ x: x, y: y }); }
        }
    }
    if (boundary.length < 4) { return null; }

    // 5. 凸包（Andrew 单调链），再 Douglas-Peucker 式简化到 ≤ 48 点控制四边形搜索量
    var hull = scanConvexHull(boundary);
    while (hull.length > 48) {
        // 每轮移除"与前驱后继连线偏离最小"的顶点（保面积损失最小的简化）
        var worst = -1, worstLoss = Infinity;
        for (var i = 0; i < hull.length; i++) {
            var prev = hull[(i - 1 + hull.length) % hull.length];
            var next = hull[(i + 1) % hull.length];
            var loss = Math.abs((next.x - prev.x) * (prev.y - hull[i].y) - (prev.x - hull[i].x) * (next.y - prev.y)) / 2;
            if (loss < worstLoss) { worstLoss = loss; worst = i; }
        }
        hull.splice(worst, 1);
    }

    // 6. 凸包上最大面积四边形（h ≤ 48 时 C(48,4)≈19 万组合，暴力可接受）
    var quad = scanMaxAreaQuad(hull);
    if (!quad) { return null; }

    // 7. 四角命名（tl=左上 tr=右上 br=右下 bl=左下）+ 面积占比校验 + 映射回原分辨率
    var named = scanNameQuad(quad);
    // 面积占比用缩图面积（dw×dh）作分母——named 四角是缩图坐标，
    // 除以原图面积会缩小 DS² 倍导致误杀（31.7% 被算成 1.98%）
    var areaRatio = Math.abs(scanQuadArea(named)) / (dw * dh);
    if (areaRatio < 0.05) { return null; }        // 文档过小视为检测失败
    [named.tl, named.tr, named.br, named.bl].forEach(function (pt) {
        pt.x = Math.max(0, Math.min(w, Math.round(pt.x * DS)));
        pt.y = Math.max(0, Math.min(h, Math.round(pt.y * DS)));
    });
    return named;
}

// Andrew 单调链凸包（点数 n log n；输入为 {x,y} 数组）
function scanConvexHull(points) {
    if (points.length < 3) { return points.slice(); }
    var pts = points.slice().sort(function (a, b) { return a.x - b.x || a.y - b.y; });
    function cross(o, a, b) { return (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x); }
    var lower = [], upper = [];
    for (var i = 0; i < pts.length; i++) {
        while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], pts[i]) <= 0) { lower.pop(); }
        lower.push(pts[i]);
    }
    for (var j = pts.length - 1; j >= 0; j--) {
        while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], pts[j]) <= 0) { upper.pop(); }
        upper.push(pts[j]);
    }
    lower.pop(); upper.pop();
    return lower.concat(upper);
}

// 凸包上最大面积四边形（顶点序遍历暴力，h ≤ 48 时约 19 万组合可接受；
// 返回按凸包顺序排列的 4 点，或 null（顶点不足 4））
function scanMaxAreaQuad(hull) {
    if (hull.length < 4) { return null; }
    var h = hull.length;
    var best = null, bestArea = -1;
    for (var a = 0; a < h - 3; a++) {
        for (var b = a + 1; b < h - 2; b++) {
            for (var c = b + 1; c < h - 1; c++) {
                for (var d = c + 1; d < h; d++) {
                    var area = 0;
                    var pts = [hull[a], hull[b], hull[c], hull[d]];
                    for (var k = 0; k < 4; k++) {
                        var p1 = pts[k], p2 = pts[(k + 1) % 4];
                        area += p1.x * p2.y - p2.x * p1.y;
                    }
                    area = Math.abs(area) / 2;
                    if (area > bestArea) {
                        bestArea = area;
                        best = { tl: hull[a], tr: hull[b], br: hull[c], bl: hull[d] };
                    }
                }
            }
        }
    }
    return best;
}

// 四角按几何位置命名：tl=左上（x+y 最小）、br=右下（x+y 最大）、
// tr=右上（y−x 最大）、bl=左下（y−x 最小）
function scanNameQuad(quadPts) {
    var pts = [quadPts.tl, quadPts.tr, quadPts.br, quadPts.bl];
    var cx = 0, cy = 0;
    pts.forEach(function (p) { cx += p.x; cy += p.y; });
    cx /= 4; cy /= 4;
    var tl = pts[0], tr = pts[0], br = pts[0], bl = pts[0];
    pts.forEach(function (p) {
        if (p.x + p.y < tl.x + tl.y) { tl = p; }
        if (p.x + p.y > br.x + br.y) { br = p; }
        if (p.y - p.x > tr.y - tr.x) { tr = p; }
        if (p.y - p.x < bl.y - bl.x) { bl = p; }
    });
    return { tl: { x: tl.x, y: tl.y }, tr: { x: tr.x, y: tr.y }, br: { x: br.x, y: br.y }, bl: { x: bl.x, y: bl.y } };
}

// ---------- V3 边界检测：Sobel 梯度 + Hough 直线（应对低对比度场景） ----------
// V2（连通域+极性二值化）在"浅色文档 + 浅色背景"时会把背景当最大组件导致
// 四角铺满全图（真实用户案例：米色桌布上的浅色出生证明）。V3 不依赖颜色
// 极性：文档边缘的阴影线/色差线在梯度图上是强响应，用 Hough 变换找四条
// 最强边界直线（上/下/左/右各一），交点即四角。近正置拍摄效果最好，
// 大角度倾斜文档由 V2 兜底。

// ---------- V5 边界检测：OpenCV Canny + 轮廓 + 四边形逼近 ----------
// 真实拍照主力算法，依赖 js/vendor/opencv.js（页面按需加载，未加载时本
// 函数被降级链跳过）。流程：
//   RGBA→灰度 → GaussianBlur 去文字纹理 → Canny(自适应阈值) → 膨胀
//   → 外部轮廓 → 面积降序逐个 approxPolyDP → 首个"4 顶点且面积 ≥15%"
//   的轮廓即文档。营业执照实测：84% 大轮廓四角命中。
// 入参兼容两种形态：gray Float32Array（内部转 Mat）或 canvas ImageData
// （含 .data/.width/.height，内部转灰度后转 Mat）。
function scanDetectBoundsV5(gray, w, h) {
    if (typeof cv === 'undefined' || !cv || !cv.Mat) { return null; }

    // 归一化输入为 Uint8 灰度数组
    var u8;
    if (gray && gray.length === w * h) {
        u8 = new Uint8Array(w * h);
        for (var gi = 0; gi < w * h; gi++) { u8[gi] = Math.max(0, Math.min(255, Math.round(gray[gi]))); }
    } else if (gray && gray.data && gray.data.length === w * h * 4) {
        // ImageData 形态：RGBA 转灰度
        u8 = new Uint8Array(w * h);
        var d = gray.data;
        for (var pi = 0; pi < w * h; pi++) {
            u8[pi] = Math.round(0.299 * d[pi * 4] + 0.587 * d[pi * 4 + 1] + 0.114 * d[pi * 4 + 2]);
        }
    } else {
        return null;
    }

    var src = null, grayMat = null, blurred = null, edges = null;
    var kernel = null, dilated = null, contours = null, hierarchy = null;
    var approx = null, cnt = null;
    try {
        src = cv.matFromImageData
            ? null
            : null;   // techstark 构建无 matFromImageData，改手动填充
        // 构建灰度 Mat（CV_8UC1）
        grayMat = new cv.Mat(h, w, cv.CV_8UC1);
        grayMat.data.set(u8);

        // GaussianBlur 5x5 去文字纹理（营业执照实测：纹理梯度会稀释轮廓精度）
        blurred = new cv.Mat();
        cv.GaussianBlur(grayMat, blurred, new cv.Size(5, 5), 0);

        // Canny：先固定阈值尝试；若有效四边形轮廓不足再降阈值重试一次
        var bestQuad = null;
        var thresholdPairs = [[30, 90], [10, 50]];
        for (var ti = 0; ti < thresholdPairs.length && !bestQuad; ti++) {
            var lo = thresholdPairs[ti][0], hi = thresholdPairs[ti][1];
            edges = new cv.Mat();
            cv.Canny(blurred, edges, lo, hi);
            kernel = cv.Mat.ones(3, 3, cv.CV_8UC1);
            dilated = new cv.Mat();
            cv.dilate(edges, dilated, kernel);
            contours = new cv.MatVector();
            hierarchy = new cv.Mat();
            cv.findContours(dilated, contours, hierarchy, cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE);

            // 面积降序，逐个 approxPolyDP 找 4 顶点大轮廓
            var areas = [];
            for (var ci = 0; ci < contours.size(); ci++) {
                areas.push({ idx: ci, area: cv.contourArea(contours.get(ci)) });
            }
            areas.sort(function (a, b) { return b.area - a.area; });
            for (var k = 0; k < Math.min(8, areas.length) && !bestQuad; k++) {
                if (areas[k].area < w * h * 0.15) { break; }   // 面积降序，后续更小直接停
                var c = contours.get(areas[k].idx);
                var peri = cv.arcLength(c, true);
                approx = new cv.Mat();
                cv.approxPolyDP(c, approx, 0.02 * peri, true);
                if (approx.rows === 4) {
                    // 校验四角在画面 ±8% 内（轮廓可能贴照片边界）
                    var pts = [];
                    var ok = true;
                    for (var j = 0; j < 4; j++) {
                        var p = approx.intPtr(j);
                        if (p[0] < -w * 0.08 || p[0] > w * 1.08 || p[1] < -h * 0.08 || p[1] > h * 1.08) { ok = false; }
                        pts.push({ x: p[0], y: p[1] });
                    }
                    if (ok) {
                        // 命名四角：approxPolyDP 输出顶点沿轮廓连续有序，
                        // 先按质心角度排序为 tl→tr→br→bl 顺时针（图像坐标系 y 向下），
                        // 极值命名（x+y/x-y）对旋转文档会错位，改用质心方位角。
                        //   1) 求质心
                        var mcx = 0, mcy = 0;
                        pts.forEach(function (p) { mcx += p.x; mcy += p.y; });
                        mcx /= 4; mcy /= 4;
                        //   2) 按 atan2(y-cy, x-cx) 升序排列（图像 y 向下，atan2 升序
                        //      对应逆时针，取出的顺序为 [右上→右下→左下→左上]，
                        //      即标准四边形的 tr→br→bl→tl）
                        var sorted = pts.slice().sort(function (a, b) {
                            return Math.atan2(a.y - mcy, a.x - mcx) - Math.atan2(b.y - mcy, b.x - mcx);
                        });
                        //   3) 从最接近左上（质心方位角 -135°）的顶点起顺时针重排
                        var startIdx = 0, bestAng = Infinity;
                        sorted.forEach(function (p, si) {
                            var ang = Math.atan2(p.y - mcy, p.x - mcx);
                            // 归一到 (-π, π]，与 -135°(-2.356) 比较环距
                            var diff = Math.abs(ang - (-Math.PI * 0.75));
                            if (diff > Math.PI) { diff = Math.PI * 2 - diff; }
                            if (diff < bestAng) { bestAng = diff; startIdx = si; }
                        });
                        var tl = sorted[startIdx % 4], tr = sorted[(startIdx + 1) % 4];
                        var br = sorted[(startIdx + 2) % 4], bl = sorted[(startIdx + 3) % 4];
                        bestQuad = { tl: { x: tl.x, y: tl.y }, tr: { x: tr.x, y: tr.y }, br: { x: br.x, y: br.y }, bl: { x: bl.x, y: bl.y } };
                    }
                }
                approx.delete(); c.delete();
            }

            // 释放本轮资源（approx 已在轮廓循环内逐轮释放，此处不再重复）
            edges.delete(); kernel.delete(); dilated.delete(); contours.delete(); hierarchy.delete();
            edges = null; kernel = null; dilated = null; contours = null; hierarchy = null;
            if (bestQuad) { break; }
        }
        grayMat.delete(); blurred.delete();
        grayMat = null; blurred = null;
        return bestQuad;
    } catch (e) {
        // 异常时清理已分配的 Mat，避免 wasm 内存泄漏
        [src, grayMat, blurred, edges, kernel, dilated, contours, hierarchy, approx, cnt].forEach(function (m) {
            if (m) { try { m.delete(); } catch (e2) { /* 已释放 */ } }
        });
        throw e;
    }
}

function scanDetectBoundsV3(gray, w, h) {
    // 降采样到最长边 ~240px（Hough 运算量受控，精度足够：1px≈原图 1.5px）
    var DS = Math.max(1, Math.ceil(Math.max(w, h) / 240));
    var dw = Math.max(40, Math.floor(w / DS));
    var dh = Math.max(40, Math.floor(h / DS));
    var sm = new Float32Array(dw * dh);
    for (var y = 0; y < dh; y++) {
        for (var x = 0; x < dw; x++) {
            sm[y * dw + x] = gray[Math.min(h - 1, Math.floor((y + 0.5) * DS)) * w + Math.min(w - 1, Math.floor((x + 0.5) * DS))];
        }
    }

    // Sobel 梯度幅值（边缘一圈置 0，避免把照片边界当文档边界）
    var mag = new Float32Array(dw * dh);
    for (y = 1; y < dh - 1; y++) {
        for (x = 1; x < dw - 1; x++) {
            var i = y * dw + x;
            var tl = sm[i - dw - 1], t = sm[i - dw], tr = sm[i - dw + 1];
            var l = sm[i - 1], r = sm[i + 1];
            var bl = sm[i + dw - 1], b = sm[i + dw], br = sm[i + dw + 1];
            var gx = (tr + 2 * r + br) - (tl + 2 * l + bl);
            var gy = (bl + 2 * b + br) - (tl + 2 * t + tr);
            mag[i] = Math.sqrt(gx * gx + gy * gy);
        }
    }

    // 边缘点：幅值 ≥ 90 分位且 ≥ 12（双门槛去噪）；超量按幅值降序截断到 3000
    var mags = [];
    for (y = 1; y < dh - 1; y++) { for (x = 1; x < dw - 1; x++) { mags.push(mag[y * dw + x]); } }
    mags.sort(function (a, b) { return a - b; });
    var thr = Math.max(12, mags[Math.floor(mags.length * 0.90)]);
    var edgePts = [];
    for (y = 1; y < dh - 1; y++) {
        for (x = 1; x < dw - 1; x++) {
            var m2 = mag[y * dw + x];
            if (m2 >= thr && m2 > 12) { edgePts.push({ x: x, y: y, m: m2 }); }
        }
    }
    if (edgePts.length > 3000) {
        edgePts.sort(function (a, b) { return b.m - a.m; });
        edgePts = edgePts.slice(0, 3000);
    }
    if (edgePts.length < 40) { return null; }

    // Hough 变换：θ ∈ [0,180) 1° 步长，ρ 居中存储
    var diag = Math.ceil(Math.sqrt(dw * dw + dh * dh));
    var nTheta = 180, nRho = diag * 2 + 1;
    var acc = new Int32Array(nTheta * nRho);
    var cosT = [], sinT = [];
    for (var t = 0; t < nTheta; t++) {
        var a = t * Math.PI / 180;
        cosT.push(Math.cos(a)); sinT.push(Math.sin(a));
    }
    for (var e = 0; e < edgePts.length; e++) {
        var px = edgePts[e].x, py = edgePts[e].y;
        for (t = 0; t < nTheta; t++) {
            var rho = Math.round(px * cosT[t] + py * sinT[t]) + diag;
            if (rho >= 0 && rho < nRho) { acc[t * nRho + rho]++; }
        }
    }

    // 峰值提取（3×3 邻域非极大抑制）——水平/垂直分组独立阈值：
    // 左右边缘线在缩图上更短、对比度更低（实测 29/33 票 vs 上下 122/152 票），
    // 统一 35% 阈值会把左右线全部过滤，必须按本组最大票数的 25% 分别取阈
    function nmsGroup(thetaIsHoriz) {
        var groupMax = 0;
        for (var t2 = 0; t2 < nTheta; t2++) {
            var isH = Math.abs(Math.sin(t2 * Math.PI / 180)) >= 0.5;
            if (isH !== thetaIsHoriz) { continue; }
            for (var r3 = 0; r3 < nRho; r3++) { if (acc[t2 * nRho + r3] > groupMax) { groupMax = acc[t2 * nRho + r3]; } }
        }
        var gThr = Math.max(14, groupMax * 0.25);
        var found = [];
        for (var t = 0; t < nTheta; t++) {
            var isH2 = Math.abs(Math.sin(t * Math.PI / 180)) >= 0.5;
            if (isH2 !== thetaIsHoriz) { continue; }
            for (var r2 = 0; r2 < nRho; r2++) {
                var v = acc[t * nRho + r2];
                if (v < gThr) { continue; }
                var isPeak = true;
                for (var dt = -1; dt <= 1 && isPeak; dt++) {
                    for (var dr = -1; dr <= 1; dr++) {
                        if (dt === 0 && dr === 0) { continue; }
                        var tt = (t + dt + nTheta) % nTheta, rr = r2 + dr;
                        if (rr >= 0 && rr < nRho && acc[tt * nRho + rr] > v) { isPeak = false; break; }
                    }
                }
                if (isPeak) { found.push({ t: t, rho: r2 - diag, votes: v }); }
            }
        }
        found.sort(function (a, b) { return b.votes - a.votes; });
        return found;
    }
    var peaks = nmsGroup(true).concat(nmsGroup(false));
    if (peaks.length < 4) { return null; }
    peaks.sort(function (a, b) { return b.votes - a.votes; });

    // 分组：水平线（|sinθ| ≥ 0.5，法线偏竖直 → 直线偏水平）按位置分上下；
    // 垂直线（其余）按位置分左右。每组取票数最高的前 3 条组成候选
    function linePointX(p) {   // 垂直线在 y=dh/2 处的 x 坐标
        return Math.abs(Math.cos(p.t * Math.PI / 180)) > 1e-6
            ? (p.rho - (dh / 2) * Math.sin(p.t * Math.PI / 180)) / Math.cos(p.t * Math.PI / 180)
            : p.rho;
    }
    function linePointY(p) {   // 水平线在 x=dw/2 处的 y 坐标
        return Math.abs(Math.sin(p.t * Math.PI / 180)) > 1e-6
            ? (p.rho - (dw / 2) * Math.cos(p.t * Math.PI / 180)) / Math.sin(p.t * Math.PI / 180)
            : p.rho;
    }
    var horiz = [], vert = [];
    for (var pi = 0; pi < peaks.length && (horiz.length < 6 || vert.length < 6); pi++) {
        var pk = peaks[pi];
        var thetaRad = pk.t * Math.PI / 180;
        if (Math.abs(Math.sin(thetaRad)) >= 0.5) {
            var yy = linePointY(pk);
            if (yy > 2 && yy < dh - 2) { horiz.push({ pk: pk, pos: yy }); }
        } else {
            var xx = linePointX(pk);
            if (xx > 2 && xx < dw - 2) { vert.push({ pk: pk, pos: xx }); }
        }
    }
    if (horiz.length < 2 || vert.length < 2) { return null; }
    horiz.sort(function (a, b) { return a.pos - b.pos; });
    vert.sort(function (a, b) { return a.pos - b.pos; });

    // 两直线交点：解 x·cos1 + y·sin1 = ρ1 与 x·cos2 + y·sin2 = ρ2
    function intersect(p1, p2) {
        var c1 = Math.cos(p1.t * Math.PI / 180), s1 = Math.sin(p1.t * Math.PI / 180);
        var c2 = Math.cos(p2.t * Math.PI / 180), s2 = Math.sin(p2.t * Math.PI / 180);
        var d = c1 * s2 - s1 * c2;
        if (Math.abs(d) < 0.05) { return null; }   // 近平行
        return { x: (p1.rho * s2 - p2.rho * s1) / d, y: (p2.rho * c1 - p1.rho * c2) / d };
    }

    // 组合评分：上/下/左/右各取一条（优先票数，位置需构成合理四边形：
    // 面积占比 8%~98%、凸、交点均在画面 ±5% 内）；score = 总票数
    var bestQuad = null, bestScore = 0;
    var topList = horiz.slice(0, Math.min(3, Math.ceil(horiz.length / 2)));
    var botList = horiz.slice(Math.max(1, horiz.length - 3));
    var leftList = vert.slice(0, Math.min(3, Math.ceil(vert.length / 2)));
    var rightList = vert.slice(Math.max(1, vert.length - 3));
    for (var ti = 0; ti < topList.length; ti++) {
        for (var bi = 0; bi < botList.length; bi++) {
            if (botList[bi].pos <= topList[ti].pos + dh * 0.1) { continue; }   // 上下距离过近
            for (var li = 0; li < leftList.length; li++) {
                for (var ri = 0; ri < rightList.length; ri++) {
                    if (rightList[ri].pos <= leftList[li].pos + dw * 0.1) { continue; }
                    var cTL = intersect(topList[ti].pk, leftList[li].pk);
                    var cTR = intersect(topList[ti].pk, rightList[ri].pk);
                    var cBR = intersect(botList[bi].pk, rightList[ri].pk);
                    var cBL = intersect(botList[bi].pk, leftList[li].pk);
                    if (!cTL || !cTR || !cBR || !cBL) { continue; }
                    var quadPts = [cTL, cTR, cBR, cBL];
                    // 交点需在画面附近（±5% 余量）
                    var inBound = true;
                    for (var q = 0; q < 4; q++) {
                        if (quadPts[q].x < -dw * 0.05 || quadPts[q].x > dw * 1.05 ||
                            quadPts[q].y < -dh * 0.05 || quadPts[q].y > dh * 1.05) { inBound = false; break; }
                    }
                    if (!inBound) { continue; }
                    var area = 0;
                    for (q = 0; q < 4; q++) {
                        var pA = quadPts[q], pB = quadPts[(q + 1) % 4];
                        area += pA.x * pB.y - pB.x * pA.y;
                    }
                    area = Math.abs(area) / 2;
                    var ratio = area / (dw * dh);
                    if (ratio < 0.08 || ratio > 0.98) { continue; }
                    var votes = topList[ti].pk.votes + botList[bi].pk.votes + leftList[li].pk.votes + rightList[ri].pk.votes;
                    if (votes > bestScore) {
                        bestScore = votes;
                        bestQuad = { tl: cTL, tr: cTR, br: cBR, bl: cBL };
                    }
                }
            }
        }
    }
    if (!bestQuad) { return null; }

    // 映射回原分辨率 + clamp
    ['tl', 'tr', 'br', 'bl'].forEach(function (k) {
        bestQuad[k].x = Math.max(0, Math.min(w, Math.round(bestQuad[k].x * DS)));
        bestQuad[k].y = Math.max(0, Math.min(h, Math.round(bestQuad[k].y * DS)));
    });
    return bestQuad;
}

// ---------- V4 边界检测：边缘扫描 + RANSAC 直线拟合 ----------
// V3（全局 Hough）在证书边缘弯曲/被印章局部遮挡时失败：单一直线无法覆盖
// 整条边，票数被稀释。V4 改为"逐行/列扫描边缘点 + RANSAC 拟合"：
//   ① 大核模糊抹掉文字纹理（保留边界色差线）
//   ② Sobel 梯度
//   ③ 每行在左侧 45% 区域取最强梯度点 → 左边缘轨迹（右/上/下同理）
//   ④ 每条轨迹 RANSAC 直线拟合（内点占比达标才接受）
//   ⑤ 四线交点 → 四角。弯曲边缘时 RANSAC 拟合主体段，交点仍接近真实角。

// 两点式直线：用 {nx, ny, rho}（单位法线 + 原点距）表示，便于求交点
function scanV4LineFromPts(pts) {
    // 最小二乘拟合（x = a*y + b 或 y = a*x + b 按跨度自选），再转法线式
    var n = pts.length;
    var sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
    for (var i = 0; i < n; i++) { sx += pts[i].x; sy += pts[i].y; sxx += pts[i].x * pts[i].x; syy += pts[i].y * pts[i].y; sxy += pts[i].x * pts[i].y; }
    var dx = sxx - sx * sx / n, dy = syy - sy * sy / n;
    var line = {};
    if (Math.abs(dx) >= Math.abs(dy)) {
        // y = a*x + b
        var a = (sxy - sx * sy / n) / (dx || 1e-9);
        var b = (sy - a * sx) / n;
        line.a = a; line.b = b; line.vertical = false;
        line.nx = a / Math.sqrt(a * a + 1); line.ny = -1 / Math.sqrt(a * a + 1);
        line.rho = Math.abs(line.ny) * b / line.ny * -1; // 占位，交点计算用 a/b
    } else {
        var a2 = (sxy - sx * sy / n) / (dy || 1e-9);
        var b2 = (sx - a2 * sy) / n;
        line.a = a2; line.b = b2; line.vertical = true;
        line.nx = -1 / Math.sqrt(a2 * a2 + 1); line.ny = a2 / Math.sqrt(a2 * a2 + 1);
    }
    line.getX = line.vertical ? function (y) { return line.a * y + line.b; } : null;
    line.getY = line.vertical ? null : function (x) { return line.a * x + line.b; };
    return line;
}

// 两直线交点（line getX/getY 形式）
function scanV4Intersect(l1, l2) {
    // l1: y = a1*x + b1（或 x = a*y + b）；统一转为 y=ax+b 与 x=cy+d 求交
    function toXY(line) {
        if (line.vertical) { return { getX: function (y) { return line.a * y + line.b; }, getY: function (x) { return (x - line.b) / (line.a || 1e-9); } }; }
        return { getX: function (y) { return (y - line.b) / (line.a || 1e-9); }, getY: function (x) { return line.a * x + line.b; } };
    }
    var A = toXY(l1), B = toXY(l2);
    // y = A.getY(x)，x = B.getX(y) → 迭代一次代入：x = B.getX(A.getY(x))
    var x = (l1.vertical || l2.vertical) ? (l1.vertical ? B.a * l1.b + B.b : l1.b) : 0;
    if (l1.vertical) { x = l1.a * ((l2.vertical ? 0 : (l2.b + l2.a * 0)) ) + l1.b; }
    // 直接解方程避免分支错误：y1(x) = a1 x + b1（非垂直时）；x2(y) = a2 y + b2（垂直时）
    // 情形1：l1 非垂直（y=a1x+b1），l2 垂直（x=a2y+b2）→ y = a1(a2y+b2)+b1 → y(1-a1a2)=a1b2+b1
    if (!l1.vertical && l2.vertical) {
        var y1 = (l1.a * l2.b + l1.b) / (1 - l1.a * l2.a);
        return { x: l2.a * y1 + l2.b, y: y1 };
    }
    if (l1.vertical && !l2.vertical) {
        var x2 = l2.getY ? l2.getY(0) : 0;
        var xx = l2.a === undefined ? 0 : 0;
        // l2 非垂直：y = a2 x + b2；x = l1.a * y + l1.b → y = a2(l1.a y + l1.b) + l2.b
        var y2 = (l2.a * l1.b + l2.b) / (1 - l2.a * l1.a);
        return { x: l1.a * y2 + l1.b, y: y2 };
    }
    if (l1.vertical && l2.vertical) {
        return { x: l1.b, y: l2.b };   // 两条垂直线不相交（应不发生）
    }
    var xa = (l2.b - l1.b) / (l1.a - l2.a || 1e-9);
    return { x: xa, y: l1.a * xa + l1.b };
}

// V4 主入口：gray → {tl,tr,br,bl} 四角（缩图坐标由调用方提供原分辨率灰度即可，
// 内部自带降采样）；任一边拟合失败返回 null（调用方降级）
function scanDetectBoundsV4(gray, w, h) {
    // 1. 双重 box blur r=2 抹文字纹理（与实验一致）
    function blur(src, r) {
        var out = new Float32Array(src.length);
        for (var y = 0; y < h; y++) for (var x = 0; x < w; x++) {
            var sum = 0, cnt = 0;
            for (var dy = -r; dy <= r; dy++) for (var dx = -r; dx <= r; dx++) {
                var xx = x + dx, yy = y + dy;
                if (xx >= 0 && xx < w && yy >= 0 && yy < h) { sum += src[yy * w + xx]; cnt++; }
            }
            out[y * w + x] = sum / cnt;
        }
        return out;
    }
    var sm = blur(blur(gray, 2), 2);

    // 2. Sobel 梯度
    var mag = new Float32Array(w * h);
    for (var y = 1; y < h - 1; y++) {
        for (var x = 1; x < w - 1; x++) {
            var i = y * w + x;
            var gx = (sm[i - w + 1] + 2 * sm[i + 1] + sm[i + w + 1]) - (sm[i - w - 1] + 2 * sm[i - 1] + sm[i + w - 1]);
            var gy = (sm[i + w - 1] + 2 * sm[i + w] + sm[i + w + 1]) - (sm[i - w - 1] + 2 * sm[i - w] + sm[i - w + 1]);
            mag[i] = Math.sqrt(gx * gx + gy * gy);
        }
    }

    // 3. 四边轨迹点收集（边距 3%，轨迹区 42%；每 2px 采样一个点控制量级）
    //    关键：文字纹理的梯度与边界相当甚至更强（实测内点率 1~5%），
    //    仅取"每行最强点"不够——再用整行梯度 90 分位做强度门槛过滤：
    //    边界色差线是持续性强边缘，行内 90 分位会高于纯文字行
    var margin = { x: Math.round(w * 0.03), y: Math.round(h * 0.03) };
    var leftPts = [], rightPts = [], topPts = [], botPts = [];
    var rowQ90 = [];
    for (y = margin.y; y < h - margin.y; y++) {
        var rowVals = [];
        for (x = margin.x; x < w - margin.x; x += 2) { rowVals.push(mag[y * w + x]); }
        rowVals.sort(function (a, b) { return a - b; });
        rowQ90.push(rowVals[Math.floor(rowVals.length * 0.9)] || 0);
    }
    var colQ90 = [];
    for (x = margin.x; x < w - margin.x; x++) {
        var colVals = [];
        for (y = margin.y; y < h - margin.y; y += 2) { colVals.push(mag[y * w + x]); }
        colVals.sort(function (a, b) { return a - b; });
        colQ90.push(colVals[Math.floor(colVals.length * 0.9)] || 0);
    }
    for (y = margin.y; y < h - margin.y; y += 2) {
        var lineThrL = Math.max(8, rowQ90[(y - margin.y)] * 0.8);
        var lineThrR = lineThrL;
        var bestL = -1, bestLv = 0, bestR = -1, bestRv = 0;
        for (x = margin.x; x < Math.round(w * 0.48); x += 2) {
            var v = mag[y * w + x];
            if (v > bestLv) { bestLv = v; bestL = x; }
        }
        for (x = Math.round(w * 0.52); x < w - margin.x; x += 2) {
            v = mag[y * w + x];
            if (v > bestRv) { bestRv = v; bestR = x; }
        }
        if (bestL > 0 && bestLv > 8 && bestLv >= lineThrL) { leftPts.push({ x: bestL, y: y }); }
        if (bestR > 0 && bestRv > 8 && bestRv >= lineThrR) { rightPts.push({ x: bestR, y: y }); }
    }
    for (x = margin.x; x < w - margin.x; x += 2) {
        var colThr = Math.max(8, colQ90[(x - margin.x)] * 0.8);
        var bestT = -1, bestTv = 0, bestB = -1, bestBv = 0;
        for (y = margin.y; y < Math.round(h * 0.48); y += 2) {
            v = mag[y * w + x];
            if (v > bestTv) { bestTv = v; bestT = y; }
        }
        for (y = Math.round(h * 0.52); y < h - margin.y; y += 2) {
            v = mag[y * w + x];
            if (v > bestBv) { bestBv = v; bestB = y; }
        }
        if (bestT > 0 && bestTv > 8 && bestTv >= colThr) { topPts.push({ x: x, y: bestT }); }
        if (bestB > 0 && bestBv > 8 && bestBv >= colThr) { botPts.push({ x: x, y: bestB }); }
    }

    // 4. 每条轨迹 RANSAC 直线拟合：以首末点连线为初始模型，取距离中位数 3× 内的点重拟合
    function fitLine(pts) {
        if (pts.length < 12) { return null; }
        // 真 RANSAC：随机采两点建线模型（首末点初始化会被跨段杂点破坏——
        // 实测轨迹里证书外边界与绿色内边框混在一起，首末点分属两条线），
        // 迭代 30 次取内点最多的模型；内点按 x/y 排序后最小二乘精化
        function lineNorm(p1, p2) {
            var dx = p2.x - p1.x, dy = p2.y - p1.y;
            var len = Math.sqrt(dx * dx + dy * dy) || 1;
            return { nx: -dy / len, ny: dx / len, px: p1.x, py: p1.y };
        }
        var rndState = 987654321;
        function rnd() { rndState = (rndState * 1103515245 + 12345) & 0x7fffffff; return rndState / 0x7fffffff; }
        var bestInliers = null, bestCount = 0;
        var total = pts.length;
        for (var it = 0; it < 30; it++) {
            var i1 = Math.floor(rnd() * total), i2 = Math.floor(rnd() * total);
            if (i1 === i2) { continue; }
            var L = lineNorm(pts[i1], pts[i2]);
            var inliers = [];
            for (var i = 0; i < total; i++) {
                var d = Math.abs((pts[i].x - L.px) * L.nx + (pts[i].y - L.py) * L.ny);
                if (d < 5) { inliers.push(pts[i]); }
            }
            if (inliers.length > bestCount) { bestCount = inliers.length; bestInliers = inliers; }
        }
        if (!bestInliers || bestCount < Math.max(12, total * 0.25)) { return null; }   // 主导线段不足 25% 视为失败
        // 内点范围截断：内点沿轨迹可能有少量离群段（如证书下边左段是桌布阴影、
        // 右段是证书边缘，两段高度不同），取内点投影坐标的 10%~90% 分位截断，
        // 只保留主体段再做最终拟合，避免两段异构点互相拉偏截距
        var proj = bestInliers.map(function (p) {
            return (bestInliers === bestInliers) ? p.x * bestInliers.length + p.y : 0;   // 投影值仅用于排序
        });
        var sorted = bestInliers.slice().sort(function (a, b) {
            return (a.x + a.y) - (b.x + b.y);   // 沿轨迹单调方向排序（x+y 与边方向单调）
        });
        var lo = Math.floor(sorted.length * 0.10), hi = Math.ceil(sorted.length * 0.90);
        var trimmed = sorted.slice(lo, hi);
        return scanV4LineFromPts(trimmed.length >= 8 ? trimmed : bestInliers);
    }

    var lLine = fitLine(leftPts), rLine = fitLine(rightPts);
    var tLine = fitLine(topPts), bLine = fitLine(botPts);
    if (!lLine || !rLine || !tLine || !bLine) { return null; }

    // 5. 交点 → 四角
    var TL = scanV4Intersect(tLine, lLine);
    var TR = scanV4Intersect(tLine, rLine);
    var BR = scanV4Intersect(bLine, rLine);
    var BL = scanV4Intersect(bLine, lLine);
    if (!TL || !TR || !BR || !BL) { return null; }
    var quad = { tl: TL, tr: TR, br: BR, bl: BL };

    // 6. 校验：面积占比 10%~99%、交点在画面 ±8% 内
    var area = Math.abs(scanQuadArea(quad)) / (w * h);
    if (area < 0.10 || area > 0.99) { return null; }
    var keys = ['tl', 'tr', 'br', 'bl'];
    for (var k = 0; k < 4; k++) {
        var pt = quad[keys[k]];
        if (pt.x < -w * 0.08 || pt.x > w * 1.08 || pt.y < -h * 0.08 || pt.y > h * 1.08) { return null; }
        if (isNaN(pt.x) || isNaN(pt.y)) { return null; }
    }
    return quad;
}

// 求输出尺寸：宽 = 上/下边长较大者，高 = 左/右边长较大者（透视下对边不等长，取大者不裁内容）
function scanOutputSize(corners) {
    function dist(a, b) {
        var dx = a.x - b.x, dy = a.y - b.y;
        return Math.sqrt(dx * dx + dy * dy);
    }
    var w = Math.max(dist(corners.tl, corners.tr), dist(corners.bl, corners.br));
    var h = Math.max(dist(corners.tl, corners.bl), dist(corners.tr, corners.br));
    return { w: Math.max(1, Math.round(w)), h: Math.max(1, Math.round(h)) };
}

// 四角围成的面积（鞋带公式），scanApply 用于退化（共线/过小）保护
function scanQuadArea(c) {
    return Math.abs(
        (c.tl.x * c.tr.y - c.tr.x * c.tl.y) +
        (c.tr.x * c.br.y - c.br.x * c.tr.y) +
        (c.br.x * c.bl.y - c.bl.x * c.br.y) +
        (c.bl.x * c.tl.y - c.tl.x * c.bl.y)
    ) / 2;
}

// 计算 3×3 单应矩阵 H（h[8]=1）：toPts ≅ H·fromPts（齐次）。
// 每组对应点展开 2 个方程，4 组共 8 元线性方程组，高斯消元（部分主元）自实现，不引库。
// 返回长度 9 的数组 [h0..h8]；退化输入（四点共线）时结果无意义，由调用方前置校验。
function scanBuildHomography(fromPts, toPts) {
    var rows = []; // 8×9 增广矩阵
    for (var i = 0; i < 4; i++) {
        var x = fromPts[i].x, y = fromPts[i].y;
        var u = toPts[i].x, v = toPts[i].y;
        // u = (h0·x + h1·y + h2) / (h6·x + h7·y + 1) 移项线性化，v 同理
        rows.push([x, y, 1, 0, 0, 0, -x * u, -y * u, u]);
        rows.push([0, 0, 0, x, y, 1, -x * v, -y * v, v]);
    }

    // 前向消元（每列选绝对值最大的行作主元，提高数值稳定性）
    var n = 8, c, r;
    for (c = 0; c < n; c++) {
        var piv = c;
        for (r = c + 1; r < n; r++) {
            if (Math.abs(rows[r][c]) > Math.abs(rows[piv][c])) piv = r;
        }
        var tmp = rows[c]; rows[c] = rows[piv]; rows[piv] = tmp;
        var pv = rows[c][c];
        if (Math.abs(pv) < 1e-12) continue; // 近似奇异列，跳过（回代时兜底为 0）
        for (r = c + 1; r < n; r++) {
            var f = rows[r][c] / pv;
            if (f === 0) continue;
            for (var k = c; k <= n; k++) rows[r][k] -= f * rows[c][k];
        }
    }

    // 回代解 h0..h7
    var h = new Array(9);
    for (r = n - 1; r >= 0; r--) {
        var s = rows[r][n];
        for (c = r + 1; c < n; c++) s -= rows[r][c] * h[c];
        h[r] = Math.abs(rows[r][r]) < 1e-12 ? 0 : s / rows[r][r];
    }
    h[8] = 1;
    return h;
}

// 透视矫正：把 corners（tl/tr/br/bl，源图坐标）围成的四边形矫正为 outW×outH 矩形。
// 做法：直接求"目标矩形 → 源四边形"的单应（等价于源→目标单应的逆 H⁻¹），
// 对目标每像素 (x,y) 逆映射回源坐标，双线性插值取色；源图范围外（半像素容差）填白。
// 透明像素按白底合成（a/255 折算），输出恒不透明——扫描件通常要铺在白纸上。
// 返回 {data: Uint8ClampedArray, width, height}（浏览器侧再升级为 ImageData 实例）。
function scanPerspectiveCrop(imageData, corners, outW, outH) {
    var w = imageData.width, h = imageData.height, sd = imageData.data;
    outW = Math.max(1, Math.round(outW));
    outH = Math.max(1, Math.round(outH));
    var out = { data: new Uint8ClampedArray(outW * outH * 4), width: outW, height: outH };
    var od = out.data;

    // 目标矩形四角 ↔ 源四角，求目标→源的逆映射单应
    var H = scanBuildHomography(
        [{ x: 0, y: 0 }, { x: outW, y: 0 }, { x: outW, y: outH }, { x: 0, y: outH }],
        [corners.tl, corners.tr, corners.br, corners.bl]
    );

    var whiteR = 255, whiteG = 255, whiteB = 255;
    for (var y = 0; y < outH; y++) {
        for (var x = 0; x < outW; x++) {
            var o = (y * outW + x) * 4;
            var den = H[6] * x + H[7] * y + 1;
            if (Math.abs(den) < 1e-12) { // 分母≈0：映射到无穷远，按出界填白
                od[o] = whiteR; od[o + 1] = whiteG; od[o + 2] = whiteB; od[o + 3] = 255;
                continue;
            }
            var sx = (H[0] * x + H[1] * y + H[2]) / den;
            var sy = (H[3] * x + H[4] * y + H[5]) / den;
            // 出界判定带半像素容差：落在 [-0.5, w-0.5] 内视为可采样（避免浮点误差误判出界）
            if (sx < -0.5 || sx > w - 0.5 || sy < -0.5 || sy > h - 0.5) {
                od[o] = whiteR; od[o + 1] = whiteG; od[o + 2] = whiteB; od[o + 3] = 255;
                continue;
            }
            // 双线性插值：坐标夹回 [0, w-1]/[0, h-1] 防止取邻域时越界
            var cx = sx < 0 ? 0 : sx > w - 1 ? w - 1 : sx;
            var cy = sy < 0 ? 0 : sy > h - 1 ? h - 1 : sy;
            var x0 = Math.floor(cx), y0 = Math.floor(cy);
            var x1 = x0 + 1 < w ? x0 + 1 : w - 1;
            var y1 = y0 + 1 < h ? y0 + 1 : h - 1;
            var fx = cx - x0, fy = cy - y0;
            var w00 = (1 - fx) * (1 - fy), w10 = fx * (1 - fy);
            var w01 = (1 - fx) * fy, w11 = fx * fy;
            var p00 = (y0 * w + x0) * 4, p10 = (y0 * w + x1) * 4;
            var p01 = (y1 * w + x0) * 4, p11 = (y1 * w + x1) * 4;
            // R/G/B/A 四通道分别插值
            var r = sd[p00] * w00 + sd[p10] * w10 + sd[p01] * w01 + sd[p11] * w11;
            var g = sd[p00 + 1] * w00 + sd[p10 + 1] * w10 + sd[p01 + 1] * w01 + sd[p11 + 1] * w11;
            var b = sd[p00 + 2] * w00 + sd[p10 + 2] * w10 + sd[p01 + 2] * w01 + sd[p11 + 2] * w11;
            var a = sd[p00 + 3] * w00 + sd[p10 + 3] * w10 + sd[p01 + 3] * w01 + sd[p11 + 3] * w11;
            // 白底合成：rgb·(a/255) + 255·(1 − a/255)；不透明输入（a=255）时即原值
            var ra = a / 255;
            od[o] = r * ra + 255 * (1 - ra);
            od[o + 1] = g * ra + 255 * (1 - ra);
            od[o + 2] = b * ra + 255 * (1 - ra);
            od[o + 3] = 255;
        }
    }
    return out;
}

// 扫描增强：
//   none —— 原样返回副本（输入不被修改，便于对拍复用）
//   auto —— 白底增强：灰度直方图 2%~98% 百分位线性拉伸（灰底拉到 255、文字压暗），
//           但按同一系数缩放 RGB 三通道（保留彩色信息，不退化为灰度图）
//   bw   —— 黑白文档：灰度 + Otsu 二值化，暗（前景/文字）= 0、亮（背景/纸面）= 255
function scanEnhance(imageData, mode) {
    var w = imageData.width, h = imageData.height;
    var out = { data: new Uint8ClampedArray(imageData.data), width: w, height: h };
    if (!mode || mode === 'none') return out;

    var gray = scanToGray(imageData);
    var n = w * h, i, p;

    if (mode === 'bw') {
        var t = scanOtsuThreshold(gray);
        for (i = 0, p = 0; i < n; i++, p += 4) {
            var v = gray[i] < t ? 0 : 255; // 前景（暗）黑、背景（亮）白
            out.data[p] = v; out.data[p + 1] = v; out.data[p + 2] = v;
            out.data[p + 3] = 255;
        }
        return out;
    }

    if (mode === 'auto') {
        // 灰度直方图求 2%/98% 百分位（避免对大图排序）
        var hist = new Array(256);
        for (i = 0; i < 256; i++) hist[i] = 0;
        for (i = 0; i < n; i++) {
            var bin = gray[i] <= 0 ? 0 : gray[i] >= 255 ? 255 : Math.round(gray[i]);
            hist[bin]++;
        }
        var lowCut = n * 0.02, highCut = n * 0.98;
        var cum = 0, low = -1, high = -1;
        for (i = 0; i < 256; i++) {
            cum += hist[i];
            if (low < 0 && cum >= lowCut) low = i;
            if (high < 0 && cum >= highCut) { high = i; break; }
        }
        if (low < 0) low = 255;
        if (high < 0) high = 255;
        if (high <= low) return out; // 近乎纯色，无动态范围可拉伸

        var scale = 255 / (high - low); // 拉伸系数：low→0、high→255
        var d = imageData.data;
        for (i = 0, p = 0; i < n; i++, p += 4) {
            // 同一系数缩放 RGB（各通道减 low 再乘 scale），白底拉满、深色压暗，色调不变
            out.data[p] = (d[p] - low) * scale;
            out.data[p + 1] = (d[p + 1] - low) * scale;
            out.data[p + 2] = (d[p + 2] - low) * scale;
            // alpha 保留（输入一般不透明；透视矫正阶段已统一铺白）
        }
        return out;
    }

    return out; // 未知模式按原图返回
}

// Node 对拍导出（浏览器环境 module 未定义，自动跳过）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        scanToGray: scanToGray,
        scanOtsuThreshold: scanOtsuThreshold,
        scanDetectBounds: scanDetectBounds,
        scanOutputSize: scanOutputSize,
        scanQuadArea: scanQuadArea,
        scanBuildHomography: scanBuildHomography,
        scanPerspectiveCrop: scanPerspectiveCrop,
        scanEnhance: scanEnhance,
        scanDetectBoundsV2: scanDetectBoundsV2,
        scanDetectBoundsV3: scanDetectBoundsV3,
        scanDetectBoundsV5: scanDetectBoundsV5,
        scanDetectBoundsV4: scanDetectBoundsV4
    };
}

// ============================================================
// 页面交互（以下含 DOM/canvas 调用，仅浏览器执行）
// ============================================================

// ---------- 文件加载 ----------

// 读取选中文件 → Image → 绘制到工作画布（过大先缩小）→ 重置角点并自动检测
function scanHandleFile(file) {
    if (!file) return;
    if (file.type && !/^image\//.test(file.type)) {
        showNotification('❌ 请选择图片文件');
        return;
    }
    var reader = new FileReader();
    reader.onerror = function () { showNotification('❌ 文件读取失败'); };
    reader.onload = function (e) {
        var img = new Image();
        img.onload = function () { scanLoadImage(img, file); };
        img.onerror = function () { showNotification('❌ 图片加载失败，请确认是有效图片'); };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// 图片就绪：按"长边 > 4000 → 等比缩至 2000"的性能口径落到工作画布，再触发自动检测
function scanLoadImage(img, file) {
    var canvas = document.getElementById('scan-canvas');
    var w = img.naturalWidth, h = img.naturalHeight;
    if (w <= 0 || h <= 0) { showNotification('❌ 图片尺寸无效'); return; }
    // 性能保护：超大图检测/矫正开销大，先等比缩到 2000px 长边处理（输出即矫正后的工作分辨率）
    if (Math.max(w, h) > 4000) {
        var s = 2000 / Math.max(w, h);
        w = Math.max(1, Math.round(w * s));
        h = Math.max(1, Math.round(h * s));
        showNotification('ℹ️ 图片较大，已等比缩至 ' + w + ' × ' + h + ' 处理');
    }
    canvas.width = w;
    canvas.height = h;
    scanCtx = canvas.getContext('2d', { willReadFrequently: true });
    scanCtx.clearRect(0, 0, w, h);
    scanCtx.drawImage(img, 0, 0, w, h);

    scanLoaded = true;
    scanW = w; scanH = h;
    scanFileName = file ? file.name : 'document';
    scanOrigW = img.naturalWidth;
    scanOrigH = img.naturalHeight;
    // 极小图提示（仍允许处理）
    if (Math.min(scanOrigW, scanOrigH) < 100) {
        showNotification('⚠️ 图片较小（小于 100px），检测与矫正效果可能不佳');
    }

    // 清掉上一张的结果
    scanClearResult();

    var wrap = document.getElementById('scan-preview-wrap');
    wrap.style.display = '';
    scanResetCorners(true);
    // 加载后自动跑一次边界检测并把角点摆到位
    scanAutoDetect(true);
}

// ---------- 角点管理 ----------

// 恢复角点为图片四角（silent = true 时不弹提示，供加载流程内部调用）
function scanResetCorners(silent) {
    if (!scanLoaded) {
        if (!silent) showNotification('请先选择图片');
        return;
    }
    scanCorners = {
        tl: { x: 0, y: 0 }, tr: { x: scanW, y: 0 },
        br: { x: scanW, y: scanH }, bl: { x: 0, y: scanH }
    };
    scanLayoutCorners();
    if (!silent) showNotification('已恢复为图片四角');
}

// 角点圆点定位：用百分比定位（x/W×100%），窗口缩放时 CSS 自动跟随，无需监听 resize
function scanLayoutCorners() {
    if (!scanLoaded || !scanCorners) return;
    var els = document.querySelectorAll('#scan-preview-wrap .scan-corner');
    for (var i = 0; i < els.length; i++) {
        var name = els[i].getAttribute('data-corner');
        var c = scanCorners[name];
        if (!c) continue;
        els[i].style.left = (c.x / scanW * 100) + '%';
        els[i].style.top = (c.y / scanH * 100) + '%';
    }
}

// 拖拽：鼠标 + 触摸共用坐标换算（显示坐标 × naturalWidth/clientWidth 即图像坐标）
function scanStartDrag(name) {
    scanDragging = name;
    var el = document.querySelector('#scan-preview-wrap .scan-corner[data-corner="' + name + '"]');
    if (el) el.classList.add('active');
}

function scanMoveDrag(clientX, clientY) {
    if (!scanDragging || !scanLoaded) return;
    var canvas = document.getElementById('scan-canvas');
    var rect = canvas.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    var x = (clientX - rect.left) / rect.width * scanW;
    var y = (clientY - rect.top) / rect.height * scanH;
    // 限制在图片范围内
    if (x < 0) x = 0; if (x > scanW) x = scanW;
    if (y < 0) y = 0; if (y > scanH) y = scanH;
    scanCorners[scanDragging] = { x: x, y: y };
    scanLayoutCorners();
}

function scanEndDrag() {
    if (!scanDragging) return;
    var el = document.querySelector('#scan-preview-wrap .scan-corner[data-corner="' + scanDragging + '"]');
    if (el) el.classList.remove('active');
    scanDragging = null;
}

// ---------- 自动检测 ----------

// 对工作画布跑一次 scanDetectBounds 并把角点摆到位（auto = true 供加载后自动调用）
function scanAutoDetect(auto) {
    if (!scanLoaded) {
        showNotification('请先选择图片');
        return;
    }
    var imgData = scanCtx.getImageData(0, 0, scanW, scanH);
    var gray = scanToGray(imgData);
    // 五级降级链（按场景适配性排序）：
    //   V5 OpenCV Canny+轮廓+四边形逼近——真实拍照主力算法（营业执照
    //      实测 84% 大轮廓四角命中），低对比度/倾斜通吃，依赖 opencv.js
    //   V3 Hough 直线——浅色文档+浅色背景（无 OpenCV 时的替代主力）
    //   V4 RANSAC 边缘扫描——边缘弯曲/局部遮挡（文字密集证书）
    //   V2 连通域+凸包——高对比度倾斜文档
    //   V1 行列投影——只找正置矩形，最后兜底
    var detectName = '';
    var b = null;
    if (typeof cv !== 'undefined' && cv && cv.Mat) {
        try {
            b = scanDetectBoundsV5(imgData, scanW, scanH);
            if (b) { detectName = 'OpenCV 轮廓'; }
        } catch (eV5) {
            console.warn('V5 检测异常，降级下一算法:', eV5 && eV5.message ? eV5.message : eV5);
            b = null;
        }
    }
    if (!b) {
        b = scanDetectBoundsV3(gray, scanW, scanH);
        if (b) { detectName = '直线检测'; }
    }
    if (!b) {
        b = scanDetectBoundsV4(gray, scanW, scanH);
        if (b) { detectName = '边缘拟合'; }
    }
    if (!b) {
        b = scanDetectBoundsV2(gray, scanW, scanH);
        if (b) { detectName = '区域轮廓'; }
    }
    if (!b) { b = scanDetectBounds(gray, scanW, scanH); detectName = '快速矩形'; }
    scanCorners = b;
    scanLayoutCorners();
    // 检测结果几乎铺满全图 → 视为未找到明显文档边界（纯色图也走此分支）
    var full = b.tl.x <= 1 && b.tl.y <= 1 && b.br.x >= scanW - 2 && b.br.y >= scanH - 2;
    if (full) {
        showNotification('⚠️ 未检测到明显的文档边界，已铺满四角，请手动拖动角点框选');
    } else if (!auto) {
        showNotification('✅ 已自动检测文档边界（' + detectName + '），可拖动角点微调');
    }
}

// ---------- 矫正并生成 ----------

// 读增强选项当前值（无选中兜底 none）
function scanGetEnhance() {
    var el = document.querySelector('input[name="scan-enhance"]:checked');
    return el ? el.value : 'none';
}

// 读输出格式当前值（无选中兜底 JPEG）
function scanGetFormat() {
    var el = document.querySelector('input[name="scan-out-format"]:checked');
    return el ? el.value : 'image/jpeg';
}

// 纯算法返回 {data,width,height} 普通对象；putImageData 需要 ImageData 实例，此处升级
// （ImageData 构造器按引用包裹不复制；老浏览器降级 ctx.createImageData 逐字节拷贝）
function scanToRealImageData(ctx, obj) {
    if (typeof ImageData === 'function') {
        if (obj instanceof ImageData) return obj;
        try { return new ImageData(obj.data, obj.width, obj.height); } catch (e) { /* 降级 */ }
    }
    var real = ctx.createImageData(obj.width, obj.height);
    real.data.set(obj.data);
    return real;
}

// 主流程：取画布像素 → 透视矫正 → 增强 → 离屏 canvas → toBlob → 预览 + 信息
function scanApply() {
    if (!scanLoaded || !scanCorners) {
        showNotification('请先选择图片');
        return;
    }
    var size = scanOutputSize(scanCorners);
    if (size.w < 2 || size.h < 2 || scanQuadArea(scanCorners) < 1) {
        showNotification('❌ 角点围成的区域过小或退化（近似共线），请重新调整');
        return;
    }

    var mode = scanGetEnhance();
    var format = scanGetFormat();

    try {
        var imgData = scanCtx.getImageData(0, 0, scanW, scanH);
        var cropped = scanPerspectiveCrop(imgData, scanCorners, size.w, size.h);
        var result = scanEnhance(cropped, mode);

        var outCanvas = document.createElement('canvas');
        outCanvas.width = result.width;
        outCanvas.height = result.height;
        var ctx = outCanvas.getContext('2d');
        ctx.putImageData(scanToRealImageData(ctx, result), 0, 0);

        var onBlob = function (blob) {
            if (!blob) {
                showNotification('❌ 生成失败：当前浏览器不支持该格式编码');
                return;
            }
            scanShowResult(blob, result.width, result.height, mode, format);
        };
        // JPEG 传质量 0.92（扫描件以文字为主，稍高质量避免字迹毛边）；PNG 无损不传质量
        if (typeof outCanvas.toBlob === 'function') {
            outCanvas.toBlob(onBlob, format, format === 'image/png' ? undefined : 0.92);
        } else {
            onBlob(null);
        }
    } catch (e) {
        showNotification('❌ 扫描失败：' + (e && e.message ? e.message : e));
    }
}

// 填充结果区：预览图 + 输出尺寸/大小（+增强方式与原图尺寸对照）
function scanShowResult(blob, w, h, mode, format) {
    scanClearResult();
    scanResultBlob = blob;
    scanResultUrl = URL.createObjectURL(blob);
    scanResultExt = format === 'image/png' ? 'png' : 'jpg';

    var preview = document.getElementById('scan-result-img');
    preview.src = scanResultUrl;
    preview.style.display = '';

    var modeText = mode === 'auto' ? '自动增强（白底拉伸）' : mode === 'bw' ? '黑白文档（二值化）' : '原图（不增强）';
    document.getElementById('scan-result-info').textContent =
        '输出尺寸：' + w + ' × ' + h + ' 像素　|　大小：' + formatFileSize(blob.size) +
        '　|　' + modeText + '　|　原图 ' + scanOrigW + ' × ' + scanOrigH;
    showNotification('✅ 扫描完成，可点击"下载"保存');
}

// 释放当前结果资源并复位结果区（保留角点与增强选项，便于调整后重新生成）
function scanClearResult() {
    if (scanResultUrl) URL.revokeObjectURL(scanResultUrl);
    scanResultBlob = null;
    scanResultUrl = '';
    scanResultExt = 'jpg';
    var preview = document.getElementById('scan-result-img');
    preview.removeAttribute('src');
    preview.style.display = 'none';
    document.getElementById('scan-result-info').textContent = '点击"矫正并生成"后此处显示输出尺寸与大小';
}

// ---------- 下载 ----------

// 下载扫描结果：文件名 = 原名去扩展名 + _scanned.扩展名（jpg/png）
function scanDownload() {
    if (!scanResultBlob) {
        showNotification('请先点击"矫正并生成"');
        return;
    }
    var baseName = scanFileName ? scanFileName.replace(/\.[^.]+$/, '') : 'document';
    var a = document.createElement('a');
    a.href = scanResultUrl;
    a.download = baseName + '_scanned.' + scanResultExt;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// ---------- 初始化 ----------

// 绑定拖拽选图区、角点拖拽（鼠标 + 触摸）
function scanInit() {
    var dropZone = document.getElementById('scan-drop');
    var fileInput = document.getElementById('scan-file');
    if (dropZone && fileInput) {
        // 点击弹文件选择框（拦截 input 冒泡回来的 click，避免无限递归）
        dropZone.addEventListener('click', function (event) {
            if (event.target === fileInput) return;
            fileInput.click();
        });
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
            if (files && files.length > 0) scanHandleFile(files[0]);
        });
        fileInput.addEventListener('change', function () {
            if (fileInput.files && fileInput.files.length > 0) {
                scanHandleFile(fileInput.files[0]);
            }
        });
    }

    // 角点拖拽：mousedown/touchstart 在角点上，move/up 挂 document（拖出角点仍有效）
    var corners = document.querySelectorAll('#scan-preview-wrap .scan-corner');
    for (var i = 0; i < corners.length; i++) {
        (function (el) {
            var name = el.getAttribute('data-corner');
            el.addEventListener('mousedown', function (event) {
                event.preventDefault();
                scanStartDrag(name);
            });
            el.addEventListener('touchstart', function (event) {
                if (event.touches.length > 0) {
                    event.preventDefault(); // 阻止触摸滚动/双击缩放
                    scanStartDrag(name);
                    scanMoveDrag(event.touches[0].clientX, event.touches[0].clientY);
                }
            }, { passive: false });
        })(corners[i]);
    }
    document.addEventListener('mousemove', function (event) {
        scanMoveDrag(event.clientX, event.clientY);
    });
    document.addEventListener('mouseup', scanEndDrag);
    document.addEventListener('touchmove', function (event) {
        if (scanDragging && event.touches.length > 0) {
            event.preventDefault();
            scanMoveDrag(event.touches[0].clientX, event.touches[0].clientY);
        }
    }, { passive: false });
    document.addEventListener('touchend', scanEndDrag);
}

// body 尾加载，正常情况下元素已就绪；readyState 判断兜底提前加载的场景
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scanInit);
    } else {
        scanInit();
    }
}
