// ============================================================
// 增强版编解码工具 - HTTP 状态码 / MIME 速查页（page-http）
// 功能：两张静态数据表 + 搜索过滤（HTTP 另有 1xx-5xx 分类单选）
// 风格参考 js/ascii.js：内置数据表 + innerHTML 一次性渲染 + 事件绑定
// 依赖（须先于本文件加载）：
//   js/app.js → showNotification（本页行无点击复制行为，实际未用到）
// 数据口径：
//   HTTP 状态码含 RFC 9110 核心码及 RFC 6585（428/429/431）、
//   RFC 4918（102/422）、RFC 2518→8 系扩展、RFC 7725（451）、RFC 2324（418）等
//   MIME 以 IANA 常见类型为准；Office 2007+ 的 openxml 长类型按实际注册名
// ============================================================

// HTTP 状态码表：[代码, 英文短语, 中文说明]，按代码升序排列
var HTTP_STATUS = [
    // 1xx 信息响应
    [100, 'Continue', '继续：客户端应继续发送请求剩余部分（Expect: 100-continue）'],
    [101, 'Switching Protocols', '切换协议：如 HTTP 升级为 WebSocket'],
    [102, 'Processing', '处理中：服务器已收到请求，尚无最终响应（WebDAV）'],
    [103, 'Early Hints', '早期提示：最终响应前先返回部分响应头（如预加载 Link）'],
    // 2xx 成功
    [200, 'OK', '成功：请求正常处理完成'],
    [201, 'Created', '已创建：请求成功并创建了新资源（常用于 POST）'],
    [202, 'Accepted', '已接受：请求已受理但未处理完成（异步任务）'],
    [204, 'No Content', '无内容：成功但响应体为空（常用于 DELETE）'],
    [206, 'Partial Content', '部分内容：Range 断点续传 / 分片下载成功'],
    // 3xx 重定向
    [301, 'Moved Permanently', '永久重定向：资源已永久迁移，搜索引擎会更新链接'],
    [302, 'Found', '临时重定向：资源暂时迁移（历史原因方法可能被改为 GET）'],
    [303, 'See Other', '见其他：须用 GET 访问另一 URI（如 POST 后跳转结果页）'],
    [304, 'Not Modified', '未修改：协商缓存命中，客户端可继续用本地缓存'],
    [307, 'Temporary Redirect', '临时重定向：严格保持原请求方法与请求体'],
    [308, 'Permanent Redirect', '永久重定向：严格保持原请求方法与请求体'],
    // 4xx 客户端错误
    [400, 'Bad Request', '错误请求：请求语法非法（参数缺失 / 报文格式错误）'],
    [401, 'Unauthorized', '未认证：缺少或提供了无效的凭证（应带 WWW-Authenticate 头）'],
    [402, 'Payment Required', '需要付款：保留状态码，实际很少使用'],
    [403, 'Forbidden', '禁止访问：已认证但无权限（与 401 的区别：身份知道，但不让进）'],
    [404, 'Not Found', '未找到：请求的资源不存在（最常见的客户端错误）'],
    [405, 'Method Not Allowed', '方法不允许：如对只读资源发 POST（应带 Allow 头）'],
    [406, 'Not Acceptable', '不可接受：无法满足 Accept 系列请求头要求的内容协商'],
    [407, 'Proxy Authentication Required', '需代理认证：须先通过代理服务器的认证'],
    [408, 'Request Timeout', '请求超时：客户端迟迟未发完请求，服务器放弃等待'],
    [409, 'Conflict', '冲突：请求与资源当前状态冲突（如并发编辑 / 版本冲突）'],
    [410, 'Gone', '已消失：资源已永久删除且无已知转发地址（语义比"未找到"更明确）'],
    [411, 'Length Required', '需要长度：服务器要求请求带 Content-Length 头'],
    [412, 'Precondition Failed', '前置条件失败：If-Match / If-Unmodified-Since 等校验未通过'],
    [413, 'Content Too Large', '内容过大：请求体超过服务器愿意处理的上限（原 Payload Too Large）'],
    [414, 'URI Too Long', 'URI 过长：请求行 URL 超过服务器能处理的长度'],
    [415, 'Unsupported Media Type', '媒体类型不支持：Content-Type 不在服务器支持范围（如要 JSON 发了 XML）'],
    [416, 'Range Not Satisfiable', '范围无法满足：Range 请求的区间超出资源实际大小'],
    [418, "I'm a teapot", '我是茶壶：1998 愚人节 HTCPCP 彩蛋状态码，茶壶不能煮咖啡'],
    [422, 'Unprocessable Content', '内容无法处理：语法正确但语义错误（表单校验失败，WebDAV 原名 Unprocessable Entity）'],
    [428, 'Precondition Required', '需要前置条件：服务器要求带 If-Match 等头以防丢失更新（RFC 6585）'],
    [429, 'Too Many Requests', '请求过多：触发限流，应按 Retry-After 头退避重试'],
    [431, 'Request Header Fields Too Large', '请求头过大：单头过大或总量过大（RFC 6585）'],
    [451, 'Unavailable For Legal Reasons', '因法律原因不可用：内容被依法屏蔽（RFC 7725，页面常提示"所在地区无法访问"）'],
    // 5xx 服务端错误
    [500, 'Internal Server Error', '服务器内部错误：未捕获异常 / 代码崩溃等通用服务端错误'],
    [501, 'Not Implemented', '未实现：服务器不支持该请求方法（如未知的新方法）'],
    [502, 'Bad Gateway', '网关错误：网关/代理从上游收到无效响应（上游崩溃或返回垃圾数据）'],
    [503, 'Service Unavailable', '服务不可用：服务器过载或停机维护（常配合 Retry-After 头）'],
    [504, 'Gateway Timeout', '网关超时：网关/代理等待上游响应超时（区别于 502：上游压根没回）'],
    [505, 'HTTP Version Not Supported', '版本不支持：服务器不支持请求行的 HTTP 版本']
];

// MIME 类型表：[扩展名, MIME 类型, 说明]，按扩展名字典序排列
var MIME_TYPES = [
    ['7z', 'application/x-7z-compressed', '7-Zip 压缩包'],
    ['avi', 'video/x-msvideo', 'AVI 视频'],
    ['bmp', 'image/bmp', 'BMP 位图'],
    ['css', 'text/css', 'CSS 样式表'],
    ['csv', 'text/csv', '逗号分隔的表格数据'],
    ['doc', 'application/msword', 'Word 97-2003 文档'],
    ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'Word 文档（Office 2007+）'],
    ['eot', 'application/vnd.ms-fontobject', 'Embedded OpenType 字体（IE 时代）'],
    ['gif', 'image/gif', 'GIF 图片（支持动画）'],
    ['gzip', 'application/gzip', 'GZIP 压缩文件（.gz）'],
    ['htm / html', 'text/html', 'HTML 网页文档'],
    ['ico', 'image/x-icon', '网站图标（favicon）'],
    ['jpg / jpeg', 'image/jpeg', 'JPEG 图片（有损压缩）'],
    ['js', 'text/javascript', 'JavaScript 脚本'],
    ['json', 'application/json', 'JSON 数据'],
    ['md', 'text/markdown', 'Markdown 文本'],
    ['mp3', 'audio/mpeg', 'MP3 音频'],
    ['mp4', 'video/mp4', 'MP4 视频'],
    ['pdf', 'application/pdf', 'PDF 文档'],
    ['png', 'image/png', 'PNG 图片（支持透明）'],
    ['ppt', 'application/vnd.ms-powerpoint', 'PowerPoint 97-2003 演示文稿'],
    ['pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'PowerPoint 演示文稿（Office 2007+）'],
    ['svg', 'image/svg+xml', 'SVG 矢量图'],
    ['tar', 'application/x-tar', 'TAR 归档包'],
    ['ttf', 'font/ttf', 'TrueType 字体'],
    ['txt', 'text/plain', '纯文本'],
    ['wasm', 'application/wasm', 'WebAssembly 二进制模块'],
    ['wav', 'audio/wav', 'WAV 波形音频'],
    ['webm', 'video/webm', 'WebM 视频'],
    ['webp', 'image/webp', 'WebP 图片（体积更小）'],
    ['woff', 'font/woff', 'Web 开放字体格式 1.0'],
    ['woff2', 'font/woff2', 'Web 开放字体格式 2.0（更小，主流）'],
    ['xls', 'application/vnd.ms-excel', 'Excel 97-2003 工作簿'],
    ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Excel 工作簿（Office 2007+）'],
    ['xml', 'application/xml', 'XML 文档'],
    ['zip', 'application/zip', 'ZIP 压缩包']
];

// 渲染 HTTP 状态码表：按搜索词（匹配代码/短语/说明，大小写不敏感）与分类过滤
function httpRender() {
    var container = document.getElementById('http-table-container');
    if (!container) { return; }
    var searchEl = document.getElementById('http-search');
    var q = searchEl && searchEl.value ? searchEl.value.trim().toLowerCase() : '';

    // 当前选中的分类：all 或 1-5（取状态码的首位数字）
    var cat = 'all';
    var checked = document.querySelector('input[name="http-cat"]:checked');
    if (checked) { cat = checked.value; }

    var rows = [];
    for (var i = 0; i < HTTP_STATUS.length; i++) {
        var item = HTTP_STATUS[i];
        if (cat !== 'all' && String(item[0]).charAt(0) !== cat) { continue; }
        if (q &&
            String(item[0]).indexOf(q) === -1 &&
            item[1].toLowerCase().indexOf(q) === -1 &&
            item[2].toLowerCase().indexOf(q) === -1) { continue; }
        rows.push(item);
    }

    // 数据为内置静态表（不含任何 < > & 字符），直接字符串拼接即可，无需转义
    var html = '<p class="httpref-count">共 ' + rows.length + ' 条</p>' +
        '<div class="httpref-wrap"><table class="query-table">' +
        '<thead><tr><th style="width:60px;">状态码</th><th style="width:200px;">英文短语</th><th>中文说明</th></tr></thead><tbody>';
    for (var r = 0; r < rows.length; r++) {
        html += '<tr><td>' + rows[r][0] + '</td><td>' + rows[r][1] + '</td><td>' + rows[r][2] + '</td></tr>';
    }
    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// 渲染 MIME 类型表：按搜索词（匹配扩展名/类型/说明，大小写不敏感）过滤
function mimeRender() {
    var container = document.getElementById('mime-table-container');
    if (!container) { return; }
    var searchEl = document.getElementById('mime-search');
    var q = searchEl && searchEl.value ? searchEl.value.trim().toLowerCase() : '';

    var rows = [];
    for (var i = 0; i < MIME_TYPES.length; i++) {
        var item = MIME_TYPES[i];
        if (q &&
            item[0].toLowerCase().indexOf(q) === -1 &&
            item[1].toLowerCase().indexOf(q) === -1 &&
            item[2].toLowerCase().indexOf(q) === -1) { continue; }
        rows.push(item);
    }

    // 数据为内置静态表，直接字符串拼接即可（与 httpRender 同一口径）
    var html = '<p class="httpref-count">共 ' + rows.length + ' 条</p>' +
        '<div class="httpref-wrap"><table class="query-table">' +
        '<thead><tr><th style="width:110px;">扩展名</th><th style="width:280px;">MIME 类型</th><th>说明</th></tr></thead><tbody>';
    for (var r = 0; r < rows.length; r++) {
        html += '<tr><td>' + rows[r][0] + '</td><td>' + rows[r][1] + '</td><td>' + rows[r][2] + '</td></tr>';
    }
    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// 页面初始化：绑定搜索输入与分类单选事件，完成首次渲染
function httprefInit() {
    var httpSearch = document.getElementById('http-search');
    if (httpSearch) {
        httpSearch.addEventListener('input', httpRender);
    }
    var mimeSearch = document.getElementById('mime-search');
    if (mimeSearch) {
        mimeSearch.addEventListener('input', mimeRender);
    }
    var radios = document.getElementsByName('http-cat');
    for (var i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', httpRender);
    }
    httpRender();
    mimeRender();
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', httprefInit);
} else {
    httprefInit();
}
