// ============================================================
// 增强版编解码工具 - GitHub 热榜页（page-github）
// 功能：调用 GitHub search/repositories API，按筛选条件展示热门仓库卡片
// 依赖（须先于本文件加载）：无（本页不依赖 app.js 的工具函数）
// 数据口径：
//   GitHub search API 无官方 trending 端点，此处用
//   "创建时间 >= N 天前 且 stars:>20，按星数倒序" 近似热榜；
//   总榜为全时间星数排序（stars:>10000，同为按星数倒序）。
//   本页是本工具唯一联网功能，其余页面均纯离线可用；
//   切换到本页不自动请求，用户点击"获取热榜"按钮才发起 fetch。
// 安全约束：
//   请求地址固定为下方 GH_API_BASE 常量（HTTPS + api.github.com 公网域名），
//   不请求任何 localhost/内网/用户输入的 URL；
//   语言筛选等用户输入只进 query 参数且整体 encodeURIComponent；
//   所有响应字段用 textContent/DOM API 渲染，不用 innerHTML 拼接。
// ============================================================

// 请求目标固定常量：GitHub 公网 search API（HTTPS），不允许被改写
var GH_API_BASE = 'https://api.github.com/search/repositories';

// 常见语言在 GitHub 上的官方色值（用于语言名前的圆点着色），未收录语言显示灰色
var GH_LANG_COLORS = {
    'JavaScript': '#f1e05a',
    'TypeScript': '#3178c6',
    'Python': '#3572A5',
    'Java': '#b07219',
    'C++': '#f34b7d',
    'C#': '#178600',
    'Go': '#00ADD8',
    'Rust': '#dea584',
    'Vue': '#41b883',
    'HTML': '#e34c26',
    'CSS': '#563d7c',
    'Shell': '#89e051'
};

// 千分位格式化：12345 → "12,345"（用于 stars / forks 展示）
function ghFormatNumber(n) {
    if (typeof n !== 'number' || isNaN(n)) {
        return '0';
    }
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// 计算今天减 N 天的日期字符串（YYYY-MM-DD）：
// toISOString 基于 UTC，先减去本地时区偏移（分钟）再转换，保证日期与本地时区一致
function ghDateDaysAgo(days) {
    var d = new Date();
    d.setDate(d.getDate() - days);
    var adjusted = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
    return adjusted.toISOString().slice(0, 10);
}

// ISO 时间串取日期部分："2026-09-01T12:34:56Z" → "2026-09-01"
function ghDateOnly(iso) {
    return String(iso || '').slice(0, 10);
}

// 读取当前选择的时间范围：today / week / month / all（默认 week）
function ghGetRange() {
    var checked = document.querySelector('input[name="gh-range"]:checked');
    return checked ? checked.value : 'week';
}

// 读取当前选择的语言：返回原始语言名；"全部" 返回空串。
// option 的 value 对 C++/C# 存的是 URL 编码形式（C%2B%2B / C%23），此处解码还原
function ghGetLanguage() {
    var select = document.getElementById('gh-language');
    if (!select || !select.value) {
        return '';
    }
    try {
        return decodeURIComponent(select.value);
    } catch (e) {
        // 值不是合法的编码形式时按原值使用
        return select.value;
    }
}

// 拼接查询串 q：
//   today/week/month → created:>=YYYY-MM-DD stars:>20（用创建时间+星数近似热榜）
//   all              → stars:>10000（全时间总榜）
// 语言非"全部"时追加 language:<名称>；调用方再对整个 q 做 encodeURIComponent
function ghBuildQuery(range, language) {
    var q;
    if (range === 'all') {
        q = 'stars:>10000';
    } else {
        var days = range === 'today' ? 1 : (range === 'month' ? 30 : 7);
        q = 'created:>=' + ghDateDaysAgo(days) + ' stars:>20';
    }
    if (language) {
        q += ' language:' + language;
    }
    return q;
}

// 状态行显示：text 为空时隐藏；isError=true 时红色（分级错误提示）
function ghShowStatus(text, isError) {
    var status = document.getElementById('gh-status');
    if (!status) {
        return;
    }
    status.textContent = text;
    status.classList.toggle('gh-status-error', !!isError);
    status.style.display = text ? 'block' : 'none';
}

// 创建单个仓库卡片（全部 DOM API + textContent，不拼 HTML，防注入）：
// 排名序号 + 仓库名链接 / 描述 / 元信息行（星数、forks、语言色点、创建日期）
function ghBuildCard(item, index) {
    var card = document.createElement('div');
    card.className = 'gh-card';

    // 标题行：排名序号 + 仓库名（链接到 GitHub，新窗口打开并断开 opener）
    var title = document.createElement('div');
    title.className = 'gh-card-title';
    var rank = document.createElement('span');
    rank.className = 'gh-rank';
    rank.textContent = '#' + (index + 1);
    var link = document.createElement('a');
    // 仅当 API 返回的 html_url 是 https 地址时才设为链接，否则退化为纯文本展示
    if (typeof item.html_url === 'string' && item.html_url.indexOf('https://') === 0) {
        link.href = item.html_url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
    }
    link.textContent = item.full_name;
    title.appendChild(rank);
    title.appendChild(link);
    card.appendChild(title);

    // 描述（description 可能为 null，统一显示占位符）
    var desc = document.createElement('div');
    desc.className = 'gh-card-desc';
    desc.textContent = item.description || '—';
    card.appendChild(desc);

    // 元信息行：⭐ 星数（千分位）、🍴 forks、语言色点、创建日期，均以 " · " 分隔
    var meta = document.createElement('div');
    meta.className = 'gh-card-meta';
    meta.appendChild(document.createTextNode(
        '⭐ ' + ghFormatNumber(item.stargazers_count) + ' · 🍴 ' + ghFormatNumber(item.forks_count)));
    if (item.language) {
        meta.appendChild(document.createTextNode(' · '));
        var lang = document.createElement('span');
        lang.className = 'gh-lang';
        var dot = document.createElement('span');
        dot.className = 'gh-lang-dot';
        dot.style.background = GH_LANG_COLORS[item.language] || '#868e96';
        lang.appendChild(dot);
        lang.appendChild(document.createTextNode(item.language));
        meta.appendChild(lang);
    }
    meta.appendChild(document.createTextNode(' · 创建于 ' + ghDateOnly(item.created_at)));
    card.appendChild(meta);

    return card;
}

// 主入口：获取热榜（由"获取热榜"按钮 onclick 触发；错误分级处理见各分支）
async function ghFetchTrending() {
    var resultBox = document.getElementById('gh-result');
    if (!resultBox) {
        return;
    }
    var q = ghBuildQuery(ghGetRange(), ghGetLanguage());
    // host 固定为 GH_API_BASE 常量；q 整体 encodeURIComponent 后追加，固定星数倒序取前 25 条
    var url = GH_API_BASE + '?q=' + encodeURIComponent(q) + '&sort=stars&order=desc&per_page=25';

    ghShowStatus('获取中...');
    resultBox.textContent = '';

    try {
        var response = await fetch(url, {
            headers: { 'Accept': 'application/vnd.github+json' }
        });
        // 403/429：未认证请求触发 GitHub 速率限制
        if (response.status === 403 || response.status === 429) {
            ghShowStatus('GitHub API 速率限制（未认证每小时 60 次），请稍后再试', true);
            return;
        }
        // 其他非 2xx：显示状态码与简要原因
        if (!response.ok) {
            ghShowStatus('GitHub API 返回错误：HTTP ' + response.status + '（请求失败，请稍后重试）', true);
            return;
        }
        var data = await response.json();
        var items = (data && data.items) || [];
        if (items.length === 0) {
            ghShowStatus('该筛选条件下没有结果，试试放宽时间范围或语言', true);
            return;
        }
        ghShowStatus('共获取 ' + items.length + ' 个仓库（按星数降序）');
        for (var i = 0; i < items.length; i++) {
            resultBox.appendChild(ghBuildCard(items[i], i));
        }
    } catch (err) {
        // 走到这里说明 fetch 本身 reject：离线 / DNS 解析失败等网络问题。
        // 本页为唯一联网功能，明确告知其余功能不受影响
        ghShowStatus('🌐 无法连接 GitHub：请检查网络连接。本页为唯一联网功能，工具其余功能均可离线使用。', true);
    }
}

// 页面初始化：本页无输入框联动，按钮 onclick 直调即可；
// 仅清空状态行保持初始干净（切页不自动请求，见文件头注释）
function ghInit() {
    ghShowStatus('');
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ghInit);
} else {
    ghInit();
}
