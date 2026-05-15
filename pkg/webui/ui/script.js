let pollTimer = null;
let allNodesList = [];
let suppliersCache = [];
let aggregateGroupsCache = [];
let currentGroupFilter = "";
let ruleGroups = [];
let currentRuleGroupIndex = 0;

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const st = await res.json();
        document.getElementById('chkProxy').checked = st.proxy;
        document.getElementById('chkMode').checked = (st.mode === 'Global');
        document.getElementById('chkTun').checked = st.tun;
        document.getElementById('chkWebRTC').checked = st.webrtc;
        document.getElementById('speedMonitor').innerHTML = '↑ ' + st.speedOut + ' &nbsp; ↓ ' + st.speedIn;
    } catch(e) {}
}

function showTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    const activeBtn = document.querySelector(`.tab-btn[onclick="showTab('${tabId}')"]`);
    if (activeBtn) activeBtn.classList.add('active');
    
    const activeContent = document.getElementById(`tab-${tabId}`);
    if (activeContent) activeContent.classList.add('active');

    if (tabId === 'dashboard') {
        startDashboardPolling();
    } else {
        stopDashboardPolling();
    }
}

function renderNodes() {
    const grid = document.getElementById('nodeGrid');
    if (!grid) return;
    grid.innerHTML = '';

    const keyword = document.getElementById('nodeSearch')?.value.trim().toLowerCase() || "";
    
    let displayNodes = allNodesList;
    if (currentGroupFilter !== "") {
        displayNodes = allNodesList.filter(n => n.group === currentGroupFilter);
    }

    if (keyword) {
        displayNodes = displayNodes.filter(n => 
            n.name.toLowerCase().includes(keyword) || 
            n.type.toLowerCase().includes(keyword)
        );
    }

    if (!displayNodes || displayNodes.length === 0) {
        grid.innerHTML = '<div class="empty-state">没有匹配的节点。</div>';
        return;
    }

    displayNodes.forEach(n => {
        let latClass = 'unknown';
        let latText = '-- ms';
        if (n.latency > 0 && n.latency < 500) {
            latClass = 'good';
            latText = n.latency + ' ms';
        } else if (n.latency >= 500) {
            latClass = 'bad';
            latText = n.latency + ' ms';
        } else if (n.latency === -1) {
            latClass = 'bad';
            latText = 'Timeout';
        }

        const card = document.createElement('div');
        card.className = 'card ' + (n.active ? 'active' : '');
        card.onclick = (e) => {
            if (e.target.tagName !== 'BUTTON') switchNode(n.index);
        };

        card.innerHTML = `
            <div class="card-header">
                <div style="display:flex;align-items:center;">
                    <span class="node-type">${n.type}</span>
                </div>
                ${n.active ? '<span style="color:#34d399;font-size:12px;font-weight:800;">✅ 运行中</span>' : ''}
            </div>
            <div class="node-name">${n.name}</div>
            <div class="card-footer">
                <span class="latency ${latClass}" id="lat-${n.index}">⚡ ${latText}</span>
                <span class="latency unknown" id="speed-${n.index}" style="margin-right:auto;margin-left:10px;"></span>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    <button class="test-btn" onclick="testSingle(${n.index})">测速</button>
                    <button class="bw-btn" onclick="testSpeed(${n.index})">带宽</button>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

function filterNodes() {
    renderNodes();
}

// ── Dashboard Logic ──
let dashTimer = null;
let trafficChart = null;
const maxDataPoints = 60;
let chartData = {
    labels: [],
    in: [],
    out: []
};

function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    const isLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    const textColor = isLight ? '#475569' : '#94a3b8';
    const gridColor = isLight ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.05)';

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartData.labels,
            datasets: [
                {
                    label: '下载 (Inbound)',
                    data: chartData.in,
                    borderColor: '#60a5fa',
                    backgroundColor: 'rgba(96, 165, 250, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0
                },
                {
                    label: '上传 (Outbound)',
                    data: chartData.out,
                    borderColor: '#a78bfa',
                    backgroundColor: 'rgba(167, 139, 250, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { labels: { color: textColor, font: { size: 12 } } }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: textColor, maxRotation: 0, autoSkip: true, maxTicksLimit: 10 }
                },
                y: {
                    grid: { color: gridColor },
                    ticks: {
                        color: textColor,
                        callback: (value) => formatBytes(value) + '/s'
                    }
                }
            }
        }
    });
}

async function updateDashboard() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        
        document.getElementById('dashSpeedIn').textContent = stats.speedIn;
        document.getElementById('dashSpeedOut').textContent = stats.speedOut;
        document.getElementById('dashTotalIn').textContent = formatBytes(stats.totalIn);
        document.getElementById('dashTotalOut').textContent = formatBytes(stats.totalOut);
        document.getElementById('dashMem').textContent = (stats.memSys / 1024 / 1024).toFixed(1) + ' MB';
        document.getElementById('dashConnections').textContent = stats.connections;

        renderConnLogs(stats.logs);

        // Parse speeds back to numbers for chart
        const parseSpeed = (s) => {
            if (!s) return 0;
            const parts = s.split(' ');
            let val = parseFloat(parts[0]);
            if (parts[1] === 'KB/s') val *= 1024;
            else if (parts[1] === 'MB/s') val *= 1024 * 1024;
            else if (parts[1] === 'GB/s') val *= 1024 * 1024 * 1024;
            return val;
        };

        const now = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        chartData.labels.push(now);
        chartData.in.push(parseSpeed(stats.speedIn));
        chartData.out.push(parseSpeed(stats.speedOut));

        if (chartData.labels.length > maxDataPoints) {
            chartData.labels.shift();
            chartData.in.shift();
            chartData.out.shift();
        }

        if (trafficChart) trafficChart.update('none');
    } catch(e) {}
}

function renderConnLogs(logs) {
    const tbody = document.getElementById('connLogBody');
    if (!tbody || !logs) return;
    
    let html = '';
    logs.forEach(l => {
        const timeStr = new Date(l.startTime).toLocaleTimeString([], {hour12:false});
        let nodeClass = 'log-node-proxy';
        if (l.node === 'Direct') nodeClass = 'log-node-direct';
        else if (l.node === 'Blocked') nodeClass = 'log-node-blocked';

        html += `
            <tr>
                <td style="color:var(--text-dim)">${timeStr}</td>
                <td title="${l.target}" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;">${l.target}</td>
                <td><span class="${nodeClass}">${l.node}</span></td>
                <td>↑ ${formatBytes(l.outbound)}</td>
                <td>↓ ${formatBytes(l.inbound)}</td>
                <td>${l.duration || '--'}</td>
                <td><span class="${l.status === 'Active' ? 'log-status-active' : 'log-status-closed'}">${l.status === 'Active' ? '● 活动' : '○ 已断开'}</span></td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

async function clearLogs() {
    await fetch('/api/clear_logs', { method: 'POST' });
    document.getElementById('connLogBody').innerHTML = '';
}

function startDashboardPolling() {
    if (dashTimer) return;
    if (!trafficChart) initChart();
    updateDashboard();
    dashTimer = setInterval(updateDashboard, 1000);
}

function stopDashboardPolling() {
    if (dashTimer) {
        clearInterval(dashTimer);
        dashTimer = null;
    }
}

async function loadSuppliers() {
    try {
        const res = await fetch('/api/suppliers');
        const suppliers = await res.json();
        suppliersCache = suppliers || [];
        const sel = document.getElementById('supplierSelect');
        sel.innerHTML = '';

        if (!suppliersCache.length) {
            const opt = document.createElement('option');
            opt.value = '';
            opt.textContent = '暂无';
            opt.disabled = true;
            opt.selected = true;
            sel.appendChild(opt);
            renderSupplierTraffic(null);
            loadAggregateGroups();
            return;
        }

        const empty = document.createElement('option');
        empty.value = '';
        empty.textContent = '';
        sel.appendChild(empty);

        suppliersCache.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.fileName;
            opt.textContent = s.name;
            if (s.active) opt.selected = true;
            sel.appendChild(opt);
        });
        renderSupplierTraffic(sel.value);
        loadAggregateGroups();
    } catch(e) {}
}

async function loadAggregateGroups() {
    try {
        const res = await fetch('/api/aggregate_groups');
        const groups = await res.json();
        aggregateGroupsCache = groups || [];
        const sel = document.getElementById('aggregateSelect');
        sel.innerHTML = '';
        if (!aggregateGroupsCache.length) {
            const empty = document.createElement('option');
            empty.value = '';
            empty.textContent = '暂无';
            empty.disabled = true;
            sel.appendChild(empty);
        } else {
            const empty = document.createElement('option');
            empty.value = '';
            empty.textContent = '';
            sel.appendChild(empty);
        }
        aggregateGroupsCache.forEach(g => {
            const opt = document.createElement('option');
            opt.value = g.fileName;
            opt.textContent = g.name;
            if (g.active) opt.selected = true;
            sel.appendChild(opt);
        });
    } catch(e) {}
}

async function switchSupplier(fileName) {
    if (!fileName) return;
    await fetch('/api/switch_supplier?file=' + encodeURIComponent(fileName), { method: 'POST' });
    document.getElementById('aggregateSelect').value = '';
    renderSupplierTraffic(fileName);
    loadNodes();
}

async function switchAggregateGroup(fileName) {
    if (!fileName) return;
    await fetch('/api/switch_aggregate_group?file=' + encodeURIComponent(fileName), { method: 'POST' });
    document.getElementById('supplierSelect').value = '';
    renderSupplierTraffic(null);
    loadNodes();
}

async function deleteAggregateGroup() {
    const sel = document.getElementById('aggregateSelect');
    const file = sel.value;
    const name = sel.options[sel.selectedIndex]?.text || file;
    if (!file) return;
    if (!confirm('确定要删除聚合组「' + name + '」吗？')) return;
    const btn = document.getElementById('btnDeleteAgg');
    btn.disabled = true;
    btn.textContent = '🗑 删除中...';
    try {
        const res = await fetch('/api/delete_aggregate_group?file=' + encodeURIComponent(file), { method: 'POST' });
        if (res.ok) {
            loadAggregateGroups();
            loadNodes();
        }
    } catch(e) {
        alert('请求失败');
    }
    btn.disabled = false;
    btn.textContent = '🗑 删除聚合组';
}

function renderSupplierTraffic(fileName) {
    const el = document.getElementById('supplierTraffic');
    if (!el) return;
    const supplier = suppliersCache.find(s => s.fileName === fileName);
    if (!supplier || !supplier.traffic || !supplier.traffic.total) {
        el.innerHTML = '<span class="traffic-pill">流量信息：<strong>暂无</strong></span>';
        return;
    }
    const t = supplier.traffic;
    const expire = t.expire ? new Date(t.expire * 1000).toLocaleDateString() : '未提供';
    let resetText = '一次性/未提供';
    if (t.reset_at) {
        resetText = new Date(t.reset_at * 1000).toLocaleString();
    } else if (t.reset_day) {
        resetText = '每月 ' + t.reset_day + ' 日';
    }
    el.innerHTML = `
        <span class="traffic-pill">剩余 <strong>${formatBytes(t.remaining)}</strong></span>
        <span class="traffic-pill">已用 <strong>${formatBytes(t.used)}</strong></span>
        <span class="traffic-pill">总量 <strong>${formatBytes(t.total)}</strong></span>
        <span class="traffic-pill">重置 <strong>${resetText}</strong></span>
        <span class="traffic-pill">到期 <strong>${expire}</strong></span>
    `;
}

function showToast(msg, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 350);
    }, duration);
}

async function importSubscription() {
    const btn = document.getElementById('btnImport');
    btn.disabled = true;
    btn.innerHTML = '<span class="spin">📋</span> 导入中...';
    try {
        const res = await fetch('/api/import_subscription', { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast(data.msg, 'success', 5000);
            loadSuppliers();
            loadNodes();
        } else {
            showToast(data.msg || '导入失败', 'error', 5000);
        }
    } catch(e) {
        showToast('导入请求失败，请检查服务是否正常运行。', 'error');
    }
    btn.disabled = false;
    btn.innerHTML = '📋 导入订阅';
}

async function doAction(type) {
    const res = await fetch('/api/action?type=' + type, { method: 'POST' });
    try {
        const data = await res.json();
        if (data && data.msg) {
            showToast(data.msg, data.ok === false ? 'error' : 'info');
        }
    } catch(e) {}
    setTimeout(loadStatus, 300);
}

async function loadNodes() {
    try {
        const res = await fetch('/api/nodes');
        const nodes = await res.json();
        allNodesList = nodes || [];
        
        renderNodes();
    } catch(e) {}
}

function renderNodes() {
    const grid = document.getElementById('nodeGrid');
    grid.innerHTML = '';

    let displayNodes = allNodesList;
    if (currentGroupFilter !== "") {
        displayNodes = allNodesList.filter(n => n.group === currentGroupFilter);
    }

    if (!displayNodes || displayNodes.length === 0) {
        grid.innerHTML = '<div class="empty-state">当前没有节点，点击 <strong>添加节点</strong> 或 <strong>导入订阅</strong> 开始使用。</div>';
        return;
    }

    displayNodes.forEach(n => {
        let latClass = 'unknown';
        let latText = '-- ms';
        if (n.latency > 0 && n.latency < 500) {
            latClass = 'good';
            latText = n.latency + ' ms';
        } else if (n.latency >= 500) {
            latClass = 'bad';
            latText = n.latency + ' ms';
        } else if (n.latency === -1) {
            latClass = 'bad';
            latText = 'Timeout';
        }

        const card = document.createElement('div');
        card.className = 'card ' + (n.active ? 'active' : '');
        card.onclick = (e) => {
            if (e.target.tagName !== 'BUTTON') switchNode(n.index);
        };

        card.innerHTML = `
            <div class="card-header">
                <div style="display:flex;align-items:center;">
                    <span class="node-type">${n.type}</span>
                </div>
                ${n.active ? '<span style="color:#34d399;font-size:12px;font-weight:800;">✅ 运行中</span>' : ''}
            </div>
            <div class="node-name">${n.name}</div>
            <div class="card-footer">
                <span class="latency ${latClass}" id="lat-${n.index}">⚡ ${latText}</span>
                <span class="latency unknown" id="speed-${n.index}" style="margin-right:auto;margin-left:10px;"></span>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    <button class="test-btn" onclick="testSingle(${n.index})">测速</button>
                    <button class="bw-btn" onclick="testSpeed(${n.index})">带宽</button>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

async function switchNode(idx) {
    await fetch('/api/switch?idx=' + idx, { method: 'POST' });
    loadNodes();
    loadStatus();
}

async function testSingle(idx) {
    const latEl = document.getElementById('lat-' + idx);
    latEl.textContent = '⚡ ...';
    latEl.className = 'latency unknown';
    await fetch('/api/test_single?idx=' + idx, { method: 'POST' });
    loadNodes();
}

function formatSpeed(bytesPerSec) {
    if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
    if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
    return (bytesPerSec / 1024 / 1024).toFixed(2) + ' MB/s';
}

function formatBytes(bytes) {
    if (!bytes || bytes < 0) return '0 B';
    if (bytes < 1024) return bytes.toFixed(0) + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
    if (bytes < 1024 * 1024 * 1024 * 1024) return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
    return (bytes / 1024 / 1024 / 1024 / 1024).toFixed(2) + ' TB';
}

async function testSpeed(idx) {
    const speedEl = document.getElementById('speed-' + idx);
    speedEl.innerHTML = '<span class="spin">🚀</span> 测速中...';
    speedEl.style.color = 'var(--text-sub)';
    try {
        const res = await fetch('/api/speedtest?idx=' + idx, { method: 'POST' });
        if (!res.ok) throw new Error('测速请求失败');
        const data = await res.json();
        speedEl.textContent = '🚀 ' + formatSpeed(data.speed);
        speedEl.style.color = 'var(--success)';
    } catch(e) {
        speedEl.textContent = '❌ 测速失败';
        speedEl.style.color = 'var(--danger)';
    }
}

async function testAll() {
    const btn = document.getElementById('btnTestAll');
    btn.disabled = true;
    btn.textContent = '⏳ 测速中...';
    await fetch('/api/test_all', { method: 'POST' });
    btn.disabled = false;
    btn.textContent = '⚡ 极速测速';
    loadNodes();
}

async function updateSupplier() {
    const sel = document.getElementById('supplierSelect');
    const file = sel.value;
    if (!file) return;
    const btn = document.getElementById('btnUpdate');
    btn.disabled = true;
    btn.innerHTML = '<span class="spin">🔄</span> 更新中...';
    try {
        const res = await fetch('/api/update_supplier?file=' + encodeURIComponent(file), { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            loadNodes();
            loadSuppliers();
        } else {
            alert('更新失败: ' + (data.msg || '未知错误'));
        }
    } catch(e) {
        alert('请求失败');
    }
    btn.disabled = false;
    btn.innerHTML = '🔄 更新';
}

async function deleteSupplier() {
    const sel = document.getElementById('supplierSelect');
    const file = sel.value;
    const name = sel.options[sel.selectedIndex]?.text || file;
    if (!file) return;
    if (!confirm('确定要删除供应商「' + name + '」吗？\n此操作将同时删除对应的本地节点文件，不可恢复。')) return;
    const btn = document.getElementById('btnDelete');
    btn.disabled = true;
    btn.textContent = '🗑 删除中...';
    try {
        const res = await fetch('/api/delete_supplier?file=' + encodeURIComponent(file), { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            loadSuppliers();
            loadNodes();
        }
    } catch(e) {
        alert('请求失败');
    }
    btn.disabled = false;
    btn.textContent = '🗑 删除订阅';
}

function openAddModal() {
    document.getElementById('addModal').style.display = 'flex';
    document.getElementById('nodeInput').value = '';
}

function closeAddModal() {
    document.getElementById('addModal').style.display = 'none';
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        document.getElementById('nodeInput').value = e.target.result;
    };
    reader.readAsText(file);
    event.target.value = '';
}

function handleQRSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);
            if (code) {
                document.getElementById('nodeInput').value = code.data;
                alert('识别成功！');
            } else {
                alert('无法在图片中识别出二维码，请重试');
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
    event.target.value = '';
}

async function submitAddNode() {
    const val = document.getElementById('nodeInput').value.trim();
    if (!val) return alert('请输入节点内容');

    const btn = document.getElementById('btnAddSubmit');
    btn.disabled = true;
    btn.textContent = '添加中...';

    try {
        const res = await fetch('/api/add_node', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({input: val})
        });
        const data = await res.json();
        if (data.ok) {
            alert('添加成功！');
            closeAddModal();
            loadNodes();
            loadSuppliers();
        } else {
            alert('添加失败: ' + data.msg);
        }
    } catch(e) {
        alert('请求失败');
    }

    btn.disabled = false;
    btn.textContent = '确定添加';
}

async function loadRules() {
    try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        ruleGroups = data || [];
        currentRuleGroupIndex = 0;
        renderRuleGroups();
    } catch(e) {}
}

function selectedRuleGroup() {
    return ruleGroups[currentRuleGroupIndex];
}

function actionName(action) {
    if (action === 'direct') return '直连';
    if (action === 'reject') return '拦截';
    return '代理';
}

function typeName(type) {
    if (type === 'domain_suffix') return '后缀';
    if (type === 'domain_keyword') return '关键字';
    if (type === 'domain') return '完整域名';
    return type;
}

function renderRuleGroups() {
    const sel = document.getElementById('ruleGroupSelect');
    sel.innerHTML = '';
    ruleGroups.forEach((group, idx) => {
        const opt = document.createElement('option');
        opt.value = idx;
        opt.textContent = group.name + ' · ' + actionName(group.action) + ' · ' + (group.rules || []).length + ' 条';
        if (idx === currentRuleGroupIndex) opt.selected = true;
        sel.appendChild(opt);
    });
    const group = selectedRuleGroup();
    document.getElementById('ruleGroupName').value = group ? group.name : '';
    document.getElementById('ruleGroupAction').value = group ? group.action : 'direct';
    renderRules();
}

function syncRuleGroupForm() {
    const group = selectedRuleGroup();
    if (!group) return;
    group.name = document.getElementById('ruleGroupName').value.trim() || group.name;
    group.action = document.getElementById('ruleGroupAction').value;
}

function selectRuleGroup(idx) {
    syncRuleGroupForm();
    currentRuleGroupIndex = Number(idx) || 0;
    renderRuleGroups();
}

function renderRules() {
    const list = document.getElementById('ruleList');
    const infoEl = document.getElementById('ruleSearchInfo');
    const keyword = (document.getElementById('ruleSearch').value || '').trim().toLowerCase();

    // ── 搜索模式：跨所有规则组查找匹配项 ──
    if (keyword) {
        let html = '';
        let matchCount = 0;
        ruleGroups.forEach((g, gIdx) => {
            (g.rules || []).forEach((r, rIdx) => {
                const haystack = (typeName(r.type) + ' ' + r.value).toLowerCase();
                if (!haystack.includes(keyword)) return;
                matchCount++;
                const actionColor = g.action === 'proxy' ? 'var(--accent)' : (g.action === 'reject' ? 'var(--danger)' : 'var(--success)');
                html += `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:14px;">
                        <div>
                            <span style="background:rgba(99,102,241,0.15);padding:2px 6px;border-radius:4px;font-size:11px;margin-right:6px;color:var(--accent);">${g.name}</span>
                            <span style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;font-size:12px;margin-right:8px;">${typeName(r.type)}</span>
                            <span>${r.value}</span>
                            <span style="color:${actionColor};font-weight:bold;margin-left:8px;font-size:12px;">[${actionName(g.action)}]</span>
                        </div>
                    </div>
                `;
            });
        });
        if (matchCount === 0) {
            list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:20px;">未找到匹配的规则</div>';
        } else {
            list.innerHTML = html;
        }
        if (infoEl) infoEl.textContent = '共匹配 ' + matchCount + ' 条规则';
        return;
    }

    // ── 普通模式：显示当前选中规则组 ──
    if (infoEl) infoEl.textContent = '';
    const group = selectedRuleGroup();
    if (!group) {
        list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:20px;">暂无规则组</div>';
        return;
    }
    const rules = group.rules || [];
    if (rules.length === 0) {
        list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:20px;">当前规则组暂无规则</div>';
        return;
    }
    let html = '';
    rules.forEach((r, idx) => {
        const actionColor = group.action === 'proxy' ? 'var(--accent)' : (group.action === 'reject' ? 'var(--danger)' : 'var(--success)');
        html += `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:10px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:14px;">
                <div>
                    <span style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;font-size:12px;margin-right:8px;">${typeName(r.type)}</span>
                    <span>${r.value}</span>
                    <span style="color:${actionColor};font-weight:bold;margin-left:8px;font-size:12px;">[${actionName(group.action)}]</span>
                </div>
                <button class="btn-ghost" style="padding:4px 8px;font-size:12px;border-color:rgba(239,68,68,0.3);color:var(--danger);" onclick="deleteRule(${idx})">删除</button>
            </div>
        `;
    });
    list.innerHTML = html;
}

function addRuleGroup() {
    syncRuleGroupForm();
    const id = 'group_' + Date.now();
    ruleGroups.push({ id, name: '新规则组', action: 'direct', rules: [] });
    currentRuleGroupIndex = ruleGroups.length - 1;
    renderRuleGroups();
}

function deleteRuleGroup() {
    syncRuleGroupForm();
    if (!ruleGroups.length) return;
    const group = selectedRuleGroup();
    if (!confirm('确定删除规则组「' + group.name + '」吗？')) return;
    ruleGroups.splice(currentRuleGroupIndex, 1);
    currentRuleGroupIndex = Math.max(0, currentRuleGroupIndex - 1);
    renderRuleGroups();
}

function addRule() {
    syncRuleGroupForm();
    const group = selectedRuleGroup();
    if (!group) return;
    const type = document.getElementById('ruleType').value;
    const val = document.getElementById('ruleValue').value.trim();
    if (!val) return;
    group.rules = group.rules || [];
    group.rules.push({ type: type, value: val });
    document.getElementById('ruleValue').value = '';
    renderRuleGroups();
    renderRules();
}

function deleteRule(idx) {
    const group = selectedRuleGroup();
    if (!group || !group.rules) return;
    group.rules.splice(idx, 1);
    renderRuleGroups();
}

async function saveRules() {
    syncRuleGroupForm();
    try {
        await fetch('/api/rules', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(ruleGroups)
        });
        alert('规则保存成功！');
        closeRuleModal();
    } catch(e) {
        alert('保存失败');
    }
}

function openRuleModal() {
    document.getElementById('ruleModal').style.display = 'flex';
    loadRules();
}

function closeRuleModal() {
    document.getElementById('ruleModal').style.display = 'none';
}

let dnsConfig = { servers: [], rules: [], default: '' };

async function loadDNSConfig() {
    try {
        const res = await fetch('/api/dns');
        dnsConfig = await res.json();
        document.getElementById('chkAutoOverwrite').checked = dnsConfig.autoOverwrite || false;
        renderDNSConfig();
    } catch(e) { showToast('加载 DNS 配置失败', 'error'); }
}

function renderDNSConfig() {
    const serverList = document.getElementById('dnsServerList');
    const ruleList = document.getElementById('dnsRuleList');
    const defaultSelect = document.getElementById('dnsDefaultServer');
    const ruleServerSelect = document.getElementById('dnsRuleServer');

    // Render Servers
    serverList.innerHTML = '';
    defaultSelect.innerHTML = '';
    ruleServerSelect.innerHTML = '';
    
    dnsConfig.servers.forEach((s, idx) => {
        serverList.innerHTML += `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid rgba(148,163,184,0.08);">
                <span style="font-size:13px;"><strong>${s.name}</strong> (${s.address})</span>
                <button class="btn-ghost" style="padding:2px 6px; font-size:11px; color:var(--danger);" onclick="deleteDNSServer(${idx})">删除</button>
            </div>
        `;
        
        const opt1 = document.createElement('option');
        opt1.value = s.id;
        opt1.textContent = s.name;
        if (s.id === dnsConfig.default) opt1.selected = true;
        defaultSelect.appendChild(opt1);

        const opt2 = document.createElement('option');
        opt2.value = s.id;
        opt2.textContent = s.name;
        ruleServerSelect.appendChild(opt2);
    });

    // Render Rules
    ruleList.innerHTML = '';
    dnsConfig.rules.forEach((r, idx) => {
        const server = dnsConfig.servers.find(s => s.id === r.serverId);
        ruleList.innerHTML += `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid rgba(148,163,184,0.08);">
                <span style="font-size:13px;"><span style="background:rgba(255,255,255,0.05); padding:2px 4px; border-radius:4px; font-size:11px; margin-right:6px;">${typeName(r.type)}</span> ${r.value} -> <strong>${server ? server.name : 'Unknown'}</strong></span>
                <button class="btn-ghost" style="padding:2px 6px; font-size:11px; color:var(--danger);" onclick="deleteDNSRule(${idx})">删除</button>
            </div>
        `;
    });
}

function addDNSServer() {
    const name = document.getElementById('dnsServerName').value.trim();
    const addr = document.getElementById('dnsServerAddr').value.trim();
    if (!name || !addr) return showToast('请输入名称和地址', 'warning');
    
    const id = 'dns_' + Date.now();
    dnsConfig.servers.push({ id, name, address: addr, type: 'udp' });
    document.getElementById('dnsServerName').value = '';
    document.getElementById('dnsServerAddr').value = '';
    renderDNSConfig();
}

function deleteDNSServer(idx) {
    dnsConfig.servers.splice(idx, 1);
    renderDNSConfig();
}

function addDNSRule() {
    const type = document.getElementById('dnsRuleType').value;
    const value = document.getElementById('dnsRuleValue').value.trim();
    const serverId = document.getElementById('dnsRuleServer').value;
    if (!value || !serverId) return showToast('请输入域名和选择服务器', 'warning');

    dnsConfig.rules.push({ type, value, serverId });
    document.getElementById('dnsRuleValue').value = '';
    renderDNSConfig();
}

function deleteDNSRule(idx) {
    dnsConfig.rules.splice(idx, 1);
    renderDNSConfig();
}

async function saveDNSConfig() {
    dnsConfig.default = document.getElementById('dnsDefaultServer').value;
    dnsConfig.autoOverwrite = document.getElementById('chkAutoOverwrite').checked;
    try {
        const res = await fetch('/api/dns', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(dnsConfig)
        });
        const data = await res.json();
        if (data.ok) {
            showToast('DNS 配置保存并应用成功！', 'success');
            closeDNSModal();
        } else {
            showToast('保存失败', 'error');
        }
    } catch(e) { showToast('请求失败', 'error'); }
}

function openDNSModal() {
    document.getElementById('dnsModal').style.display = 'flex';
    loadDNSConfig();
}

function closeDNSModal() {
    document.getElementById('dnsModal').style.display = 'none';
}

let allSubsNodesCache = [];
let expandedAggSubs = {};
let selectedAggNodes = {};
let aggEditFile = '';
let aggCurrentNodesList = [];

async function openAggGroupModal() {
    document.getElementById('aggGroupModal').style.display = 'flex';
    const list = document.getElementById('aggNodeList');
    list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:20px;">加载中...</div>';

    // 构建模式选择器
    const sel = document.getElementById('aggModeSelect');
    sel.innerHTML = '<option value="new">➕ 新建分组</option>';
    aggregateGroupsCache.forEach(g => {
        const opt = document.createElement('option');
        opt.value = g.fileName;
        opt.textContent = '✏️ ' + g.name;
        sel.appendChild(opt);
    });

    // 如果已选中聚合组，默认进入编辑模式
    const currentAggFile = document.getElementById('aggregateSelect').value;
    if (currentAggFile) {
        sel.value = currentAggFile;
    }

    onAggModeChange(sel.value);

    // 加载所有订阅节点
    try {
        const res = await fetch('/api/all_nodes_all_subs');
        const groups = await res.json();
        allSubsNodesCache = groups || [];
        expandedAggSubs = {};
        selectedAggNodes = {};
        renderAggSubscriptions();
    } catch(e) {
        list.innerHTML = '<div style="text-align:center;color:var(--danger);padding:20px;">加载失败</div>';
    }
}

async function onAggModeChange(value) {
    aggEditFile = (value === 'new') ? '' : value;
    const currentSection = document.getElementById('aggCurrentSection');
    const nameInput = document.getElementById('aggGroupName');
    const btnSubmit = document.getElementById('btnAggSubmit');

    if (aggEditFile) {
        currentSection.style.display = 'block';
        btnSubmit.textContent = '添加选中节点到此分组';
        const group = aggregateGroupsCache.find(g => g.fileName === aggEditFile);
        nameInput.value = group ? group.name : '';
        nameInput.disabled = true;
        try {
            const res = await fetch('/api/aggregate_group_nodes?file=' + encodeURIComponent(aggEditFile));
            aggCurrentNodesList = await res.json() || [];
        } catch(e) { aggCurrentNodesList = []; }
        renderAggCurrentNodes();
    } else {
        currentSection.style.display = 'none';
        nameInput.value = '';
        nameInput.disabled = false;
        btnSubmit.textContent = '保存聚合分组';
        aggCurrentNodesList = [];
    }
}

function renderAggCurrentNodes() {
    const list = document.getElementById('aggCurrentNodeList');
    if (!aggCurrentNodesList || aggCurrentNodesList.length === 0) {
        list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:12px;">暂无节点</div>';
        return;
    }
    let html = '';
    aggCurrentNodesList.forEach((n, idx) => {
        html += `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:13px;">
                <div style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                    <span style="color:var(--text-dim);font-size:11px;margin-right:6px;">[${n.Type}]</span>
                    <span>${n.Name}</span>
                </div>
                <button class="btn-ghost" style="padding:3px 8px;font-size:11px;border-color:rgba(239,68,68,0.3);color:var(--danger);flex-shrink:0;margin-left:8px;" onclick="removeAggNode(${idx})">移除</button>
            </div>
        `;
    });
    list.innerHTML = html;
}

async function removeAggNode(idx) {
    if (!aggEditFile) return;
    try {
        const res = await fetch('/api/aggregate_group_remove_node?file=' + encodeURIComponent(aggEditFile) + '&idx=' + idx, { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast('节点已移除', 'success');
            const res2 = await fetch('/api/aggregate_group_nodes?file=' + encodeURIComponent(aggEditFile));
            aggCurrentNodesList = await res2.json() || [];
            renderAggCurrentNodes();
            if (document.getElementById('aggregateSelect').value === aggEditFile) loadNodes();
        }
    } catch(e) { showToast('移除失败', 'error'); }
}

function renderAggSubscriptions() {
    const list = document.getElementById('aggNodeList');
    if (!allSubsNodesCache || allSubsNodesCache.length === 0) {
        list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:20px;">暂无任何订阅</div>';
        return;
    }
    let html = '';
    allSubsNodesCache.forEach((group, gIdx) => {
        const expanded = !!expandedAggSubs[gIdx];
        html += `
            <div style="margin-top:10px;">
                <button class="btn-ghost" style="width:100%;display:flex;justify-content:space-between;align-items:center;text-align:left;" onclick="toggleAggSubscription(${gIdx})">
                    <span>${expanded ? '▾' : '▸'} ${group.subName}</span>
                    <span style="font-size:11px;opacity:0.65;">${group.nodes.length} 个节点</span>
                </button>
                <div id="aggSubNodes_${gIdx}" style="display:${expanded ? 'block' : 'none'};padding-left:10px;">
        `;
        if (expanded) {
            group.nodes.forEach((n, nIdx) => {
                html += `
                    <label style="display:flex;align-items:center;padding:8px;border-bottom:1px solid rgba(148,163,184,0.1);cursor:pointer;font-size:13px;transition:all 0.2s;">
                        <input type="checkbox" id="aggNodeCheck_${gIdx}_${nIdx}" ${selectedAggNodes[gIdx + '_' + nIdx] ? 'checked' : ''} onchange="setAggNodeSelected(${gIdx}, ${nIdx}, this.checked)" style="margin-right:10px;">
                        <span style="flex:1;">${n.Name}</span>
                        <span style="color:var(--text-dim);font-size:11px;">[${n.Type}]</span>
                    </label>
                `;
            });
        }
        html += '</div></div>';
    });
    list.innerHTML = html;
}

function toggleAggSubscription(gIdx) {
    expandedAggSubs[gIdx] = !expandedAggSubs[gIdx];
    renderAggSubscriptions();
}

function setAggNodeSelected(gIdx, nIdx, checked) {
    const key = gIdx + '_' + nIdx;
    if (checked) selectedAggNodes[key] = true;
    else delete selectedAggNodes[key];
}

function closeAggGroupModal() {
    document.getElementById('aggGroupModal').style.display = 'none';
}

function getSelectedAggNodes() {
    const nodes = [];
    Object.keys(selectedAggNodes).forEach(key => {
        const parts = key.split('_');
        const gIdx = Number(parts[0]);
        const nIdx = Number(parts[1]);
        const node = allSubsNodesCache[gIdx]?.nodes?.[nIdx];
        if (node) nodes.push(node);
    });
    return nodes;
}

async function submitAggAction() {
    const selectedNodes = getSelectedAggNodes();

    if (aggEditFile) {
        // 编辑模式：添加节点到已有分组
        if (selectedNodes.length === 0) return showToast('请从下方订阅中勾选要添加的节点', 'warning');
        try {
            const res = await fetch('/api/aggregate_group_add_nodes', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ file: aggEditFile, nodes: selectedNodes })
            });
            const data = await res.json();
            if (data.ok) {
                showToast('成功添加 ' + selectedNodes.length + ' 个节点！', 'success');
                selectedAggNodes = {};
                renderAggSubscriptions();
                const res2 = await fetch('/api/aggregate_group_nodes?file=' + encodeURIComponent(aggEditFile));
                aggCurrentNodesList = await res2.json() || [];
                renderAggCurrentNodes();
                if (document.getElementById('aggregateSelect').value === aggEditFile) loadNodes();
            } else {
                showToast('添加失败', 'error');
            }
        } catch(e) { showToast('请求失败', 'error'); }
    } else {
        // 新建模式
        const name = document.getElementById('aggGroupName').value.trim();
        if (!name) return showToast('请输入分组名称', 'warning');
        if (selectedNodes.length === 0) return showToast('请至少选择一个节点', 'warning');
        try {
            const res = await fetch('/api/create_aggregated_group', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ name: name, nodes: selectedNodes })
            });
            const data = await res.json();
            if (data.ok) {
                showToast('聚合分组创建成功！', 'success');
                closeAggGroupModal();
                loadAggregateGroups();
            } else {
                showToast('创建失败', 'error');
            }
        } catch(e) { showToast('请求失败', 'error'); }
    }
}

window.onload = () => {
    loadStatus();
    loadSuppliers();
    loadNodes();
    // Default to Nodes tab
    showTab('nodes');
    
    pollTimer = setInterval(() => {
        loadStatus();
        const sel = document.getElementById('supplierSelect');
        if (sel && sel.value) renderSupplierTraffic(sel.value);
    }, 2000);
};
