let pollTimer = null;
let allNodesList = [];
let suppliersCache = [];
let aggregateGroupsCache = [];
let currentGroupFilter = "";
let ruleGroups = [];
let cmdRules = [];
let currentRuleGroupIndex = 0;
let activeTab = "nodes";
let lastDashboardPoll = 0;
let nodeGroupMode = "subscription";
let selectedNodeGroupFile = "";
let switchingNodeIndex = null;

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[ch]));
}

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
    activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    const activeBtn = document.querySelector(`.tab-btn[onclick="showTab('${tabId}')"]`);
    if (activeBtn) activeBtn.classList.add('active');
    
    const activeContent = document.getElementById(`tab-${tabId}`);
    if (activeContent) activeContent.classList.add('active');

    if (tabId === 'dashboard') loadDashboard();
}


function setNodeGroupMode(mode) {
    nodeGroupMode = mode === "aggregate" ? "aggregate" : "subscription";
    selectedNodeGroupFile = "";
    document.querySelectorAll('.node-source-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === nodeGroupMode);
    });
    renderNodes();
}

function renderNodes() {
    const grid = document.getElementById('nodeGrid');
    if (!grid) return;
    grid.innerHTML = '';

    const groups = nodeGroupMode === "aggregate"
        ? aggregateGroupsCache.map(g => ({
            fileName: g.fileName,
            name: g.name,
            active: !!g.active,
            count: g.count || 0,
            type: "aggregate"
        }))
        : suppliersCache.map(s => ({
            fileName: s.fileName,
            name: s.name,
            active: !!s.active,
            count: s.nodeCount || s.count || 0,
            traffic: s.traffic,
            type: "subscription"
        }));

    const activeGroup = groups.find(g => g.active);
    if (!selectedNodeGroupFile && activeGroup) {
        selectedNodeGroupFile = activeGroup.fileName;
    }
    const selectedGroup = groups.find(g => g.fileName === selectedNodeGroupFile);

    if (!groups.length) {
        grid.innerHTML = `<div class="empty-state">${nodeGroupMode === "aggregate" ? "暂无聚合组，可在系统设置中创建。" : "当前没有订阅组，点击 <strong>导入订阅</strong> 开始使用。"}</div>`;
        return;
    }

    const keyword = document.getElementById('nodeSearch')?.value.trim().toLowerCase() || "";
    groups.forEach(g => {
        g.count = allNodesList.filter(n => n.fileName === g.fileName).length;
    });
    const selectedNodes = selectedGroup ? filterNodeRows(allNodesList.filter(n => n.fileName === selectedGroup.fileName), keyword) : [];
    const groupList = groups.filter(g => !keyword || g.name.toLowerCase().includes(keyword) || (selectedGroup && g.fileName === selectedGroup.fileName));

    grid.innerHTML = `
        <aside class="node-group-sidebar">
            <div class="node-group-sidebar-title">${nodeGroupMode === "aggregate" ? "聚合组" : "订阅组"}</div>
            <div class="node-group-list"></div>
        </aside>
        <section class="node-detail-pane">
            <div class="node-detail-header">
                <div>
                    <div class="node-detail-title">${selectedGroup ? escapeHTML(selectedGroup.name) : "未展开组"}</div>
                    <div class="node-detail-subtitle">${selectedGroup ? `${selectedNodes.length} 个节点${keyword ? "匹配当前搜索" : ""}` : "点击左侧组名查看节点，再点一次收起"}</div>
                </div>
                <div class="node-detail-actions">${renderSelectedGroupActions(selectedGroup)}</div>
            </div>
            <div class="node-detail-body"></div>
        </section>
    `;

    const list = grid.querySelector('.node-group-list');
    groupList.forEach(group => {
        const item = document.createElement('button');
        const isSelected = selectedGroup && group.fileName === selectedGroup.fileName;
        item.className = `node-group-item ${isSelected ? 'selected' : ''} ${group.active ? 'active' : ''}`;
        item.onclick = () => selectNodeGroup(group.fileName);
        item.innerHTML = `
            <span class="node-group-name">${escapeHTML(group.name)}</span>
            <span class="node-group-meta">${group.active ? '当前' : ''}${group.count ? ` · ${group.count}` : ''}</span>
        `;
        list.appendChild(item);
    });

    const body = grid.querySelector('.node-detail-body');
    if (!selectedGroup) {
        body.innerHTML = '<div class="empty-state">点击左侧组名称展开节点列表。</div>';
        return;
    }
    if (!selectedNodes.length) {
        body.innerHTML = '<div class="empty-state">没有匹配的节点。</div>';
        return;
    }
    body.appendChild(renderNodeTable(selectedNodes));
}

function filterNodes() {
    renderNodes();
}

function filterNodeRows(nodes, keyword) {
    if (!keyword) return nodes || [];
    return (nodes || []).filter(n =>
        (n.name || "").toLowerCase().includes(keyword) ||
        (n.type || "").toLowerCase().includes(keyword) ||
        (n.group || "").toLowerCase().includes(keyword)
    );
}

function renderSelectedGroupActions(group) {
    if (!group || group.type !== "subscription") return "";
    const file = encodeURIComponent(group.fileName);
    return `
        <button class="btn-mini" title="分享订阅" onclick="shareSupplierFile('${file}', event)">分享</button>
        <button class="btn-mini" title="刷新订阅" onclick="updateSupplierFile('${file}', this, event)">刷新</button>
        <button class="btn-mini btn-mini-danger" title="删除订阅" onclick="deleteSupplierFile('${file}', event)">删除</button>
    `;
}

function renderNodeTable(nodes) {
    const table = document.createElement('table');
    table.className = 'win-explorer-table';
    table.innerHTML = `
        <thead>
            <tr>
                <th style="width: 50px; text-align: center;">状态</th>
                <th>节点名称</th>
                <th style="width: 100px;">协议类型</th>
                <th style="width: 100px; text-align: right;">延迟</th>
                <th style="width: 120px; text-align: right;">带宽</th>
                <th style="width: 280px; text-align: center;">操作</th>
            </tr>
        </thead>
        <tbody></tbody>
    `;
    const tbody = table.querySelector('tbody');
    nodes.forEach(n => {
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
        let speedClass = 'unknown';
        let speedText = '--';
        if (n.speed > 0) {
            speedClass = 'good';
            speedText = formatSpeed(n.speed);
        } else if (n.speed === -1) {
            speedClass = 'bad';
            speedText = '失败';
        }

        const tr = document.createElement('tr');
        if (n.active) tr.className = 'active';
        tr.ondblclick = () => switchNode(n.index);
        tr.innerHTML = `
            <td class="status-cell"><span class="status-dot ${n.active ? 'active' : ''}"></span></td>
            <td class="node-name-cell">${escapeHTML(n.name || '')}</td>
            <td><span class="node-type">${escapeHTML(n.type || '')}</span></td>
            <td style="text-align: right;" class="latency ${latClass}" id="lat-${n.index}">${latText}</td>
            <td style="text-align: right;" class="latency ${speedClass}" id="speed-${n.index}">↓ ${speedText}</td>
            <td class="node-actions-cell">
                <button class="btn-action ${n.active ? 'btn-action-primary' : ''}" ${switchingNodeIndex !== null ? 'disabled' : ''} onclick="switchNode(${n.index})">${switchingNodeIndex === n.index ? '切换中' : (n.active ? '已选择' : '选择')}</button>
                <button class="btn-action" onclick="testSingle(${n.index})">延迟</button>
                <button class="btn-action" onclick="testSpeed(${n.index})">带宽</button>
                <button class="btn-action" onclick="shareNode(${n.index})">分享</button>
                <button class="btn-action btn-action-danger" onclick="deleteNode(${n.index})">删除</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
    return table;
}

async function selectNodeGroup(fileName) {
    if (selectedNodeGroupFile === fileName) {
        selectedNodeGroupFile = "";
        renderNodes();
        return;
    }
    selectedNodeGroupFile = fileName;
    renderNodes();
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
            await loadAggregateGroups();
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
        await loadAggregateGroups();
        renderNodes();
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
        renderNodes();
    } catch(e) {}
}

async function switchSupplier(fileName) {
    if (!fileName) return;
    await fetch('/api/switch_supplier?file=' + encodeURIComponent(fileName), { method: 'POST' });
    suppliersCache.forEach(s => s.active = s.fileName === fileName);
    aggregateGroupsCache.forEach(g => g.active = false);
    document.getElementById('supplierSelect').value = fileName;
    document.getElementById('aggregateSelect').value = '';
    renderSupplierTraffic(fileName);
    await loadNodes();
}

async function switchAggregateGroup(fileName) {
    if (!fileName) return;
    await fetch('/api/switch_aggregate_group?file=' + encodeURIComponent(fileName), { method: 'POST' });
    aggregateGroupsCache.forEach(g => g.active = g.fileName === fileName);
    suppliersCache.forEach(s => s.active = false);
    document.getElementById('aggregateSelect').value = fileName;
    document.getElementById('supplierSelect').value = '';
    renderSupplierTraffic(null);
    await loadNodes();
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
    btn.innerHTML = '<span class="spin">↻</span> 导入中...';
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
    btn.innerHTML = '导入订阅';
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
        
        const activeNode = allNodesList.find(n => n.active);
        const nodeDisplayEl = document.getElementById('selectedNodeDisplay');
        if (nodeDisplayEl) {
            nodeDisplayEl.textContent = activeNode ? `当前节点: ${activeNode.name}` : '当前节点: 直连 (Direct)';
        }
        
        renderNodes();
    } catch(e) {}
}



async function switchNode(idx) {
    if (switchingNodeIndex !== null) {
        showToast('节点正在切换中，请稍候。', 'info');
        return;
    }
    switchingNodeIndex = idx;
    const previousNodes = allNodesList.map(n => ({ ...n }));
    allNodesList = allNodesList.map(n => ({ ...n, active: n.index === idx }));
    renderNodes();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
        const res = await fetch('/api/switch?idx=' + idx, { method: 'POST', signal: controller.signal });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
            allNodesList = previousNodes;
            showToast(data.msg || '节点切换失败', 'error');
            return;
        }
        if (data.msg) showToast(data.msg, 'info', 1800);
        setTimeout(loadNodes, 500);
        setTimeout(loadNodes, 1800);
        loadStatus();
    } catch(e) {
        allNodesList = previousNodes;
        showToast(e.name === 'AbortError' ? '节点切换请求超时，请稍后查看当前节点状态。' : '节点切换请求失败。', 'error');
    } finally {
        clearTimeout(timeout);
        setTimeout(() => {
            switchingNodeIndex = null;
            renderNodes();
        }, 700);
    }
}

async function testSingle(idx) {
    const latEl = document.getElementById('lat-' + idx);
    latEl.textContent = '检测中';
    latEl.className = 'latency unknown';
    await fetch('/api/test_single?idx=' + idx, { method: 'POST' });
    loadNodes();
}

function formatSpeed(bytesPerSec) {
    bytesPerSec = Number(bytesPerSec) || 0;
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

function formatTime(value) {
    if (!value) return '--';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '--';
    return d.toLocaleTimeString();
}

async function loadDashboard() {
    try {
        const res = await fetch('/api/stats');
        const st = await res.json();
        const totalTraffic = (st.totalIn || 0) + (st.totalOut || 0);
        const mem = st.memAlloc || st.heapInuse || 0;
        const sessions = st.trafficSessions || {};
        const current = sessions.current || null;

        document.getElementById('dashMemory').textContent = formatBytes(mem);
        document.getElementById('dashConnections').textContent = String(st.connections || 0);
        document.getElementById('dashTraffic').textContent = current
            ? ('代理 ' + formatBytes(current.proxyTotal || 0) + ' / 直连 ' + formatBytes(current.directTotal || 0))
            : formatBytes(totalTraffic);
        document.getElementById('dashSpeed').textContent = '↑ ' + (st.speedOut || '0 B/s') + ' / ↓ ' + (st.speedIn || '0 B/s');

        renderDashboardTraffic(sessions);
        renderDashboardHistory(sessions);
    } catch(e) {
        showToast('数据看板加载失败', 'error');
    }
}

function renderDashboardTraffic(sessions) {
    const el = document.getElementById('dashboardNodeTraffic');
    if (!el) return;
    const current = sessions?.current;
    if (!current) {
        el.innerHTML = '<div class="empty-state" style="padding:16px;border-radius:12px;">当前没有正在统计的开启记录</div>';
        return;
    }
    const proxyTotal = current.proxyTotal || 0;
    const directTotal = current.directTotal || 0;
    const max = Math.max(proxyTotal, directTotal, 1);
    const rows = [
        ['代理流量', proxyTotal, current.proxyIn || 0, current.proxyOut || 0],
        ['直连流量', directTotal, current.directIn || 0, current.directOut || 0],
    ];
    el.innerHTML = rows.map(([label, total, inbound, outbound]) => `
        <div class="traffic-row">
            <div class="traffic-row-main">
                <span class="traffic-node">${label}</span>
                <span>${formatBytes(total)}</span>
            </div>
            <div class="traffic-bar"><span style="width:${Math.max(4, total / max * 100)}%"></span></div>
            <div class="traffic-row-sub">流入 ${formatBytes(inbound)} · 流出 ${formatBytes(outbound)}</div>
        </div>
    `).join('');
}

function renderDashboardHistory(sessions) {
    const tbody = document.getElementById('dashboardHistory');
    if (!tbody) return;
    const rows = [];
    if (sessions?.current) rows.push(sessions.current);
    rows.push(...(sessions?.history || []));
    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-sub);">暂无记录</td></tr>';
        return;
    }
    tbody.innerHTML = rows.map(log => `
        <tr>
            <td>${formatTime(log.startTime)}</td>
            <td>${log.endTime ? formatTime(log.endTime) : '进行中'}</td>
            <td>${log.duration || '--'}</td>
            <td>${log.mode || '--'}</td>
            <td class="log-node-proxy">${formatBytes(log.proxyTotal || 0)}</td>
            <td class="log-node-direct">${formatBytes(log.directTotal || 0)}</td>
            <td>${formatBytes(log.total || 0)}</td>
            <td class="${log.status === 'Active' ? 'log-status-active' : 'log-status-closed'}">${log.status || '--'}</td>
        </tr>
    `).join('');
}

let testingNodes = new Set();

async function testSpeed(idx) {
    if (testingNodes.has(idx)) return;
    testingNodes.add(idx);

    const speedEl = document.getElementById('speed-' + idx);
    if (!speedEl) {
        testingNodes.delete(idx);
        return;
    }
    speedEl.innerHTML = '<span class="spin">🚀</span> 测速中...';
    speedEl.style.color = 'var(--text-sub)';
    try {
        const res = await fetch('/api/speedtest?idx=' + idx, { method: 'POST' });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            let msg = data.error || '测速失败';
            if (data.stage) msg = `[${data.stage}] ${msg}`;
            speedEl.textContent = '❌ ' + msg;
            speedEl.style.color = 'var(--danger)';
            return;
        }
        speedEl.textContent = '↓ ' + formatSpeed(data.speed);
        speedEl.style.color = 'var(--success)';
        const node = allNodesList.find(n => n.index === idx);
        if (node) node.speed = Number(data.speed) || 0;
    } catch(e) {
        speedEl.textContent = '❌ 测速失败';
        speedEl.style.color = 'var(--danger)';
        const node = allNodesList.find(n => n.index === idx);
        if (node) node.speed = -1;
    } finally {
        testingNodes.delete(idx);
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
    const btn = document.getElementById('btnUpdate');
    btn.disabled = true;
    btn.innerHTML = '<span class="spin">🔄</span>';
    
    try {
        const sRes = await fetch('/api/suppliers');
        const list = await sRes.json();
        suppliersCache = list || [];
    } catch(e) {}

    if (!suppliersCache || suppliersCache.length === 0) {
        showToast('当前没有任何可更新的订阅。', 'warning');
        btn.disabled = false;
        btn.innerHTML = '🔄';
        return;
    }

    let successCount = 0;
    for (const sub of suppliersCache) {
        try {
            const res = await fetch('/api/update_supplier?file=' + encodeURIComponent(sub.fileName), { method: 'POST' });
            const data = await res.json();
            if (data.ok) successCount++;
        } catch(e) {}
    }

    showToast(`成功更新 ${successCount} / ${suppliersCache.length} 个订阅！`, 'success');
    loadNodes();
    loadSuppliers();

    btn.disabled = false;
    btn.innerHTML = '🔄';
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

async function updateSupplierFile(encodedFile, btn, event) {
    if (event) event.stopPropagation();
    const file = decodeURIComponent(encodedFile);
    if (!file || !btn) return;
    const oldText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '⏳';
    try {
        const res = await fetch('/api/update_supplier?file=' + encodeURIComponent(file), { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast(data.msg || '订阅已刷新', 'success');
            await loadSuppliers();
            await loadNodes();
        } else {
            showToast(data.msg || '刷新订阅失败', 'error');
        }
    } catch(e) {
        showToast('刷新订阅请求失败', 'error');
    }
    btn.disabled = false;
    btn.textContent = oldText;
}

async function deleteSupplierFile(encodedFile, event) {
    if (event) event.stopPropagation();
    const file = decodeURIComponent(encodedFile);
    const supplier = suppliersCache.find(s => s.fileName === file);
    const name = supplier?.name || file;
    if (!file) return;
    if (!confirm('确定要删除订阅「' + name + '」吗？\n此操作将同时删除对应的本地节点文件，不可恢复。')) return;
    try {
        const res = await fetch('/api/delete_supplier?file=' + encodeURIComponent(file), { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast('订阅已删除', 'success');
            await loadSuppliers();
            await loadNodes();
        } else {
            showToast(data.msg || '删除订阅失败', 'error');
        }
    } catch(e) {
        showToast('删除订阅请求失败', 'error');
    }
}

async function shareSupplierFile(encodedFile, event) {
    if (event) event.stopPropagation();
    const file = decodeURIComponent(encodedFile);
    const supplier = suppliersCache.find(s => s.fileName === file);
    if (!supplier || !supplier.url) {
        showToast('该订阅没有可分享的原始链接', 'warning');
        return;
    }
    try {
        await copyText(supplier.url);
        showToast('订阅链接已复制到剪贴板', 'success');
    } catch(e) {
        showToast('复制订阅链接失败', 'error');
    }
}

async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
    }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
}

async function shareNode(idx) {
    try {
        const res = await fetch('/api/node_link?idx=' + idx);
        const data = await res.json();
        if (!data.ok) {
            showToast(data.msg || '该节点暂不支持分享链接', 'warning');
            return;
        }
        await copyText(data.link);
        showToast('节点链接已复制到剪贴板', 'success');
    } catch(e) {
        showToast('获取节点链接失败', 'error');
    }
}

async function deleteNode(idx) {
    const node = allNodesList.find(n => n.index === idx);
    const name = node?.name || ('节点 ' + idx);
    if (!confirm('确定要删除节点「' + name + '」吗？')) return;
    try {
        const res = await fetch('/api/delete_node?idx=' + idx, { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast('节点已删除', 'success');
            await loadNodes();
            await loadSuppliers();
        } else {
            showToast(data.msg || '删除节点失败', 'error');
        }
    } catch(e) {
        showToast('删除节点请求失败', 'error');
    }
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

let jsQRLoader = null;

function ensureJsQR() {
    if (window.jsQR) return Promise.resolve();
    if (jsQRLoader) return jsQRLoader;
    jsQRLoader = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js';
        script.async = true;
        script.onload = resolve;
        script.onerror = () => reject(new Error('jsQR load failed'));
        document.head.appendChild(script);
    });
    return jsQRLoader;
}

async function handleQRSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
        await ensureJsQR();
    } catch(e) {
        showToast('二维码识别库加载失败，请改用文本导入。', 'error');
        event.target.value = '';
        return;
    }
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
                showToast('二维码识别成功', 'success');
            } else {
                showToast('无法在图片中识别出二维码，请重试', 'warning');
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
    loadCmdRules();
}

async function loadCmdRules() {
    try {
        const res = await fetch('/api/cmd_rules');
        const data = await res.json();
        cmdRules = data || [];
        renderCmdRules();
    } catch(e) {
        cmdRules = [];
        renderCmdRules();
    }
}

function selectedRuleGroup() {
    return ruleGroups[currentRuleGroupIndex];
}

function actionName(action) {
    if (action === 'direct') return '直连';
    if (action === 'reject') return '拦截';
    if (action === 'proxy') return '代理模式';
    return action || '直连';
}

function typeName(type) {
    if (type === 'domain_suffix') return '后缀';
    if (type === 'domain_keyword') return '关键字';
    if (type === 'domain') return '完整域名';
    return type;
}

function escapeAttr(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function ruleTypeOptions(selected) {
    const types = [
        ['domain_suffix', '域名后缀'],
        ['domain_keyword', '域名关键字'],
        ['domain', '完整域名'],
    ];
    return types.map(([value, label]) => `<option value="${value}" ${value === selected ? 'selected' : ''}>${label}</option>`).join('');
}

function updateRuleType(gIdx, rIdx, type) {
    const group = ruleGroups[gIdx];
    if (!group || !group.rules || !group.rules[rIdx]) return;
    group.rules[rIdx].type = type;
    renderRuleGroups();
}

function updateRuleValue(gIdx, rIdx, value) {
    const group = ruleGroups[gIdx];
    if (!group || !group.rules || !group.rules[rIdx]) return;
    group.rules[rIdx].value = value.trim();
    renderRuleGroups();
}

function ruleEditControls(gIdx, rIdx, r) {
    return `
        <select onchange="updateRuleType(${gIdx}, ${rIdx}, this.value)" style="min-width:112px;padding:5px 8px;border-radius:8px;font-size:12px;margin-right:8px;">
            ${ruleTypeOptions(r.type)}
        </select>
        <input type="text" value="${escapeAttr(r.value)}" onblur="updateRuleValue(${gIdx}, ${rIdx}, this.value)" onkeydown="if(event.key==='Enter') this.blur()" style="min-width:220px;max-width:420px;width:38vw;background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.18);color:white;padding:6px 9px;border-radius:8px;outline:none;font-size:13px;">
    `;
}

function populateRuleGroupActionSelect(currentAction) {
    const sel = document.getElementById('ruleGroupAction');
    if (!sel) return;
    
    sel.innerHTML = `
        <option value="direct">直连 (Direct)</option>
        <option value="proxy">代理模式 (Proxy)</option>
        <option value="reject">拦截 (Reject)</option>
    `;
    
    const nodeNames = [];
    if (typeof allNodesList !== 'undefined' && allNodesList) {
        allNodesList.forEach(n => {
            if (n.Name && !nodeNames.includes(n.Name)) {
                nodeNames.push(n.Name);
            }
        });
    }
    
    const groupNames = [];
    if (typeof allNodesList !== 'undefined' && allNodesList) {
        allNodesList.forEach(n => {
            if (n.Group && !groupNames.includes(n.Group)) {
                groupNames.push(n.Group);
            }
        });
    }
    
    if (typeof aggregateGroupsCache !== 'undefined' && aggregateGroupsCache) {
        aggregateGroupsCache.forEach(g => {
            if (g.name && !groupNames.includes(g.name)) {
                groupNames.push(g.name);
            }
        });
    }
    
    if (nodeNames.length > 0) {
        const nodeOptGroup = document.createElement('optgroup');
        nodeOptGroup.label = "选择特定节点 (Nodes)";
        nodeNames.forEach(name => {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            nodeOptGroup.appendChild(opt);
        });
        sel.appendChild(nodeOptGroup);
    }
    
    if (groupNames.length > 0) {
        const groupOptGroup = document.createElement('optgroup');
        groupOptGroup.label = "选择特定分组 (Groups)";
        groupNames.forEach(name => {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            groupOptGroup.appendChild(opt);
        });
        sel.appendChild(groupOptGroup);
    }
    
    if (currentAction && !Array.from(sel.options).some(opt => opt.value === currentAction)) {
        const opt = document.createElement('option');
        opt.value = currentAction;
        opt.textContent = currentAction;
        sel.appendChild(opt);
    }
    sel.value = currentAction || 'direct';
}

let ruleSelectorNodesCache = {
    subscriptions: [],
    aggregateGroups: []
};
let ruleSelectorExpandedStates = {};

async function loadRuleSelectorNodes() {
    try {
        const resSub = await fetch('/api/all_nodes_all_subs');
        const subs = await resSub.json();
        ruleSelectorNodesCache.subscriptions = subs || [];
        
        const resAgg = await fetch('/api/aggregate_groups');
        const aggs = await resAgg.json();
        ruleSelectorNodesCache.aggregateGroups = [];
        if (aggs && aggs.length > 0) {
            for (const g of aggs) {
                try {
                    const resNodes = await fetch('/api/aggregate_group_nodes?file=' + encodeURIComponent(g.fileName));
                    const nodes = await resNodes.json();
                    ruleSelectorNodesCache.aggregateGroups.push({
                        name: g.name,
                        fileName: g.fileName,
                        nodes: nodes || []
                    });
                } catch(e) {}
            }
        }
    } catch (e) {
        console.error("Failed to load rule selector nodes:", e);
    }
}

function renderIndividualRuleActionSelector(idx) {
    const group = selectedRuleGroup();
    if (!group) return '';
    const r = group.rules[idx];
    if (!r) return '';
    
    const effectiveAction = r.action || '';
    
    let html = `
        <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
            <button class="tree-quick-btn" onclick="setIndividualRuleAction(${idx}, '')" style="background:${effectiveAction === '' ? 'rgba(99,102,241,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === '' ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === '' ? 'var(--accent)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                🔄 跟随规则组默认
            </button>
            <button class="tree-quick-btn" onclick="setIndividualRuleAction(${idx}, 'direct')" style="background:${effectiveAction === 'direct' ? 'rgba(34,197,94,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === 'direct' ? 'var(--success)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === 'direct' ? 'var(--success)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                🟢 直连 (Direct)
            </button>
            <button class="tree-quick-btn" onclick="setIndividualRuleAction(${idx}, 'proxy')" style="background:${effectiveAction === 'proxy' ? 'rgba(99,102,241,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === 'proxy' ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === 'proxy' ? 'var(--accent)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                ⚡ 代理模式 (Proxy)
            </button>
            <button class="tree-quick-btn" onclick="setIndividualRuleAction(${idx}, 'reject')" style="background:${effectiveAction === 'reject' ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === 'reject' ? 'var(--danger)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === 'reject' ? 'var(--danger)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                ❌ 拦截 (Reject)
            </button>
        </div>
        
        <div style="font-size:12px;color:var(--text-sub);margin-bottom:8px;font-weight:bold;">🗂️ 选择特定订阅组或聚合组：</div>
    `;
    
    if (!ruleSelectorExpandedStates[idx]) {
        ruleSelectorExpandedStates[idx] = {};
    }
    const states = ruleSelectorExpandedStates[idx];
    
    if (ruleSelectorNodesCache.subscriptions && ruleSelectorNodesCache.subscriptions.length > 0) {
        ruleSelectorNodesCache.subscriptions.forEach((subGroup, sIdx) => {
            const groupKey = 'sub_' + subGroup.subName;
            const isExpanded = !!states[groupKey];
            const isGroupSelected = effectiveAction === subGroup.subName;
            
            html += `
                <div style="margin-bottom:6px;border-bottom:1px solid rgba(148,163,184,0.05);padding-bottom:6px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 6px;border-radius:6px;background:${isGroupSelected ? 'rgba(99,102,241,0.1)' : 'transparent'};transition:all 0.2s;">
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setIndividualRuleAction(${idx}, '${subGroup.subName}')">
                            <span style="color:var(--accent);font-size:14px;">🗂️</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--accent)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${subGroup.subName}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[订阅组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--accent);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleRuleSelectorGroupExpand(${idx}, '${groupKey}', event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
                                ${isExpanded ? '收起 ▴' : `展开(${subGroup.nodes.length}) ▾`}
                            </button>
                        </div>
                    </div>
            `;
            
            if (isExpanded) {
                html += `
                    <div style="margin:6px 0 0 16px;padding:8px;border-left:2px solid rgba(99,102,241,0.2);background:rgba(255,255,255,0.01);border-radius:0 8px 8px 0;">
                        <table style="width:100%;border-collapse:collapse;font-size:12px;text-align:left;">
                            <thead>
                                <tr style="color:var(--text-dim);border-bottom:1px solid rgba(148,163,184,0.1);">
                                    <th style="padding:4px 8px;">节点名称 (Name)</th>
                                    <th style="padding:4px 8px;width:70px;">协议 (Type)</th>
                                    <th style="padding:4px 8px;width:80px;text-align:right;">操作 (Select)</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                subGroup.nodes.forEach(node => {
                    const isNodeSelected = effectiveAction === node.Name;
                    html += `
                        <tr style="border-bottom:1px solid rgba(148,163,184,0.04);background:${isNodeSelected ? 'rgba(99,102,241,0.08)' : 'transparent'};">
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${node.Name}">${node.Name}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${node.Type.toUpperCase()}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setIndividualRuleAction(${idx}, '${node.Name}')" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
                                    ${isNodeSelected ? '已选择' : '选择'}
                                </button>
                            </td>
                        </tr>
                    `;
                });
                html += `
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            html += `</div>`;
        });
    }
    
    if (ruleSelectorNodesCache.aggregateGroups && ruleSelectorNodesCache.aggregateGroups.length > 0) {
        ruleSelectorNodesCache.aggregateGroups.forEach((aggGroup, gIdx2) => {
            const groupKey = 'agg_' + aggGroup.name;
            const isExpanded = !!states[groupKey];
            const isGroupSelected = effectiveAction === aggGroup.name;
            
            html += `
                <div style="margin-bottom:6px;border-bottom:1px solid rgba(148,163,184,0.05);padding-bottom:6px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 6px;border-radius:6px;background:${isGroupSelected ? 'rgba(99,102,241,0.1)' : 'transparent'};transition:all 0.2s;">
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setIndividualRuleAction(${idx}, '${aggGroup.name}')">
                            <span style="color:var(--success);font-size:14px;">📁</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--success)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${aggGroup.name}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[聚合组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--success);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleRuleSelectorGroupExpand(${idx}, '${groupKey}', event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
                                ${isExpanded ? '收起 ▴' : `展开(${aggGroup.nodes.length}) ▾`}
                            </button>
                        </div>
                    </div>
            `;
            
            if (isExpanded) {
                html += `
                    <div style="margin:6px 0 0 16px;padding:8px;border-left:2px solid rgba(34,197,94,0.2);background:rgba(255,255,255,0.01);border-radius:0 8px 8px 0;">
                        <table style="width:100%;border-collapse:collapse;font-size:12px;text-align:left;">
                            <thead>
                                <tr style="color:var(--text-dim);border-bottom:1px solid rgba(148,163,184,0.1);">
                                    <th style="padding:4px 8px;">节点名称 (Name)</th>
                                    <th style="padding:4px 8px;width:70px;">协议 (Type)</th>
                                    <th style="padding:4px 8px;width:80px;text-align:right;">操作 (Select)</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                aggGroup.nodes.forEach(node => {
                    const isNodeSelected = effectiveAction === node.Name;
                    html += `
                        <tr style="border-bottom:1px solid rgba(148,163,184,0.04);background:${isNodeSelected ? 'rgba(99,102,241,0.08)' : 'transparent'};">
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${node.Name}">${node.Name}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${node.Type.toUpperCase()}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setIndividualRuleAction(${idx}, '${node.Name}')" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
                                    ${isNodeSelected ? '已选择' : '选择'}
                                </button>
                            </td>
                        </tr>
                    `;
                });
                html += `
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            html += `</div>`;
        });
    }
    
    return html;
}

function renderSearchRuleActionSelector(gIdx, rIdx) {
    const group = ruleGroups[gIdx];
    if (!group) return '';
    const r = group.rules[rIdx];
    if (!r) return '';
    
    const effectiveAction = r.action || '';
    
    let html = `
        <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
            <button class="tree-quick-btn" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, '')" style="background:${effectiveAction === '' ? 'rgba(99,102,241,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === '' ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === '' ? 'var(--accent)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                🔄 跟随规则组默认
            </button>
            <button class="tree-quick-btn" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, 'direct')" style="background:${effectiveAction === 'direct' ? 'rgba(34,197,94,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === 'direct' ? 'var(--success)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === 'direct' ? 'var(--success)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                🟢 直连 (Direct)
            </button>
            <button class="tree-quick-btn" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, 'proxy')" style="background:${effectiveAction === 'proxy' ? 'rgba(99,102,241,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === 'proxy' ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === 'proxy' ? 'var(--accent)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                ⚡ 代理模式 (Proxy)
            </button>
            <button class="tree-quick-btn" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, 'reject')" style="background:${effectiveAction === 'reject' ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)'};border:1px solid ${effectiveAction === 'reject' ? 'var(--danger)' : 'rgba(148,163,184,0.15)'};color:${effectiveAction === 'reject' ? 'var(--danger)' : 'white'};padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:bold;">
                ❌ 拦截 (Reject)
            </button>
        </div>
        
        <div style="font-size:12px;color:var(--text-sub);margin-bottom:8px;font-weight:bold;">🗂️ 选择特定订阅组或聚合组：</div>
    `;
    
    const statesKey = `search_${gIdx}_${rIdx}`;
    if (!ruleSelectorExpandedStates[statesKey]) {
        ruleSelectorExpandedStates[statesKey] = {};
    }
    const states = ruleSelectorExpandedStates[statesKey];
    
    if (ruleSelectorNodesCache.subscriptions && ruleSelectorNodesCache.subscriptions.length > 0) {
        ruleSelectorNodesCache.subscriptions.forEach((subGroup, sIdx) => {
            const groupKey = 'sub_' + subGroup.subName;
            const isExpanded = !!states[groupKey];
            const isGroupSelected = effectiveAction === subGroup.subName;
            
            html += `
                <div style="margin-bottom:6px;border-bottom:1px solid rgba(148,163,184,0.05);padding-bottom:6px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 6px;border-radius:6px;background:${isGroupSelected ? 'rgba(99,102,241,0.1)' : 'transparent'};transition:all 0.2s;">
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, '${subGroup.subName}')">
                            <span style="color:var(--accent);font-size:14px;">🗂️</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--accent)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${subGroup.subName}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[订阅组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--accent);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleSearchRuleSelectorGroupExpand(${gIdx}, ${rIdx}, '${groupKey}', event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
                                ${isExpanded ? '收起 ▴' : `展开(${subGroup.nodes.length}) ▾`}
                            </button>
                        </div>
                    </div>
            `;
            
            if (isExpanded) {
                html += `
                    <div style="margin:6px 0 0 16px;padding:8px;border-left:2px solid rgba(99,102,241,0.2);background:rgba(255,255,255,0.01);border-radius:0 8px 8px 0;">
                        <table style="width:100%;border-collapse:collapse;font-size:12px;text-align:left;">
                            <thead>
                                <tr style="color:var(--text-dim);border-bottom:1px solid rgba(148,163,184,0.1);">
                                    <th style="padding:4px 8px;">节点名称 (Name)</th>
                                    <th style="padding:4px 8px;width:70px;">协议 (Type)</th>
                                    <th style="padding:4px 8px;width:80px;text-align:right;">操作 (Select)</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                subGroup.nodes.forEach(node => {
                    const isNodeSelected = effectiveAction === node.Name;
                    html += `
                        <tr style="border-bottom:1px solid rgba(148,163,184,0.04);background:${isNodeSelected ? 'rgba(99,102,241,0.08)' : 'transparent'};">
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${node.Name}">${node.Name}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${node.Type.toUpperCase()}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setSearchRuleAction(${gIdx}, ${rIdx}, '${node.Name}')" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
                                    ${isNodeSelected ? '已选择' : '选择'}
                                </button>
                            </td>
                        </tr>
                    `;
                });
                html += `
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            html += `</div>`;
        });
    }
    
    if (ruleSelectorNodesCache.aggregateGroups && ruleSelectorNodesCache.aggregateGroups.length > 0) {
        ruleSelectorNodesCache.aggregateGroups.forEach((aggGroup, gIdx2) => {
            const groupKey = 'agg_' + aggGroup.name;
            const isExpanded = !!states[groupKey];
            const isGroupSelected = effectiveAction === aggGroup.name;
            
            html += `
                <div style="margin-bottom:6px;border-bottom:1px solid rgba(148,163,184,0.05);padding-bottom:6px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 6px;border-radius:6px;background:${isGroupSelected ? 'rgba(99,102,241,0.1)' : 'transparent'};transition:all 0.2s;">
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, '${aggGroup.name}')">
                            <span style="color:var(--success);font-size:14px;">📁</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--success)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${aggGroup.name}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[聚合组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--success);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleSearchRuleSelectorGroupExpand(${gIdx}, ${rIdx}, '${groupKey}', event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
                                ${isExpanded ? '收起 ▴' : `展开(${aggGroup.nodes.length}) ▾`}
                            </button>
                        </div>
                    </div>
            `;
            
            if (isExpanded) {
                html += `
                    <div style="margin:6px 0 0 16px;padding:8px;border-left:2px solid rgba(34,197,94,0.2);background:rgba(255,255,255,0.01);border-radius:0 8px 8px 0;">
                        <table style="width:100%;border-collapse:collapse;font-size:12px;text-align:left;">
                            <thead>
                                <tr style="color:var(--text-dim);border-bottom:1px solid rgba(148,163,184,0.1);">
                                    <th style="padding:4px 8px;">节点名称 (Name)</th>
                                    <th style="padding:4px 8px;width:70px;">协议 (Type)</th>
                                    <th style="padding:4px 8px;width:80px;text-align:right;">操作 (Select)</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                aggGroup.nodes.forEach(node => {
                    const isNodeSelected = effectiveAction === node.Name;
                    html += `
                        <tr style="border-bottom:1px solid rgba(148,163,184,0.04);background:${isNodeSelected ? 'rgba(99,102,241,0.08)' : 'transparent'};">
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${node.Name}">${node.Name}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${node.Type.toUpperCase()}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setSearchRuleAction(${gIdx}, ${rIdx}, '${node.Name}')" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
                                    ${isNodeSelected ? '已选择' : '选择'}
                                </button>
                            </td>
                        </tr>
                    `;
                });
                html += `
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            html += `</div>`;
        });
    }
    
    return html;
}

function toggleIndividualRuleActionSelector(idx, event) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    const el = document.getElementById(`rule-action-selector-${idx}`);
    if (!el) return;
    const isHidden = el.style.display === 'none';
    
    document.querySelectorAll('.rule-action-selector-drawer').forEach(drawer => {
        drawer.style.display = 'none';
    });
    
    if (isHidden) {
        el.style.display = 'block';
        el.innerHTML = renderIndividualRuleActionSelector(idx);
    } else {
        el.style.display = 'none';
    }
}

function toggleRuleSelectorGroupExpand(idx, groupKey, event) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    if (!ruleSelectorExpandedStates[idx]) {
        ruleSelectorExpandedStates[idx] = {};
    }
    ruleSelectorExpandedStates[idx][groupKey] = !ruleSelectorExpandedStates[idx][groupKey];
    const el = document.getElementById(`rule-action-selector-${idx}`);
    if (el) {
        el.innerHTML = renderIndividualRuleActionSelector(idx);
    }
}

function setIndividualRuleAction(idx, action) {
    const group = selectedRuleGroup();
    if (!group || !group.rules || !group.rules[idx]) return;
    
    if (action === '') {
        delete group.rules[idx].action;
    } else {
        group.rules[idx].action = action;
    }
    
    renderRuleGroups();
    
    const el = document.getElementById(`rule-action-selector-${idx}`);
    if (el) {
        el.style.display = 'block';
        el.innerHTML = renderIndividualRuleActionSelector(idx);
    }
}

function toggleSearchRuleActionSelector(gIdx, rIdx, event) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    const el = document.getElementById(`rule-action-selector-search-${gIdx}-${rIdx}`);
    if (!el) return;
    const isHidden = el.style.display === 'none';
    
    document.querySelectorAll('.rule-action-selector-drawer').forEach(drawer => {
        drawer.style.display = 'none';
    });
    
    if (isHidden) {
        el.style.display = 'block';
        el.innerHTML = renderSearchRuleActionSelector(gIdx, rIdx);
    } else {
        el.style.display = 'none';
    }
}

function toggleSearchRuleSelectorGroupExpand(gIdx, rIdx, groupKey, event) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    const statesKey = `search_${gIdx}_${rIdx}`;
    if (!ruleSelectorExpandedStates[statesKey]) {
        ruleSelectorExpandedStates[statesKey] = {};
    }
    ruleSelectorExpandedStates[statesKey][groupKey] = !ruleSelectorExpandedStates[statesKey][groupKey];
    const el = document.getElementById(`rule-action-selector-search-${gIdx}-${rIdx}`);
    if (el) {
        el.innerHTML = renderSearchRuleActionSelector(gIdx, rIdx);
    }
}

function setSearchRuleAction(gIdx, rIdx, action) {
    const group = ruleGroups[gIdx];
    if (!group || !group.rules || !group.rules[rIdx]) return;
    
    if (action === '') {
        delete group.rules[rIdx].action;
    } else {
        group.rules[rIdx].action = action;
    }
    
    renderRules();
    
    const el = document.getElementById(`rule-action-selector-search-${gIdx}-${rIdx}`);
    if (el) {
        el.style.display = 'block';
        el.innerHTML = renderSearchRuleActionSelector(gIdx, rIdx);
    }
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
    populateRuleGroupActionSelect(group ? group.action : 'direct');
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
    ruleSelectorExpandedStates = {};
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
                const effectiveAction = r.action || g.action || 'direct';
                const actionColor = (effectiveAction === 'direct') ? 'var(--success)' : ((effectiveAction === 'reject') ? 'var(--danger)' : 'var(--accent)');
                html += `
                    <div class="rule-item-container" style="border-bottom:1px solid rgba(148,163,184,0.1);padding:10px 0;">
                        <div style="display:flex;justify-content:space-between;align-items:center;font-size:14px;padding:0 10px;">
                            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-width:0;">
                                <span style="background:rgba(99,102,241,0.15);padding:2px 6px;border-radius:4px;font-size:11px;margin-right:6px;color:var(--accent);">${g.name}</span>
                                ${ruleEditControls(gIdx, rIdx, r)}
                                <span class="rule-action-badge" style="color:${actionColor};font-weight:bold;margin-left:8px;font-size:12px;cursor:pointer;border:1px solid ${actionColor}33;padding:2px 8px;border-radius:10px;background:${actionColor}11;display:inline-flex;align-items:center;gap:4px;user-select:none;transition:all 0.2s;" onclick="toggleSearchRuleActionSelector(${gIdx}, ${rIdx}, event)">
                                    ${actionName(effectiveAction)} ▾
                                </span>
                            </div>
                        </div>
                        <div id="rule-action-selector-search-${gIdx}-${rIdx}" class="rule-action-selector-drawer" style="display:none;margin:10px 10px 5px 10px;padding:12px;border:1px solid rgba(148,163,184,0.15);border-radius:14px;background:rgba(255,255,255,0.015);box-shadow:inset 0 2px 8px rgba(0,0,0,0.2);">
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
        const effectiveAction = r.action || group.action || 'direct';
        const actionColor = (effectiveAction === 'direct') ? 'var(--success)' : ((effectiveAction === 'reject') ? 'var(--danger)' : 'var(--accent)');
        html += `
            <div class="rule-item-container" style="border-bottom:1px solid rgba(148,163,184,0.1);padding:10px 0;">
                <div style="display:flex;justify-content:space-between;align-items:center;font-size:14px;padding:0 10px;">
                    <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-width:0;">
                        ${ruleEditControls(currentRuleGroupIndex, idx, r)}
                        <span class="rule-action-badge" style="color:${actionColor};font-weight:bold;margin-left:8px;font-size:12px;cursor:pointer;border:1px solid ${actionColor}33;padding:2px 8px;border-radius:10px;background:${actionColor}11;display:inline-flex;align-items:center;gap:4px;user-select:none;transition:all 0.2s;" onclick="toggleIndividualRuleActionSelector(${idx}, event)">
                            ${actionName(effectiveAction)} ▾
                        </span>
                    </div>
                    <button class="btn-ghost" style="padding:4px 8px;font-size:12px;border-color:rgba(239,68,68,0.3);color:var(--danger);" onclick="deleteRule(${idx})">删除</button>
                </div>
                
                <div id="rule-action-selector-${idx}" class="rule-action-selector-drawer" style="display:none;margin:10px 10px 5px 10px;padding:12px;border:1px solid rgba(148,163,184,0.15);border-radius:14px;background:rgba(255,255,255,0.015);box-shadow:inset 0 2px 8px rgba(0,0,0,0.2);">
                </div>
            </div>
        `;
    });
    list.innerHTML = html;
}

function cmdRuleTypeName(type) {
    return type === 'exact' ? '完整命令' : '命令前缀';
}

function renderCmdRules() {
    const list = document.getElementById('cmdRuleList');
    if (!list) return;
    if (!cmdRules || cmdRules.length === 0) {
        list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:14px;">暂无命令行规则</div>';
        return;
    }
    list.innerHTML = cmdRules.map((rule, idx) => {
        const action = rule.action || 'direct';
        const actionColor = action === 'direct' ? 'var(--success)' : 'var(--accent)';
        return `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 2px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:13px;">
                <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;flex-wrap:wrap;">
                    <span style="background:rgba(255,255,255,0.06);border:1px solid rgba(148,163,184,0.15);padding:2px 6px;border-radius:6px;font-size:11px;color:var(--text-sub);">${cmdRuleTypeName(rule.type)}</span>
                    <code style="color:var(--text-main);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:430px;">${escapeHtml(rule.pattern)}</code>
                    <span style="color:${actionColor};font-weight:700;">${actionName(action)}</span>
                </div>
                <button class="btn-ghost" style="padding:4px 8px;font-size:12px;border-color:rgba(239,68,68,0.3);color:var(--danger);" onclick="deleteCmdRule(${idx})">删除</button>
            </div>
        `;
    }).join('');
}

function addCmdRule() {
    const patternEl = document.getElementById('cmdRulePattern');
    const pattern = (patternEl.value || '').trim();
    if (!pattern) return showToast('请输入命令行匹配内容', 'warning');
    const type = document.getElementById('cmdRuleType').value || 'prefix';
    const action = document.getElementById('cmdRuleAction').value || 'direct';
    cmdRules.push({ pattern, type, action });
    patternEl.value = '';
    renderCmdRules();
}

function deleteCmdRule(idx) {
    if (!cmdRules || idx < 0 || idx >= cmdRules.length) return;
    cmdRules.splice(idx, 1);
    renderCmdRules();
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
        const ruleRes = await fetch('/api/rules', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(ruleGroups)
        });
        const cmdRes = await fetch('/api/cmd_rules', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(cmdRules)
        });
        if (!ruleRes.ok || !cmdRes.ok) throw new Error('save failed');
        alert('规则保存成功！');
        closeRuleModal();
    } catch(e) {
        alert('保存失败');
    }
}

function openRuleModal() {
    document.getElementById('ruleModal').style.display = 'flex';
    ruleSelectorExpandedStates = {};
    loadRules();
    loadRuleSelectorNodes();
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
    
    showTab('nodes');
    
    pollTimer = setInterval(() => {
        loadStatus();
        if (activeTab === 'dashboard' && Date.now() - lastDashboardPoll > 4000) {
            lastDashboardPoll = Date.now();
            loadDashboard();
        }
        if (allNodesList && allNodesList.length > 0) {
            const activeNode = allNodesList.find(n => n.active);
            if (activeNode) {
                renderSupplierTraffic(activeNode.fileName);
            }
        }
    }, 2000);
};
