package ins

import (
	"fmt"
	"net/http"
)

func serveHTML(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>High-Mae 控制面板</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --card-border: rgba(255, 255, 255, 0.1);
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: 'Segoe UI', system-ui, sans-serif;
            margin: 0;
            padding: 20px 20px 20px 20px;
            background-image: radial-gradient(circle at top right, #1e1b4b, #0f172a);
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding: 20px;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(16px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            position: sticky;
            top: 10px;
            z-index: 100;
        }
        h1 {
            margin: 0;
            font-size: 24px;
            background: linear-gradient(to right, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .speed-monitor {
            font-family: monospace;
            background: rgba(0,0,0,0.3);
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 14px;
        }
        .controls {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            margin-bottom: 20px;
            padding: 16px 20px;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(16px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            position: sticky;
            top: 80px;
            z-index: 99;
        }
        .control-card {
            background: rgba(255,255,255,0.05);
            padding: 10px 16px;
            border-radius: 10px;
            border: 1px solid var(--card-border);
            display: flex;
            align-items: center;
            gap: 10px;
            white-space: nowrap;
        }
        .supplier-actions {
            display: flex;
            gap: 8px;
        }
        .btn-update {
            background: linear-gradient(135deg, #10b981, #059669) !important;
            color: white !important;
            font-size: 12px;
            padding: 6px 14px;
        }
        .btn-update:hover { background: linear-gradient(135deg, #059669, #047857) !important; }
        .btn-delete {
            background: linear-gradient(135deg, #ef4444, #dc2626) !important;
            color: white !important;
            font-size: 12px;
            padding: 6px 14px;
        }
        .btn-delete:hover { background: linear-gradient(135deg, #dc2626, #b91c1c) !important; }
        .btn-update:disabled, .btn-delete:disabled {
            background: #475569 !important;
            cursor: not-allowed;
            transform: none;
        }
        select, button {
            background: var(--accent);
            color: black;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
            outline: none;
        }
        select { background: rgba(255,255,255,0.1); color: var(--text-main); border: 1px solid var(--card-border); }
        select option { background: #1e293b; color: #f8fafc; }
        button:hover { background: var(--accent-hover); transform: translateY(-2px); }
        button:disabled { background: #475569; cursor: not-allowed; transform: none; }
        
        .toggle {
            position: relative;
            display: inline-block;
            width: 44px;
            height: 24px;
        }
        .toggle input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background-color: rgba(255,255,255,0.2);
            transition: .4s;
            border-radius: 24px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 18px; width: 18px;
            left: 3px; bottom: 3px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        input:checked + .slider { background-color: var(--success); }
        input:checked + .slider:before { transform: translateX(20px); }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 2px solid transparent;
            border-radius: 16px;
            padding: 20px;
            transition: all 0.3s;
            display: flex;
            flex-direction: column;
            cursor: pointer;
            box-shadow: inset 0 0 0 1px var(--card-border);
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: inset 0 0 0 1px var(--accent), 0 10px 15px -3px rgba(0, 0, 0, 0.2);
        }
        .card.active {
            border-color: var(--success);
            background: rgba(16, 185, 129, 0.1);
            box-shadow: inset 0 0 0 1px var(--success), 0 0 20px rgba(16, 185, 129, 0.2);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .node-type {
            font-size: 12px;
            padding: 4px 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            color: var(--text-sub);
            text-transform: uppercase;
        }
        .node-name {
            font-size: 16px;
            font-weight: 600;
            word-break: break-all;
            margin-bottom: 15px;
            flex-grow: 1;
        }
        .card-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: auto;
        }
        .latency { font-family: monospace; font-size: 14px; }
        .latency.good { color: var(--success); }
        .latency.bad { color: var(--danger); }
        .latency.unknown { color: var(--text-sub); }
        
        .test-btn {
            background: transparent;
            border: 1px solid var(--card-border);
            color: var(--text-sub);
            padding: 6px 12px;
            border-radius: 6px;
        }
        .test-btn:hover { background: rgba(255,255,255,0.1); color: white; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .spin { display: inline-block; animation: spin 1s linear infinite; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>High-Mae</h1>
            <div class="speed-monitor" id="speedMonitor">↑ 0 B/s &nbsp; ↓ 0 B/s</div>
            <div>
                <button onclick="doAction('import')">📋 导入订阅</button>
                <button id="btnTestAll" onclick="testAll()">⚡ 极速测速</button>
            </div>
        </div>

        <div class="controls">
            <div class="control-card">
                <span>🗂️</span>
                <select id="supplierSelect" onchange="switchSupplier(this.value)"></select>
            </div>
            <div class="supplier-actions">
                <button class="btn-update" id="btnUpdate" onclick="updateSupplier()">🔄 更新订阅</button>
                <button class="btn-delete" id="btnDelete" onclick="deleteSupplier()">🗑 删除订阅</button>
            </div>
            <div class="control-card">
                <span>🟢 系统代理</span>
                <label class="toggle"><input type="checkbox" id="chkProxy" onchange="doAction('proxy')"><span class="slider"></span></label>
            </div>
            <div class="control-card">
                <span>🔄 路由模式 (全局)</span>
                <label class="toggle"><input type="checkbox" id="chkMode" onchange="doAction('mode')"><span class="slider"></span></label>
            </div>
            <div class="control-card">
                <span>🔌 虚拟网卡 (TUN)</span>
                <label class="toggle"><input type="checkbox" id="chkTun" onchange="doAction('tun')"><span class="slider"></span></label>
            </div>
        </div>

        <div class="grid" id="nodeGrid"></div>
    </div>

    <script>
        let pollTimer = null;

        async function loadStatus() {
            try {
                const res = await fetch('/api/status');
                const st = await res.json();
                document.getElementById('chkProxy').checked = st.proxy;
                document.getElementById('chkMode').checked = (st.mode === 'Global');
                document.getElementById('chkTun').checked = st.tun;
                document.getElementById('speedMonitor').innerHTML = '↑ ' + st.speedOut + ' &nbsp; ↓ ' + st.speedIn;
            } catch(e) {}
        }

        async function loadSuppliers() {
            try {
                const res = await fetch('/api/suppliers');
                const suppliers = await res.json();
                const sel = document.getElementById('supplierSelect');
                sel.innerHTML = '';
                if (!suppliers || suppliers.length === 0) {
                    const opt = document.createElement('option');
                    opt.textContent = '暂无供应商';
                    opt.disabled = true;
                    sel.appendChild(opt);
                    return;
                }
                suppliers.forEach(s => {
                    const opt = document.createElement('option');
                    opt.value = s.fileName;
                    opt.textContent = s.name;
                    if (s.active) opt.selected = true;
                    sel.appendChild(opt);
                });
            } catch(e) {}
        }

        async function switchSupplier(fileName) {
            await fetch('/api/switch_supplier?file=' + encodeURIComponent(fileName), { method: 'POST' });
            loadNodes();
        }

        async function doAction(type) {
            await fetch('/api/action?type=' + type, { method: 'POST' });
            if (type === 'import') {
                setTimeout(loadSuppliers, 1500);
                setTimeout(loadNodes, 1500);
            }
            setTimeout(loadStatus, 300);
        }

        async function loadNodes() {
            try {
                const res = await fetch('/api/nodes');
                const nodes = await res.json();
                const grid = document.getElementById('nodeGrid');
                grid.innerHTML = '';
                if (!nodes || nodes.length === 0) return;
                
                nodes.forEach(n => {
                    let latClass = 'unknown';
                    let latText = '-- ms';
                    if (n.latency > 0 && n.latency < 500) { latClass = 'good'; latText = n.latency + ' ms'; }
                    else if (n.latency >= 500) { latClass = 'bad'; latText = n.latency + ' ms'; }
                    else if (n.latency === -1) { latClass = 'bad'; latText = 'Timeout'; }

                    const card = document.createElement('div');
                    card.className = 'card ' + (n.active ? 'active' : '');
                    card.onclick = (e) => {
                        if(e.target.tagName !== 'BUTTON') switchNode(n.index);
                    };
                    
                    card.innerHTML = ` + "`" + `
                        <div class="card-header">
                            <span class="node-type">${n.type}</span>
                            ${n.active ? '<span style="color:var(--success);font-size:12px;font-weight:bold;">✅ 运行中</span>' : ''}
                        </div>
                        <div class="node-name">${n.name}</div>
                        <div class="card-footer">
                            <span class="latency ${latClass}" id="lat-${n.index}">⚡ ${latText}</span>
                            <button class="test-btn" onclick="testSingle(${n.index})">TCP测速</button>
                        </div>
                    ` + "`" + `;
                    grid.appendChild(card);
                });
            } catch(e) {}
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
            } catch(e) { alert('请求失败'); }
            btn.disabled = false;
            btn.innerHTML = '🔄 更新订阅';
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
            } catch(e) { alert('请求失败'); }
            btn.disabled = false;
            btn.textContent = '🗑 删除订阅';
        }

        // Init
        loadSuppliers();
        loadNodes();
        loadStatus();
        setInterval(loadStatus, 3000);
    </script>
</body>
</html>`
	fmt.Fprint(w, html)
}
