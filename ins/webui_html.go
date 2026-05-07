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
            --bg-0: #070b14;
            --bg-1: #0b1220;
            --bg-2: #111b2e;
            --card-bg: rgba(17, 27, 46, 0.76);
            --card-bg-strong: rgba(15, 23, 42, 0.92);
            --card-border: rgba(148, 163, 184, 0.16);
            --card-border-strong: rgba(96, 165, 250, 0.35);
            --text-main: #eef2ff;
            --text-sub: #94a3b8;
            --text-dim: #64748b;
            --accent: #60a5fa;
            --accent-2: #a78bfa;
            --accent-hover: #3b82f6;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --radius: 18px;
            --shadow: 0 18px 50px rgba(0, 0, 0, 0.35);
            --shadow-soft: 0 10px 30px rgba(0, 0, 0, 0.22);
        }

        * {
            box-sizing: border-box;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            margin: 0;
            min-height: 100vh;
            color: var(--text-main);
            font-family: Inter, "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif;
            background:
                radial-gradient(circle at top left, rgba(96, 165, 250, 0.18), transparent 28%),
                radial-gradient(circle at top right, rgba(167, 139, 250, 0.14), transparent 26%),
                radial-gradient(circle at bottom left, rgba(16, 185, 129, 0.08), transparent 24%),
                linear-gradient(180deg, var(--bg-0), var(--bg-1) 38%, #0a1020 100%);
            background-attachment: fixed;
            padding: 20px;
            overflow-x: hidden;
        }

        body::before {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 48px 48px;
            mask-image: linear-gradient(180deg, rgba(0,0,0,0.4), transparent 90%);
            opacity: 0.35;
        }

        .container {
            position: relative;
            max-width: 1240px;
            margin: 0 auto;
        }

        .header,
        .controls,
        .card,
        .modal {
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
        }

        .header {
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            justify-content: space-between;
            align-items: center;
            padding: 18px 20px;
            margin-bottom: 18px;
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.98), rgba(15, 23, 42, 0.86));
            border: 1px solid var(--card-border);
            border-radius: var(--radius);
            box-shadow: var(--shadow-soft);
            position: sticky;
            top: 12px;
            z-index: 100;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 0;
        }

        .brand-badge {
            width: 42px;
            height: 42px;
            border-radius: 14px;
            display: grid;
            place-items: center;
            font-weight: 800;
            color: white;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            box-shadow: 0 10px 24px rgba(96, 165, 250, 0.25);
            flex: 0 0 auto;
        }

        h1 {
            margin: 0;
            font-size: 24px;
            line-height: 1.2;
            letter-spacing: 0.2px;
            background: linear-gradient(90deg, #dbeafe 0%, #93c5fd 40%, #c4b5fd 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .subtitle {
            margin-top: 4px;
            color: var(--text-sub);
            font-size: 12px;
            line-height: 1.4;
        }

        .speed-monitor {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
            background: rgba(2, 6, 23, 0.45);
            border: 1px solid rgba(148, 163, 184, 0.14);
            padding: 9px 14px;
            border-radius: 12px;
            font-size: 13px;
            color: #dbeafe;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
            white-space: nowrap;
        }

        .header-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }

        .controls {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            margin-bottom: 20px;
            padding: 16px;
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.96), rgba(15, 23, 42, 0.82));
            border: 1px solid var(--card-border);
            border-radius: var(--radius);
            box-shadow: var(--shadow-soft);
            position: sticky;
            top: 86px;
            z-index: 99;
        }

        .control-card {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px;
            border-radius: 14px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(148, 163, 184, 0.12);
            color: var(--text-main);
            white-space: nowrap;
        }

        .supplier-actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 18px;
            padding-bottom: 10px;
        }

        .card {
            position: relative;
            background:
                linear-gradient(180deg, rgba(17, 27, 46, 0.86), rgba(15, 23, 42, 0.72));
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 18px;
            transition: transform 0.22s ease, box-shadow 0.22s ease, border-color 0.22s ease, background 0.22s ease;
            display: flex;
            flex-direction: column;
            min-height: 176px;
            box-shadow: var(--shadow-soft);
            overflow: hidden;
        }

        .card::before {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(96,165,250,0.08), transparent 42%, rgba(167,139,250,0.05));
            pointer-events: none;
        }

        .card:hover {
            transform: translateY(-4px);
            border-color: var(--card-border-strong);
            box-shadow: 0 18px 36px rgba(0, 0, 0, 0.28);
        }

        .card.active {
            border-color: rgba(16, 185, 129, 0.45);
            background:
                linear-gradient(180deg, rgba(16, 185, 129, 0.12), rgba(15, 23, 42, 0.72));
            box-shadow: 0 0 0 1px rgba(16, 185, 129, 0.14) inset, 0 18px 36px rgba(0,0,0,0.28);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
            position: relative;
            z-index: 1;
        }

        .node-type {
            font-size: 11px;
            padding: 5px 10px;
            border-radius: 999px;
            letter-spacing: 0.6px;
            text-transform: uppercase;
            color: #bfdbfe;
            background: rgba(96, 165, 250, 0.12);
            border: 1px solid rgba(96, 165, 250, 0.16);
            flex: 0 0 auto;
        }

        .node-name {
            font-size: 15px;
            font-weight: 600;
            line-height: 1.6;
            word-break: break-all;
            color: var(--text-main);
            margin-bottom: 16px;
            flex-grow: 1;
            position: relative;
            z-index: 1;
        }

        .card-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: auto;
            gap: 10px;
            flex-wrap: wrap;
            position: relative;
            z-index: 1;
        }

        .latency {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
            font-size: 13px;
        }

        .latency.good { color: #34d399; }
        .latency.bad { color: #f87171; }
        .latency.unknown { color: var(--text-sub); }

        .test-btn,
        .bw-btn,
        .btn-update,
        .btn-delete,
        .action-btn {
            border: 1px solid transparent;
            border-radius: 12px;
            padding: 10px 14px;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.2s ease, filter 0.2s ease, background 0.2s ease, border-color 0.2s ease, opacity 0.2s ease;
            outline: none;
            white-space: nowrap;
        }

        button:hover {
            transform: translateY(-1px);
            filter: brightness(1.04);
        }

        button:active {
            transform: translateY(0);
        }

        button:disabled {
            opacity: 0.55;
            cursor: not-allowed;
            transform: none;
            filter: none;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent), var(--accent-hover));
            color: #fff;
            box-shadow: 0 10px 24px rgba(59, 130, 246, 0.18);
        }

        .btn-success {
            background: linear-gradient(135deg, #10b981, #059669);
            color: #fff;
            box-shadow: 0 10px 24px rgba(16, 185, 129, 0.18);
        }

        .btn-danger {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: #fff;
            box-shadow: 0 10px 24px rgba(239, 68, 68, 0.18);
        }

        .btn-ghost {
            background: rgba(255,255,255,0.04);
            color: var(--text-main);
            border-color: rgba(148, 163, 184, 0.16);
        }

        .btn-update {
            background: linear-gradient(135deg, #10b981, #059669) !important;
            color: white !important;
            font-size: 12px;
            padding: 8px 12px;
        }

        .btn-update:hover {
            background: linear-gradient(135deg, #059669, #047857) !important;
        }

        .btn-delete {
            background: linear-gradient(135deg, #ef4444, #dc2626) !important;
            color: white !important;
            font-size: 12px;
            padding: 8px 12px;
        }

        .btn-delete:hover {
            background: linear-gradient(135deg, #dc2626, #b91c1c) !important;
        }

        .test-btn {
            background: rgba(255,255,255,0.04);
            border-color: rgba(148, 163, 184, 0.18);
            color: #cbd5e1;
            padding: 8px 12px;
            border-radius: 10px;
        }

        .test-btn:hover {
            background: rgba(255,255,255,0.08);
            color: white;
        }

        .bw-btn {
            background: rgba(96, 165, 250, 0.08);
            border-color: rgba(96, 165, 250, 0.32);
            color: #93c5fd;
            padding: 8px 12px;
            border-radius: 10px;
        }

        .bw-btn:hover {
            background: rgba(96, 165, 250, 0.16);
            color: white;
        }

        select {
            background: rgba(255,255,255,0.05);
            color: var(--text-main);
            border: 1px solid rgba(148, 163, 184, 0.18);
            padding: 10px 14px;
            border-radius: 12px;
            cursor: pointer;
            font-weight: 600;
            outline: none;
            min-width: 180px;
            max-width: 280px;
        }

        select:hover {
            border-color: rgba(96, 165, 250, 0.35);
        }

        select option {
            background: #0f172a;
            color: #f8fafc;
        }

        .toggle {
            position: relative;
            display: inline-block;
            width: 46px;
            height: 26px;
            flex: 0 0 auto;
        }

        .toggle input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            inset: 0;
            background-color: rgba(255,255,255,0.16);
            transition: 0.25s ease;
            border-radius: 999px;
            border: 1px solid rgba(148, 163, 184, 0.15);
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 2px;
            top: 2px;
            background-color: white;
            transition: 0.25s ease;
            border-radius: 50%;
            box-shadow: 0 4px 10px rgba(0,0,0,0.2);
        }

        input:checked + .slider {
            background: linear-gradient(135deg, var(--success), #059669);
        }

        input:checked + .slider:before {
            transform: translateX(20px);
        }

        .speed-positive {
            color: #34d399;
        }

        .speed-negative {
            color: #f87171;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .spin {
            display: inline-block;
            animation: spin 1s linear infinite;
        }

        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(2, 6, 23, 0.72);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            padding: 20px;
        }

        .modal {
            width: min(560px, 100%);
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.98), rgba(15, 23, 42, 0.92));
            border: 1px solid rgba(148, 163, 184, 0.16);
            border-radius: 22px;
            padding: 22px;
            box-shadow: var(--shadow);
        }

        .modal h2 {
            margin: 0 0 14px;
            font-size: 20px;
            line-height: 1.3;
        }

        .modal textarea {
            width: 100%;
            min-height: 140px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(148, 163, 184, 0.18);
            color: white;
            border-radius: 14px;
            padding: 14px;
            margin-bottom: 14px;
            box-sizing: border-box;
            resize: vertical;
            outline: none;
            font-size: 14px;
            line-height: 1.6;
        }

        .modal textarea:focus {
            border-color: rgba(96, 165, 250, 0.45);
            box-shadow: 0 0 0 4px rgba(96, 165, 250, 0.08);
        }

        .modal .btn-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 14px;
        }

        .modal .btn-group button {
            flex: 1 1 180px;
            padding: 10px 12px;
            font-size: 13px;
        }

        .modal .action-bar {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            flex-wrap: wrap;
        }

        .empty-state {
            grid-column: 1 / -1;
            border: 1px dashed rgba(148, 163, 184, 0.22);
            background: rgba(255,255,255,0.03);
            border-radius: 20px;
            padding: 28px;
            text-align: center;
            color: var(--text-sub);
        }

        .empty-state strong {
            color: var(--text-main);
        }

        @media (max-width: 860px) {
            body {
                padding: 14px;
            }

            .header {
                position: static;
            }

            .controls {
                position: static;
            }

            .header-actions,
            .supplier-actions {
                width: 100%;
            }

            .header-actions button,
            .supplier-actions button,
            .control-card,
            select {
                width: 100%;
            }

            .grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 540px) {
            h1 {
                font-size: 20px;
            }

            .speed-monitor {
                width: 100%;
                text-align: center;
            }

            .header {
                padding: 16px;
            }

            .controls {
                padding: 14px;
            }

            .card {
                min-height: 0;
            }
        }

        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(15, 23, 42, 0.85);
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(148, 163, 184, 0.32);
            border-radius: 999px;
            border: 2px solid rgba(15, 23, 42, 0.85);
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(148, 163, 184, 0.46);
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="brand">
                <div class="brand-badge">HM</div>
                <div>
                    <h1>High-Mae 控制面板</h1>
                    <div class="subtitle">节点管理 · 订阅更新 · 极速测速 · TUN / 全局模式</div>
                </div>
            </div>

            <div class="speed-monitor" id="speedMonitor">↑ 0 B/s &nbsp; ↓ 0 B/s</div>

            <div class="header-actions">
                <button class="btn-success" onclick="openAddModal()">➕ 添加节点</button>
                <button class="btn-ghost" onclick="doAction('import')">📋 导入订阅</button>
                <button class="btn-primary" id="btnTestAll" onclick="testAll()">⚡ 极速测速</button>
            </div>
        </div>

        <div class="controls">
            <div class="control-card">
                <span>🗂️</span>
                <select id="supplierSelect" onchange="switchSupplier(this.value)"></select>
            </div>

            <div class="supplier-actions">
                <button class="btn-update" id="btnUpdate" onclick="updateSupplier()">🔄 更新</button>
                <button class="btn-delete" id="btnDelete" onclick="deleteSupplier()">🗑 删除</button>
            </div>

            <div class="control-card">
                <span>🟢 代理</span>
                <label class="toggle"><input type="checkbox" id="chkProxy" onchange="doAction('proxy')"><span class="slider"></span></label>
            </div>

            <div class="control-card">
                <span>🔄 全局</span>
                <label class="toggle"><input type="checkbox" id="chkMode" onchange="doAction('mode')"><span class="slider"></span></label>
            </div>

            <div class="control-card">
                <span>🔌 TUN</span>
                <label class="toggle"><input type="checkbox" id="chkTun" onchange="doAction('tun')"><span class="slider"></span></label>
            </div>
        </div>

        <div class="grid" id="nodeGrid"></div>
    </div>

    <div class="modal-overlay" id="addModal">
        <div class="modal">
            <h2>添加单节点</h2>
            <textarea id="nodeInput" placeholder="在此粘贴节点链接(vless://, hy2://) 或配置文件内容..."></textarea>

            <div class="btn-group">
                <button class="btn-ghost" onclick="document.getElementById('fileInput').click()">📁 选择文件</button>
                <input type="file" id="fileInput" style="display:none" onchange="handleFileSelect(event)">

                <button class="btn-ghost" onclick="document.getElementById('qrInput').click()">📷 扫描二维码</button>
                <input type="file" id="qrInput" accept="image/*" style="display:none" onchange="handleQRSelect(event)">
            </div>

            <div class="action-bar">
                <button class="btn-ghost" onclick="closeAddModal()">取消</button>
                <button class="btn-success" onclick="submitAddNode()" id="btnAddSubmit">确定添加</button>
            </div>
        </div>
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
                    opt.selected = true;
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
            if (!fileName) return;
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

                if (!nodes || nodes.length === 0) {
                    grid.innerHTML = '<div class="empty-state">当前没有节点，点击 <strong>添加节点</strong> 或 <strong>导入订阅</strong> 开始使用。</div>';
                    return;
                }

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

                    const card = document.createElement('div');
                    card.className = 'card ' + (n.active ? 'active' : '');
                    card.onclick = (e) => {
                        if (e.target.tagName !== 'BUTTON') switchNode(n.index);
                    };

                    card.innerHTML = ` + "`" + `
                        <div class="card-header">
                            <span class="node-type">${n.type}</span>
                            ${n.active ? '<span style="color:#34d399;font-size:12px;font-weight:800;">✅ 运行中</span>' : ''}
                        </div>
                        <div class="node-name">${n.name}</div>
                        <div class="card-footer">
                            <span class="latency ${latClass}" id="lat-${n.index}">⚡ ${latText}</span>
                            <span class="latency unknown" id="speed-${n.index}" style="margin-right:auto;margin-left:10px;"></span>
                            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                                <button class="test-btn" onclick="testSingle(${n.index})">TCP测速</button>
                                <button class="bw-btn" onclick="testSpeed(${n.index})">带宽测速</button>
                            </div>
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

        function formatSpeed(bytesPerSec) {
            if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
            if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
            return (bytesPerSec / 1024 / 1024).toFixed(2) + ' MB/s';
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
            if (!confirm('确定要删除供应商「' + name + '」吗？\\n此操作将同时删除对应的本地节点文件，不可恢复。')) return;
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
            btn.textContent = '🗑 删除';
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

        loadSuppliers();
        loadNodes();
        loadStatus();
        setInterval(loadStatus, 3000);
    </script>
</body>
</html>`
	fmt.Fprint(w, html)
}
