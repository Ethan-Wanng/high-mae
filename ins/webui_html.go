package ins

import (
	"io"
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
            max-width: 1440px;
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
            display: grid;
            gap: 12px;
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

        .control-row {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
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

        .supplier-traffic {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            color: var(--text-sub);
            font-size: 12px;
            line-height: 1.4;
            min-height: 38px;
            align-items: center;
        }

        .traffic-pill {
            padding: 5px 8px;
            border-radius: 999px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(148, 163, 184, 0.12);
            white-space: nowrap;
        }

        .traffic-pill strong {
            color: var(--text-main);
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
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
            .supplier-actions,
            .control-row {
                width: 100%;
            }

            .header-actions button,
            .supplier-actions button,
            .control-card,
            select {
                width: 100%;
            }

            .grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
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

            .grid {
                grid-template-columns: 1fr;
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

        /* ── Toast 通知 ── */
        .toast-container {
            position: fixed;
            top: 24px;
            right: 24px;
            z-index: 99999;
            display: flex;
            flex-direction: column;
            gap: 10px;
            pointer-events: none;
        }
        .toast {
            pointer-events: auto;
            min-width: 280px;
            max-width: 420px;
            padding: 14px 20px;
            border-radius: 14px;
            font-size: 14px;
            line-height: 1.5;
            color: var(--text-main);
            backdrop-filter: blur(18px);
            border: 1px solid rgba(148,163,184,0.18);
            box-shadow: 0 12px 40px rgba(0,0,0,0.45);
            animation: toastIn 0.35s cubic-bezier(0.16,1,0.3,1) forwards;
            transition: opacity 0.3s, transform 0.3s;
        }
        .toast.success { background: rgba(16,185,129,0.18); border-color: rgba(16,185,129,0.35); }
        .toast.error   { background: rgba(239,68,68,0.18);  border-color: rgba(239,68,68,0.35);  }
        .toast.info    { background: rgba(96,165,250,0.18);  border-color: rgba(96,165,250,0.35); }
        .toast.warning { background: rgba(245,158,11,0.18);  border-color: rgba(245,158,11,0.35); }
        .toast.fade-out { opacity: 0; transform: translateX(30px); }
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(50px); }
            to   { opacity: 1; transform: translateX(0); }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
</head>
<body>
    <div class="toast-container" id="toastContainer"></div>
    <div class="container">
        <div class="header">
            <div class="brand">
                <div class="brand-badge">HM</div>
                <div>
                    <h1>High-Mae 控制面板</h1>
                    <div class="subtitle"></div>
                </div>
            </div>

            <div class="speed-monitor" id="speedMonitor">↑ 0 B/s &nbsp; ↓ 0 B/s</div>

            <div class="header-actions">
                <button class="btn-success" onclick="openAddModal()">➕ 添加节点</button>
                <button class="btn-ghost" id="btnImport" onclick="importSubscription()">📋 导入订阅</button>
                <button class="btn-primary" id="btnTestAll" onclick="testAll()">⚡ 极速测速</button>
                <button class="btn-ghost" onclick="openRuleModal()">🛠 规则管理</button>
                <button class="btn-ghost" onclick="openAggGroupModal()">📁 聚合分组管理</button>
            </div>
        </div>

        <div class="controls">
            <div class="control-row">
                <div class="control-card">
                    <span>🗂️ 订阅组</span>
                    <select id="supplierSelect" onchange="switchSupplier(this.value)"></select>
                </div>

                <div class="control-card">
                    <span>📁 聚合组</span>
                    <select id="aggregateSelect" onchange="switchAggregateGroup(this.value)"></select>
                </div>

                <div class="supplier-actions">
                    <button class="btn-update" id="btnUpdate" onclick="updateSupplier()">🔄 更新订阅</button>
                    <button class="btn-delete" id="btnDelete" onclick="deleteSupplier()">🗑 删除订阅</button>
                    <button class="btn-delete" id="btnDeleteAgg" onclick="deleteAggregateGroup()">🗑 删除聚合组</button>
                </div>
            </div>

            <div class="control-row">
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

            <div class="control-row">
                <div class="supplier-traffic" id="supplierTraffic"></div>
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

    <div class="modal-overlay" id="ruleModal">
        <div class="modal" style="width: min(860px, 100%);">
            <h2>规则组管理</h2>
            <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap;">
                <select id="ruleGroupSelect" style="min-width:180px;" onchange="selectRuleGroup(this.value)"></select>
                <input type="text" id="ruleGroupName" placeholder="规则组名称" style="flex:1;min-width:160px;background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.18);color:white;padding:10px;border-radius:12px;outline:none;">
                <select id="ruleGroupAction" style="min-width:110px;">
                    <option value="direct">直连</option>
                    <option value="proxy">代理</option>
                    <option value="reject">拦截</option>
                </select>
                <button class="btn-success" onclick="addRuleGroup()">新建组</button>
                <button class="btn-delete" onclick="deleteRuleGroup()">删除组</button>
            </div>
            <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap;">
                <select id="ruleType" style="min-width:120px;">
                    <option value="domain_suffix">域名后缀</option>
                    <option value="domain_keyword">域名关键字</option>
                    <option value="domain">完整域名</option>
                </select>
                <input type="text" id="ruleValue" placeholder="例如: google.com" style="flex:1;min-width:220px;background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.18);color:white;padding:10px;border-radius:12px;outline:none;">
                <button class="btn-success" onclick="addRule()">添加规则</button>
            </div>
            <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap;">
                <input type="text" id="ruleSearch" placeholder="搜索全部规则，确认是否已存在..." oninput="renderRules()" style="flex:1;min-width:220px;background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.18);color:white;padding:10px;border-radius:12px;outline:none;">
                <span id="ruleSearchInfo" style="color:var(--text-sub);font-size:12px;"></span>
            </div>
            <div id="ruleList" style="max-height: 300px; overflow-y: auto; margin-bottom: 14px; border: 1px solid rgba(148,163,184,0.18); border-radius: 12px; padding: 10px; background: rgba(255,255,255,0.02);">
            </div>
            <div class="action-bar">
                <button class="btn-ghost" onclick="closeRuleModal()">关闭</button>
                <button class="btn-primary" onclick="saveRules()">保存并应用</button>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="aggGroupModal">
        <div class="modal" style="width: min(800px, 100%);">
            <h2>聚合分组管理</h2>
            <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap;">
                <select id="aggModeSelect" onchange="onAggModeChange(this.value)" style="min-width:200px;"></select>
                <input type="text" id="aggGroupName" placeholder="分组名称" style="flex:1;min-width:160px;background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.18);color:white;padding:10px;border-radius:12px;outline:none;">
            </div>
            <div id="aggCurrentSection" style="display:none;margin-bottom:14px;">
                <div style="font-size:13px;color:var(--text-sub);margin-bottom:8px;">📋 当前节点</div>
                <div id="aggCurrentNodeList" style="max-height:200px;overflow-y:auto;border:1px solid rgba(148,163,184,0.18);border-radius:12px;padding:8px;background:rgba(255,255,255,0.02);"></div>
            </div>
            <div style="font-size:13px;color:var(--text-sub);margin-bottom:8px;">📦 从订阅中选择节点</div>
            <div id="aggNodeList" style="max-height: 250px; overflow-y: auto; margin-bottom: 14px; border: 1px solid rgba(148,163,184,0.18); border-radius: 12px; padding: 10px; background: rgba(255,255,255,0.02);">
                <div style="text-align:center;color:var(--text-dim);padding:20px;">加载中...</div>
            </div>
            <div class="action-bar">
                <button class="btn-ghost" onclick="closeAggGroupModal()">关闭</button>
                <button class="btn-success" id="btnAggSubmit" onclick="submitAggAction()">保存聚合分组</button>
            </div>
        </div>
    </div>

    <script>
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
                document.getElementById('speedMonitor').innerHTML = '↑ ' + st.speedOut + ' &nbsp; ↓ ' + st.speedIn;
            } catch(e) {}
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
            el.innerHTML = ` + "`" + `
                <span class="traffic-pill">剩余 <strong>${formatBytes(t.remaining)}</strong></span>
                <span class="traffic-pill">已用 <strong>${formatBytes(t.used)}</strong></span>
                <span class="traffic-pill">总量 <strong>${formatBytes(t.total)}</strong></span>
                <span class="traffic-pill">重置 <strong>${resetText}</strong></span>
                <span class="traffic-pill">到期 <strong>${expire}</strong></span>
            ` + "`" + `;
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

                card.innerHTML = ` + "`" + `
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
                ` + "`" + `;
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
                        html += ` + "`" + `
                            <div style="display:flex;justify-content:space-between;align-items:center;padding:10px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:14px;">
                                <div>
                                    <span style="background:rgba(99,102,241,0.15);padding:2px 6px;border-radius:4px;font-size:11px;margin-right:6px;color:var(--accent);">${g.name}</span>
                                    <span style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;font-size:12px;margin-right:8px;">${typeName(r.type)}</span>
                                    <span>${r.value}</span>
                                    <span style="color:${actionColor};font-weight:bold;margin-left:8px;font-size:12px;">[${actionName(g.action)}]</span>
                                </div>
                            </div>
                        ` + "`" + `;
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
                html += ` + "`" + `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:14px;">
                        <div>
                            <span style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;font-size:12px;margin-right:8px;">${typeName(r.type)}</span>
                            <span>${r.value}</span>
                            <span style="color:${actionColor};font-weight:bold;margin-left:8px;font-size:12px;">[${actionName(group.action)}]</span>
                        </div>
                        <button class="btn-ghost" style="padding:4px 8px;font-size:12px;border-color:rgba(239,68,68,0.3);color:var(--danger);" onclick="deleteRule(${idx})">删除</button>
                    </div>
                ` + "`" + `;
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
                html += ` + "`" + `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:13px;">
                        <div style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                            <span style="color:var(--text-dim);font-size:11px;margin-right:6px;">[${n.Type}]</span>
                            <span>${n.Name}</span>
                        </div>
                        <button class="btn-ghost" style="padding:3px 8px;font-size:11px;border-color:rgba(239,68,68,0.3);color:var(--danger);flex-shrink:0;margin-left:8px;" onclick="removeAggNode(${idx})">移除</button>
                    </div>
                ` + "`" + `;
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
                html += ` + "`" + `
                    <div style="margin-top:10px;">
                        <button class="btn-ghost" style="width:100%;display:flex;justify-content:space-between;align-items:center;text-align:left;" onclick="toggleAggSubscription(${gIdx})">
                            <span>${expanded ? '▾' : '▸'} ${group.subName}</span>
                            <span style="font-size:11px;opacity:0.65;">${group.nodes.length} 个节点</span>
                        </button>
                        <div id="aggSubNodes_${gIdx}" style="display:${expanded ? 'block' : 'none'};padding-left:10px;">
                ` + "`" + `;
                if (expanded) {
                    group.nodes.forEach((n, nIdx) => {
                        html += ` + "`" + `
                            <label style="display:flex;align-items:center;padding:8px;border-bottom:1px solid rgba(148,163,184,0.1);cursor:pointer;font-size:13px;transition:all 0.2s;">
                                <input type="checkbox" id="aggNodeCheck_${gIdx}_${nIdx}" ${selectedAggNodes[gIdx + '_' + nIdx] ? 'checked' : ''} onchange="setAggNodeSelected(${gIdx}, ${nIdx}, this.checked)" style="margin-right:10px;">
                                <span style="flex:1;">${n.Name}</span>
                                <span style="color:var(--text-dim);font-size:11px;">[${n.Type}]</span>
                            </label>
                        ` + "`" + `;
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

        loadSuppliers();
        loadAggregateGroups();
        loadNodes();
        loadStatus();
        setInterval(loadStatus, 3000);
    </script>
</body>
</html>`
	io.WriteString(w, html)
}
