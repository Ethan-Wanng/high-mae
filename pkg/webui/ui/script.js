let pollTimer = null;
let allNodesList = [];
let suppliersCache = [];
let aggregateGroupsCache = [];
let currentGroupFilter = "";
let ruleGroups = [];
let cmdRules = [];
let currentRuleGroupIndex = 0;
let activeTab = "nodes";
let bottomTabsCollapsed = true;
let lastDashboardPoll = 0;
let nodeGroupMode = "subscription";
let selectedNodeGroupFile = "";
let nodeGroupManualCollapsed = false;
let switchingNodeIndex = null;
let pendingActions = new Set();
let freeTrafficState = null;
let siteTargetsCache = [];
let siteResultsCache = [];
let testingSiteIds = new Set();
let autoSelectConfig = null;
let groupLatencyTesting = new Set();
let autoSelectTimer = null;
let autoSelectRunning = false;
let autoSelectSaveTimer = null;
let autoSelectRunTimer = null;
let autoSelectRenderTimer = null;
let autoSelectEventsBound = false;
let autoSelectQueuedRun = null;
let autoSelectAbortController = null;
let autoSelectRunSeq = 0;
let autoSelectRuleChangeRestartTimer = null;
let nodeGroupAnimationSeq = 0;
let autoSelectEditingRuleId = "";
let autoSelectLastDrawnRuleId = "";
let lastConnectionStatus = {};
let appUpdateInfo = null;
let appUpdateNoticeShown = false;
let islandIdleTimer = null;
let currentSettingsSubtab = 'run';

applyThemeMode(localStorage.getItem('wing_theme_mode') || 'system');
let shareQRCodeURL = "";

const statusPollIntervalMs = 5000;
const dashboardPollIntervalMs = 10000;

const nativeFetch = window.fetch.bind(window);
window.fetch = (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    const target = new URL(url, window.location.href);
    if (!target.pathname.startsWith('/api/')) {
        return nativeFetch(input, init);
    }
    const headers = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined));
    headers.set('X-Wing-Request', 'webui');
    return nativeFetch(input, { ...init, headers });
};

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[ch]));
}

function jsArg(value) {
    return JSON.stringify(String(value ?? ''));
}

let customSelectSyncTimer = null;
let customSelectMutating = false;
let customSelectInitialized = false;

function eventElement(event) {
    return event.target instanceof Element ? event.target : null;
}

function initCustomSelects() {
    if (customSelectInitialized) {
        scheduleCustomSelectSync();
        return;
    }
    customSelectInitialized = true;

    enhanceSelectControls();
    document.addEventListener('click', event => {
        const target = eventElement(event);
        const button = target?.closest('.custom-select-button');
        if (button) {
            const wrapper = button.closest('.custom-select');
            toggleCustomSelect(wrapper);
            return;
        }

        const option = target?.closest('.custom-select-option');
        if (option) {
            selectCustomOption(option);
            return;
        }

        closeCustomSelects();
    });

    document.addEventListener('keydown', event => {
        const target = eventElement(event);
        const button = target?.closest('.custom-select-button');
        if (!button) return;
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggleCustomSelect(button.closest('.custom-select'));
    } else if (event.key === 'Escape') {
            closeCustomSelects();
        }
    });
}

function scheduleCustomSelectSync() {
    if (customSelectSyncTimer) return;
    const raf = window.requestAnimationFrame || (callback => setTimeout(callback, 16));
    customSelectSyncTimer = raf(() => {
        customSelectSyncTimer = null;
        customSelectMutating = true;
        enhanceSelectControls();
        syncCustomSelects();
        setTimeout(() => {
            customSelectMutating = false;
        }, 0);
    });
}

function enhanceSelectControls(root = document) {
    root.querySelectorAll('select:not([data-custom-select-ready])').forEach(select => {
        if (select.multiple) return;
        const wrapper = document.createElement('span');
        wrapper.className = 'custom-select';
        if (select.style.minWidth) wrapper.style.minWidth = select.style.minWidth;
        if (select.style.width) wrapper.style.width = select.style.width;
        if (select.style.maxWidth) wrapper.style.maxWidth = select.style.maxWidth;

        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'custom-select-button';
        button.setAttribute('aria-haspopup', 'listbox');
        button.setAttribute('aria-expanded', 'false');

        const menu = document.createElement('div');
        menu.className = 'custom-select-menu';
        menu.setAttribute('role', 'listbox');

        select.parentNode.insertBefore(wrapper, select);
        wrapper.appendChild(select);
        wrapper.appendChild(button);
        wrapper.appendChild(menu);
        select.dataset.customSelectReady = 'true';
        select.addEventListener('change', () => syncCustomSelect(select));
        syncCustomSelect(select);
    });
}

function syncCustomSelects() {
    document.querySelectorAll('select[data-custom-select-ready]').forEach(syncCustomSelect);
}

function syncCustomSelect(select) {
    customSelectMutating = true;
    const wrapper = select.closest('.custom-select');
    if (!wrapper) {
        customSelectMutating = false;
        return;
    }
    const button = wrapper.querySelector('.custom-select-button');
    const menu = wrapper.querySelector('.custom-select-menu');
    if (!button || !menu) {
        customSelectMutating = false;
        return;
    }

    const isHidden = select.hidden || select.style.display === 'none' || select.closest('[hidden]');
    wrapper.classList.toggle('custom-select-hidden', !!isHidden);
    wrapper.classList.toggle('disabled', !!select.disabled);
    button.disabled = !!select.disabled;

    const selected = select.options[select.selectedIndex] || select.options[0];
    button.textContent = selected?.textContent?.trim() || '';
    menu.innerHTML = '';
    Array.from(select.options).forEach((option, index) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'custom-select-option';
        item.dataset.value = option.value;
        item.dataset.index = String(index);
        item.textContent = option.textContent;
        item.disabled = option.disabled;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', option.selected ? 'true' : 'false');
        if (option.selected) item.classList.add('selected');
        menu.appendChild(item);
    });
    setTimeout(() => {
        customSelectMutating = false;
    }, 0);
}

function initDesktopWheelDamping() {
    if (window.__wingWheelDampingReady) return;
    window.__wingWheelDampingReady = true;

    const finePointer = window.matchMedia?.('(pointer: fine)').matches ?? true;
    if (!finePointer) return;

    const wheelScale = 0.24;
    const preciseWheelScale = 0.72;
    const trackpadThreshold = 48;
    const lineHeight = 16;
    const scrollAnimations = new WeakMap();

    const normalizeWheelDelta = event => {
        if (event.deltaMode === 1) {
            return { x: event.deltaX * lineHeight, y: event.deltaY * lineHeight };
        }
        if (event.deltaMode === 2) {
            const pageStep = Math.max(window.innerHeight * 0.85, 320);
            return { x: event.deltaX * pageStep, y: event.deltaY * pageStep };
        }
        return { x: event.deltaX, y: event.deltaY };
    };

    const canScroll = (element, axis, delta) => {
        if (!element) return false;
        const isRoot = element === document.scrollingElement || element === document.documentElement || element === document.body;
        if (!isRoot) {
            const style = getComputedStyle(element);
            const overflow = axis === 'y' ? style.overflowY : style.overflowX;
            if (!/(auto|scroll|overlay)/.test(overflow)) return false;
        }

        const maxScroll = axis === 'y'
            ? element.scrollHeight - element.clientHeight
            : element.scrollWidth - element.clientWidth;
        if (maxScroll <= 1) return false;

        const current = axis === 'y' ? element.scrollTop : element.scrollLeft;
        if (delta < 0) return current > 0;
        if (delta > 0) return current < maxScroll - 1;
        return true;
    };

    const findScrollTarget = (start, axis, delta, event) => {
        const path = typeof event?.composedPath === 'function' ? event.composedPath() : [];
        for (const item of path) {
            if (item instanceof Element && canScroll(item, axis, delta)) return item;
        }

        let element = start;
        while (element && element !== document.body) {
            if (canScroll(element, axis, delta)) return element;
            element = element.parentElement;
        }

        const root = document.scrollingElement || document.documentElement;
        return canScroll(root, axis, delta) ? root : null;
    };

    const scrollPosition = (element, axis) => axis === 'y' ? element.scrollTop : element.scrollLeft;

    const setScrollPosition = (element, axis, value) => {
        if (axis === 'y') element.scrollTop = value;
        else element.scrollLeft = value;
    };

    const maxScrollFor = (element, axis) => axis === 'y'
        ? element.scrollHeight - element.clientHeight
        : element.scrollWidth - element.clientWidth;

    const animateScroll = (element, axis, delta) => {
        const maxScroll = maxScrollFor(element, axis);
        const current = scrollPosition(element, axis);
        const state = scrollAnimations.get(element) || {};
        const active = state[axis];
        const target = Math.max(0, Math.min(maxScroll, (active?.target ?? current) + delta));
        if (Math.abs(target - current) < 0.5) return;
        if (active?.frame) cancelAnimationFrame(active.frame);

        const start = performance.now();
        const from = current;
        const duration = Math.min(190, Math.max(120, Math.abs(target - from) * 0.85));
        const animation = { target, frame: 0 };
        state[axis] = animation;
        scrollAnimations.set(element, state);

        const tick = now => {
            const progress = Math.min(1, (now - start) / duration);
            const eased = 1 - Math.pow(1 - progress, 3);
            setScrollPosition(element, axis, from + (target - from) * eased);
            if (progress < 1) {
                animation.frame = requestAnimationFrame(tick);
                return;
            }
            setScrollPosition(element, axis, target);
            if (state[axis] === animation) delete state[axis];
        };
        animation.frame = requestAnimationFrame(tick);
    };

    document.addEventListener('wheel', event => {
        if (event.defaultPrevented || event.ctrlKey || event.metaKey) return;
        const target = event.target instanceof Element ? event.target : null;
        if (!target) return;
        if (target.closest('input, textarea, select, [contenteditable="true"]')) return;

        const delta = normalizeWheelDelta(event);
        const largestDelta = Math.max(Math.abs(delta.x), Math.abs(delta.y));
        const isPreciseWheel = event.deltaMode === 0 && largestDelta < trackpadThreshold;

        const horizontalIntent = event.shiftKey || Math.abs(delta.x) > Math.abs(delta.y);
        const axis = horizontalIntent ? 'x' : 'y';
        const scale = isPreciseWheel ? preciseWheelScale : wheelScale;
        const amount = axis === 'x'
            ? (delta.x || delta.y) * scale
            : delta.y * scale;
        if (Math.abs(amount) < 1) return;

        const scrollTarget = findScrollTarget(target, axis, amount, event);
        if (!scrollTarget) return;

        event.preventDefault();
        animateScroll(scrollTarget, axis, amount);
    }, { passive: false });
}

function toggleCustomSelect(wrapper) {
    if (!wrapper || wrapper.classList.contains('disabled')) return;
    const isOpen = wrapper.classList.contains('open');
    closeCustomSelects();
    if (!isOpen) {
        wrapper.classList.add('open');
        wrapper.querySelector('.custom-select-button')?.setAttribute('aria-expanded', 'true');
    }
}

function closeCustomSelects() {
    document.querySelectorAll('.custom-select.open').forEach(wrapper => {
        wrapper.classList.remove('open');
        wrapper.querySelector('.custom-select-button')?.setAttribute('aria-expanded', 'false');
    });
}

function selectCustomOption(option) {
    const wrapper = option.closest('.custom-select');
    const select = wrapper?.querySelector('select');
    if (!select || option.disabled) return;
    const index = Number.parseInt(option.dataset.index || '-1', 10);
    if (index < 0 || index >= select.options.length) return;
    const oldValue = select.value;
    select.selectedIndex = index;
    syncCustomSelect(select);
    closeCustomSelects();
    if (select.value !== oldValue) {
        select.dispatchEvent(new Event('change', { bubbles: true }));
    }
}

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const st = await res.json();
        lastConnectionStatus = st || {};
        const proxyEl = document.getElementById('chkProxy');
        const modeEl = document.getElementById('chkMode');
        const tunEl = document.getElementById('chkTun');
        const webrtcEl = document.getElementById('chkWebRTC');
        const speedEl = document.getElementById('speedMonitor');
        if (proxyEl) proxyEl.checked = st.proxy;
        if (modeEl) modeEl.checked = (st.mode === 'Global');
        if (tunEl) tunEl.checked = st.tun;
        if (webrtcEl) webrtcEl.checked = st.webrtc;
        if (speedEl) speedEl.innerHTML = '↑ ' + st.speedOut + ' &nbsp; ↓ ' + st.speedIn;
        updateConnectionState(st);
        renderFreeTrafficState(st.freeTraffic);
        updateConnectionNodeSummary();
    } catch(e) {}
}

function updateConnectionState(status = {}) {
    const proxyOn = !!status.proxy;
    const tunOn = !!status.tun;
    let state = 'direct';
    if (proxyOn && tunOn) {
        state = 'proxy_tun';
    } else if (proxyOn) {
        state = 'proxy';
    } else if (tunOn) {
        state = 'tun';
    }
    document.body.dataset.networkState = state;
    const card = document.getElementById('connectionCard');
    if (card) card.dataset.state = state;
    document.querySelectorAll('.proxy-mode-button').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.preset === state);
    });
    updateModeLogos();
}

function effectiveThemeMode() {
    const theme = document.documentElement.dataset.theme || localStorage.getItem('wing_theme_mode') || 'system';
    if (theme === 'light' || theme === 'dark') return theme;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function currentModeLogoSrc() {
    const state = document.body?.dataset?.networkState || 'direct';
    if (state === 'proxy_tun') return 'logo-mark-proxy-tun.png';
    if (state === 'proxy') return 'logo-mark-proxy.png';
    if (state === 'tun') return 'logo-mark-tun.png';
    return effectiveThemeMode() === 'light' ? 'logo-mark-direct-light.png' : 'logo-mark-direct-dark.png';
}

function updateModeLogos() {
    const src = currentModeLogoSrc();
    document.querySelectorAll('img.mode-logo').forEach(img => {
        if (img.getAttribute('src') !== src) {
            img.setAttribute('src', src);
        }
    });
}

function updateConnectionNodeSummary() {
    const activeNode = allNodesList.find(n => n.active);
    const nodeDisplayEl = document.getElementById('selectedNodeDisplay');
    const islandNameEl = document.getElementById('islandNodeName');
    const islandLabelEl = document.getElementById('islandNodeLabel');
    if (nodeDisplayEl) {
        nodeDisplayEl.textContent = activeNode ? activeNode.name : (freeTrafficState?.active ? '免费流量' : '未选择节点');
    }
    if (islandNameEl) {
        islandNameEl.textContent = activeNode ? activeNode.name : (freeTrafficState?.active ? '免费流量' : '未选择节点');
    }
    const protocolEl = document.getElementById('selectedNodeProtocolDisplay');
    if (protocolEl) {
        protocolEl.textContent = activeNode ? `协议 ${displayProtocolName(activeNode)}` : (freeTrafficState?.active ? '协议 FREE' : '协议 --');
    }
    if (islandLabelEl) {
        const protocol = activeNode ? displayProtocolName(activeNode) : (freeTrafficState?.active ? 'FREE' : '--');
        islandLabelEl.textContent = `${currentNodeGroupLabel(activeNode)} · ${protocol}`;
    }
    renderSelectedNodeGroup(activeNode);
}

function displayProtocolName(node) {
    const type = String(node?.type || '').trim();
    return type ? type.toUpperCase() : '--';
}

function handleBottomTabClick(tabId) {
    if (document.activeElement?.closest?.('#islandCenter')) {
        document.activeElement.blur();
    }
    if (activeTab === tabId && !bottomTabsCollapsed) {
        collapseBottomTabs();
        return;
    }
    showTab(tabId);
}

function collapseBottomTabs() {
    bottomTabsCollapsed = true;
    document.body.classList.add('tabs-collapsed');
    document.getElementById('tabsExpandButton')?.setAttribute('aria-expanded', 'false');
}

function expandBottomTabs() {
    bottomTabsCollapsed = false;
    document.body.classList.remove('tabs-collapsed');
    document.getElementById('tabsExpandButton')?.setAttribute('aria-expanded', 'true');
}

function initIslandBehavior() {
    updateIslandScrollState();
    wakeIsland();
    const islandCenter = document.getElementById('islandCenter');
    const islandModeStrip = document.getElementById('islandModeStrip');
    const speedMonitor = document.getElementById('speedMonitor');
    if (islandCenter && speedMonitor?.parentElement !== islandCenter) {
        speedMonitor.classList.add('island-speed-monitor');
        islandCenter.appendChild(speedMonitor);
    }
    if (islandModeStrip && islandModeStrip.parentElement !== document.body) {
        document.body.appendChild(islandModeStrip);
    }
    islandCenter?.addEventListener('mouseenter', () => {
        document.body.classList.add('island-hovered');
    });
    islandCenter?.addEventListener('mouseleave', event => {
        if (event.relatedTarget?.closest?.('#islandModeStrip')) {
            return;
        }
        if (document.activeElement?.closest?.('#islandCenter')) {
            document.activeElement.blur();
        }
        document.body.classList.remove('island-hovered');
        document.body.classList.remove('island-node-expanded');
    });
    islandModeStrip?.addEventListener('mouseenter', () => {
        if (document.body.classList.contains('island-mode-expanded')) {
            document.body.classList.add('island-hovered');
        }
    });
    islandModeStrip?.addEventListener('mouseleave', event => {
        if (event.relatedTarget?.closest?.('#islandCenter')) {
            return;
        }
        document.body.classList.remove('island-hovered');
        document.body.classList.remove('island-mode-expanded');
    });
    ['mousemove', 'pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(eventName => {
        window.addEventListener(eventName, wakeIsland, { passive: true });
    });
    window.addEventListener('scroll', () => {
        updateIslandScrollState();
        wakeIsland();
    }, { passive: true });
    document.addEventListener('click', event => {
        if (!event.target?.closest?.('#islandCenter, #islandModeStrip')) {
            document.body.classList.remove('island-node-expanded');
            document.body.classList.remove('island-mode-expanded');
        }
    });
}

function wakeIsland() {
    document.body.classList.remove('island-idle');
    if (islandIdleTimer) clearTimeout(islandIdleTimer);
    islandIdleTimer = setTimeout(() => {
        document.body.classList.add('island-idle');
    }, 2600);
}

function updateIslandScrollState() {
    const scrolled = (document.scrollingElement?.scrollTop || window.scrollY || 0) > 24;
    document.body.classList.toggle('is-scrolled', scrolled);
}

function toggleIslandNodeModes(event) {
    event?.stopPropagation?.();
    document.body.classList.toggle('island-mode-expanded');
    wakeIsland();
}

function showSettingsSubtab(tab = 'run') {
    currentSettingsSubtab = ['run', 'prefs', 'entry', 'manage'].includes(tab) ? tab : 'run';
    document.querySelectorAll('.settings-subtab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.settingsTab === currentSettingsSubtab);
    });
    document.querySelectorAll('[data-settings-section]').forEach(section => {
        section.classList.toggle('settings-section-hidden', section.dataset.settingsSection !== currentSettingsSubtab);
    });
}

function showTab(tabId, options = {}) {
    if (options.expand !== false) {
        expandBottomTabs();
    }
    activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    const activeBtn = document.querySelector(`.tab-btn[onclick="handleBottomTabClick('${tabId}')"]`);
    if (activeBtn) activeBtn.classList.add('active');
    
    const activeContent = document.getElementById(`tab-${tabId}`);
    if (activeContent) activeContent.classList.add('active');

    if (tabId === 'dashboard') loadDashboard();
    if (tabId === 'sitecheck') loadSiteTargets();
}


function setNodeGroupMode(mode) {
    nodeGroupMode = ["subscription", "aggregate", "auto", "auto_nodes"].includes(mode) ? mode : "subscription";
    if (nodeGroupMode !== "auto") selectedNodeGroupFile = "";
    nodeGroupManualCollapsed = false;
    document.querySelectorAll('.node-source-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === nodeGroupMode);
    });
    renderNodes();
}

function renderNodes(options = {}) {
    const grid = document.getElementById('nodeGrid');
    const autoPane = document.getElementById('autoSelectNodePane');
    if (!grid) return;
    if (nodeGroupMode === "auto" || nodeGroupMode === "auto_nodes") {
        grid.style.display = "none";
        if (autoPane) {
            autoPane.style.display = nodeGroupMode === "auto" ? "block" : "none";
            if (nodeGroupMode === "auto") renderAutoSelectConfig();
        }
        if (nodeGroupMode === "auto_nodes") {
            grid.style.display = "";
            renderAutoNodes();
        }
        return;
    }
    grid.style.display = "";
    if (autoPane) autoPane.style.display = "none";
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
            updateIntervalMinutes: s.updateIntervalMinutes,
            lastUpdatedAt: s.lastUpdatedAt,
            type: "subscription"
        }));

    const activeGroup = groups.find(g => g.active);
    if (!selectedNodeGroupFile && activeGroup && !nodeGroupManualCollapsed) {
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
    const selectedGroupTraffic = selectedGroup?.type === 'subscription' ? supplierTrafficInline(selectedGroup, { compact: false }) : '';

    grid.innerHTML = `
        <section class="node-card-table">
            <div class="node-card-table-header">
                <div>
                    <div class="node-card-table-title">${nodeGroupMode === "aggregate" ? "聚合组" : "订阅组"}</div>
                    ${keyword ? `<div class="node-card-table-subtitle">已按搜索过滤</div>` : ''}
                </div>
                <div class="node-card-table-actions">${selectedGroup ? renderSelectedGroupActions(selectedGroup) : ''}</div>
            </div>
            <div class="source-card-deck"></div>
            <div class="node-deck-window">
                <div class="node-detail-header">
                    <div>
                        <div class="node-detail-title">${selectedGroup ? `${escapeHTML(selectedGroup.name)}${selectedGroupTraffic}` : "未展开组"}</div>
                        <div class="node-detail-subtitle">${selectedGroup ? `${selectedNodes.length} 个节点${keyword ? "匹配当前搜索" : ""}` : "点击上方订阅组展开节点"}</div>
                    </div>
                </div>
                <div class="node-detail-body"></div>
            </div>
        </section>
    `;

    const list = grid.querySelector('.source-card-deck');
    groupList.forEach(group => {
        const item = document.createElement('button');
        const isSelected = selectedGroup && group.fileName === selectedGroup.fileName;
        const showActive = !autoSelectConfig?.enabled && group.active;
        item.className = `source-push-card ${isSelected ? 'selected' : ''} ${showActive ? 'active' : ''}`;
        item.dataset.fileName = group.fileName;
        item.onclick = () => selectNodeGroup(group.fileName);
        const traffic = '';
        item.innerHTML = `
            <span class="source-card-shine"></span>
            <span class="node-group-name"><span class="node-group-name-text">${escapeHTML(group.name)}</span>${traffic}</span>
            <span class="node-group-meta">${showActive ? '当前 · ' : ''}${group.count || 0} 节点</span>
        `;
        list.appendChild(item);
    });

    const body = grid.querySelector('.node-detail-body');
    if (!selectedGroup) {
        body.innerHTML = '<div class="empty-state">点击上方订阅组展开节点列表。</div>';
        return;
    }
    if (!selectedNodes.length) {
        body.innerHTML = '<div class="empty-state">没有匹配的节点。</div>';
        return;
    }
    body.appendChild(renderNodeTable(selectedNodes, { animateDeal: !!options.animateDeck }));
}

function renderAutoNodes() {
    const grid = document.getElementById('nodeGrid');
    if (!grid) return;
    grid.innerHTML = '';
    
    let candidates = autoSelectCandidates().filter(nodePassesAutoSelectRules);
    const keyword = document.getElementById('nodeSearch')?.value.trim().toLowerCase() || "";
    candidates = filterNodeRows(candidates, keyword);

    grid.innerHTML = `
        <section class="node-detail-pane" style="grid-column: 1 / -1; width: 100%; border-left: none;">
            <div class="node-detail-header">
                <div>
                    <div class="node-detail-title">自动选择节点范围</div>
                    <div class="node-detail-subtitle">${candidates.length} 个候选节点${keyword ? "匹配当前搜索" : ""}</div>
                </div>
                <div class="node-detail-actions">
                    ${autoSelectExcludedNodeCount() ? `<button class="btn-mini" onclick="clearAutoSelectExcludedNodes()">恢复已排除节点 (${autoSelectExcludedNodeCount()})</button>` : ''}
                </div>
            </div>
            <div class="node-detail-body"></div>
        </section>
    `;

    const body = grid.querySelector('.node-detail-body');
    if (!candidates.length) {
        body.innerHTML = '<div class="empty-state">没有符合自动选择规则的候选节点。</div>';
        return;
    }
    body.appendChild(renderAutoNodeList(candidates, { autoSelect: true }));
}

let filterNodesTimeout = null;
function filterNodes() {
    if (filterNodesTimeout) clearTimeout(filterNodesTimeout);
    filterNodesTimeout = setTimeout(() => {
        if (nodeGroupMode === "auto_nodes") renderAutoNodes();
        else renderNodes();
    }, 200);
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
    const interval = Number(group.updateIntervalMinutes || 360);
    return `
        <button class="btn-mini" title="分享订阅" onclick="shareSupplierFile('${file}', event)">分享</button>
        <button class="btn-mini" title="刷新订阅" onclick="updateSupplierFile('${file}', this, event)">刷新</button>
        <button class="btn-mini" title="自动更新间隔：${interval} 分钟" onclick="setSupplierInterval('${file}', ${interval}, event)">间隔 ${formatInterval(interval)}</button>
        <button class="btn-mini btn-mini-danger" title="删除订阅" onclick="deleteSupplierFile('${file}', event)">删除</button>
    `;
}

function renderNodeTable(nodes, options = {}) {
    return renderAutoNodeList(nodes, {
        autoSelect: !!options.autoSelect,
        animateDeal: !!options.animateDeal
    });
}

function renderAutoNodeList(nodes, options = {}) {
    const list = document.createElement('div');
    list.className = 'auto-node-list';
    if (options.animateDeal) list.classList.add('auto-node-list-dealing');
    const fragment = document.createDocumentFragment();
    nodes.forEach((n, index) => {
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

        const item = document.createElement('article');
        item.className = `auto-node-item ${n.active ? 'active' : ''}`;
        item.style.setProperty('--deal-index', String(Math.min(index, 18)));
        const sourceLabel = supplierNameForNode(n) || aggregateNameByFile(n.fileName) || n.group || n.fileName || '';
        const deleteButton = options.autoSelect
            ? `<button class="btn-action btn-action-danger" title="从自动选择候选中排除，不删除原订阅或聚合组节点" onclick="excludeAutoSelectNode('${encodeURIComponent(autoSelectNodeKey(n))}')">删除</button>`
            : `<button class="btn-action btn-action-danger" title="删除节点" onclick="deleteNode(${n.index})">删除</button>`;
        const shareButton = options.autoSelect ? '' : `<button class="btn-action" onclick="shareNode(${n.index})">分享</button>`;
        item.innerHTML = `
            <div class="auto-node-main">
                <span class="status-dot ${n.active ? 'active' : ''}"></span>
                <div class="auto-node-name">${escapeHTML(n.name || '')}</div>
                <div class="auto-node-source">${escapeHTML(sourceLabel)}</div>
            </div>
            <div class="auto-node-metrics">
                <span class="node-type">${escapeHTML(n.type || '')}</span>
                <span class="latency ${latClass}" id="lat-${n.index}">${latText}</span>
                <span class="latency ${speedClass}" id="speed-${n.index}">↓ ${speedText}</span>
            </div>
            <div class="auto-node-actions">
                <button class="btn-action ${n.active ? 'btn-action-primary' : ''}" ${switchingNodeIndex !== null ? 'disabled' : ''} onclick="switchNode(${n.index})">${switchingNodeIndex === n.index ? '切换中' : (n.active ? '已选择' : '选择')}</button>
                <button class="btn-action" onclick="testSingle(${n.index})">延迟</button>
                <button class="btn-action" onclick="testSpeed(${n.index})">带宽</button>
                ${shareButton}
                ${deleteButton}
            </div>
        `;
        fragment.appendChild(item);
    });
    list.appendChild(fragment);
    return list;
}

function findSourceCardByFileName(fileName) {
    return Array.from(document.querySelectorAll('.source-push-card'))
        .find(card => card.dataset.fileName === fileName) || null;
}

async function selectNodeGroup(fileName) {
    const seq = ++nodeGroupAnimationSeq;
    if (selectedNodeGroupFile === fileName) {
        const deck = document.querySelector('.node-detail-body .auto-node-list');
        const sourceCard = findSourceCardByFileName(fileName);
        if (deck) {
            deck.classList.add('auto-node-list-collecting');
            sourceCard?.classList.add('collecting');
            await sleep(260);
            if (seq !== nodeGroupAnimationSeq) return;
        }
        selectedNodeGroupFile = "";
        nodeGroupManualCollapsed = true;
        renderNodes();
        return;
    }
    selectedNodeGroupFile = fileName;
    nodeGroupManualCollapsed = false;
    renderNodes({ animateDeck: true });
    setTimeout(() => {
        if (selectedNodeGroupFile === fileName && !nodeGroupManualCollapsed) {
            autoTestSelectedNodeGroup(fileName);
        }
    }, 620);
}

async function loadSuppliers() {
    try {
        const res = await fetch('/api/suppliers');
        const suppliers = await res.json();
        suppliersCache = suppliers || [];
        const sel = document.getElementById('supplierSelect');
        if (sel) sel.innerHTML = '';

        if (!suppliersCache.length) {
            if (sel) {
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = '暂无';
                opt.disabled = true;
                opt.selected = true;
                sel.appendChild(opt);
            }
            renderSupplierTraffic(null);
            await loadAggregateGroups();
            return;
        }

        if (sel) {
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
        }
        renderSupplierTraffic(sel?.value);
        await loadAggregateGroups();
        renderAutoSelectConfig();
        renderNodes();
    } catch(e) {}
}

async function loadAggregateGroups() {
    try {
        const res = await fetch('/api/aggregate_groups');
        const groups = await res.json();
        aggregateGroupsCache = Array.isArray(groups) ? groups : [];
        const sel = document.getElementById('aggregateSelect');
        if (sel) {
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
        }
        renderAutoSelectConfig();
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

function renderFreeTrafficState(state) {
    const btn = document.getElementById('btnFreeTraffic');
    if (!state) return;
    freeTrafficState = state;
    if (!btn) return;
    const remaining = formatBytes(state.remaining || 0);
    btn.textContent = state.active ? `免费流量 ${remaining}` : '获取免费流量';
    btn.disabled = !!state.exceeded;
    btn.title = state.exceeded ? '本周免费流量已用完，下周自动恢复' : `本周剩余 ${remaining}`;

    const activeNodeEl = document.getElementById('selectedNodeDisplay');
    if (activeNodeEl && state.active) {
        activeNodeEl.textContent = '免费流量';
    }
    const groupEl = document.getElementById('selectedNodeGroupDisplay');
    if (groupEl && state.active) {
        groupEl.textContent = '来源组: 免费流量';
    }
    const protocolEl = document.getElementById('selectedNodeProtocolDisplay');
    if (protocolEl && state.active) {
        protocolEl.textContent = '协议 FREE';
    }
    if (state.active) {
        document.getElementById('islandNodeLabel')?.replaceChildren(document.createTextNode('免费流量 · FREE'));
        document.getElementById('islandNodeName')?.replaceChildren(document.createTextNode('免费流量'));
    }
}

function supplierTrafficInline(supplier, options = {}) {
    if (!supplier?.traffic || !supplier.traffic.total) return '';
    const t = supplier.traffic;
    const remaining = options.compact ? formatBytesCompact(t.remaining || 0) : formatBytes(t.remaining || 0);
    const total = options.compact ? formatBytesCompact(t.total || 0) : formatBytes(t.total || 0);
    return `<span class="source-traffic-inline">${remaining} / ${total}</span>`;
}

async function useFreeTraffic() {
    const btn = document.getElementById('btnFreeTraffic');
    if (!btn) return;
    const oldText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '启用中';
    try {
        const res = await fetch('/api/free_traffic', { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast(data.msg || '免费流量已启用', 'success');
            renderFreeTrafficState(data.traffic);
            loadStatus();
            loadNodes();
        } else {
            showToast(data.msg || '免费流量暂时不可用', 'error');
            renderFreeTrafficState(data.traffic);
        }
    } catch(e) {
        showToast('启用免费流量失败', 'error');
    }
    if (btn.textContent === '启用中') btn.textContent = oldText;
    btn.disabled = false;
    loadStatus();
}

async function selectDirect() {
    const btn = document.getElementById('btnDirect');
    const oldText = btn?.textContent || '直连';
    if (btn) {
        btn.disabled = true;
        btn.textContent = '切换中';
    }
    try {
        const res = await fetch('/api/direct', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
            showToast(data.msg || '切换直连失败', 'error');
            return;
        }
        allNodesList = allNodesList.map(n => ({ ...n, active: false }));
        showToast(data.msg || '已不选择节点，当前为直连', 'success');
        await loadNodes();
        loadStatus();
    } catch(e) {
        showToast('切换直连请求失败', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = oldText;
        }
    }
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

function renderAppUpdateButton(info) {
    const button = document.getElementById('appUpdateButton');
    if (!button) return;
    const available = !!info?.available && !!(info.downloadUrl || info.pageUrl);
    button.hidden = !available;
    if (!available) return;
    const label = button.querySelector('span:last-child');
    if (label) {
        label.textContent = info.latestVersion ? `下载 ${info.latestVersion}` : '下载更新';
    }
    button.title = info.latestVersion
        ? `发现新版本 ${info.latestVersion}，点击下载`
        : '发现新版本，点击下载';
}

async function checkAppUpdate(options = {}) {
    try {
        const res = await fetch('/api/app_update');
        const info = await res.json().catch(() => ({}));
        appUpdateInfo = info;
        renderAppUpdateButton(info);
        if (info?.available && !appUpdateNoticeShown) {
            appUpdateNoticeShown = true;
            const versionText = info.latestVersion ? ` ${info.latestVersion}` : '';
            showToast(`发现新版本${versionText}，可在左上角下载。`, 'info', 5200);
        }
    } catch(e) {
        if (!options.silent) {
            showToast('更新检查失败', 'warning', 2200);
        }
    }
}

async function openAppUpdate() {
    if (!appUpdateInfo?.available) {
        await checkAppUpdate({ silent: true });
    }
    const target = appUpdateInfo?.downloadUrl || appUpdateInfo?.pageUrl || '';
    if (!target) {
        showToast('暂未找到可下载的新版本', 'warning');
        return;
    }
    try {
        const res = await fetch('/api/app_update/open', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: target })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
            throw new Error(data.msg || 'open failed');
        }
        showToast('已打开更新下载页', 'success', 2200);
    } catch(e) {
        window.open(target, '_blank', 'noopener');
        showToast('已尝试打开更新下载页', 'info', 2200);
    }
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

async function doAction(type, desiredState = null) {
    if (pendingActions.has(type)) {
        showToast('正在切换中，请稍候。', 'info', 1600);
        loadStatus();
        return { ok: false, pending: true };
    }
    pendingActions.add(type);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), (type === 'tun' || type === 'tunnel') ? 12000 : 5000);
    try {
        const params = new URLSearchParams({ type });
        if (typeof desiredState === 'boolean') {
            params.set('enable', desiredState ? 'true' : 'false');
        }
        const res = await fetch('/api/action?' + params.toString(), { method: 'POST', signal: controller.signal });
        const data = await res.json();
        if (data && data.msg) {
            showToast(data.msg, data.ok === false ? 'error' : 'info');
        }
        if (data?.requiresAdmin && !data?.restarting) {
            const autoRestartEl = document.getElementById('chkAutoRestartAsAdmin');
            if (!autoRestartEl?.checked && confirm('开启该功能需要管理员权限。是否现在以管理员身份重启 wing？')) {
                await restartAsAdmin();
            }
        }
        return data;
    } catch(e) {
        const timeoutMsg = e?.name === 'AbortError' ? '切换请求超时，请稍后查看状态。' : '切换请求失败，请检查 wing 是否仍在运行。';
        showToast(timeoutMsg, 'error');
        return { ok: false, error: timeoutMsg };
    }
    finally {
        clearTimeout(timeout);
        setTimeout(() => pendingActions.delete(type), (type === 'tun' || type === 'tunnel') ? 1500 : 400);
        setTimeout(loadStatus, 300);
        if (type === 'tun' || type === 'tunnel') setTimeout(loadStatus, 2500);
    }
}

async function activateProxyPreset(preset) {
    const proxyControl = document.getElementById('chkProxy');
    const tunControl = document.getElementById('chkTun');
    const proxyOn = proxyControl ? !!proxyControl.checked : !!lastConnectionStatus.proxy;
    const tunOn = tunControl ? !!tunControl.checked : !!lastConnectionStatus.tun;
    const wantProxy = preset === 'proxy' || preset === 'proxy_tun';
    const wantTun = preset === 'tun' || preset === 'proxy_tun';
    if (proxyOn !== wantProxy) {
        const result = await doAction('proxy', wantProxy);
        if (result?.ok === false) return;
        await sleep(250);
    }
    if (tunOn !== wantTun) {
        const result = await doAction('tun', wantTun);
        if (result?.ok === false) return;
    }
    setTimeout(loadStatus, 350);
    setTimeout(loadStatus, 1800);
}

async function loadSystemConfig() {
    try {
        const res = await fetch('/api/system_config');
        const config = await res.json();
        const portEl = document.getElementById('txtProxyPort');
        if (portEl) portEl.value = config.proxyPort || '10808';
        const bingGuardEl = document.getElementById('chkBingRedirectGuard');
        if (bingGuardEl) bingGuardEl.checked = !!config.preventBingCNRedirect;
        const preferIPv6El = document.getElementById('chkPreferIPv6');
        if (preferIPv6El) preferIPv6El.checked = !!config.preferIPv6;
        const autoRestartEl = document.getElementById('chkAutoRestartAsAdmin');
        if (autoRestartEl) autoRestartEl.checked = !!config.autoRestartAsAdmin;
        const startupEl = document.getElementById('chkStartupEnabled');
        if (startupEl) startupEl.checked = !!config.startupEnabled;
        const themeEl = document.getElementById('themeModeSelect');
        const themeMode = ['light', 'dark', 'system'].includes(config.themeMode) ? config.themeMode : 'system';
        if (themeEl) themeEl.value = themeMode;
        applyThemeMode(themeMode);
    } catch(e) {
        showToast('系统设置加载失败', 'warning', 2200);
    }
}

function applyThemeMode(mode) {
    const theme = ['light', 'dark', 'system'].includes(mode) ? mode : 'system';
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('wing_theme_mode', theme);
    updateModeLogos();
}

if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
        if ((document.documentElement.dataset.theme || 'system') === 'system') {
            updateModeLogos();
        }
    });
}

function buildSystemConfigPayload() {
    const portEl = document.getElementById('txtProxyPort');
    const port = (portEl?.value || '').trim();
    const portNum = Number.parseInt(port, 10);
    if (!Number.isFinite(portNum) || portNum <= 0 || portNum > 65535) {
        showToast('请输入有效端口号', 'warning');
        return null;
    }
    const bingGuardEl = document.getElementById('chkBingRedirectGuard');
    const preferIPv6El = document.getElementById('chkPreferIPv6');
    const autoRestartEl = document.getElementById('chkAutoRestartAsAdmin');
    const startupEl = document.getElementById('chkStartupEnabled');
    const themeEl = document.getElementById('themeModeSelect');
    return {
        proxyPort: String(portNum),
        preventBingCNRedirect: !!bingGuardEl?.checked,
        preferIPv6: !!preferIPv6El?.checked,
        autoRestartAsAdmin: !!autoRestartEl?.checked,
        startupEnabled: !!startupEl?.checked,
        themeMode: themeEl?.value || 'system'
    };
}

async function saveSystemConfigOption(successMessage, errorMessage) {
    const payload = buildSystemConfigPayload();
    if (!payload) {
        await loadSystemConfig();
        return;
    }
    applyThemeMode(payload.themeMode);
    try {
        const res = await fetch('/api/system_config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            data.ok = false;
            data.msg = data.msg || '保存失败';
        }
        showToast(data.msg || (data.ok === false ? '保存失败' : successMessage), data.ok === false ? 'error' : 'success');
        await loadSystemConfig();
        await loadStatus();
    } catch(e) {
        showToast(errorMessage, 'error');
        await loadSystemConfig();
    }
}

async function saveProxyPort() {
    const payload = buildSystemConfigPayload();
    if (!payload) {
        return;
    }
    try {
        const res = await fetch('/api/system_config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            data.ok = false;
            data.msg = data.msg || '保存失败';
        }
        showToast(data.msg || (data.ok === false ? '保存失败' : '系统设置已保存'), data.ok === false ? 'error' : 'success');
        await loadStatus();
    } catch(e) {
        showToast('保存系统设置失败', 'error');
    }
}

async function saveBingRedirectGuard() {
    await saveSystemConfigOption('Bing 跳转保护已更新', '保存 Bing 跳转保护失败');
}

async function savePreferIPv6() {
    await saveSystemConfigOption('IPv6 开关已更新', '保存 IPv6 开关失败');
}

async function saveAutoRestartAsAdmin() {
    await saveSystemConfigOption('管理员自动重启设置已更新', '保存管理员自动重启设置失败');
}

async function saveStartupEnabled() {
    await saveSystemConfigOption('开机自启动设置已更新', '保存开机自启动设置失败');
}

async function saveThemeMode(value) {
    applyThemeMode(value);
    await saveSystemConfigOption('主题设置已更新', '保存主题设置失败');
}

async function restartAsAdmin() {
    try {
        const res = await fetch('/api/restart_admin', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        showToast(data.msg || (data.ok === false ? '请求管理员权限失败' : '正在请求管理员权限并重启'), data.ok === false ? 'error' : 'success');
    } catch(e) {
        showToast('请求管理员权限失败', 'error');
    }
}

async function restartApp() {
    if (!confirm('现在重启 wing 吗？')) return;
    try {
        const res = await fetch('/api/restart', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        showToast(data.msg || (data.ok === false ? '重启失败' : '正在重启 wing'), data.ok === false ? 'error' : 'success');
    } catch(e) {
        showToast('重启失败，请检查 wing 是否仍在运行。', 'error');
    }
}

async function loadNodes() {
    try {
        const res = await fetch('/api/nodes');
        const nodes = await res.json();
        allNodesList = nodes || [];
        updateConnectionNodeSummary();
        renderNodes();
    } catch(e) {}
}

function renderSelectedNodeGroup(activeNode) {
    const groupEl = document.getElementById('selectedNodeGroupDisplay');
    if (!groupEl) return;
    if (activeNode) {
        const groupType = currentNodeGroupType(activeNode);
        const sourceName = activeNode.sourceFile && activeNode.sourceFile !== activeNode.fileName
            ? supplierNameByFile(activeNode.sourceFile)
            : '';
        groupEl.textContent = sourceName
            ? `${groupType} / ${activeNode.group || '--'} · 原订阅 ${sourceName}`
            : `${groupType} / ${activeNode.group || '--'}`;
    } else if (freeTrafficState?.active) {
        groupEl.textContent = '免费流量';
    } else {
        groupEl.textContent = '未选择来源组';
    }
}

function currentNodeGroupType(activeNode) {
    if (!activeNode) return freeTrafficState?.active ? '免费流量' : '订阅组';
    const aggregateGroups = Array.isArray(aggregateGroupsCache) ? aggregateGroupsCache : [];
    return aggregateGroups.some(g => g.fileName === activeNode.fileName) ? '聚合组' : '订阅组';
}

function currentNodeGroupLabel(activeNode) {
    if (!activeNode) return freeTrafficState?.active ? '免费流量' : '未选择来源组';
    const sourceName = activeNode.sourceFile && activeNode.sourceFile !== activeNode.fileName
        ? supplierNameByFile(activeNode.sourceFile)
        : '';
    const name = sourceName || activeNode.group || '--';
    return `${currentNodeGroupType(activeNode)} / ${name}`;
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
    updateConnectionNodeSummary();

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
        setTimeout(loadNodes, 4500);
        loadStatus();
    } catch(e) {
        allNodesList = previousNodes;
        showToast(e.name === 'AbortError' ? '节点切换请求超时，请稍后查看当前节点状态。' : '节点切换请求失败。', 'error');
    } finally {
        clearTimeout(timeout);
        setTimeout(() => {
            switchingNodeIndex = null;
            renderNodes();
            updateConnectionNodeSummary();
        }, 1800);
    }
}

async function testSingle(idx) {
    const latEl = document.getElementById('lat-' + idx);
    latEl.textContent = '检测中';
    latEl.className = 'latency unknown';
    const node = allNodesList.find(n => n.index === idx);
    const current = node?.active ? '&current=1' : '';
    await fetch('/api/test_single?idx=' + idx + current, { method: 'POST' });
    loadNodes();
}

async function autoTestSelectedNodeGroup(fileName) {
    if (!fileName || groupLatencyTesting.has(fileName)) return;
    const groupNodes = allNodesList.filter(n => n.fileName === fileName);
    if (!groupNodes.length) return;

    groupLatencyTesting.add(fileName);
    groupNodes.forEach(n => {
        const latEl = document.getElementById('lat-' + n.index);
        if (latEl) {
            latEl.textContent = '检测中';
            latEl.className = 'latency unknown';
        }
    });

    const queue = [...groupNodes];
    const workerCount = Math.min(8, queue.length);
    async function worker() {
        while (queue.length) {
            const node = queue.shift();
            try {
                await fetch('/api/test_single?idx=' + node.index, { method: 'POST' });
            } catch(e) {}
        }
    }

    await Promise.all(Array.from({ length: workerCount }, worker));
    groupLatencyTesting.delete(fileName);
    await loadNodes();
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

function formatBytesCompact(bytes) {
    if (!bytes || bytes < 0) return '0B';
    if (bytes < 1024) return bytes.toFixed(0) + 'B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0) + 'K';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0) + 'M';
    if (bytes < 1024 * 1024 * 1024 * 1024) return (bytes / 1024 / 1024 / 1024).toFixed(bytes < 10 * 1024 * 1024 * 1024 ? 1 : 0) + 'G';
    return (bytes / 1024 / 1024 / 1024 / 1024).toFixed(1) + 'T';
}

function formatTime(value) {
    if (!value) return '--';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '--';
    return d.toLocaleTimeString();
}

function formatDate(value) {
    if (!value) return '--';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '--';
    return d.toLocaleDateString();
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
            <div class="traffic-row-sub">下载 ${formatBytes(inbound)} · 上传 ${formatBytes(outbound)}</div>
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
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-sub);">暂无记录</td></tr>';
        return;
    }
    tbody.innerHTML = rows.map(log => `
        <tr>
            <td>${formatDate(log.startTime)}</td>
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

async function loadSiteTargets() {
    try {
        const res = await fetch('/api/site_targets');
        siteTargetsCache = await res.json() || [];
        renderSiteTargets();
        renderSiteResults();
        renderAutoSelectConfig();
    } catch(e) {
        showToast('测试网站加载失败', 'error');
    }
}

function renderSiteTargets() {
    const list = document.getElementById('siteTargetList');
    if (!list) return;
    if (!siteTargetsCache.length) {
        list.innerHTML = '<div class="empty-state">暂无测试网站。</div>';
        return;
    }
    list.innerHTML = siteTargetsCache.map(target => `
        <div class="site-target-row">
            <div class="site-target-main">
                <span class="site-target-name">${escapeHTML(target.name)}</span>
                <span class="site-target-category">${escapeHTML(target.category || '自定义')}</span>
                ${target.preset ? '<span class="site-target-lock">预设</span>' : ''}
            </div>
            <div class="site-target-url">${escapeHTML(target.url)}</div>
            <div class="site-target-actions">
                <button class="btn-mini" ${testingSiteIds.has(target.id) ? 'disabled' : ''} onclick="runSingleSiteTest('${encodeURIComponent(target.id)}')">${testingSiteIds.has(target.id) ? '测试中' : '测试'}</button>
                <button class="btn-mini btn-mini-danger" ${target.preset ? 'disabled title="预设网站不能删除"' : ''} onclick="deleteSiteTarget('${encodeURIComponent(target.id)}')">删除</button>
            </div>
        </div>
    `).join('');
}

async function addSiteTarget() {
    const nameEl = document.getElementById('siteTargetName');
    const categoryEl = document.getElementById('siteTargetCategory');
    const urlEl = document.getElementById('siteTargetURL');
    const payload = {
        name: (nameEl?.value || '').trim(),
        category: (categoryEl?.value || '').trim() || '自定义',
        url: (urlEl?.value || '').trim()
    };
    if (!payload.name || !payload.url) {
        showToast('请输入网站名称和网址', 'warning');
        return;
    }
    try {
        const res = await fetch('/api/site_targets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.ok) {
            nameEl.value = '';
            categoryEl.value = '';
            urlEl.value = '';
            showToast('测试网站已添加', 'success');
            await loadSiteTargets();
        } else {
            showToast(data.msg || '添加失败', 'error');
        }
    } catch(e) {
        showToast('添加测试网站失败', 'error');
    }
}

async function deleteSiteTarget(encodedId) {
    const id = decodeURIComponent(encodedId);
    const target = siteTargetsCache.find(t => t.id === id);
    if (!target || target.preset) return;
    if (!confirm('确定删除测试网站「' + target.name + '」吗？')) return;
    try {
        const res = await fetch('/api/site_targets?id=' + encodeURIComponent(id), { method: 'DELETE' });
        const data = await res.json();
        if (data.ok) {
            showToast('测试网站已删除', 'success');
            await loadSiteTargets();
        } else {
            showToast(data.msg || '删除失败', 'error');
        }
    } catch(e) {
        showToast('删除测试网站失败', 'error');
    }
}

async function runSiteTests() {
    const btn = document.getElementById('btnRunSiteTests');
    const summary = document.getElementById('siteCheckSummary');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '测试中';
    }
    if (summary) summary.textContent = '正在通过当前节点逐个访问测试网站...';
    siteResultsCache = [];
    renderSiteResults(true);
    try {
        const res = await fetch('/api/site_test', { method: 'POST' });
        const data = await res.json();
        if (!data.ok) {
            showToast(data.msg || '网站测试失败', 'error');
            if (summary) summary.textContent = data.msg || '网站测试失败';
            return;
        }
        siteResultsCache = data.results || [];
        const okCount = siteResultsCache.filter(r => r.ok).length;
        if (summary) summary.textContent = `当前节点「${data.node || '未命名'}」可访问 ${okCount} / ${siteResultsCache.length} 个测试网站`;
        renderSiteResults();
    } catch(e) {
        showToast('网站测试请求失败', 'error');
        if (summary) summary.textContent = '网站测试请求失败';
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '测试当前节点';
        }
    }
}

async function runSingleSiteTest(encodedId) {
    const id = decodeURIComponent(encodedId);
    const target = siteTargetsCache.find(t => t.id === id);
    const summary = document.getElementById('siteCheckSummary');
    if (!target || testingSiteIds.has(id)) return;
    testingSiteIds.add(id);
    renderSiteTargets();
    upsertSiteResult({
        id,
        name: target.name,
        category: target.category,
        url: target.url,
        ok: false,
        message: '测试中'
    });
    renderSiteResults();
    if (summary) summary.textContent = `正在测试「${target.name}」...`;
    try {
        const res = await fetch('/api/site_test?id=' + encodeURIComponent(id), { method: 'POST' });
        const data = await res.json();
        if (!data.ok) {
            showToast(data.msg || '单点测试失败', 'error');
            if (summary) summary.textContent = data.msg || '单点测试失败';
            return;
        }
        const result = (data.results || [])[0];
        if (result) {
            upsertSiteResult(result);
            if (summary) summary.textContent = `当前节点「${data.node || '未命名'}」测试「${result.name}」：${result.ok ? '可访问' : '不可用'}`;
        }
        renderSiteResults();
    } catch(e) {
        showToast('单点测试请求失败', 'error');
        if (summary) summary.textContent = '单点测试请求失败';
    } finally {
        testingSiteIds.delete(id);
        renderSiteTargets();
    }
}

function upsertSiteResult(result) {
    const idx = siteResultsCache.findIndex(r => r.id === result.id);
    if (idx >= 0) {
        siteResultsCache[idx] = result;
    } else {
        siteResultsCache.push(result);
    }
}

function renderSiteResults(loading = false) {
    const el = document.getElementById('siteCheckResults');
    if (!el) return;
    if (loading) {
        el.innerHTML = '<div class="empty-state">正在逐个测试，请稍候...</div>';
        return;
    }
    if (!siteResultsCache.length) {
        el.innerHTML = '<div class="empty-state">尚未运行测试。</div>';
        return;
    }
    el.innerHTML = siteResultsCache.map(result => `
        <div class="site-result-row ${result.ok ? 'ok' : 'fail'}">
            <div class="site-result-status">${result.ok ? '可访问' : '不可用'}</div>
            <div class="site-result-main">
                <div>
                    <span class="site-target-name">${escapeHTML(result.name)}</span>
                    <span class="site-target-category">${escapeHTML(result.category || '')}</span>
                </div>
                <div class="site-target-url">${escapeHTML(result.url)}</div>
            </div>
            <div class="site-result-meta">
                <span>${result.latencyMs ? result.latencyMs + ' ms' : '--'}</span>
                <span>${escapeHTML(result.message || '')}${result.statusCode ? ' · HTTP ' + result.statusCode : ''}</span>
            </div>
        </div>
    `).join('');
}

function defaultAutoSelectConfig() {
    return {
        enabled: false,
        scope: 'subscription',
        subscriptionFiles: [],
        aggregateFiles: [],
        intervalMinutes: 5,
        startupMode: 'none',
        siteCheck: {
            mode: 'none',
            ids: [],
            defaultSelectionApplied: false
        },
        ignoreTimeout: false,
        excludedNodeKeys: [],
        discardedRules: [],
        rules: [
            { id: 'preset_no_hk', type: 'exclude_keyword', value: '香港', label: '不使用香港的节点' }
        ]
    };
}

async function loadAutoSelectConfig() {
    let loadedFromServer = false;
    try {
        const res = await fetch('/api/auto_select_config');
        const data = await res.json();
        if (data.ok && data.config) {
            autoSelectConfig = data.config;
            loadedFromServer = true;
        }
    } catch(e) {
    }
    if (!autoSelectConfig) {
        try {
            const raw = localStorage.getItem('wing_auto_select_config');
            autoSelectConfig = raw ? JSON.parse(raw) : defaultAutoSelectConfig();
        } catch(e) {
            autoSelectConfig = defaultAutoSelectConfig();
        }
    }
    normalizeAutoSelectConfig();
    localStorage.setItem('wing_auto_select_config', JSON.stringify(autoSelectConfig));
    if (!loadedFromServer) persistAutoSelectConfigToServer();
    renderAutoSelectConfig();
}

function normalizeAutoSelectConfig() {
    if (!autoSelectConfig || typeof autoSelectConfig !== 'object' || Array.isArray(autoSelectConfig)) {
        autoSelectConfig = defaultAutoSelectConfig();
    }
    const defaults = defaultAutoSelectConfig();
    autoSelectConfig.enabled = !!autoSelectConfig.enabled;
    if (!['all', 'subscription', 'aggregate'].includes(autoSelectConfig.scope)) autoSelectConfig.scope = defaults.scope;
    if (autoSelectConfig.subscriptionFile) {
        autoSelectConfig.subscriptionFiles = [autoSelectConfig.subscriptionFile];
        delete autoSelectConfig.subscriptionFile;
    }
    if (!Array.isArray(autoSelectConfig.subscriptionFiles)) autoSelectConfig.subscriptionFiles = [];
    autoSelectConfig.subscriptionFiles = normalizedFileList(autoSelectConfig.subscriptionFiles);
    if (autoSelectConfig.aggregateFile) {
        autoSelectConfig.aggregateFiles = [autoSelectConfig.aggregateFile];
        delete autoSelectConfig.aggregateFile;
    }
    if (!Array.isArray(autoSelectConfig.aggregateFiles)) autoSelectConfig.aggregateFiles = [];
    autoSelectConfig.aggregateFiles = normalizedFileList(autoSelectConfig.aggregateFiles);
    autoSelectConfig.intervalMinutes = normalizeAutoSelectInterval(autoSelectConfig.intervalMinutes);
    if (!['none', 'proxy', 'tun', 'proxy_tun'].includes(autoSelectConfig.startupMode)) autoSelectConfig.startupMode = 'none';
    if (!autoSelectConfig.siteCheck || typeof autoSelectConfig.siteCheck !== 'object') {
        autoSelectConfig.siteCheck = { mode: 'none', ids: [], defaultSelectionApplied: false };
    }
    if (!Array.isArray(autoSelectConfig.siteCheck.ids)) autoSelectConfig.siteCheck.ids = [];
    autoSelectConfig.siteCheck.defaultSelectionApplied = !!autoSelectConfig.siteCheck.defaultSelectionApplied;
    if (!['none', 'any', 'all'].includes(autoSelectConfig.siteCheck.mode)) autoSelectConfig.siteCheck.mode = 'none';
    autoSelectConfig.ignoreTimeout = !!autoSelectConfig.ignoreTimeout;
    if (!Array.isArray(autoSelectConfig.excludedNodeKeys)) autoSelectConfig.excludedNodeKeys = [];
    autoSelectConfig.excludedNodeKeys = normalizedStringList(autoSelectConfig.excludedNodeKeys);
    if (!Array.isArray(autoSelectConfig.discardedRules)) autoSelectConfig.discardedRules = [];
    autoSelectConfig.discardedRules = autoSelectConfig.discardedRules
        .filter(rule => rule && typeof rule === 'object')
        .slice(0, 5);
    if (!Array.isArray(autoSelectConfig.rules)) autoSelectConfig.rules = [];
}

function normalizedFileList(values) {
    const out = [];
    const seen = new Set();
    (values || []).forEach(value => {
        let file = String(value || '').trim();
        try { file = decodeURIComponent(file); } catch(e) {}
        if (!file || seen.has(file)) return;
        seen.add(file);
        out.push(file);
    });
    return out;
}

function normalizedStringList(values) {
    const out = [];
    const seen = new Set();
    (values || []).forEach(value => {
        const text = String(value || '').trim();
        if (!text || seen.has(text)) return;
        seen.add(text);
        out.push(text);
    });
    return out;
}

function saveAutoSelectConfig(options = {}) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    normalizeAutoSelectConfig();
    localStorage.setItem('wing_auto_select_config', JSON.stringify(autoSelectConfig));
    scheduleAutoSelectConfigSave();
    if (options.timer !== false) scheduleAutoSelectTimer();
    if (options.render !== false) scheduleAutoSelectConfigRender();
    if (autoSelectConfig.enabled && options.restart === true) requestAutoSelectRestart({ silent: options.silent !== false });
    else if (autoSelectConfig.enabled && options.run === true) scheduleAutoSelectRun(700);
}

function scheduleAutoSelectConfigSave() {
    if (autoSelectSaveTimer) clearTimeout(autoSelectSaveTimer);
    autoSelectSaveTimer = setTimeout(persistAutoSelectConfigToServer, 180);
}

function scheduleAutoSelectConfigRender() {
    if (autoSelectRenderTimer) return;
    const raf = window.requestAnimationFrame || (callback => setTimeout(callback, 16));
    autoSelectRenderTimer = raf(() => {
        autoSelectRenderTimer = null;
        refreshAutoSelectViews();
    });
}

async function persistAutoSelectConfigToServer() {
    if (!autoSelectConfig) return;
    try {
        await fetch('/api/auto_select_config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(autoSelectConfig)
        });
    } catch(e) {}
}

function refreshAutoSelectViews() {
    if (nodeGroupMode === 'auto') renderAutoSelectConfig();
    if (nodeGroupMode === 'auto_nodes') renderAutoNodes();
    if (nodeGroupMode === 'subscription' || nodeGroupMode === 'aggregate') renderNodes();
}

function decodeAutoSelectParam(value) {
    try {
        return decodeURIComponent(value || '');
    } catch(e) {
        return value || '';
    }
}

function bindAutoSelectConfigEvents() {
    const pane = document.getElementById('autoSelectNodePane');
    if (!pane || autoSelectEventsBound) return;
    autoSelectEventsBound = true;

    pane.addEventListener('change', event => {
        const target = event.target;
        if (!target?.dataset) return;
        const action = target.dataset.autoSelectAction;
        if (!action) return;

        if (action === 'subscription') {
            toggleAutoSelectSubscription(target.dataset.fileName || '', target.checked);
        } else if (action === 'aggregate') {
            toggleAutoSelectAggregate(target.dataset.fileName || '', target.checked);
        } else if (action === 'site-target') {
            setAutoSelectSiteTarget(target.dataset.targetId || '', target.checked);
        } else if (action === 'scope') {
            setAutoSelectScope(target.value);
        } else if (action === 'startup-mode') {
            setAutoSelectStartupMode(target.value);
        } else if (action === 'site-mode') {
            setAutoSelectSiteMode(target.value);
        } else if (action === 'new-rule-type') {
            renderAutoSelectRulePicker();
        } else if (action === 'rule-picker') {
            syncAutoSelectPickerValue('autoSelectRuleValue', 'autoSelectRulePicker');
        } else if (action === 'rule-type') {
            updateAutoSelectRuleType(target.dataset.ruleId || '', target.value);
        } else if (action === 'rule-picked') {
            updateAutoSelectRulePickedValue(target.dataset.ruleId || '', target.dataset.value || '', target.checked);
        }
    });

    pane.addEventListener('keydown', event => {
        const target = event.target;
        if (event.key === 'Enter' && target?.dataset?.autoSelectAction === 'rule-value') {
            event.preventDefault();
            target.blur();
        }
    });

    pane.addEventListener('focusout', event => {
        const target = event.target;
        if (target?.dataset?.autoSelectAction === 'rule-value') {
            updateAutoSelectRuleValue(target.dataset.ruleId || '', target.value);
        }
    });

    pane.addEventListener('click', event => {
        const source = event.target instanceof Element ? event.target : event.target?.parentElement;
        const button = source?.closest('button[data-auto-select-action]');
        if (!button) return;
        const action = button.dataset.autoSelectAction;
        if (action === 'delete-rule') {
            deleteAutoSelectRule(button.dataset.ruleId || '');
        } else if (action === 'subscription-card') {
            toggleAutoSelectSubscription(button.dataset.fileName || '', !button.classList.contains('selected'));
            renderAutoSelectConfig();
        } else if (action === 'aggregate-card') {
            toggleAutoSelectAggregate(button.dataset.fileName || '', !button.classList.contains('selected'));
            renderAutoSelectConfig();
        } else if (action === 'site-target-card') {
            setAutoSelectSiteTarget(button.dataset.targetId || '', !button.classList.contains('selected'));
            renderAutoSelectConfig();
        } else if (action === 'open-rule-card') {
            openAutoSelectRuleModal(button.dataset.ruleId || '');
        } else if (action === 'restore-discarded-rule') {
            restoreAutoSelectDiscardedRule(button.dataset.discardIndex || '');
        }
    });
}

function scheduleAutoSelectRun(delay = 700) {
    if (autoSelectRunTimer) clearTimeout(autoSelectRunTimer);
    autoSelectRunTimer = setTimeout(() => {
        autoSelectRunTimer = null;
        runAutoSelectCycle({ silent: true });
    }, delay);
}

function queueAutoSelectRun(options = {}) {
    if (autoSelectRunTimer) {
        clearTimeout(autoSelectRunTimer);
        autoSelectRunTimer = null;
    }
    autoSelectQueuedRun = { ...options, force: true };
}

function drainAutoSelectQueuedRun(delay = 0) {
    if (!autoSelectQueuedRun) return;
    const queued = autoSelectQueuedRun;
    autoSelectQueuedRun = null;
    setTimeout(() => runAutoSelectCycle(queued), delay);
}

function requestAutoSelectRestart(options = {}) {
    if (!autoSelectConfig?.enabled && !options.force) return;
    const queued = {
        ...options,
        force: true,
        silent: options.silent !== false
    };
    setAutoSelectNowButtonBusy(true);
    queueAutoSelectRun(queued);
    if (autoSelectAbortController) {
        autoSelectAbortController.abort();
    }
    if (!autoSelectRunning) {
        drainAutoSelectQueuedRun();
    }
}

function scheduleAutoSelectRuleChangeRestart(delay = 620) {
    if (!autoSelectConfig?.enabled) return;
    if (autoSelectRuleChangeRestartTimer) clearTimeout(autoSelectRuleChangeRestartTimer);
    autoSelectRuleChangeRestartTimer = setTimeout(() => {
        autoSelectRuleChangeRestartTimer = null;
        requestAutoSelectRestart({ silent: true });
    }, delay);
}

function setAutoSelectNowButtonBusy(isBusy) {
    const btn = document.querySelector('.auto-select-section-actions .btn-primary');
    if (!btn) return;
    if (!btn.dataset.idleText) btn.dataset.idleText = btn.textContent || '立即选择';
    btn.textContent = isBusy ? '选择中' : (btn.dataset.idleText || '立即选择');
}

function stopAutoSelectSelection() {
    if (autoSelectTimer) {
        clearInterval(autoSelectTimer);
        autoSelectTimer = null;
    }
    if (autoSelectRunTimer) {
        clearTimeout(autoSelectRunTimer);
        autoSelectRunTimer = null;
    }
    autoSelectQueuedRun = null;
    autoSelectRunSeq += 1;
    if (autoSelectAbortController) {
        autoSelectAbortController.abort();
        autoSelectAbortController = null;
    }
    setAutoSelectNowButtonBusy(false);
}

function autoSelectStoppedError() {
    return new Error('auto_select_stopped');
}

function assertAutoSelectActive(runContext, options = {}) {
    if (!runContext || runContext.signal.aborted || runContext.seq !== autoSelectRunSeq) {
        throw autoSelectStoppedError();
    }
    if (!options.force && !autoSelectConfig?.enabled) {
        throw autoSelectStoppedError();
    }
}

function renderAutoSelectConfig() {
    bindAutoSelectConfigEvents();
    const enabledEl = document.getElementById('autoSelectEnabled');
    const scopeEl = document.getElementById('autoSelectScope');
    const subscriptionEl = document.getElementById('autoSelectSubscriptions');
    const aggregateEl = document.getElementById('autoSelectAggregates');
    const intervalEl = document.getElementById('autoSelectIntervalMinutes');
    const startupEl = document.getElementById('autoSelectStartupMode');
    const siteModeEl = document.getElementById('autoSelectSiteMode');
    const siteListEl = document.getElementById('autoSelectSiteList');
    const listEl = document.getElementById('autoSelectRuleList');
    const discardEl = document.getElementById('autoSelectDiscardPile');
    const ignoreTimeoutEl = document.getElementById('autoSelectIgnoreTimeout');
    if (!enabledEl || !scopeEl || !listEl || !autoSelectConfig) return;

    const autoNodesTab = document.getElementById('autoNodesTab');
    if (autoNodesTab) autoNodesTab.style.display = autoSelectConfig.enabled ? 'inline-block' : 'none';
    if (!autoSelectConfig.enabled && nodeGroupMode === 'auto_nodes') {
        setNodeGroupMode('subscription');
    }

    enabledEl.checked = !!autoSelectConfig.enabled;
    scopeEl.value = autoSelectConfig.scope || 'subscription';
    if (intervalEl) intervalEl.value = normalizeAutoSelectInterval(autoSelectConfig.intervalMinutes);
    if (startupEl) startupEl.value = autoSelectConfig.startupMode || 'none';
    if (ignoreTimeoutEl) ignoreTimeoutEl.checked = !!autoSelectConfig.ignoreTimeout;
    if (subscriptionEl) {
        subscriptionEl.style.display = autoSelectConfig.scope === 'subscription' ? '' : 'none';
        if (!suppliersCache.length) {
            subscriptionEl.innerHTML = '<div class="auto-select-empty">暂无订阅组</div>';
        } else {
            const selected = new Set(autoSelectConfig.subscriptionFiles || []);
            subscriptionEl.innerHTML = suppliersCache.map((s, index) => renderAutoSelectSourceCard({
                kind: 'subscription',
                value: s.fileName,
                title: s.name || s.fileName,
                meta: autoSelectSourceMeta('subscription', s),
                selected: selected.has(s.fileName),
                index
            })).join('');
        }
    }
    if (aggregateEl) {
        aggregateEl.style.display = autoSelectConfig.scope === 'aggregate' ? '' : 'none';
        if (!aggregateGroupsCache.length) {
            aggregateEl.innerHTML = '<div class="auto-select-empty">暂无聚合组</div>';
        } else {
            const selected = new Set(autoSelectConfig.aggregateFiles || []);
            aggregateEl.innerHTML = aggregateGroupsCache.map((g, index) => renderAutoSelectSourceCard({
                kind: 'aggregate',
                value: g.fileName,
                title: g.name || g.fileName,
                meta: autoSelectSourceMeta('aggregate', g),
                selected: selected.has(g.fileName),
                index
            })).join('');
        }
    }
    if (siteModeEl) siteModeEl.value = autoSelectConfig.siteCheck?.mode || 'none';
    if (siteListEl) {
        if (!siteTargetsCache.length) {
            siteListEl.innerHTML = '<div class="auto-select-empty">测试网站加载后可选择。</div>';
        } else {
            if (!autoSelectConfig.siteCheck) autoSelectConfig.siteCheck = { mode: 'none', ids: [], defaultSelectionApplied: false };
            if (!Array.isArray(autoSelectConfig.siteCheck.ids)) autoSelectConfig.siteCheck.ids = [];
            if (!autoSelectConfig.siteCheck.ids.length && !autoSelectConfig.siteCheck.defaultSelectionApplied) {
                autoSelectConfig.siteCheck.ids = siteTargetsCache.map(target => target.id);
                autoSelectConfig.siteCheck.defaultSelectionApplied = true;
                saveAutoSelectConfig({ render: false, run: false, timer: false });
            }
            const ids = new Set(autoSelectConfig.siteCheck?.ids || []);
            siteListEl.innerHTML = siteTargetsCache.map((target, index) => renderAutoSelectSiteCard(target, ids.has(target.id), index)).join('');
        }
    }
    if (!autoSelectConfig.rules.length) {
        listEl.innerHTML = '<div class="auto-select-empty">暂无筛选规则，添加规则开始过滤候选节点。</div>';
        renderAutoSelectRulePicker();
        renderAutoSelectDiscardPile(discardEl);
        scheduleCustomSelectSync();
        return;
    }
    listEl.innerHTML = autoSelectConfig.rules.map((rule, index) => renderAutoSelectRuleCard(rule, {
        index,
        justDrawn: rule.id === autoSelectLastDrawnRuleId
    })).join('');
    autoSelectLastDrawnRuleId = "";
    renderAutoSelectDiscardPile(discardEl);
    renderAutoSelectRulePicker();
    scheduleCustomSelectSync();
}

function renderAutoSelectSourceCard({ kind, value, title, meta, selected, index }) {
    const action = kind === 'aggregate' ? 'aggregate-card' : 'subscription-card';
    const rank = kind === 'aggregate' ? 'AG' : 'SUB';
    return `
        <button type="button" class="auto-select-choice-card ${selected ? 'selected' : ''}" data-auto-select-action="${action}" data-file-name="${escapeAttr(value)}" aria-pressed="${selected ? 'true' : 'false'}" style="--deal-index:${Math.min(index || 0, 12)}">
            <span class="auto-select-card-corner">${rank}</span>
            <span class="auto-select-card-mark"><img class="mode-logo" src="${currentModeLogoSrc()}" alt="" aria-hidden="true"></span>
            <span class="auto-select-card-title">${escapeHTML(title)}</span>
            <span class="auto-select-card-meta">${escapeHTML(meta)}</span>
        </button>
    `;
}

function isAggregateNode(node) {
    if (!node?.fileName) return false;
    return aggregateGroupsCache.some(group => group.fileName === node.fileName);
}

function autoSelectSourceNodes(kind, fileName) {
    if (!fileName) return [];
    if (kind === 'subscription') {
        return (allNodesList || []).filter(node => node.fileName === fileName && !isAggregateNode(node));
    }
    return (allNodesList || []).filter(node => node.fileName === fileName);
}

function autoSelectSourceNodeCount(kind, source) {
    const fileName = source?.fileName || '';
    if (!fileName) return 0;
    const liveCount = autoSelectSourceNodes(kind, fileName).length;
    const cachedCount = Number(source?.nodeCount || source?.count || 0);
    if (allNodesList?.length) return liveCount;
    return Number.isFinite(cachedCount) ? cachedCount : 0;
}

function autoSelectSourceMeta(kind, source) {
    const total = autoSelectSourceNodeCount(kind, source);
    const selected = kind === 'subscription'
        ? (autoSelectConfig?.subscriptionFiles || []).includes(source.fileName)
        : (autoSelectConfig?.aggregateFiles || []).includes(source.fileName);
    return `${total} 个节点${selected ? ' · 已选择' : ''}`;
}

function renderAutoSelectSiteCard(target, selected, index) {
    return `
        <button type="button" class="auto-select-choice-card site ${selected ? 'selected' : ''}" data-auto-select-action="site-target-card" data-target-id="${escapeAttr(target.id)}" aria-pressed="${selected ? 'true' : 'false'}" style="--deal-index:${Math.min(index || 0, 12)}">
            <span class="auto-select-card-corner">WEB</span>
            <span class="auto-select-card-mark"><img class="mode-logo" src="${currentModeLogoSrc()}" alt="" aria-hidden="true"></span>
            <span class="auto-select-card-title">${escapeHTML(target.name || target.url || target.id)}</span>
            <span class="auto-select-card-meta">${escapeHTML(target.category || '网站')}</span>
        </button>
    `;
}

function renderAutoSelectRuleCard(rule, options = {}) {
    const values = autoSelectRuleValues(rule);
    const description = autoSelectRuleDescription(rule);
    const detail = autoSelectRuleDetail(rule);
    return `
        <button type="button" class="auto-select-rule-card ${options.justDrawn ? 'drawn' : ''}" data-auto-select-action="open-rule-card" data-rule-id="${escapeAttr(rule.id)}" title="${escapeAttr(detail)}" style="--deal-index:${Math.min(options.index || 0, 18)}">
            <span class="auto-select-rule-rank">${escapeHTML(autoSelectRuleCardRank(rule.type))}</span>
            <span class="auto-select-rule-suit"><img class="mode-logo" src="${currentModeLogoSrc()}" alt="" aria-hidden="true"></span>
            <span class="auto-select-rule-title">${escapeHTML(autoSelectRuleLabel(rule))}</span>
            <span class="auto-select-rule-desc">${escapeHTML(description)}</span>
            <span class="auto-select-rule-meta">${values.length || 1} 个条件 · 点击查看/编辑</span>
        </button>
    `;
}

function renderAutoSelectDiscardPile(container) {
    if (!container || !autoSelectConfig) return;
    const pile = autoSelectConfig.discardedRules || [];
    if (!pile.length) {
        container.innerHTML = `
            <div class="auto-select-discard-title">弃置区</div>
            <div class="auto-select-discard-empty">暂无弃置规则</div>
        `;
        return;
    }
    container.innerHTML = `
        <div class="auto-select-discard-title">弃置区 <span>${pile.length} 条</span></div>
        <div class="auto-select-discard-stack">
            ${pile.map((rule, index) => renderAutoSelectDiscardCard(rule, index)).join('')}
        </div>
    `;
}

function renderAutoSelectDiscardCard(rule, index) {
    const detail = autoSelectRuleDetail(rule);
    return `
        <button type="button" class="auto-select-rule-card discarded" data-auto-select-action="restore-discarded-rule" data-discard-index="${index}" title="${escapeAttr(detail)}" aria-label="查看弃置：${escapeAttr(autoSelectRuleLabel(rule))}" style="--discard-index:${index}">
            <span class="auto-select-rule-rank">${escapeHTML(autoSelectRuleCardRank(rule.type))}</span>
            <span class="auto-select-rule-suit"><img class="mode-logo" src="${currentModeLogoSrc()}" alt="" aria-hidden="true"></span>
            <span class="auto-select-rule-title">${escapeHTML(autoSelectRuleLabel(rule))}</span>
            <span class="auto-select-rule-desc">${escapeHTML(autoSelectRuleDescription(rule))}</span>
        </button>
    `;
}

function setAutoSelectEnabled(checked) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    autoSelectConfig.enabled = !!checked;
    saveAutoSelectConfig({ render: false, run: false, timer: false });
    if (!autoSelectConfig.enabled) stopAutoSelectSelection();
    
    const autoNodesTab = document.getElementById('autoNodesTab');
    if (autoNodesTab) autoNodesTab.style.display = autoSelectConfig.enabled ? 'inline-block' : 'none';
    if (!autoSelectConfig.enabled && nodeGroupMode === 'auto_nodes') {
        setNodeGroupMode('subscription');
    }

    renderAutoSelectConfig();
    if (autoSelectConfig.enabled) {
        scheduleAutoSelectTimer();
        runAutoSelectCycle({ silent: false, force: true });
    }
}

function setAutoSelectIgnoreTimeout(checked) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    autoSelectConfig.ignoreTimeout = !!checked;
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
}

function setAutoSelectScope(scope) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    autoSelectConfig.scope = ['all', 'subscription', 'aggregate'].includes(scope) ? scope : 'subscription';
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoSelectConfig();
}

function toggleAutoSelectSubscription(encodedFileName, checked) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    const fileName = decodeAutoSelectParam(encodedFileName);
    const set = new Set(autoSelectConfig.subscriptionFiles || []);
    if (checked) set.add(fileName);
    else set.delete(fileName);
    autoSelectConfig.subscriptionFiles = Array.from(set);
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
}

function toggleAutoSelectAggregate(encodedFileName, checked) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    const fileName = decodeAutoSelectParam(encodedFileName);
    const set = new Set(autoSelectConfig.aggregateFiles || []);
    if (checked) set.add(fileName);
    else set.delete(fileName);
    autoSelectConfig.aggregateFiles = Array.from(set);
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
}

function normalizeAutoSelectInterval(value) {
    const minutes = Number.parseInt(value, 10);
    if (!Number.isFinite(minutes) || minutes < 1) return 5;
    return Math.min(minutes, 1440);
}

function setAutoSelectInterval(value) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    autoSelectConfig.intervalMinutes = normalizeAutoSelectInterval(value);
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    scheduleAutoSelectTimer();
}

function setAutoSelectStartupMode(mode) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    autoSelectConfig.startupMode = ['none', 'proxy', 'tun', 'proxy_tun'].includes(mode) ? mode : 'none';
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
}

function setAutoSelectSiteMode(mode) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    autoSelectConfig.siteCheck.mode = ['none', 'any', 'all'].includes(mode) ? mode : 'none';
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
}

function setAutoSelectSiteTarget(encodedId, checked) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    const id = decodeAutoSelectParam(encodedId);
    const ids = new Set(autoSelectConfig.siteCheck.ids || []);
    if (checked) ids.add(id);
    else ids.delete(id);
    autoSelectConfig.siteCheck.ids = Array.from(ids);
    autoSelectConfig.siteCheck.defaultSelectionApplied = true;
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
}

function addAutoSelectRule() {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    const typeEl = document.getElementById('autoSelectRuleType');
    const input = document.getElementById('autoSelectRuleValue');
    const type = typeEl?.value || 'exclude_keyword';
    const value = (input?.value || '').trim();
    if (!value) {
        showToast('请输入规则内容，多个值可用逗号分隔', 'warning');
        return;
    }
    const rule = {
        id: 'rule_' + Date.now(),
        type,
        value,
        values: splitAutoSelectValues(value),
        createdAt: Date.now()
    };
    autoSelectConfig.rules.unshift(rule);
    autoSelectLastDrawnRuleId = rule.id;
    if (input) input.value = '';
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: false });
    renderAutoSelectConfig();
    scheduleAutoSelectRuleChangeRestart();
}

function autoSelectRuleTypeOptions(selected) {
    const types = [
        ['exclude_keyword', '不使用包含'],
        ['include_region', '只选择地区'],
        ['include_node', '只选择节点'],
        ['include_subscription', '只选择订阅组'],
        ['include_aggregate_group', '只选择聚合组'],
        ['include_protocol', '只使用协议'],
        ['exclude_protocol', '不使用协议'],
    ];
    return types.map(([value, label]) => `<option value="${value}" ${value === selected ? 'selected' : ''}>${label}</option>`).join('');
}

function selectableAutoSelectValues(type) {
    const unique = new Map();
    if (type === 'include_node') {
        (allNodesList || []).forEach(n => {
            if (n.name) unique.set(n.name, n.name);
        });
    } else if (type === 'include_subscription') {
        (suppliersCache || []).forEach(s => unique.set(s.name || s.fileName, s.name || s.fileName));
    } else if (type === 'include_aggregate_group') {
        (aggregateGroupsCache || []).forEach(g => unique.set(g.name || g.fileName, g.name || g.fileName));
    } else if (type === 'include_protocol' || type === 'exclude_protocol') {
        (allNodesList || []).forEach(n => {
            if (n.type) unique.set(n.type.toLowerCase(), n.type);
        });
    }
    return Array.from(unique.values()).sort((a, b) => a.localeCompare(b));
}

function autoSelectRuleUsesPicker(type) {
    return ['include_node', 'include_subscription', 'include_aggregate_group', 'include_protocol', 'exclude_protocol'].includes(type);
}

function renderAutoSelectRulePicker() {
    const type = document.getElementById('autoSelectRuleType')?.value || 'exclude_keyword';
    const input = document.getElementById('autoSelectRuleValue');
    const picker = document.getElementById('autoSelectRulePicker');
    if (!picker || !input) return;
    const values = selectableAutoSelectValues(type);
    if (!autoSelectRuleUsesPicker(type) || !values.length) {
        picker.innerHTML = '';
        picker.hidden = true;
        input.style.display = '';
        return;
    }
    picker.hidden = false;
    input.style.display = 'none';
    const selected = new Set(splitAutoSelectValues(input.value));
    picker.innerHTML = values.map(value => `
        <label class="auto-select-check">
            <input type="checkbox" ${selected.has(value) ? 'checked' : ''} data-auto-select-action="rule-picker">
            <span>${escapeHTML(value)}</span>
        </label>
    `).join('');
}

function syncAutoSelectPickerValue(inputId, pickerId) {
    const input = document.getElementById(inputId);
    const picker = document.getElementById(pickerId);
    if (!input || !picker) return;
    const values = Array.from(picker.querySelectorAll('label')).filter(label => label.querySelector('input')?.checked).map(label => label.textContent.trim());
    input.value = values.join(',');
}

function autoSelectRuleValueEditor(rule) {
    const values = autoSelectRuleValues(rule);
    if (!autoSelectRuleUsesPicker(rule.type)) {
        return `<input type="text" value="${escapeAttr(values.join(','))}" data-auto-select-action="rule-value" data-rule-id="${escapeAttr(rule.id)}">`;
    }
    const options = selectableAutoSelectValues(rule.type);
    if (!options.length) {
        return `<input type="text" value="${escapeAttr(values.join(','))}" data-auto-select-action="rule-value" data-rule-id="${escapeAttr(rule.id)}">`;
    }
    const selected = new Set(values);
    return `<div class="auto-select-picker compact">${options.map(value => `
        <label class="auto-select-check">
            <input type="checkbox" ${selected.has(value) ? 'checked' : ''} data-auto-select-action="rule-picked" data-rule-id="${escapeAttr(rule.id)}" data-value="${escapeAttr(value)}">
            <span>${escapeHTML(value)}</span>
        </label>
    `).join('')}</div>`;
}

function updateAutoSelectRuleType(encodedId, type) {
    const id = decodeAutoSelectParam(encodedId);
    const rule = autoSelectConfig?.rules?.find(r => r.id === id);
    if (!rule) return;
    rule.type = type;
    rule.values = [];
    rule.value = '';
    delete rule.label;
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoSelectConfig();
}

function updateAutoSelectRuleValue(encodedId, value) {
    const id = decodeAutoSelectParam(encodedId);
    const rule = autoSelectConfig?.rules?.find(r => r.id === id);
    if (!rule) return;
    const nextValue = value.trim();
    if (rule.value === nextValue && JSON.stringify(rule.values || []) === JSON.stringify(splitAutoSelectValues(value))) return;
    rule.value = nextValue;
    rule.values = splitAutoSelectValues(value);
    delete rule.label;
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoSelectConfig();
}

function updateAutoSelectRulePickedValue(encodedId, encodedValue, checked) {
    const id = decodeAutoSelectParam(encodedId);
    const value = decodeAutoSelectParam(encodedValue);
    const rule = autoSelectConfig?.rules?.find(r => r.id === id);
    if (!rule) return;
    const values = new Set(autoSelectRuleValues(rule));
    if (checked) values.add(value);
    else values.delete(value);
    rule.values = Array.from(values);
    rule.value = rule.values.join(',');
    delete rule.label;
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoSelectConfig();
}

function openAutoSelectRuleModal(encodedId) {
    const id = decodeAutoSelectParam(encodedId);
    const rule = autoSelectConfig?.rules?.find(r => r.id === id);
    const modal = document.getElementById('autoSelectRuleModal');
    const typeEl = document.getElementById('autoSelectEditRuleType');
    const valueEl = document.getElementById('autoSelectEditRuleValue');
    if (!modal || !typeEl || !valueEl || !rule) return;
    autoSelectEditingRuleId = id;
    typeEl.innerHTML = autoSelectRuleTypeOptions(rule.type);
    typeEl.value = rule.type || 'exclude_keyword';
    valueEl.value = autoSelectRuleValues(rule).join(',');
    renderAutoSelectRuleModalPicker();
    scheduleCustomSelectSync();
    modal.style.display = 'flex';
}

function closeAutoSelectRuleModal() {
    const modal = document.getElementById('autoSelectRuleModal');
    if (modal) modal.style.display = 'none';
    autoSelectEditingRuleId = "";
}

function onAutoSelectRuleModalTypeChange(type) {
    const valueEl = document.getElementById('autoSelectEditRuleValue');
    if (valueEl) valueEl.value = '';
    renderAutoSelectRuleModalPicker(type);
    scheduleCustomSelectSync();
}

function renderAutoSelectRuleModalPicker(type = '') {
    const typeEl = document.getElementById('autoSelectEditRuleType');
    const valueWrap = document.getElementById('autoSelectEditRuleValueWrap');
    const valueEl = document.getElementById('autoSelectEditRuleValue');
    const picker = document.getElementById('autoSelectEditRulePicker');
    if (!typeEl || !valueWrap || !valueEl || !picker) return;
    const currentType = type || typeEl.value || 'exclude_keyword';
    const options = selectableAutoSelectValues(currentType);
    if (!autoSelectRuleUsesPicker(currentType) || !options.length) {
        valueWrap.style.display = '';
        picker.innerHTML = '';
        picker.hidden = true;
        return;
    }
    valueWrap.style.display = 'none';
    picker.hidden = false;
    const selected = new Set(splitAutoSelectValues(valueEl.value));
    picker.innerHTML = options.map(value => `
        <label class="auto-select-check auto-select-modal-check">
            <input type="checkbox" ${selected.has(value) ? 'checked' : ''} onchange="syncAutoSelectRuleModalPicker()">
            <span>${escapeHTML(value)}</span>
        </label>
    `).join('');
}

function syncAutoSelectRuleModalPicker() {
    const valueEl = document.getElementById('autoSelectEditRuleValue');
    const picker = document.getElementById('autoSelectEditRulePicker');
    if (!valueEl || !picker) return;
    const labels = Array.from(picker.querySelectorAll('label'));
    if (!labels.length) return;
    valueEl.value = labels
        .filter(label => label.querySelector('input')?.checked)
        .map(label => label.textContent.trim())
        .join(',');
}

function saveEditingAutoSelectRule() {
    const rule = autoSelectConfig?.rules?.find(r => r.id === autoSelectEditingRuleId);
    const typeEl = document.getElementById('autoSelectEditRuleType');
    const valueEl = document.getElementById('autoSelectEditRuleValue');
    if (!rule || !typeEl || !valueEl) return;
    syncAutoSelectRuleModalPicker();
    const values = splitAutoSelectValues(valueEl.value);
    if (!values.length) {
        showToast('请输入规则内容，多个值可用逗号分隔', 'warning');
        return;
    }
    rule.type = typeEl.value || 'exclude_keyword';
    rule.value = values.join(',');
    rule.values = values;
    rule.updatedAt = Date.now();
    delete rule.label;
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    closeAutoSelectRuleModal();
    renderAutoSelectConfig();
    showToast('规则已更新', 'success', 1800);
}

function discardEditingAutoSelectRule() {
    if (!autoSelectEditingRuleId) return;
    const encodedId = encodeURIComponent(autoSelectEditingRuleId);
    closeAutoSelectRuleModal();
    deleteAutoSelectRule(encodedId);
    showToast('规则已弃置', 'success', 1800);
}

function deleteAutoSelectRule(encodedId) {
    if (!autoSelectConfig) return;
    const id = decodeAutoSelectParam(encodedId);
    const rule = autoSelectConfig.rules.find(r => r.id === id);
    if (rule) pushAutoSelectDiscardedRules([rule]);
    autoSelectConfig.rules = autoSelectConfig.rules.filter(rule => rule.id !== id);
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoSelectConfig();
}

async function clearAutoSelectRules() {
    if (!autoSelectConfig?.rules?.length) return;
    const listEl = document.getElementById('autoSelectRuleList');
    if (listEl) {
        listEl.classList.add('discarding');
        await sleep(420);
    }
    pushAutoSelectDiscardedRules(autoSelectConfig.rules);
    autoSelectConfig.rules = [];
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoSelectConfig();
    showToast('规则已全部弃置', 'success');
}

function pushAutoSelectDiscardedRules(rules) {
    if (!autoSelectConfig) return;
    const next = (rules || [])
        .filter(rule => rule && typeof rule === 'object')
        .map(rule => ({
            id: rule.id || ('discard_' + Date.now()),
            type: rule.type || 'exclude_keyword',
            value: rule.value || '',
            values: autoSelectRuleValues(rule),
            label: rule.label || '',
            discardedAt: Date.now()
        }));
    autoSelectConfig.discardedRules = [
        ...next,
        ...(autoSelectConfig.discardedRules || [])
    ].slice(0, 20);
}

function restoreAutoSelectDiscardedRule(indexValue) {
    if (!autoSelectConfig) return;
    const index = Number.parseInt(indexValue, 10);
    if (!Number.isInteger(index) || index < 0) return;
    const discarded = autoSelectConfig.discardedRules || [];
    const rule = discarded[index];
    if (!rule) return;
    const detail = autoSelectRuleDetail(rule);
    if (!confirm('查看弃置内容：\n\n' + detail + '\n\n是否重新启用这张规则？')) {
        return;
    }
    autoSelectConfig.discardedRules = discarded.filter((_, itemIndex) => itemIndex !== index);
    const restored = {
        ...rule,
        id: rule.id || ('rule_' + Date.now()),
        values: autoSelectRuleValues(rule),
        restoredAt: Date.now()
    };
    delete restored.discardedAt;
    autoSelectConfig.rules.unshift(restored);
    autoSelectLastDrawnRuleId = restored.id;
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: false });
    renderAutoSelectConfig();
    scheduleAutoSelectRuleChangeRestart();
    showToast('规则已重新启用', 'success', 1800);
}

function autoSelectScopeName(scope) {
    switch (scope) {
        case 'all': return '全部节点';
        case 'aggregate': return '聚合组';
        default: return '订阅组';
    }
}

function splitAutoSelectValues(value) {
    return String(value || '')
        .split(/[,\n，、]/)
        .map(v => v.trim())
        .filter(Boolean);
}

function autoSelectRuleValues(rule) {
    return Array.isArray(rule.values) && rule.values.length
        ? rule.values
        : splitAutoSelectValues(rule.value);
}

function autoSelectRuleLabel(rule) {
    if (rule.label) return rule.label;
    switch (rule.type) {
        case 'include_region': return '只选择指定地区';
        case 'include_node': return '只选择指定节点';
        case 'include_subscription': return '只选择指定订阅组';
        case 'include_aggregate_group': return '只选择指定聚合组';
        case 'include_protocol': return '只使用指定协议';
        case 'exclude_protocol': return '不使用指定协议';
        default: return '不使用指定关键字';
    }
}

function autoSelectRuleTypeLabel(type) {
    const labels = {
        exclude_keyword: '不使用包含',
        include_region: '只选择地区',
        include_node: '只选择节点',
        include_subscription: '只选择订阅组',
        include_aggregate_group: '只选择聚合组',
        include_protocol: '只使用协议',
        exclude_protocol: '不使用协议'
    };
    return labels[type] || labels.exclude_keyword;
}

function autoSelectRuleCardRank(type) {
    const ranks = {
        exclude_keyword: 'XK',
        include_region: 'RG',
        include_node: 'ND',
        include_subscription: 'SUB',
        include_aggregate_group: 'AG',
        include_protocol: 'PT',
        exclude_protocol: 'XP'
    };
    return ranks[type] || 'RL';
}

function autoSelectRuleSuit(type) {
    if (String(type || '').startsWith('exclude')) return '弃';
    if (type === 'include_protocol' || type === 'exclude_protocol') return '协';
    if (type === 'include_subscription' || type === 'include_aggregate_group') return '组';
    if (type === 'include_node') return '点';
    return '选';
}

function autoSelectRuleDescription(rule) {
    const values = autoSelectRuleValues(rule).join('、') || rule.value || '';
    switch (rule.type) {
        case 'include_region': return '地区/关键字：' + values;
        case 'include_node': return '节点：' + values;
        case 'include_subscription': return '订阅组：' + values;
        case 'include_aggregate_group': return '聚合组：' + values;
        case 'include_protocol': return '协议：' + values;
        case 'exclude_protocol': return '排除协议：' + values;
        default: return '排除：' + values;
    }
}

function autoSelectRuleDetail(rule) {
    const values = autoSelectRuleValues(rule);
    const content = values.length ? values.join('\n') : (rule.value || '（空）');
    return `${autoSelectRuleLabel(rule)}\n${autoSelectRuleTypeLabel(rule.type)}\n\n${content}`;
}

function supplierNameByFile(fileName) {
    return suppliersCache.find(s => s.fileName === fileName)?.name || '';
}

function supplierNameForNode(node) {
    return supplierNameByFile(node.sourceFile || node.fileName);
}

function aggregateNameByFile(fileName) {
    return aggregateGroupsCache.find(g => g.fileName === fileName)?.name || '';
}

function selectedSubscriptionFiles() {
    if (autoSelectConfig?.subscriptionFiles?.length > 0) return autoSelectConfig.subscriptionFiles;
    const active = suppliersCache.find(s => s.active);
    if (active) return [active.fileName];
    return suppliersCache[0] ? [suppliersCache[0].fileName] : [];
}

function selectedAggregateFiles() {
    if (autoSelectConfig?.aggregateFiles?.length > 0) return autoSelectConfig.aggregateFiles;
    const active = aggregateGroupsCache.find(g => g.active);
    if (active) return [active.fileName];
    return aggregateGroupsCache[0] ? [aggregateGroupsCache[0].fileName] : [];
}

function nodeSearchText(node) {
    const sourceName = supplierNameForNode(node) || aggregateNameByFile(node.fileName);
    return [
        node.name || '',
        node.sourceName || '',
        node.group || '',
        node.type || '',
        node.fileName || '',
        node.sourceFile || '',
        sourceName
    ].join(' ').toLowerCase();
}

function valuesMatchText(values, text) {
    const haystack = String(text || '').toLowerCase();
    return values.some(value => {
        const needle = String(value || '').trim().toLowerCase();
        return needle && haystack.includes(needle);
    });
}

function nodePassesAutoSelectRules(node) {
    if (autoSelectNodeExcluded(node)) {
        return false;
    }
    if (autoSelectConfig?.ignoreTimeout && node.latency === -1) {
        return false;
    }
    const rules = autoSelectConfig?.rules || [];
    const text = nodeSearchText(node);
    const supplierText = [node.sourceFile || node.fileName || '', supplierNameForNode(node)].join(' ');
    const aggregateText = [node.fileName || '', aggregateNameByFile(node.fileName)].join(' ');
    return rules.every(rule => {
        const values = autoSelectRuleValues(rule);
        if (!values.length) return true;
        switch (rule.type) {
            case 'exclude_keyword':
                return !valuesMatchText(values, text);
            case 'include_region':
            case 'include_node':
                return valuesMatchText(values, text);
            case 'include_subscription':
                return valuesMatchText(values, supplierText);
            case 'include_aggregate_group':
                return valuesMatchText(values, aggregateText);
            case 'include_protocol':
                return valuesMatchText(values, node.type || '');
            case 'exclude_protocol':
                return !valuesMatchText(values, node.type || '');
            default:
                return true;
        }
    });
}

function autoSelectNodeKey(node) {
    return [
        node?.fileName || '',
        node?.sourceFile || '',
        node?.subIndex ?? '',
        node?.sourceName || '',
        node?.name || '',
        node?.type || ''
    ].join('\u001f');
}

function autoSelectNodeExcluded(node) {
    if (!autoSelectConfig?.excludedNodeKeys?.length) return false;
    return autoSelectConfig.excludedNodeKeys.includes(autoSelectNodeKey(node));
}

function autoSelectExcludedNodeCount() {
    return autoSelectConfig?.excludedNodeKeys?.length || 0;
}

function excludeAutoSelectNode(encodedKey) {
    if (!autoSelectConfig) autoSelectConfig = defaultAutoSelectConfig();
    let key = '';
    try { key = decodeURIComponent(encodedKey || ''); } catch(e) {}
    const node = (allNodesList || []).find(n => autoSelectNodeKey(n) === key);
    const name = node?.name || '该节点';
    if (!key) return;
    if (!confirm('确定从自动选择候选中删除「' + name + '」吗？\n这不会删除订阅组或聚合组里的原节点。')) return;
    const excluded = new Set(autoSelectConfig.excludedNodeKeys || []);
    excluded.add(key);
    autoSelectConfig.excludedNodeKeys = Array.from(excluded);
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoNodes();
    showToast('已从自动选择候选中排除，不影响原节点', 'success');
}

function clearAutoSelectExcludedNodes() {
    if (!autoSelectConfig?.excludedNodeKeys?.length) return;
    if (!confirm('确定恢复所有已排除的自动选择候选节点吗？')) return;
    autoSelectConfig.excludedNodeKeys = [];
    saveAutoSelectConfig({ render: false, run: false, timer: false, restart: true });
    renderAutoNodes();
    showToast('已恢复自动选择候选节点', 'success');
}

function autoSelectCandidates(fileName = '') {
    const scope = autoSelectConfig?.scope || 'subscription';
    if (scope === 'all') return allNodesList || [];
    if (scope === 'subscription') {
        const targets = fileName ? [fileName] : selectedSubscriptionFiles();
        if (!targets.length) return [];
        return targets.flatMap(target => autoSelectSourceNodes('subscription', target));
    }
    if (scope === 'aggregate') {
        const targets = fileName ? [fileName] : selectedAggregateFiles();
        if (!targets.length) return [];
        return targets.flatMap(target => autoSelectSourceNodes('aggregate', target));
    }
    return [];
}

function bestAutoSelectNode(fileName = selectedNodeGroupFile) {
    const candidates = autoSelectCandidates(fileName)
        .filter(n => n.latency > 0)
        .filter(nodePassesAutoSelectRules);
    candidates.sort((a, b) => a.latency - b.latency);
    return candidates[0] || null;
}

function maybeAutoSelectNode(fileName = selectedNodeGroupFile) {
    if (!autoSelectConfig?.enabled || switchingNodeIndex !== null) return;
    const best = bestAutoSelectNode(fileName);
    if (!best) {
        showToast(`${autoSelectScopeName(autoSelectConfig.scope)}自动选择未找到可用节点`, 'warning');
        return;
    }
    if (best.active) return;
    showToast(`自动选择 ${best.name} · ${best.latency} ms`, 'success');
    switchNode(best.index);
}

function sleep(ms, signal) {
    if (signal?.aborted) return Promise.reject(autoSelectStoppedError());
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, ms);
        if (!signal) return;
        signal.addEventListener('abort', () => {
            clearTimeout(timer);
            reject(autoSelectStoppedError());
        }, { once: true });
    });
}

async function testAutoSelectCandidateLatencies(candidates, runContext, options = {}) {
    const unique = Array.from(new Map(candidates.map(n => [n.index, n])).values());
    if (!unique.length) return;
    unique.forEach(n => {
        const latEl = document.getElementById('lat-' + n.index);
        if (latEl) {
            latEl.textContent = '检测中';
            latEl.className = 'latency unknown';
        }
    });
    const queue = [...unique];
    const workerCount = Math.min(8, queue.length);
    async function worker() {
        while (queue.length) {
            assertAutoSelectActive(runContext, options);
            const node = queue.shift();
            try {
                await fetch('/api/test_single?idx=' + node.index, { method: 'POST', signal: runContext.signal });
            } catch(e) {}
        }
    }
    await Promise.all(Array.from({ length: workerCount }, worker));
    assertAutoSelectActive(runContext, options);
    await loadNodes();
}

function autoSelectSiteTargetIds() {
    const mode = autoSelectConfig?.siteCheck?.mode || 'none';
    if (mode === 'none') return [];
    const configured = autoSelectConfig?.siteCheck?.ids || [];
    if (configured.length) return configured;
    return siteTargetsCache.map(t => t.id);
}

async function ensureSiteTargetsLoaded() {
    if (siteTargetsCache.length) return;
    try {
        const res = await fetch('/api/site_targets');
        siteTargetsCache = await res.json() || [];
    } catch(e) {}
}

async function switchNodeAndWait(idx, runContext, options = {}) {
    assertAutoSelectActive(runContext, options);
    const node = allNodesList.find(n => n.index === idx);
    if (node?.active) return true;
    await switchNode(idx);
    await sleep(5500, runContext.signal);
    assertAutoSelectActive(runContext, options);
    await loadNodes();
    return !!allNodesList.find(n => n.index === idx && n.active);
}

async function testActiveNodeSitesForAutoSelect(runContext, options = {}) {
    const mode = autoSelectConfig?.siteCheck?.mode || 'none';
    if (mode === 'none') return true;
    await ensureSiteTargetsLoaded();
    const ids = autoSelectSiteTargetIds();
    if (!ids.length) return true;
    let passed = 0;
    for (const id of ids) {
        assertAutoSelectActive(runContext, options);
        try {
            const res = await fetch('/api/site_test?id=' + encodeURIComponent(id), { method: 'POST', signal: runContext.signal });
            const data = await res.json();
            const result = (data.results || [])[0];
            if (data.ok && result?.ok) passed++;
            if (mode === 'any' && passed > 0) return true;
        } catch(e) {}
    }
    return mode === 'all' ? passed === ids.length : passed > 0;
}

async function pickAutoSelectNodeWithSiteRules(candidates, runContext, options = {}) {
    const siteMode = autoSelectConfig?.siteCheck?.mode || 'none';
    if (siteMode === 'none') return candidates[0] || null;
    const original = allNodesList.find(n => n.active);
    for (const candidate of candidates) {
        assertAutoSelectActive(runContext, options);
        if (!(await switchNodeAndWait(candidate.index, runContext, options))) continue;
        if (await testActiveNodeSitesForAutoSelect(runContext, options)) return candidate;
    }
    if (original && !allNodesList.find(n => n.index === original.index && n.active)) {
        await switchNodeAndWait(original.index, runContext, options);
    }
    return null;
}

async function runAutoSelectCycle(options = {}) {
    if (!autoSelectConfig?.enabled && !options.force) {
        if (!options.silent) showToast('请先开启自动选择节点', 'warning');
        return;
    }
    if (autoSelectRunning || switchingNodeIndex !== null) {
        if (options.force) {
            queueAutoSelectRun(options);
            if (!autoSelectRunning) drainAutoSelectQueuedRun(600);
        } else if (!options.silent) {
            showToast('自动选择正在运行，请稍候。', 'info');
        }
        return;
    }
    const controller = new AbortController();
    const runContext = {
        seq: autoSelectRunSeq,
        signal: controller.signal
    };
    autoSelectAbortController = controller;
    autoSelectRunning = true;
    try {
        await loadSuppliers();
        assertAutoSelectActive(runContext, options);
        await loadNodes();
        assertAutoSelectActive(runContext, options);
        await ensureAutoSelectNetworkMode();
        assertAutoSelectActive(runContext, options);
        const candidates = autoSelectCandidates(options.fileName)
            .filter(nodePassesAutoSelectRules);
        if (!candidates.length) {
            if (!options.silent) showToast(`${autoSelectScopeName(autoSelectConfig.scope)}自动选择没有符合规则的候选节点`, 'warning');
            return;
        }
        if (!options.silent) showToast('正在重测候选节点延迟...', 'info', 1800);
        await testAutoSelectCandidateLatencies(candidates, runContext, options);
        assertAutoSelectActive(runContext, options);
        const ranked = autoSelectCandidates(options.fileName)
            .filter(n => n.latency > 0)
            .filter(nodePassesAutoSelectRules)
            .sort((a, b) => a.latency - b.latency);
        if (!ranked.length) {
            if (!options.silent) showToast(`${autoSelectScopeName(autoSelectConfig.scope)}自动选择未找到可用节点`, 'warning');
            return;
        }
        const best = await pickAutoSelectNodeWithSiteRules(ranked, runContext, options);
        assertAutoSelectActive(runContext, options);
        if (!best) {
            if (!options.silent) showToast('没有节点满足网站可用性规则', 'warning');
            return;
        }
        const active = allNodesList.find(n => n.active);
        if (active?.index === best.index) {
            if (!options.silent) showToast(`当前已是最佳节点 ${best.name} · ${best.latency} ms`, 'success');
            return;
        }
        showToast(`自动选择 ${best.name} · ${best.latency} ms`, 'success');
        await switchNodeAndWait(best.index, runContext, options);
    } catch(e) {
        if (e?.message !== 'auto_select_stopped') {
            throw e;
        }
    } finally {
        if (autoSelectAbortController === controller) {
            autoSelectAbortController = null;
        }
        const hasQueuedRun = !!autoSelectQueuedRun;
        autoSelectRunning = false;
        if (autoSelectConfig?.enabled || options.force) {
            drainAutoSelectQueuedRun();
        } else {
            autoSelectQueuedRun = null;
        }
        setAutoSelectNowButtonBusy(hasQueuedRun);
    }
}

async function ensureAutoSelectNetworkMode() {
    const mode = autoSelectConfig?.startupMode || 'none';
    if (mode === 'none') return;
    await loadStatus();
    const modeLabel = {
        proxy: '系统代理',
        tun: 'TUN',
        proxy_tun: '代理+TUN'
    }[mode] || '';
    if (modeLabel) showToast('自动选择已开启，正在切换到 ' + modeLabel, 'info', 1800);
    await activateProxyPreset(mode);
}

async function runAutoSelectNow() {
    if (!autoSelectConfig?.enabled) {
        showToast('请先开启自动选择节点', 'warning');
        return;
    }
    requestAutoSelectRestart({ silent: false, force: true });
}

function scheduleAutoSelectTimer() {
    if (autoSelectTimer) {
        clearInterval(autoSelectTimer);
        autoSelectTimer = null;
    }
    if (!autoSelectConfig?.enabled) return;
    const intervalMs = normalizeAutoSelectInterval(autoSelectConfig.intervalMinutes) * 60 * 1000;
    autoSelectTimer = setInterval(() => {
        runAutoSelectCycle({ silent: true });
    }, intervalMs);
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
        const targetNode = allNodesList.find(n => n.index === idx);
        const current = targetNode?.active ? '&current=1' : '';
        const res = await fetch('/api/speedtest?idx=' + idx + current, { method: 'POST' });
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
        if (targetNode) targetNode.speed = Number(data.speed) || 0;
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
    const queue = [...suppliersCache];
    const workerCount = Math.min(3, queue.length);
    async function worker() {
        while (queue.length) {
            const sub = queue.shift();
            try {
                const res = await fetch('/api/update_supplier?file=' + encodeURIComponent(sub.fileName), { method: 'POST' });
                const data = await res.json();
                if (data.ok) successCount++;
            } catch(e) {}
        }
    }
    await Promise.all(Array.from({ length: workerCount }, worker));

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

function formatInterval(minutes) {
    minutes = Number(minutes) || 0;
    if (minutes >= 1440 && minutes % 1440 === 0) return (minutes / 1440) + '天';
    if (minutes >= 60 && minutes % 60 === 0) return (minutes / 60) + '小时';
    return minutes + '分钟';
}

async function setSupplierInterval(encodedFile, currentMinutes, event) {
    if (event) event.stopPropagation();
    const file = decodeURIComponent(encodedFile);
    const input = prompt('设置该订阅的自动更新间隔（分钟，最低 15 分钟）', String(currentMinutes || 360));
    if (input === null) return;
    const minutes = Number(input);
    if (!Number.isFinite(minutes) || minutes <= 0) {
        showToast('请输入有效的分钟数', 'warning');
        return;
    }
    try {
        const res = await fetch('/api/set_supplier_update_interval?file=' + encodeURIComponent(file) + '&minutes=' + encodeURIComponent(Math.round(minutes)), { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast(data.msg || '自动更新间隔已保存', 'success');
            await loadSuppliers();
        } else {
            showToast(data.msg || '保存失败', 'error');
        }
    } catch(e) {
        showToast('保存自动更新间隔失败', 'error');
    }
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
    let copied = false;
    try {
        await copyText(supplier.url);
        copied = true;
    } catch(e) {}
    await showShareModal('订阅组：' + (supplier.name || file), supplier.url);
    showToast(copied ? '订阅链接已复制到剪贴板' : '已生成订阅二维码，复制链接失败', copied ? 'success' : 'warning');
}

async function createQRCodeURL(text) {
    const res = await fetch('/api/qrcode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
    });
    if (!res.ok) throw new Error('QR request failed');
    const blob = await res.blob();
    return URL.createObjectURL(blob);
}

function releaseShareQRCodeURL() {
    if (shareQRCodeURL) {
        URL.revokeObjectURL(shareQRCodeURL);
        shareQRCodeURL = "";
    }
}

async function showShareModal(title, text) {
    const modal = document.getElementById('shareModal');
    const titleEl = document.getElementById('shareModalTitle');
    const textEl = document.getElementById('shareText');
    const img = document.getElementById('shareQRCode');
    const status = document.getElementById('shareQRStatus');
    if (!modal || !textEl || !img) return;

    releaseShareQRCodeURL();
    if (titleEl) titleEl.textContent = title || '分享';
    textEl.value = text || '';
    img.removeAttribute('src');
    img.style.display = 'none';
    if (status) status.textContent = '正在生成二维码...';
    modal.style.display = 'flex';

    try {
        shareQRCodeURL = await createQRCodeURL(text);
        img.src = shareQRCodeURL;
        img.style.display = 'block';
        if (status) status.textContent = '扫码导入或复制链接分享。';
    } catch(e) {
        if (status) status.textContent = '二维码生成失败，链接仍可复制。';
    }
}

function closeShareModal() {
    const modal = document.getElementById('shareModal');
    if (modal) modal.style.display = 'none';
    releaseShareQRCodeURL();
}

async function copyShareModalText() {
    const text = document.getElementById('shareText')?.value || '';
    if (!text) return;
    try {
        await copyText(text);
        showToast('分享内容已复制', 'success');
    } catch(e) {
        showToast('复制分享内容失败', 'error');
    }
}

const helpTopics = {
    projectIntro: {
        title: '项目介绍',
        summary: 'wing 是 Flutter + Go 构建的跨平台代理客户端，核心目标是把节点选择、分流、TUN 和 DNS 管理收进一个轻量桌面入口。',
        body: `
            <h3>wing 是什么</h3>
            <ul>
                <li>wing 使用 Go 后端常驻本机，负责代理入口、节点存储、测速、规则分流、DNS、TUN 和系统托盘。</li>
                <li>桌面端使用 Flutter WebView 承载本机控制面板，启动后自动显示；首屏以居中的节点入口卡片作为默认操作入口。</li>
                <li>顶部灵动岛默认保持收缩，鼠标悬停后展开为纯图标导航，并会随直连、代理、TUN、代理+TUN 状态切换配色。</li>
                <li>移动端使用 Flutter WebView 访问本机、模拟器或局域网控制面板。</li>
                <li>控制面板默认只监听 127.0.0.1:10809，不对外网暴露。</li>
            </ul>
            <h3>核心能力</h3>
            <ul>
                <li>支持导入订阅、手动添加节点、订阅组、聚合组、免费流量和自动选择。</li>
                <li>支持系统代理、TUN 隧道、规则分流、命令行进程规则、DNS 分流、DNS 自动覆写和 WebRTC 防泄露。</li>
                <li>支持延迟测速、带宽测速和常用网站可用性测试。</li>
            </ul>
            <h3>技术栈</h3>
            <ul>
                <li>桌面与移动壳：Flutter。</li>
                <li>后端与托盘：Go、net/http、getlantern/systray。</li>
                <li>代理与隧道：sing-box、Mieru Client、Wintun 等项目内适配层。</li>
                <li>本地存储：bbolt 与 AES-GCM 安全存储封装。</li>
            </ul>
            <div class="help-topic-links">
                <a href="https://flutter.dev/multi-platform/desktop" target="_blank" rel="noopener">Flutter Desktop</a>
                <a href="https://go.dev/doc/" target="_blank" rel="noopener">Go 文档</a>
                <a href="https://sing-box.sagernet.org/" target="_blank" rel="noopener">sing-box 文档</a>
                <a href="https://github.com/enfein/mieru" target="_blank" rel="noopener">Mieru 项目</a>
            </div>
        `
    },
    quickStart: {
        title: '快速开始',
        summary: '从导入节点到验证可用性，按这个顺序走可以最快确认软件是否工作正常。',
        body: `
            <h3>推荐流程</h3>
            <ol>
                <li>点击顶部“导入订阅”，粘贴订阅链接、单节点链接或配置内容。</li>
                <li>在“节点管理”中打开订阅组或聚合组，点击节点卡片或表格中的“选择”。</li>
                <li>普通浏览器和多数桌面软件可先开启“代理服务”；游戏、命令行、部分不认系统代理的软件建议开启 TUN。</li>
                <li>先用“极速测速”确认延迟，再用“测试网站”确认目标服务能否访问。</li>
            </ol>
            <h3>注意</h3>
            <ul>
                <li>系统代理只影响遵循系统代理的软件，TUN 才会接管更多流量。</li>
                <li>如果订阅刚导入后列表为空，优先检查订阅地址能否正常访问。</li>
            </ul>
            <div class="help-topic-links">
                <a href="https://support.microsoft.com/windows/use-a-proxy-server-in-windows-03096c53-0554-4ffe-b6ab-8b1deee8dae1" target="_blank" rel="noopener">Windows 代理设置</a>
                <a href="https://sing-box.sagernet.org/configuration/inbound/tun/" target="_blank" rel="noopener">sing-box TUN 文档</a>
            </div>
        `
    },
    autoSelect: {
        title: '自动选择',
        summary: '自动选择会从指定候选范围里重测延迟，再按规则和网站可用性挑出当前最佳节点。',
        body: `
            <h3>候选范围</h3>
            <ul>
                <li>“全部节点”会从当前所有订阅组和聚合组中选择。</li>
                <li>“指定订阅组”只从勾选的订阅组里选择。</li>
                <li>“指定聚合组”只从勾选的聚合组里选择。</li>
            </ul>
            <h3>立即选择和删除候选</h3>
            <ul>
                <li>点击“立即选择”时，如果上一轮还没结束，软件不会显示排队提示；上一轮结束后会马上重新选择。</li>
                <li>关闭自动选择开关会中止当前选择任务和后续网站检查。</li>
                <li>自动节点列表里的“删除”只会把该节点从自动选择候选中排除，不会删除订阅组或聚合组里的原节点。</li>
            </ul>
            <h3>网站验证</h3>
            <ul>
                <li>网站可用性验证会临时切换候选节点，确认目标网站能访问后再确定最终节点。</li>
                <li>如果开启“忽略超时节点”，延迟为 Timeout 的节点不会进入候选排序。</li>
            </ul>
        `
    },
    leakProtection: {
        title: '防止 DNS / IP 泄露',
        summary: '泄露通常来自不走系统代理的软件、DNS 没被接管、IPv6 路径绕过或浏览器 WebRTC。',
        body: `
            <h3>系统代理与 TUN</h3>
            <ul>
                <li>系统代理只对遵循系统代理的软件生效。</li>
                <li>TUN 会创建虚拟网卡并接管路由，适合游戏、命令行工具和不支持系统代理的软件。</li>
                <li>TUN 开启后，DNS 查询会通过本地 DNS 入口处理。</li>
            </ul>
            <h3>DNS 自动覆写和 IPv6</h3>
            <ul>
                <li>DNS 自动覆写会把物理网卡 DNS 指向 127.0.0.2，退出时会尝试恢复。</li>
                <li>TUN 模式开启时会跳过物理网卡 DNS 自动覆写，由 TUN/DNS 接管。</li>
                <li>IPv6 开关开启后，节点域名解析和 TUN DNS 会优先使用 IPv6；关闭时限制为 IPv4，减少 IPv6 绕路风险。</li>
            </ul>
            <h3>WebRTC</h3>
            <ul>
                <li>WebRTC 防泄露会写入 Chrome / Edge 策略，减少浏览器通过实时通信接口暴露真实地址。</li>
                <li>策略写入后建议重启浏览器，或打开 chrome://policy / edge://policy 刷新策略。</li>
            </ul>
            <div class="help-topic-links">
                <a href="https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Connectivity" target="_blank" rel="noopener">MDN WebRTC 连接</a>
                <a href="https://chromeenterprise.google/policies/#WebRtcIPHandling" target="_blank" rel="noopener">Chrome WebRTC 策略</a>
                <a href="https://sing-box.sagernet.org/configuration/inbound/tun/" target="_blank" rel="noopener">TUN 入站说明</a>
            </div>
        `
    },
    dnsRules: {
        title: 'DNS 规则怎么用',
        summary: 'DNS 规则只决定域名交给哪台 DNS 服务器解析；真正走代理、直连或拦截，仍由规则分流决定。',
        body: `
            <h3>匹配方式</h3>
            <ul>
                <li>完整域名：只匹配单个域名，例如 www.example.com。</li>
                <li>域名后缀：匹配整个站点或区域，例如 cn 可匹配 .cn 域名。</li>
                <li>域名关键字：匹配包含该关键字的域名，例如 baidu 或 alicdn。</li>
            </ul>
            <h3>匹配顺序</h3>
            <ul>
                <li>DNS 查询会从上到下匹配 DNS 分流规则。</li>
                <li>没有命中任何规则时，使用“默认服务器”。</li>
                <li>DNS 服务器建议写成 IP:端口，例如 8.8.8.8:53 或 223.5.5.5:53。</li>
            </ul>
            <h3>常见配置</h3>
            <ul>
                <li>国内域名后缀 cn 可用 Aliyun 或 Tencent DNS。</li>
                <li>baidu、alicdn 等关键字可以分配给国内 DNS。</li>
                <li>默认服务器可选 Google、Cloudflare、Quad9 等公共 DNS。</li>
                <li>DNS 自动覆写开启后会把物理网卡 DNS 指向本程序本地 DNS 服务；TUN 开启时会跳过该物理网卡覆写。</li>
            </ul>
            <div class="help-topic-links">
                <a href="https://www.cloudflare.com/learning/dns/what-is-dns/" target="_blank" rel="noopener">Cloudflare DNS 介绍</a>
                <a href="https://developers.google.com/speed/public-dns/docs/using" target="_blank" rel="noopener">Google Public DNS</a>
                <a href="https://www.quad9.net/service/service-addresses-and-features/" target="_blank" rel="noopener">Quad9 服务地址</a>
            </div>
        `
    },
    privacy: {
        title: '隐私与本地数据',
        summary: '控制面板监听本机地址，节点和订阅会加密保存；订阅拉取、测速和网站测试会产生必要网络请求。',
        body: `
            <h3>本地数据</h3>
            <ul>
                <li>控制面板仅监听本机地址，不对局域网开放。</li>
                <li>节点配置和订阅链接使用本机派生密钥做 AES-GCM 加密存储。</li>
                <li>DNS 规则、路由规则和使用统计属于本机配置数据，不会主动上传。</li>
            </ul>
            <h3>必要网络请求</h3>
            <ul>
                <li>导入或更新订阅时，会访问对应订阅地址。</li>
                <li>延迟测速、带宽测速、网站测试会访问测试目标，这是功能必需行为。</li>
                <li>订阅服务商能看到订阅拉取请求；目标网站能看到通过当前出口访问的请求。</li>
            </ul>
            <div class="help-topic-links">
                <a href="https://pkg.go.dev/crypto/cipher#NewGCM" target="_blank" rel="noopener">AES-GCM 说明</a>
                <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener">OWASP Top 10</a>
            </div>
        `
    },
    troubleshooting: {
        title: '常见排查',
        summary: '优先确认软件是否走系统代理、DNS 是否按预期解析、浏览器策略是否生效。',
        body: `
            <h3>软件不走代理</h3>
            <ul>
                <li>网页正常但某个软件不走代理时，先确认该软件是否支持系统代理。</li>
                <li>不支持系统代理的软件，建议开启 TUN。</li>
            </ul>
            <h3>DNS 结果异常</h3>
            <ul>
                <li>打开“DNS 规则管理”，确认默认服务器和分流规则。</li>
                <li>如果刚关闭程序后 DNS 仍异常，可以手动检查系统网卡 DNS 是否恢复。</li>
            </ul>
            <h3>托盘或桌面窗口</h3>
            <ul>
                <li>托盘点击无响应时，确认 wing_ui.exe 已随主程序一起构建，并放在同目录或 flutter_ui 子目录。</li>
                <li>桌面端首次打开慢，通常是 Flutter UI 进程启动和 WebView 初始化；后续托盘点击会复用已启动窗口。</li>
            </ul>
        `
    },
    security: {
        title: '安全建议',
        summary: '订阅和节点本身就是敏感信息，日常使用里要控制来源、分享范围和公共网络风险。',
        body: `
            <h3>订阅来源</h3>
            <ul>
                <li>不要导入来源不明的订阅链接。</li>
                <li>订阅服务商能看到订阅拉取请求，订阅地址也可能包含你的身份标识。</li>
            </ul>
            <h3>公共网络</h3>
            <ul>
                <li>公共 Wi-Fi 下优先开启 TUN 和 WebRTC 防泄露。</li>
                <li>如果本机网络支持 IPv6，但代理出口不稳定，可以关闭 IPv6 开关减少绕路。</li>
            </ul>
            <h3>分享节点</h3>
            <ul>
                <li>只分享必要节点，不要把完整订阅链接发给他人。</li>
                <li>定期删除不用的节点和订阅，减少本机保存的敏感配置。</li>
            </ul>
        `
    }
};

function openHelpTopicByKey(event, topicId) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    openHelpTopic(topicId);
}

function openHelpTopic(topicId) {
    const topic = helpTopics[topicId];
    if (!topic) return;
    document.getElementById('helpTopicTitle').textContent = topic.title;
    document.getElementById('helpTopicSummary').textContent = topic.summary;
    document.getElementById('helpTopicBody').innerHTML = topic.body;
    document.getElementById('helpTopicModal').style.display = 'flex';
}

function closeHelpTopic() {
    document.getElementById('helpTopicModal').style.display = 'none';
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
        const node = allNodesList.find(n => n.index === idx);
        let copied = false;
        try {
            await copyText(data.link);
            copied = true;
        } catch(e) {}
        await showShareModal('节点：' + (node?.name || ('节点 ' + idx)), data.link);
        showToast(copied ? '节点链接已复制到剪贴板' : '已生成节点二维码，复制链接失败', copied ? 'success' : 'warning');
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
    jsQRLoader = Promise.reject(new Error('二维码识别库未内置，已阻止从外部 CDN 加载脚本'));
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

function updateSearchRuleType(gIdx, rIdx, type) {
    const group = ruleGroups[gIdx];
    if (!group || !group.rules || !group.rules[rIdx]) return;
    group.rules[rIdx].type = type;
    renderRules();
    showToast('规则类型已更新，保存后生效', 'success', 1200);
}

function updateSearchRuleValue(gIdx, rIdx, value) {
    const group = ruleGroups[gIdx];
    if (!group || !group.rules || !group.rules[rIdx]) return;
    group.rules[rIdx].value = value.trim();
    renderRules();
    showToast('规则已更新，保存后生效', 'success', 1200);
}

function ruleEditControls(gIdx, rIdx, r, options = {}) {
    const typeHandler = options.search ? 'updateSearchRuleType' : 'updateRuleType';
    const valueHandler = options.search ? 'updateSearchRuleValue' : 'updateRuleValue';
    return `
        <select onchange="${typeHandler}(${gIdx}, ${rIdx}, this.value)" style="min-width:112px;padding:5px 8px;border-radius:8px;font-size:12px;margin-right:8px;">
            ${ruleTypeOptions(r.type)}
        </select>
        <input type="text" value="${escapeAttr(r.value)}" onblur="${valueHandler}(${gIdx}, ${rIdx}, this.value)" onkeydown="if(event.key==='Enter') this.blur()" style="min-width:220px;max-width:420px;width:38vw;background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.18);color:white;padding:6px 9px;border-radius:8px;outline:none;font-size:13px;">
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
    scheduleCustomSelectSync();
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
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setIndividualRuleAction(${idx}, ${jsArg(subGroup.subName)})">
                            <span style="color:var(--accent);font-size:14px;">🗂️</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--accent)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(subGroup.subName)}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[订阅组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--accent);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleRuleSelectorGroupExpand(${idx}, ${jsArg(groupKey)}, event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
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
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${escapeAttr(node.Name)}">${escapeHTML(node.Name)}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${escapeHTML(String(node.Type || '').toUpperCase())}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setIndividualRuleAction(${idx}, ${jsArg(node.Name)})" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
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
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setIndividualRuleAction(${idx}, ${jsArg(aggGroup.name)})">
                            <span style="color:var(--success);font-size:14px;">📁</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--success)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(aggGroup.name)}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[聚合组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--success);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleRuleSelectorGroupExpand(${idx}, ${jsArg(groupKey)}, event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
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
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${escapeAttr(node.Name)}">${escapeHTML(node.Name)}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${escapeHTML(String(node.Type || '').toUpperCase())}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setIndividualRuleAction(${idx}, ${jsArg(node.Name)})" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
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
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, ${jsArg(subGroup.subName)})">
                            <span style="color:var(--accent);font-size:14px;">🗂️</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--accent)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(subGroup.subName)}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[订阅组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--accent);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleSearchRuleSelectorGroupExpand(${gIdx}, ${rIdx}, ${jsArg(groupKey)}, event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
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
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${escapeAttr(node.Name)}">${escapeHTML(node.Name)}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${escapeHTML(String(node.Type || '').toUpperCase())}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setSearchRuleAction(${gIdx}, ${rIdx}, ${jsArg(node.Name)})" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
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
                        <div style="display:flex;align-items:center;gap:6px;cursor:pointer;flex:1;min-width:0;" onclick="setSearchRuleAction(${gIdx}, ${rIdx}, ${jsArg(aggGroup.name)})">
                            <span style="color:var(--success);font-size:14px;">📁</span>
                            <span style="font-size:13px;font-weight:${isGroupSelected ? 'bold' : 'normal'};color:${isGroupSelected ? 'var(--success)' : 'white'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(aggGroup.name)}</span>
                            <span style="font-size:11px;color:var(--text-dim);">[聚合组]</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            ${isGroupSelected ? '<span style="color:var(--success);font-size:11px;font-weight:bold;">已选此组</span>' : ''}
                            <button onclick="toggleSearchRuleSelectorGroupExpand(${gIdx}, ${rIdx}, ${jsArg(groupKey)}, event)" style="background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.15);color:var(--text-sub);padding:2px 8px;border-radius:6px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;user-select:none;">
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
                            <td style="padding:6px 8px;color:${isNodeSelected ? 'var(--accent)' : 'var(--text)'};font-weight:${isNodeSelected ? 'bold' : 'normal'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;" title="${escapeAttr(node.Name)}">${escapeHTML(node.Name)}</td>
                            <td style="padding:6px 8px;color:var(--text-sub);">${escapeHTML(String(node.Type || '').toUpperCase())}</td>
                            <td style="padding:6px 8px;text-align:right;">
                                <button onclick="setSearchRuleAction(${gIdx}, ${rIdx}, ${jsArg(node.Name)})" style="background:${isNodeSelected ? 'var(--accent)' : 'rgba(255,255,255,0.05)'};color:${isNodeSelected ? 'white' : 'var(--text-sub)'};border:1px solid ${isNodeSelected ? 'var(--accent)' : 'rgba(148,163,184,0.15)'};padding:2px 6px;border-radius:4px;font-size:11px;cursor:pointer;">
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
    renderRuleGroupTags();
    renderRules();
}

function isSniffedRuleGroup(group) {
    return group?.id === 'direct_sniff' || group?.name === '嗅探到规则';
}

function sniffedRuleGroupIndex() {
    return ruleGroups.findIndex(isSniffedRuleGroup);
}

function renderRuleGroupTags() {
    const wrap = document.getElementById('ruleGroupTags');
    if (!wrap) return;
    const sniffIdx = sniffedRuleGroupIndex();
    if (sniffIdx < 0) {
        wrap.innerHTML = '';
        return;
    }
    const group = ruleGroups[sniffIdx];
    const count = group?.rules?.length || 0;
    wrap.innerHTML = `
        <button type="button" class="rule-group-tag ${currentRuleGroupIndex === sniffIdx ? 'active' : ''}" onclick="selectRuleGroup(${sniffIdx})">
            嗅探到规则 <span>${count}</span>
        </button>
    `;
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
                                ${ruleEditControls(gIdx, rIdx, r, { search: true })}
                                <span class="rule-action-badge" style="color:${actionColor};font-weight:bold;margin-left:8px;font-size:12px;cursor:pointer;border:1px solid ${actionColor}33;padding:2px 8px;border-radius:10px;background:${actionColor}11;display:inline-flex;align-items:center;gap:4px;user-select:none;transition:all 0.2s;" onclick="toggleSearchRuleActionSelector(${gIdx}, ${rIdx}, event)">
                                    ${actionName(effectiveAction)} ▾
                                </span>
                            </div>
                            <button class="btn-ghost" style="padding:4px 8px;font-size:12px;border-color:rgba(239,68,68,0.3);color:var(--danger);" onclick="deleteSearchRule(${gIdx}, ${rIdx})">删除</button>
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
    scheduleCustomSelectSync();
}

function cmdRuleTypeName(type) {
    return type === 'exact' ? '完整命令' : '命令前缀';
}

function renderCmdRules() {
    const list = document.getElementById('cmdRuleList');
    if (!list) return;
    if (!cmdRules || cmdRules.length === 0) {
        list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:14px;">暂无命令行规则</div>';
        scheduleCustomSelectSync();
        return;
    }
    list.innerHTML = cmdRules.map((rule, idx) => {
        return `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 2px;border-bottom:1px solid rgba(148,163,184,0.1);font-size:13px;">
                <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;flex-wrap:wrap;">
                    <select onchange="updateCmdRule(${idx}, 'type', this.value)" style="min-width:110px;padding:5px 8px;border-radius:8px;font-size:12px;">
                        <option value="prefix" ${(rule.type || 'prefix') === 'prefix' ? 'selected' : ''}>命令前缀</option>
                        <option value="exact" ${rule.type === 'exact' ? 'selected' : ''}>完整命令</option>
                    </select>
                    <input type="text" value="${escapeAttr(rule.pattern)}" onblur="updateCmdRule(${idx}, 'pattern', this.value)" onkeydown="if(event.key==='Enter') this.blur()" style="min-width:260px;max-width:430px;width:36vw;background:rgba(255,255,255,0.05);border:1px solid rgba(148,163,184,0.18);color:white;padding:6px 9px;border-radius:8px;outline:none;font-size:13px;">
                    <select onchange="updateCmdRule(${idx}, 'action', this.value)" style="min-width:90px;padding:5px 8px;border-radius:8px;font-size:12px;">
                        <option value="direct" ${(rule.action || 'direct') === 'direct' ? 'selected' : ''}>直连</option>
                        <option value="proxy" ${rule.action === 'proxy' ? 'selected' : ''}>代理</option>
                    </select>
                </div>
                <button class="btn-ghost" style="padding:4px 8px;font-size:12px;border-color:rgba(239,68,68,0.3);color:var(--danger);" onclick="deleteCmdRule(${idx})">删除</button>
            </div>
        `;
    }).join('');
    scheduleCustomSelectSync();
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

function updateCmdRule(idx, field, value) {
    if (!cmdRules || idx < 0 || idx >= cmdRules.length) return;
    if (field === 'pattern') cmdRules[idx].pattern = value.trim();
    if (field === 'type') cmdRules[idx].type = value === 'exact' ? 'exact' : 'prefix';
    if (field === 'action') cmdRules[idx].action = value === 'proxy' ? 'proxy' : 'direct';
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
    showToast('规则已删除，保存后生效', 'success', 1800);
}

function deleteSearchRule(gIdx, rIdx) {
    const group = ruleGroups[gIdx];
    if (!group || !group.rules || rIdx < 0 || rIdx >= group.rules.length) return;
    group.rules.splice(rIdx, 1);
    renderRuleGroups();
    showToast('搜索结果中的规则已删除，保存后生效', 'success', 1800);
}

async function saveRules() {
    syncRuleGroupForm();
    try {
        const res = await fetch('/api/rules/apply', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ruleGroups, cmdRules })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) throw new Error(data.msg || 'save failed');
        ruleGroups = data.ruleGroups || ruleGroups;
        cmdRules = data.cmdRules || cmdRules;
        renderRuleGroups();
        renderCmdRules();
        showToast(data.msg || '规则保存并应用成功', 'success');
        closeRuleModal();
        setTimeout(loadStatus, 250);
    } catch(e) {
        showToast(e.message || '保存失败', 'error');
    }
}

async function resetRulesToDefault() {
    if (!confirm('确定恢复默认规则组吗？当前规则分流组会被默认规则覆盖，命令行进程规则不会变更。')) return;
    try {
        const res = await fetch('/api/rules/reset_default', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
            throw new Error(data.msg || 'reset failed');
        }
        ruleGroups = data.groups || [];
        currentRuleGroupIndex = 0;
        const searchEl = document.getElementById('ruleSearch');
        if (searchEl) searchEl.value = '';
        renderRuleGroups();
        showToast('规则组已恢复默认', 'success');
    } catch(e) {
        showToast('恢复默认规则失败', 'error');
    }
}

async function sniffDirectDomains(button) {
    const oldHTML = button?.innerHTML;
    if (button) {
        button.disabled = true;
        button.textContent = '嗅探中...';
    }
    try {
        const res = await fetch('/api/sniff_direct_domains', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
            throw new Error(data.msg || '嗅探失败');
        }
        if (Array.isArray(data.groups)) {
            ruleGroups = data.groups;
            const sniffIdx = sniffedRuleGroupIndex();
            if (sniffIdx >= 0) {
                currentRuleGroupIndex = sniffIdx;
                const searchEl = document.getElementById('ruleSearch');
                if (searchEl) searchEl.value = '';
            }
            renderRuleGroups();
        } else {
            await openRuleModal();
        }
        const added = Array.isArray(data.added) ? data.added : [];
        showToast(added.length ? `已添加 ${added.length} 条直连规则` : '未发现需要新增的直连规则', added.length ? 'success' : 'info');
    } catch(e) {
        showToast(e.message || '嗅探直连域名失败', 'error');
    } finally {
        if (button) {
            button.disabled = false;
            button.innerHTML = oldHTML || '嗅探直连';
        }
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
                <span style="font-size:13px;"><strong>${escapeHTML(s.name)}</strong> (${escapeHTML(s.address)})</span>
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
                <span style="font-size:13px;"><span style="background:rgba(255,255,255,0.05); padding:2px 4px; border-radius:4px; font-size:11px; margin-right:6px;">${escapeHTML(typeName(r.type))}</span> ${escapeHTML(r.value)} -> <strong>${escapeHTML(server ? server.name : 'Unknown')}</strong></span>
                <button class="btn-ghost" style="padding:2px 6px; font-size:11px; color:var(--danger);" onclick="deleteDNSRule(${idx})">删除</button>
            </div>
        `;
    });
    scheduleCustomSelectSync();
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
    scheduleCustomSelectSync();

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

window.onload = async () => {
    initDesktopWheelDamping();
    initIslandBehavior();
    initCustomSelects();
    showSettingsSubtab(currentSettingsSubtab);
    checkAppUpdate({ silent: true });
    await loadSystemConfig();
    await loadAutoSelectConfig();
    await loadStatus();
    await loadSuppliers();
    await loadNodes();
    await ensureSiteTargetsLoaded();
    renderAutoSelectConfig();
    scheduleCustomSelectSync();
    scheduleAutoSelectTimer();

    showTab('nodes', { expand: false });
    collapseBottomTabs();

    pollTimer = setInterval(() => {
        if (document.hidden) return;
        loadStatus();
        if (activeTab === 'dashboard' && Date.now() - lastDashboardPoll > dashboardPollIntervalMs) {
            lastDashboardPoll = Date.now();
            loadDashboard();
        }
        if (activeTab === 'nodes' && allNodesList && allNodesList.length > 0) {
            const activeNode = allNodesList.find(n => n.active);
            if (activeNode) {
                renderSupplierTraffic(activeNode.fileName);
            }
        }
    }, statusPollIntervalMs);
};
