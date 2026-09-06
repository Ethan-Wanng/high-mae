import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

const _nativeChannel = MethodChannel('com.highmae.wing/vpn');
const _apiBase = 'http://127.0.0.1:10809';

class AndroidBackendState {
  const AndroidBackendState({
    required this.ready,
    required this.token,
    this.error,
    this.abi,
  });

  final bool ready;
  final String token;
  final String? error;
  final String? abi;

  factory AndroidBackendState.fromPlatform(Object? value) {
    final map = Map<Object?, Object?>.from(value as Map? ?? const {});
    return AndroidBackendState(
      ready: map['ready'] == true,
      token: map['token']?.toString() ?? '',
      error: map['error']?.toString(),
      abi: map['abi']?.toString(),
    );
  }
}

class AndroidBackendLauncher {
  static Future<AndroidBackendState> start() async {
    try {
      final value = await _nativeChannel.invokeMethod<Object?>('startBackend');
      return AndroidBackendState.fromPlatform(value);
    } catch (error) {
      return AndroidBackendState(
        ready: false,
        token: '',
        error: '无法启动内置代理核心：$error',
      );
    }
  }
}

abstract class WingApi {
  Future<Map<String, dynamic>> getStatus();
  Future<List<Map<String, dynamic>>> getNodes();
  Future<List<Map<String, dynamic>>> getSuppliers();
  Future<Map<String, dynamic>> getStats();
  Future<Map<String, dynamic>> getDns();
  Future<List<Map<String, dynamic>>> getRules();
  Future<Map<String, dynamic>> switchNode(int index);
  Future<int> testNode(int index);
  Future<void> testAllNodes();
  Future<Map<String, dynamic>> importSubscription(String input);
  Future<Map<String, dynamic>> updateSupplier(String fileName);
  Future<Map<String, dynamic>> deleteSupplier(String fileName);
  Future<Map<String, dynamic>> setGlobalMode(bool global);
  Future<Map<String, dynamic>> testSites();
}

class LocalWingApi implements WingApi {
  LocalWingApi(this.token);

  final String token;

  Future<Object?> _request(
    String path, {
    String method = 'GET',
    Object? body,
    Duration timeout = const Duration(seconds: 20),
  }) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
    try {
      final uri = Uri.parse('$_apiBase$path');
      final request = await client.openUrl(method, uri);
      request.headers.set('X-Wing-Mobile-Token', token);
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (body != null) {
        request.headers.contentType = ContentType.json;
        request.write(jsonEncode(body));
      }
      final response = await request.close().timeout(timeout);
      final text = await utf8.decoder.bind(response).join();
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw WingApiException(
          text.trim().isEmpty ? '请求失败 (${response.statusCode})' : text.trim(),
        );
      }
      if (text.trim().isEmpty) return null;
      return jsonDecode(text);
    } on TimeoutException {
      throw const WingApiException('操作超时，请检查当前网络或节点');
    } on SocketException {
      throw const WingApiException('内置代理核心未响应');
    } finally {
      client.close(force: true);
    }
  }

  Map<String, dynamic> _map(Object? value) =>
      Map<String, dynamic>.from(value as Map? ?? const {});

  List<Map<String, dynamic>> _list(Object? value) =>
      (value as List? ?? const [])
          .map((item) => Map<String, dynamic>.from(item as Map))
          .toList(growable: false);

  @override
  Future<Map<String, dynamic>> getStatus() async =>
      _map(await _request('/api/status'));

  @override
  Future<List<Map<String, dynamic>>> getNodes() async =>
      _list(await _request('/api/nodes'));

  @override
  Future<List<Map<String, dynamic>>> getSuppliers() async =>
      _list(await _request('/api/suppliers'));

  @override
  Future<Map<String, dynamic>> getStats() async =>
      _map(await _request('/api/stats'));

  @override
  Future<Map<String, dynamic>> getDns() async =>
      _map(await _request('/api/dns'));

  @override
  Future<List<Map<String, dynamic>>> getRules() async =>
      _list(await _request('/api/rules'));

  @override
  Future<Map<String, dynamic>> switchNode(int index) async =>
      _map(await _request('/api/switch?idx=$index', method: 'POST'));

  @override
  Future<int> testNode(int index) async {
    final data = _map(
      await _request(
        '/api/test_single?idx=$index',
        method: 'POST',
        timeout: const Duration(seconds: 15),
      ),
    );
    return (data['latency'] as num?)?.toInt() ?? -1;
  }

  @override
  Future<void> testAllNodes() async {
    await _request(
      '/api/test_all',
      method: 'POST',
      timeout: const Duration(minutes: 2),
    );
  }

  @override
  Future<Map<String, dynamic>> importSubscription(String input) async => _map(
    await _request(
      '/api/import_subscription',
      method: 'POST',
      body: {'input': input},
      timeout: const Duration(minutes: 1),
    ),
  );

  @override
  Future<Map<String, dynamic>> updateSupplier(String fileName) async => _map(
    await _request(
      '/api/update_supplier?file=${Uri.encodeQueryComponent(fileName)}',
      method: 'POST',
      timeout: const Duration(minutes: 1),
    ),
  );

  @override
  Future<Map<String, dynamic>> deleteSupplier(String fileName) async => _map(
    await _request(
      '/api/delete_supplier?file=${Uri.encodeQueryComponent(fileName)}',
      method: 'POST',
    ),
  );

  @override
  Future<Map<String, dynamic>> setGlobalMode(bool global) async => _map(
    await _request('/api/action?type=mode&enable=$global', method: 'POST'),
  );

  @override
  Future<Map<String, dynamic>> testSites() async => _map(
    await _request(
      '/api/site_test',
      method: 'POST',
      timeout: const Duration(minutes: 2),
    ),
  );
}

class WingApiException implements Exception {
  const WingApiException(this.message);
  final String message;

  @override
  String toString() => message;
}

class WingAndroidBootstrap extends StatefulWidget {
  const WingAndroidBootstrap({super.key});

  @override
  State<WingAndroidBootstrap> createState() => _WingAndroidBootstrapState();
}

class _WingAndroidBootstrapState extends State<WingAndroidBootstrap> {
  late Future<AndroidBackendState> _launch;

  @override
  void initState() {
    super.initState();
    _launch = AndroidBackendLauncher.start();
  }

  void _retry() => setState(() => _launch = AndroidBackendLauncher.start());

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'wing',
      debugShowCheckedModeBanner: false,
      theme: _androidTheme(),
      home: FutureBuilder<AndroidBackendState>(
        future: _launch,
        builder: (context, snapshot) {
          if (!snapshot.hasData) {
            return const _BackendLoadingPage();
          }
          final backend = snapshot.data!;
          if (!backend.ready || backend.token.isEmpty) {
            return _BackendErrorPage(backend: backend, onRetry: _retry);
          }
          return WingAndroidHome(
            api: LocalWingApi(backend.token),
            backend: backend,
          );
        },
      ),
    );
  }
}

class WingAndroidApp extends StatelessWidget {
  const WingAndroidApp({
    super.key,
    required this.api,
    this.backend = const AndroidBackendState(ready: true, token: 'test'),
  });

  final WingApi api;
  final AndroidBackendState backend;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'wing',
      debugShowCheckedModeBanner: false,
      theme: _androidTheme(),
      home: WingAndroidHome(api: api, backend: backend),
    );
  }
}

ThemeData _androidTheme() {
  const seed = Color(0xFF27C7AE);
  final scheme = ColorScheme.fromSeed(
    seedColor: seed,
    brightness: Brightness.dark,
    surface: const Color(0xFF111820),
  );
  return ThemeData(
    colorScheme: scheme,
    scaffoldBackgroundColor: const Color(0xFF0B1118),
    useMaterial3: true,
    cardTheme: const CardThemeData(
      elevation: 0,
      color: Color(0xFF141E28),
      margin: EdgeInsets.zero,
    ),
    inputDecorationTheme: const InputDecorationTheme(
      filled: true,
      fillColor: Color(0xFF141E28),
      border: OutlineInputBorder(borderSide: BorderSide.none),
    ),
  );
}

class _BackendLoadingPage extends StatelessWidget {
  const _BackendLoadingPage();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            _WingMark(size: 72),
            SizedBox(height: 28),
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('正在启动内置代理核心'),
          ],
        ),
      ),
    );
  }
}

class _BackendErrorPage extends StatelessWidget {
  const _BackendErrorPage({required this.backend, required this.onRetry});

  final AndroidBackendState backend;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.error_outline_rounded,
                  size: 64,
                  color: Theme.of(context).colorScheme.error,
                ),
                const SizedBox(height: 18),
                Text(
                  '代理核心启动失败',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 12),
                Text(
                  backend.error ?? '未知错误',
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white70),
                ),
                if (backend.abi != null) ...[
                  const SizedBox(height: 8),
                  Text(
                    '设备架构：${backend.abi}',
                    style: const TextStyle(color: Colors.white54),
                  ),
                ],
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: onRetry,
                  icon: const Icon(Icons.refresh_rounded),
                  label: const Text('重新启动'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class WingAndroidHome extends StatefulWidget {
  const WingAndroidHome({super.key, required this.api, required this.backend});

  final WingApi api;
  final AndroidBackendState backend;

  @override
  State<WingAndroidHome> createState() => _WingAndroidHomeState();
}

class _WingAndroidHomeState extends State<WingAndroidHome> {
  int _tab = 0;
  Map<String, dynamic> _status = const {};
  Map<String, dynamic> _stats = const {};
  bool _vpnRunning = false;
  bool _busy = false;
  String? _error;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _refreshStatus();
    _timer = Timer.periodic(
      const Duration(seconds: 2),
      (_) => _refreshStatus(),
    );
  }

  Future<void> _refreshStatus() async {
    try {
      final values = await Future.wait<Object?>([
        widget.api.getStatus(),
        widget.api.getStats(),
        _nativeChannel.invokeMethod<bool>('getVpnStatus'),
      ]);
      if (!mounted) return;
      setState(() {
        _status = Map<String, dynamic>.from(values[0] as Map);
        _stats = Map<String, dynamic>.from(values[1] as Map);
        _vpnRunning = values[2] == true;
        _error = null;
      });
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    }
  }

  Future<void> _toggleVpn() async {
    if (_busy) return;
    if (!_vpnRunning &&
        (_status['activeNodeName']?.toString().isEmpty ?? true)) {
      _message('请先在“节点”中选择一个节点');
      setState(() => _tab = 1);
      return;
    }
    setState(() => _busy = true);
    try {
      final allowed = await _nativeChannel.invokeMethod<bool>(
        _vpnRunning ? 'stopVpn' : 'startVpn',
      );
      if (allowed != true) {
        _message('需要允许系统 VPN 请求才能建立连接');
      }
      await Future<void>.delayed(const Duration(milliseconds: 450));
      await _refreshStatus();
    } catch (error) {
      _message('VPN 操作失败：$error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _message(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    final pages = [
      _OverviewPage(
        status: _status,
        stats: _stats,
        vpnRunning: _vpnRunning,
        busy: _busy,
        error: _error,
        onToggleVpn: _toggleVpn,
        onRefresh: _refreshStatus,
        onModeChanged: (global) async {
          await widget.api.setGlobalMode(global);
          await _refreshStatus();
        },
      ),
      _NodesPage(api: widget.api, onChanged: _refreshStatus),
      _SubscriptionsPage(api: widget.api, onChanged: _refreshStatus),
      _ToolsPage(api: widget.api, abi: widget.backend.abi),
    ];

    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [_WingMark(size: 30), SizedBox(width: 10), Text('wing')],
        ),
        actions: [
          IconButton(
            tooltip: '刷新',
            onPressed: _refreshStatus,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
      ),
      body: IndexedStack(index: _tab, children: pages),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (value) => setState(() => _tab = value),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: '连接',
          ),
          NavigationDestination(
            icon: Icon(Icons.hub_outlined),
            selectedIcon: Icon(Icons.hub),
            label: '节点',
          ),
          NavigationDestination(
            icon: Icon(Icons.cloud_download_outlined),
            selectedIcon: Icon(Icons.cloud_download),
            label: '订阅',
          ),
          NavigationDestination(
            icon: Icon(Icons.tune_outlined),
            selectedIcon: Icon(Icons.tune),
            label: '工具',
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }
}

class _OverviewPage extends StatelessWidget {
  const _OverviewPage({
    required this.status,
    required this.stats,
    required this.vpnRunning,
    required this.busy,
    required this.error,
    required this.onToggleVpn,
    required this.onRefresh,
    required this.onModeChanged,
  });

  final Map<String, dynamic> status;
  final Map<String, dynamic> stats;
  final bool vpnRunning;
  final bool busy;
  final String? error;
  final VoidCallback onToggleVpn;
  final Future<void> Function() onRefresh;
  final ValueChanged<bool> onModeChanged;

  @override
  Widget build(BuildContext context) {
    final activeName = status['activeNodeName']?.toString();
    final global = status['mode'] == 'Global';
    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.fromLTRB(18, 12, 18, 28),
        children: [
          const SizedBox(height: 18),
          Center(
            child: Semantics(
              button: true,
              label: vpnRunning ? '断开 VPN' : '连接 VPN',
              child: InkWell(
                borderRadius: BorderRadius.circular(88),
                onTap: busy ? null : onToggleVpn,
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  width: 172,
                  height: 172,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color:
                        vpnRunning
                            ? const Color(0xFF173D37)
                            : const Color(0xFF151F29),
                    border: Border.all(
                      color:
                          vpnRunning ? const Color(0xFF31D6B8) : Colors.white24,
                      width: 3,
                    ),
                    boxShadow:
                        vpnRunning
                            ? const [
                              BoxShadow(
                                color: Color(0x5531D6B8),
                                blurRadius: 32,
                                spreadRadius: 2,
                              ),
                            ]
                            : null,
                  ),
                  child:
                      busy
                          ? const Padding(
                            padding: EdgeInsets.all(62),
                            child: CircularProgressIndicator(),
                          )
                          : Icon(
                            Icons.power_settings_new_rounded,
                            size: 66,
                            color:
                                vpnRunning
                                    ? const Color(0xFF55E7CB)
                                    : Colors.white70,
                          ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 20),
          Text(
            vpnRunning ? '已连接' : '未连接',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 6),
          Text(
            activeName == null || activeName.isEmpty ? '尚未选择节点' : activeName,
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(color: Colors.white60),
          ),
          if (error != null) ...[
            const SizedBox(height: 12),
            Text(
              error!,
              textAlign: TextAlign.center,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
          const SizedBox(height: 26),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(18),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    '代理模式',
                    style: TextStyle(fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 14),
                  SizedBox(
                    width: double.infinity,
                    child: SegmentedButton<bool>(
                      segments: const [
                        ButtonSegment(
                          value: false,
                          icon: Icon(Icons.alt_route),
                          label: Text('规则分流'),
                        ),
                        ButtonSegment(
                          value: true,
                          icon: Icon(Icons.public),
                          label: Text('全局代理'),
                        ),
                      ],
                      selected: {global},
                      onSelectionChanged:
                          (values) => onModeChanged(values.first),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: '下载',
                  value: '${_formatBytes(status['speedIn'])}/s',
                  icon: Icons.south_rounded,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _MetricCard(
                  label: '上传',
                  value: '${_formatBytes(status['speedOut'])}/s',
                  icon: Icons.north_rounded,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: '累计下载',
                  value: _formatBytes(stats['totalIn']),
                  icon: Icons.download_done_rounded,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _MetricCard(
                  label: '累计上传',
                  value: _formatBytes(stats['totalOut']),
                  icon: Icons.upload_rounded,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _NodesPage extends StatefulWidget {
  const _NodesPage({required this.api, required this.onChanged});
  final WingApi api;
  final Future<void> Function() onChanged;

  @override
  State<_NodesPage> createState() => _NodesPageState();
}

class _NodesPageState extends State<_NodesPage> {
  List<Map<String, dynamic>> _nodes = const [];
  final _search = TextEditingController();
  bool _loading = true;
  bool _testingAll = false;
  final Set<int> _testing = {};
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    if (mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }
    try {
      final nodes = await widget.api.getNodes();
      if (mounted) setState(() => _nodes = nodes);
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _switch(Map<String, dynamic> node) async {
    final response = await widget.api.switchNode(
      (node['index'] as num).toInt(),
    );
    if (response['ok'] != true) {
      throw WingApiException(response['msg']?.toString() ?? '节点切换失败');
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
    await _load();
    await widget.onChanged();
  }

  Future<void> _test(Map<String, dynamic> node) async {
    final index = (node['index'] as num).toInt();
    setState(() => _testing.add(index));
    try {
      final latency = await widget.api.testNode(index);
      final position = _nodes.indexWhere((item) => item['index'] == index);
      if (mounted && position >= 0) {
        setState(
          () => _nodes[position] = {..._nodes[position], 'latency': latency},
        );
      }
    } finally {
      if (mounted) setState(() => _testing.remove(index));
    }
  }

  Future<void> _testAll() async {
    setState(() => _testingAll = true);
    try {
      await widget.api.testAllNodes();
      await _load();
    } catch (error) {
      if (mounted) {
        _snack(context, error.toString());
      }
    } finally {
      if (mounted) setState(() => _testingAll = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final query = _search.text.trim().toLowerCase();
    final filtered = _nodes
        .where((node) {
          return query.isEmpty ||
              node['name'].toString().toLowerCase().contains(query) ||
              node['group'].toString().toLowerCase().contains(query);
        })
        .toList(growable: false);
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 10, 16, 8),
          child: TextField(
            controller: _search,
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              hintText: '搜索节点或订阅组',
              prefixIcon: const Icon(Icons.search_rounded),
              suffixIcon: IconButton(
                tooltip: '全部测速',
                onPressed: _testingAll ? null : _testAll,
                icon:
                    _testingAll
                        ? const Padding(
                          padding: EdgeInsets.all(12),
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                        : const Icon(Icons.speed_rounded),
              ),
            ),
          ),
        ),
        Expanded(
          child: RefreshIndicator(
            onRefresh: _load,
            child:
                _loading && _nodes.isEmpty
                    ? const Center(child: CircularProgressIndicator())
                    : _error != null
                    ? _ScrollableMessage(
                      icon: Icons.cloud_off,
                      message: _error!,
                      action: _load,
                    )
                    : filtered.isEmpty
                    ? const _ScrollableMessage(
                      icon: Icons.hub_outlined,
                      message: '暂无节点，请先导入订阅',
                    )
                    : ListView.separated(
                      padding: const EdgeInsets.fromLTRB(12, 6, 12, 28),
                      itemCount: filtered.length,
                      separatorBuilder: (_, __) => const SizedBox(height: 6),
                      itemBuilder: (context, index) {
                        final node = filtered[index];
                        final active = node['active'] == true;
                        final latency = (node['latency'] as num?)?.toInt() ?? 0;
                        final nodeIndex = (node['index'] as num).toInt();
                        final nodeType = node['type']?.toString() ?? '';
                        return Card(
                          color: active ? const Color(0xFF173D37) : null,
                          child: ListTile(
                            onTap: () async {
                              try {
                                await _switch(node);
                              } catch (error) {
                                if (context.mounted) {
                                  _snack(context, error.toString());
                                }
                              }
                            },
                            leading: CircleAvatar(
                              backgroundColor:
                                  active
                                      ? const Color(0xFF31D6B8)
                                      : const Color(0xFF25313C),
                              child: Text(
                                nodeType.isEmpty
                                    ? '?'
                                    : nodeType.substring(0, 1).toUpperCase(),
                              ),
                            ),
                            title: Text(
                              node['name']?.toString() ?? '未命名',
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                            subtitle: Text(
                              '${node['group'] ?? '未分组'} · ${node['type'] ?? 'unknown'}',
                            ),
                            trailing:
                                _testing.contains(nodeIndex)
                                    ? const SizedBox.square(
                                      dimension: 24,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                      ),
                                    )
                                    : TextButton(
                                      onPressed: () async {
                                        try {
                                          await _test(node);
                                        } catch (error) {
                                          if (context.mounted) {
                                            _snack(context, error.toString());
                                          }
                                        }
                                      },
                                      child: Text(
                                        latency == 0
                                            ? '测速'
                                            : latency < 0
                                            ? '超时'
                                            : '$latency ms',
                                      ),
                                    ),
                          ),
                        );
                      },
                    ),
          ),
        ),
      ],
    );
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }
}

class _SubscriptionsPage extends StatefulWidget {
  const _SubscriptionsPage({required this.api, required this.onChanged});
  final WingApi api;
  final Future<void> Function() onChanged;

  @override
  State<_SubscriptionsPage> createState() => _SubscriptionsPageState();
}

class _SubscriptionsPageState extends State<_SubscriptionsPage> {
  List<Map<String, dynamic>> _suppliers = const [];
  bool _loading = true;
  final Set<String> _working = {};
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    if (mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }
    try {
      final suppliers = await widget.api.getSuppliers();
      if (mounted) setState(() => _suppliers = suppliers);
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _add() async {
    final controller = TextEditingController();
    final input = await showDialog<String>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('导入订阅'),
            content: TextField(
              controller: controller,
              autofocus: true,
              minLines: 2,
              maxLines: 5,
              keyboardType: TextInputType.url,
              decoration: const InputDecoration(hintText: '粘贴订阅链接或节点链接'),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, controller.text.trim()),
                child: const Text('导入'),
              ),
            ],
          ),
    );
    controller.dispose();
    if (input == null || input.isEmpty) return;
    try {
      final response = await widget.api.importSubscription(input);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '导入失败');
      }
      if (mounted) _snack(context, response['msg']?.toString() ?? '订阅已导入');
      await _load();
      await widget.onChanged();
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    }
  }

  Future<void> _update(Map<String, dynamic> supplier) async {
    final file = supplier['fileName']?.toString() ?? '';
    setState(() => _working.add(file));
    try {
      final response = await widget.api.updateSupplier(file);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '更新失败');
      }
      if (mounted) _snack(context, response['msg']?.toString() ?? '更新完成');
      await _load();
      await widget.onChanged();
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    } finally {
      if (mounted) setState(() => _working.remove(file));
    }
  }

  Future<void> _delete(Map<String, dynamic> supplier) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('删除订阅？'),
            content: Text('将删除“${supplier['name']}”及其本地节点。'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('删除'),
              ),
            ],
          ),
    );
    if (confirmed != true) return;
    final file = supplier['fileName']?.toString() ?? '';
    try {
      final response = await widget.api.deleteSupplier(file);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '删除失败');
      }
      await _load();
      await widget.onChanged();
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.transparent,
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _add,
        icon: const Icon(Icons.add_link_rounded),
        label: const Text('导入订阅'),
      ),
      body: RefreshIndicator(
        onRefresh: _load,
        child:
            _loading && _suppliers.isEmpty
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                ? _ScrollableMessage(
                  icon: Icons.cloud_off,
                  message: _error!,
                  action: _load,
                )
                : _suppliers.isEmpty
                ? const _ScrollableMessage(
                  icon: Icons.cloud_download_outlined,
                  message: '暂无订阅，点击右下角导入',
                )
                : ListView.separated(
                  padding: const EdgeInsets.fromLTRB(14, 12, 14, 96),
                  itemCount: _suppliers.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 10),
                  itemBuilder: (context, index) {
                    final supplier = _suppliers[index];
                    final file = supplier['fileName']?.toString() ?? '';
                    final traffic = supplier['traffic'] as Map?;
                    return Card(
                      color:
                          supplier['active'] == true
                              ? const Color(0xFF173D37)
                              : null,
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Expanded(
                                  child: Text(
                                    supplier['name']?.toString() ?? '未命名订阅',
                                    style:
                                        Theme.of(context).textTheme.titleMedium,
                                  ),
                                ),
                                if (supplier['active'] == true)
                                  const Chip(label: Text('当前')),
                              ],
                            ),
                            const SizedBox(height: 4),
                            Text(
                              supplier['url']?.toString() ?? '',
                              style: const TextStyle(color: Colors.white54),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            if (traffic != null) ...[
                              const SizedBox(height: 10),
                              Text(
                                _trafficText(traffic),
                                style: const TextStyle(color: Colors.white70),
                              ),
                            ],
                            const SizedBox(height: 10),
                            Row(
                              mainAxisAlignment: MainAxisAlignment.end,
                              children: [
                                TextButton.icon(
                                  onPressed:
                                      _working.contains(file)
                                          ? null
                                          : () => _update(supplier),
                                  icon:
                                      _working.contains(file)
                                          ? const SizedBox.square(
                                            dimension: 16,
                                            child: CircularProgressIndicator(
                                              strokeWidth: 2,
                                            ),
                                          )
                                          : const Icon(Icons.sync_rounded),
                                  label: const Text('刷新'),
                                ),
                                TextButton.icon(
                                  onPressed: () => _delete(supplier),
                                  icon: const Icon(Icons.delete_outline),
                                  label: const Text('删除'),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
      ),
    );
  }
}

class _ToolsPage extends StatefulWidget {
  const _ToolsPage({required this.api, required this.abi});
  final WingApi api;
  final String? abi;

  @override
  State<_ToolsPage> createState() => _ToolsPageState();
}

class _ToolsPageState extends State<_ToolsPage> {
  Map<String, dynamic> _dns = const {};
  List<Map<String, dynamic>> _rules = const [];
  List<Map<String, dynamic>> _siteResults = const [];
  bool _testing = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final values = await Future.wait<Object?>([
        widget.api.getDns(),
        widget.api.getRules(),
      ]);
      if (!mounted) return;
      setState(() {
        _dns = Map<String, dynamic>.from(values[0] as Map);
        _rules = List<Map<String, dynamic>>.from(values[1] as List);
      });
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    }
  }

  Future<void> _testSites() async {
    setState(() => _testing = true);
    try {
      final response = await widget.api.testSites();
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '网站测试失败');
      }
      final values = response['results'] as List? ?? const [];
      if (mounted) {
        setState(
          () =>
              _siteResults =
                  values
                      .map((item) => Map<String, dynamic>.from(item as Map))
                      .toList(),
        );
      }
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    } finally {
      if (mounted) setState(() => _testing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final servers = _dns['servers'] as List? ?? const [];
    final dnsRules = _dns['rules'] as List? ?? const [];
    final routingRuleCount = _rules.fold<int>(
      0,
      (sum, group) => sum + ((group['rules'] as List?)?.length ?? 0),
    );
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
      children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.dns_outlined),
            title: const Text('DNS 分流'),
            subtitle: Text(
              '${servers.length} 个服务器 · ${dnsRules.length} 条规则 · 默认 ${_dns['default'] ?? '--'}',
            ),
          ),
        ),
        const SizedBox(height: 10),
        Card(
          child: ListTile(
            leading: const Icon(Icons.alt_route_rounded),
            title: const Text('路由规则'),
            subtitle: Text('${_rules.length} 个规则组 · $routingRuleCount 条规则'),
          ),
        ),
        const SizedBox(height: 10),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Expanded(
                      child: Text(
                        '网站可用性测试',
                        style: TextStyle(fontWeight: FontWeight.w600),
                      ),
                    ),
                    FilledButton.tonalIcon(
                      onPressed: _testing ? null : _testSites,
                      icon:
                          _testing
                              ? const SizedBox.square(
                                dimension: 16,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                              : const Icon(Icons.play_arrow_rounded),
                      label: const Text('测试'),
                    ),
                  ],
                ),
                if (_siteResults.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  ..._siteResults.map(
                    (result) => ListTile(
                      contentPadding: EdgeInsets.zero,
                      dense: true,
                      leading: Icon(
                        result['ok'] == true
                            ? Icons.check_circle
                            : Icons.cancel,
                        color:
                            result['ok'] == true
                                ? const Color(0xFF55E7CB)
                                : Theme.of(context).colorScheme.error,
                      ),
                      title: Text(result['name']?.toString() ?? '测试网站'),
                      subtitle: Text(result['message']?.toString() ?? ''),
                      trailing: Text(
                        result['latencyMs'] == null
                            ? ''
                            : '${result['latencyMs']} ms',
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 10),
        Card(
          child: ListTile(
            leading: const _WingMark(size: 42),
            title: const Text('wing 1.0.6.2'),
            subtitle: Text(
              'Android 原生客户端 · 内置代理核心\n架构：${widget.abi ?? 'unknown'} · MIT License',
            ),
            isThreeLine: true,
          ),
        ),
      ],
    );
  }
}

class _WingMark extends StatelessWidget {
  const _WingMark({required this.size});
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: const BoxDecoration(
        shape: BoxShape.circle,
        gradient: LinearGradient(
          colors: [Color(0xFF22D3EE), Color(0xFF34D399), Color(0xFFA78BFA)],
        ),
      ),
      child: Icon(
        Icons.flight_rounded,
        size: size * .58,
        color: const Color(0xFF071018),
      ),
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.label,
    required this.value,
    required this.icon,
  });
  final String label;
  final String value;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(15),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, size: 20, color: Theme.of(context).colorScheme.primary),
            const SizedBox(height: 12),
            Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 3),
            Text(
              label,
              style: const TextStyle(color: Colors.white54, fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }
}

class _ScrollableMessage extends StatelessWidget {
  const _ScrollableMessage({
    required this.icon,
    required this.message,
    this.action,
  });
  final IconData icon;
  final String message;
  final Future<void> Function()? action;

  @override
  Widget build(BuildContext context) {
    return ListView(
      physics: const AlwaysScrollableScrollPhysics(),
      children: [
        SizedBox(height: MediaQuery.sizeOf(context).height * .22),
        Icon(icon, size: 54, color: Colors.white30),
        const SizedBox(height: 14),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 28),
          child: Text(
            message,
            textAlign: TextAlign.center,
            style: const TextStyle(color: Colors.white60),
          ),
        ),
        if (action != null) ...[
          const SizedBox(height: 16),
          Center(
            child: OutlinedButton.icon(
              onPressed: action,
              icon: const Icon(Icons.refresh),
              label: const Text('重试'),
            ),
          ),
        ],
      ],
    );
  }
}

String _formatBytes(Object? raw) {
  var value = (raw as num?)?.toDouble() ?? 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  final digits = value >= 100 || unit == 0 ? 0 : 1;
  return '${value.toStringAsFixed(digits)} ${units[unit]}';
}

String _trafficText(Map<dynamic, dynamic> traffic) {
  final upload = traffic['upload'] ?? traffic['Upload'];
  final download = traffic['download'] ?? traffic['Download'];
  final total = traffic['total'] ?? traffic['Total'];
  return '已用 ${_formatBytes((upload as num? ?? 0) + (download as num? ?? 0))} / ${_formatBytes(total)}';
}

void _snack(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message)));
}
