import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

part 'android_editors.dart';
part 'android_auto_select.dart';

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
  Future<Map<String, dynamic>> saveDns(Map<String, dynamic> config);
  Future<Map<String, dynamic>> saveRules(List<Map<String, dynamic>> groups);
  Future<Map<String, dynamic>> resetRules();
  Future<Map<String, dynamic>> getAutoSelectConfig();
  Future<Map<String, dynamic>> saveAutoSelectConfig(
    Map<String, dynamic> config,
  );
  Future<Map<String, dynamic>> switchNode(Map<String, dynamic> node);
  Future<int> testNode(Map<String, dynamic> node);
  Future<void> testAllNodes();
  Future<Map<String, dynamic>> importSubscription(String input);
  Future<Map<String, dynamic>> switchSupplier(String fileName);
  Future<String> getSupplierUrl(String fileName);
  Future<Map<String, dynamic>> editSupplier(
    String fileName,
    String url,
    int updateIntervalMinutes,
  );
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
    for (var attempt = 0; attempt < 2; attempt++) {
      try {
        return await _requestOnce(
          path,
          method: method,
          body: body,
          timeout: timeout,
        );
      } on SocketException {
        if (attempt == 0) {
          final backend = await AndroidBackendLauncher.start();
          if (backend.ready) continue;
        }
        throw const WingApiException('内置代理核心未响应');
      } on HttpException {
        if (attempt == 0) {
          final backend = await AndroidBackendLauncher.start();
          if (backend.ready) continue;
        }
        throw const WingApiException('内置代理核心连接已中断');
      }
    }
    throw const WingApiException('内置代理核心未响应');
  }

  Future<Object?> _requestOnce(
    String path, {
    required String method,
    required Object? body,
    required Duration timeout,
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
      _map(await _request('/api/stats?summary=1'));

  @override
  Future<Map<String, dynamic>> getDns() async =>
      _map(await _request('/api/dns'));

  @override
  Future<List<Map<String, dynamic>>> getRules() async =>
      _list(await _request('/api/rules'));

  @override
  Future<Map<String, dynamic>> saveDns(Map<String, dynamic> config) async =>
      _map(await _request('/api/dns', method: 'POST', body: config));

  @override
  Future<Map<String, dynamic>> saveRules(
    List<Map<String, dynamic>> groups,
  ) async => _map(await _request('/api/rules', method: 'POST', body: groups));

  @override
  Future<Map<String, dynamic>> resetRules() async =>
      _map(await _request('/api/rules/reset_default', method: 'POST'));

  @override
  Future<Map<String, dynamic>> getAutoSelectConfig() async {
    final response = _map(await _request('/api/auto_select_config'));
    return Map<String, dynamic>.from(
      response['config'] as Map? ?? _defaultAutoSelectConfig(),
    );
  }

  @override
  Future<Map<String, dynamic>> saveAutoSelectConfig(
    Map<String, dynamic> config,
  ) async => _map(
    await _request('/api/auto_select_config', method: 'POST', body: config),
  );

  @override
  Future<Map<String, dynamic>> switchNode(Map<String, dynamic> node) async =>
      _map(
        await _request(
          '/api/switch?${_nodeQuery(node, extra: const {'wait': '1'})}',
          method: 'POST',
          timeout: const Duration(seconds: 30),
        ),
      );

  @override
  Future<int> testNode(Map<String, dynamic> node) async {
    final data = _map(
      await _request(
        '/api/test_single?${_nodeQuery(node)}',
        method: 'POST',
        timeout: const Duration(seconds: 15),
      ),
    );
    return (data['latency'] as num?)?.toInt() ?? -1;
  }

  String _nodeQuery(
    Map<String, dynamic> node, {
    Map<String, String> extra = const {},
  }) =>
      Uri(
        queryParameters: {
          'idx': node['index']?.toString() ?? '-1',
          'file': node['fileName']?.toString() ?? '',
          'sub': node['subIndex']?.toString() ?? '-1',
          'name': node['name']?.toString() ?? '',
          ...extra,
        },
      ).query;

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
  Future<Map<String, dynamic>> switchSupplier(String fileName) async {
    return _map(
      await _request(
        '/api/switch_supplier?file=${Uri.encodeQueryComponent(fileName)}',
        method: 'POST',
        timeout: const Duration(seconds: 30),
      ),
    );
  }

  @override
  Future<String> getSupplierUrl(String fileName) async {
    final response = _map(
      await _request(
        '/api/supplier_url?file=${Uri.encodeQueryComponent(fileName)}',
        method: 'POST',
      ),
    );
    if (response['ok'] != true || response['url'] == null) {
      throw WingApiException(response['msg']?.toString() ?? '无法读取订阅链接');
    }
    return response['url'].toString();
  }

  @override
  Future<Map<String, dynamic>> editSupplier(
    String fileName,
    String url,
    int updateIntervalMinutes,
  ) async => _map(
    await _request(
      '/api/edit_supplier?file=${Uri.encodeQueryComponent(fileName)}',
      method: 'POST',
      body: {'url': url, 'updateIntervalMinutes': updateIntervalMinutes},
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
  bool _refreshing = false;
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

  Future<void> _refreshStatus({bool refreshStats = false}) async {
    if (_refreshing) return;
    _refreshing = true;
    try {
      final includeStats = refreshStats || _tab == 0 || _stats.isEmpty;
      final values = await Future.wait<Object?>([
        widget.api.getStatus(),
        _nativeChannel.invokeMethod<bool>('getVpnStatus'),
        if (includeStats) widget.api.getStats(),
      ]);
      if (!mounted) return;
      void apply() {
        _status = Map<String, dynamic>.from(values[0] as Map);
        _vpnRunning = values[1] == true;
        if (includeStats) {
          _stats = Map<String, dynamic>.from(values[2] as Map);
        }
        _error = null;
      }

      if (_tab == 0) {
        setState(apply);
      } else {
        apply();
      }
    } catch (error) {
      if (mounted) {
        if (_tab == 0) {
          setState(() => _error = error.toString());
        } else {
          _error = error.toString();
        }
      }
    } finally {
      _refreshing = false;
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
    if (!_vpnRunning) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder:
            (context) => AlertDialog(
              title: const Text('建立系统 VPN 连接'),
              content: const Text(
                'wing 将创建 Android 系统级 VPN 隧道来接管设备流量。首次连接时，Android 还会显示系统授权窗口；连接后状态栏会出现 VPN 图标，并保留常驻连接通知。',
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, false),
                  child: const Text('取消'),
                ),
                FilledButton(
                  onPressed: () => Navigator.pop(context, true),
                  child: const Text('继续连接'),
                ),
              ],
            ),
      );
      if (confirmed != true || !mounted) return;
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
    final Widget page;
    switch (_tab) {
      case 0:
        page = _OverviewPage(
          status: _status,
          stats: _stats,
          vpnRunning: _vpnRunning,
          busy: _busy,
          error: _error,
          onToggleVpn: _toggleVpn,
          onRefresh: () => _refreshStatus(refreshStats: true),
          onModeChanged: (global) async {
            await widget.api.setGlobalMode(global);
            await _refreshStatus();
          },
        );
      case 1:
        page = _NodesPage(api: widget.api, onChanged: _refreshStatus);
      case 2:
        page = _SubscriptionsPage(api: widget.api, onChanged: _refreshStatus);
      default:
        page = _ToolsPage(api: widget.api, abi: widget.backend.abi);
    }

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
      body: page,
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (value) {
          setState(() => _tab = value);
          if (value == 0) {
            unawaited(_refreshStatus(refreshStats: true));
          }
        },
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
                  value: _formatSpeed(status['speedIn']),
                  icon: Icons.south_rounded,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _MetricCard(
                  label: '上传',
                  value: _formatSpeed(status['speedOut']),
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
  bool _autoSelecting = false;
  int? _switchingIndex;
  final Set<int> _testing = {};
  String? _error;
  Timer? _autoTimer;

  @override
  void initState() {
    super.initState();
    _initialize();
    _autoTimer = Timer.periodic(
      const Duration(minutes: 10),
      (_) => _runAutoSelect(onlyWhenEnabled: true, silent: true),
    );
  }

  Future<void> _initialize() async {
    await _load();
    await _runAutoSelect(onlyWhenEnabled: true, silent: true);
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
    if (_switchingIndex != null) return;
    final index = (node['index'] as num).toInt();
    setState(() => _switchingIndex = index);
    try {
      final response = await widget.api.switchNode(node);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '节点切换失败');
      }
      await _load();
      await widget.onChanged();
    } finally {
      if (mounted) setState(() => _switchingIndex = null);
    }
  }

  Future<void> _test(Map<String, dynamic> node) async {
    final index = (node['index'] as num).toInt();
    setState(() => _testing.add(index));
    try {
      final latency = await widget.api.testNode(node);
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

  Future<void> _runAutoSelect({
    bool onlyWhenEnabled = false,
    bool silent = false,
  }) async {
    if (_autoSelecting || _switchingIndex != null || _nodes.isEmpty) return;
    setState(() => _autoSelecting = true);
    try {
      final config = await widget.api.getAutoSelectConfig();
      if (onlyWhenEnabled && config['enabled'] != true) return;
      final result = await _performAutoSelect(
        widget.api,
        config,
        onProgress:
            silent || !mounted ? null : (message) => _snack(context, message),
      );
      await _load();
      await widget.onChanged();
      if (!silent && mounted) {
        _snack(context, '已选择 ${result['name']} · ${result['latency']} ms');
      }
    } catch (error) {
      if (!silent && mounted) _snack(context, error.toString());
    } finally {
      if (mounted) setState(() => _autoSelecting = false);
    }
  }

  Future<void> _openAutoSelectSettings() async {
    final enabled = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => _AutoSelectSettingsPage(api: widget.api),
      ),
    );
    if (enabled == true) {
      await _runAutoSelect();
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
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 6),
          child: Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _autoSelecting ? null : _openAutoSelectSettings,
                  icon: const Icon(Icons.auto_awesome_rounded),
                  label: const Text('自动选择设置'),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: FilledButton.icon(
                  onPressed: _autoSelecting ? null : _runAutoSelect,
                  icon:
                      _autoSelecting
                          ? const SizedBox.square(
                            dimension: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                          : const Icon(Icons.bolt_rounded),
                  label: Text(_autoSelecting ? '正在选优' : '立即选优'),
                ),
              ),
            ],
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
                    : ListView.builder(
                      padding: const EdgeInsets.fromLTRB(12, 6, 12, 28),
                      itemCount: filtered.length,
                      itemExtent: 82,
                      itemBuilder: (context, index) {
                        final node = filtered[index];
                        final active = node['active'] == true;
                        final latency = (node['latency'] as num?)?.toInt() ?? 0;
                        final nodeIndex = (node['index'] as num).toInt();
                        final nodeType = node['type']?.toString() ?? '';
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 6),
                          child: Card(
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
                                  _switchingIndex == nodeIndex ||
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
    _autoTimer?.cancel();
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

  Future<void> _switchSupplier(Map<String, dynamic> supplier) async {
    final file = supplier['fileName']?.toString() ?? '';
    if (file.isEmpty || _working.contains(file)) return;
    setState(() => _working.add(file));
    try {
      final response = await widget.api.switchSupplier(file);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '订阅切换失败');
      }
      await _load();
      await widget.onChanged();
      if (mounted) _snack(context, '已切换到 ${supplier['name']}');
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    } finally {
      if (mounted) setState(() => _working.remove(file));
    }
  }

  Future<void> _share(Map<String, dynamic> supplier) async {
    final file = supplier['fileName']?.toString() ?? '';
    try {
      final url = await widget.api.getSupplierUrl(file);
      await _nativeChannel.invokeMethod<bool>('shareText', {
        'title': supplier['name']?.toString() ?? 'wing 订阅',
        'text': url,
      });
    } catch (error) {
      if (mounted) _snack(context, '分享失败：$error');
    }
  }

  Future<void> _edit(Map<String, dynamic> supplier) async {
    final file = supplier['fileName']?.toString() ?? '';
    String originalUrl;
    try {
      originalUrl = await widget.api.getSupplierUrl(file);
    } catch (error) {
      if (mounted) _snack(context, error.toString());
      return;
    }
    if (!mounted) return;
    final url = TextEditingController(text: originalUrl);
    final interval = TextEditingController(
      text: '${supplier['updateIntervalMinutes'] ?? 360}',
    );
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: Text('编辑 ${supplier['name'] ?? '订阅'}'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: url,
                  autofocus: true,
                  minLines: 2,
                  maxLines: 4,
                  keyboardType: TextInputType.url,
                  decoration: const InputDecoration(labelText: '订阅 URL'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: interval,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(labelText: '自动更新间隔（分钟）'),
                ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () {
                  final minutes = int.tryParse(interval.text.trim());
                  if (url.text.trim().isEmpty ||
                      minutes == null ||
                      minutes <= 0) {
                    return;
                  }
                  Navigator.pop(context, {
                    'url': url.text.trim(),
                    'minutes': minutes,
                  });
                },
                child: const Text('保存'),
              ),
            ],
          ),
    );
    url.dispose();
    interval.dispose();
    if (result == null || !mounted) return;
    try {
      final response = await widget.api.editSupplier(
        file,
        result['url'].toString(),
        result['minutes'] as int,
      );
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '订阅保存失败');
      }
      await _load();
      if (mounted) _snack(context, response['msg']?.toString() ?? '订阅已保存');
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    }
  }

  Future<void> _runSupplierAction(
    String action,
    Map<String, dynamic> supplier,
  ) async {
    switch (action) {
      case 'share':
        await _share(supplier);
      case 'edit':
        await _edit(supplier);
      case 'update':
        await _update(supplier);
      case 'delete':
        await _delete(supplier);
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
                              children: [
                                Expanded(
                                  child: FilledButton.tonalIcon(
                                    onPressed:
                                        supplier['active'] == true ||
                                                _working.contains(file)
                                            ? null
                                            : () => _switchSupplier(supplier),
                                    icon:
                                        _working.contains(file)
                                            ? const SizedBox.square(
                                              dimension: 16,
                                              child: CircularProgressIndicator(
                                                strokeWidth: 2,
                                              ),
                                            )
                                            : const Icon(
                                              Icons.swap_horiz_rounded,
                                            ),
                                    label: Text(
                                      supplier['active'] == true
                                          ? '当前订阅'
                                          : '切换订阅',
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                PopupMenuButton<String>(
                                  tooltip: '更多操作',
                                  enabled: !_working.contains(file),
                                  onSelected:
                                      (action) =>
                                          _runSupplierAction(action, supplier),
                                  itemBuilder:
                                      (_) => const [
                                        PopupMenuItem(
                                          value: 'share',
                                          child: ListTile(
                                            leading: Icon(Icons.share_outlined),
                                            title: Text('分享订阅'),
                                          ),
                                        ),
                                        PopupMenuItem(
                                          value: 'edit',
                                          child: ListTile(
                                            leading: Icon(Icons.edit_outlined),
                                            title: Text('编辑订阅'),
                                          ),
                                        ),
                                        PopupMenuItem(
                                          value: 'update',
                                          child: ListTile(
                                            leading: Icon(Icons.sync_rounded),
                                            title: Text('刷新订阅'),
                                          ),
                                        ),
                                        PopupMenuItem(
                                          value: 'delete',
                                          child: ListTile(
                                            leading: Icon(Icons.delete_outline),
                                            title: Text('删除订阅'),
                                          ),
                                        ),
                                      ],
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
            onTap: () async {
              await Navigator.of(context).push<void>(
                MaterialPageRoute(
                  builder: (_) => _DnsEditorPage(api: widget.api),
                ),
              );
              await _load();
            },
            leading: const Icon(Icons.dns_outlined),
            title: const Text('DNS 分流'),
            subtitle: Text(
              '${servers.length} 个服务器 · ${dnsRules.length} 条规则 · 默认 ${_dns['default'] ?? '--'}',
            ),
            trailing: const Icon(Icons.chevron_right_rounded),
          ),
        ),
        const SizedBox(height: 10),
        Card(
          child: ListTile(
            onTap: () async {
              await Navigator.of(context).push<void>(
                MaterialPageRoute(
                  builder: (_) => _RoutingEditorPage(api: widget.api),
                ),
              );
              await _load();
            },
            leading: const Icon(Icons.alt_route_rounded),
            title: const Text('路由规则'),
            subtitle: Text('${_rules.length} 个规则组 · $routingRuleCount 条规则'),
            trailing: const Icon(Icons.chevron_right_rounded),
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
    return SizedBox(
      width: size,
      height: size,
      child: Image.asset(
        'assets/logo-mark-app.png',
        width: size,
        height: size,
        fit: BoxFit.contain,
        filterQuality: FilterQuality.high,
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
  if (raw is String) {
    final value = raw.trim();
    return value.isEmpty ? '0 B' : value.replaceAll(RegExp(r'/s$'), '');
  }
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

String _formatSpeed(Object? raw) {
  if (raw is String) {
    final value = raw.trim();
    if (value.isEmpty) return '0 B/s';
    return value.endsWith('/s') ? value : '$value/s';
  }
  return '${_formatBytes(raw)}/s';
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
