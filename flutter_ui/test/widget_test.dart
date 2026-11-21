import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wing_ui/android_app.dart';
import 'package:wing_ui/main.dart';

void main() {
  testWidgets('renders backend connection state', (tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: WingWebView(
          initialUrl: 'http://127.0.0.1:10809/',
          autoConnect: false,
        ),
      ),
    );

    expect(find.text('正在打开控制面板'), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
  });

  testWidgets(
    'Android app renders native controls instead of a WebView shell',
    (tester) async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            const MethodChannel('com.highmae.wing/vpn'),
            (call) async => call.method == 'getVpnStatus' ? false : true,
          );

      final api = _FakeWingApi();
      await tester.pumpWidget(WingAndroidApp(api: api));
      await tester.pumpAndSettle();

      expect(find.text('wing'), findsOneWidget);
      expect(find.text('未连接'), findsOneWidget);
      expect(find.text('规则分流'), findsOneWidget);
      expect(find.text('1.0 KB/s'), findsOneWidget);
      expect(find.text('节点'), findsOneWidget);
      expect(find.text('订阅'), findsOneWidget);
      expect(find.text('工具'), findsOneWidget);
      expect(find.textContaining('127.0.0.1'), findsNothing);
      expect(find.byType(WingWebView), findsNothing);

      await tester.tap(find.text('节点'));
      await tester.pumpAndSettle();
      expect(find.text('测试节点 0'), findsOneWidget);
      await tester.tap(find.widgetWithText(ListTile, '测试节点 0'));
      await tester.pumpAndSettle();
      expect(api.switchedNode, 0);

      await tester.fling(
        find.byType(Scrollable).last,
        const Offset(0, -1200),
        1600,
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('opening nodes does not trigger automatic selection', (
    tester,
  ) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('com.highmae.wing/vpn'),
          (call) async => call.method == 'getVpnStatus' ? false : true,
        );

    final api = _FakeWingApi(nodeCount: 12);
    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();
    expect(api.switchedNode, isNull);

    await tester.tap(find.text('节点'));
    await tester.pumpAndSettle();

    expect(api.switchedNode, isNull);
  });

  testWidgets('switching subscription replaces the visible node list', (
    tester,
  ) async {
    final api = _FakeWingApi(nodeCount: 8);
    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();
    await tester.tap(find.text('节点'));
    await tester.pumpAndSettle();

    expect(find.text('测试节点 0'), findsOneWidget);
    await tester.tap(find.byType(DropdownButton<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('备用订阅').last);
    await tester.pumpAndSettle();

    expect(api.activeFile, 'test.yml');
    expect(api.lastRequestedFile, 'backup.yml');
    expect(api.switchSupplierCalls, 0);
    expect(find.text('备用节点 0'), findsOneWidget);
    expect(find.text('测试节点 0'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('connected VPN can be disconnected', (tester) async {
    var connected = true;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('com.highmae.wing/vpn'), (
          call,
        ) async {
          if (call.method == 'getVpnStatus') return connected;
          if (call.method == 'stopVpn') {
            connected = false;
            return true;
          }
          return true;
        });

    await tester.pumpWidget(WingAndroidApp(api: _FakeWingApi()));
    await tester.pumpAndSettle();
    expect(find.bySemanticsLabel('断开 VPN'), findsOneWidget);
    await tester.tap(find.bySemanticsLabel('断开 VPN'));
    await tester.pumpAndSettle();

    expect(connected, isFalse);
    expect(find.bySemanticsLabel('连接 VPN'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('pausing lifecycle stops background polling until resumed', (
    tester,
  ) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('com.highmae.wing/vpn'),
          (call) async => call.method == 'getVpnStatus' ? false : true,
        );

    final api = _FakeWingApi();
    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();

    final callsBeforePause = api.statusCalls;
    final statsBeforePause = api.statsCalls;

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    await tester.pump(const Duration(seconds: 6));

    expect(api.statusCalls, callsBeforePause);
    expect(api.statsCalls, statsBeforePause);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    await tester.pumpAndSettle();

    expect(api.statusCalls, greaterThan(callsBeforePause));
    expect(api.statsCalls, greaterThan(statsBeforePause));
    expect(tester.takeException(), isNull);
  });

  testWidgets('nodes page handles empty or duplicate supplier metadata safely', (
    tester,
  ) async {
    final api = _FakeWingApi(nodeCount: 0, duplicateSuppliers: true);
    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();

    await tester.tap(find.text('节点'));
    await tester.pumpAndSettle();

    expect(find.text('暂无节点，请先导入订阅'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('routing editor renders large rule groups lazily and searches', (
    tester,
  ) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('com.highmae.wing/vpn'),
          (call) async => call.method == 'getVpnStatus' ? false : true,
        );

    final api = _FakeWingApi(routingRulesCount: 500);
    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();

    await tester.tap(find.text('工具'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('路由规则'));
    await tester.pumpAndSettle();

    expect(find.text('直连'), findsOneWidget);
    expect(find.textContaining('500 条规则'), findsOneWidget);
    expect(find.text('rule-499.example.com'), findsNothing);

    await tester.tap(find.text('直连'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), '499');
    await tester.pumpAndSettle();

    expect(find.text('rule-499.example.com'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  test('AutoSelectConfig normalizes and filters protocol and keyword rules', () {
    final defaults = AutoSelectConfig.defaults();
    expect(defaults.enabled, isFalse);
    expect(defaults.scope, 'subscription');
    expect(defaults.rules.length, 1);
    expect(defaults.rules.first.type, 'exclude_keyword');

    final normalized = AutoSelectConfig.fromJson({
      'enabled': true,
      'scope': 'subscription',
      'subscriptionFile': 'sub%20a.yml',
      'rules': [
        {'id': 'r1', 'type': 'include_protocol', 'value': 'vless, ss'},
        {'id': 'r2', 'type': 'exclude_protocol', 'value': 'hy2'},
      ],
    });
    expect(normalized.subscriptionFiles, ['sub a.yml']);
    expect(normalized.rules.length, 2);

    final suppliers = [
      {'name': '主订阅', 'fileName': 'sub a.yml', 'active': true},
      {'name': '其他订阅', 'fileName': 'other.yml', 'active': false},
    ];
    final allNodes = [
      {
        'index': 0,
        'name': '美国 VLESS',
        'group': '主订阅',
        'fileName': 'sub a.yml',
        'subIndex': 0,
        'type': 'vless',
        'latency': 80,
      },
      {
        'index': 1,
        'name': '日本 VLESS 超时',
        'group': '主订阅',
        'fileName': 'sub a.yml',
        'subIndex': 1,
        'type': 'vless',
        'latency': -1,
      },
      {
        'index': 2,
        'name': '日本 HY2',
        'group': '主订阅',
        'fileName': 'sub a.yml',
        'subIndex': 2,
        'type': 'hysteria2',
        'latency': 40,
      },
      {
        'index': 3,
        'name': '其他订阅 VLESS',
        'group': '其他订阅',
        'fileName': 'other.yml',
        'subIndex': 0,
        'type': 'vless',
        'latency': 30,
      },
    ];

    final candidates = filterAutoSelectCandidates(allNodes, normalized, suppliers);
    expect(candidates.map((e) => e['name']).toList(), ['美国 VLESS']);

    final ssOnlyConfig = AutoSelectConfig(
      enabled: true,
      scope: 'all',
      rules: const [
        AutoSelectRule(id: 'ss', type: 'include_protocol', value: 'ss', values: ['ss']),
      ],
    );
    final ssCandidates = filterAutoSelectCandidates(allNodes, ssOnlyConfig, suppliers);
    expect(ssCandidates, isEmpty);

    final excludedKey = autoSelectNodeKey(allNodes.first);
    final excludedCandidates = filterAutoSelectCandidates(
      allNodes,
      normalized.copyWith(excludedNodeKeys: [excludedKey]),
      suppliers,
    );
    expect(excludedCandidates, isEmpty);
  });

  testWidgets('auto-select adds rules and picks fastest matching node with site check', (
    tester,
  ) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('com.highmae.wing/vpn'),
          (call) async => call.method == 'getVpnStatus' ? false : true,
        );

    final api = _FakeWingApi(
      customNodes: [
        {
          'index': 0,
          'name': '香港 01',
          'group': '测试订阅',
          'fileName': 'test.yml',
          'subIndex': 0,
          'type': 'vless',
          'latency': 25,
          'active': true,
        },
        {
          'index': 1,
          'name': '日本 VMess',
          'group': '测试订阅',
          'fileName': 'test.yml',
          'subIndex': 1,
          'type': 'vmess',
          'latency': 35,
          'active': false,
        },
        {
          'index': 2,
          'name': '新加坡 VLESS',
          'group': '测试订阅',
          'fileName': 'test.yml',
          'subIndex': 2,
          'type': 'vless',
          'latency': 50,
          'active': false,
        },
        {
          'index': 3,
          'name': '美国 VLESS',
          'group': '测试订阅',
          'fileName': 'test.yml',
          'subIndex': 3,
          'type': 'vless',
          'latency': 110,
          'active': false,
        },
      ],
      customLatencies: {0: 25, 1: 35, 2: 50, 3: 110},
      failingSiteNodeIndices: {2},
    );

    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();

    await tester.tap(find.text('节点'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('自动选择'));
    await tester.pumpAndSettle();

    expect(find.text('不使用包含'), findsOneWidget);
    await tester.tap(find.text('添加规则'));
    await tester.pumpAndSettle();

    await tester.tap(find.byType(DropdownButtonFormField<String>).last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('只使用协议').last);
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(FilterChip, 'vless'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, '添加'));
    await tester.pumpAndSettle();

    expect(find.text('只使用协议'), findsOneWidget);
    expect(find.text('候选节点 (2)'), findsOneWidget);

    await tester.tap(find.text('立即选择'));
    await tester.pumpAndSettle();
    expect(api.switchedNode, 2);

    await tester.pump(const Duration(seconds: 5));
    await tester.pumpAndSettle();
    final siteDropdown = find.widgetWithText(
      DropdownButtonFormField<String>,
      '不要求',
    );
    await tester.ensureVisible(siteDropdown);
    await tester.pumpAndSettle();
    await tester.tap(siteDropdown);
    await tester.pumpAndSettle();
    await tester.tap(find.text('任一可用').last);
    await tester.pumpAndSettle();

    await tester.ensureVisible(find.text('立即选择'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('立即选择'));
    await tester.pumpAndSettle();

    expect(api.switchedNode, 3);
    expect(api.savedAutoSelectConfig, isNotNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('VPN status stays connected even when API status request fails', (
    tester,
  ) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('com.highmae.wing/vpn'),
          (call) async => call.method == 'getVpnStatus' ? true : true,
        );

    final api = _FakeWingApi(failStatus: true);
    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();

    expect(find.text('已连接'), findsOneWidget);
    expect(find.bySemanticsLabel('断开 VPN'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

class _FakeWingApi implements WingApi {
  _FakeWingApi({
    this.nodeCount = 120,
    this.duplicateSuppliers = false,
    this.routingRulesCount = 0,
    this.failStatus = false,
    this.customNodes,
    this.customLatencies = const {},
    this.failingSiteNodeIndices = const {},
  });

  final int nodeCount;
  final bool duplicateSuppliers;
  final int routingRulesCount;
  final bool failStatus;
  final List<Map<String, dynamic>>? customNodes;
  final Map<int, int> customLatencies;
  final Set<int> failingSiteNodeIndices;
  int? switchedNode;
  String activeFile = 'test.yml';
  String? lastRequestedFile;
  int switchSupplierCalls = 0;
  int statusCalls = 0;
  int statsCalls = 0;
  Map<String, dynamic>? savedAutoSelectConfig;

  @override
  Future<Map<String, dynamic>> getStatus() async {
    statusCalls++;
    if (failStatus) {
      throw const WingApiException('内置代理核心未响应');
    }
    return {
      'mode': 'Rule',
      'activeNodeName': '测试节点',
      'speedIn': '1.0 KB/s',
      'speedOut': '512 B/s',
    };
  }

  @override
  Future<Map<String, dynamic>> getStats() async {
    statsCalls++;
    return {'totalIn': 2048, 'totalOut': 1024};
  }

  @override
  Future<Map<String, dynamic>> getDns() async => {
    'servers': <Object>[],
    'rules': <Object>[],
    'default': '',
  };

  @override
  Future<List<Map<String, dynamic>>> getRules() async => [
    {
      'id': 'direct',
      'name': '直连',
      'action': 'direct',
      'rules': List.generate(
        routingRulesCount,
        (index) => {
          'type': 'domain_suffix',
          'value': 'rule-$index.example.com',
        },
      ),
    },
  ];

  @override
  Future<List<Map<String, dynamic>>> getNodes({String? fileName}) async {
    lastRequestedFile = fileName;
    if (customNodes != null) {
      return customNodes!
          .where((n) => fileName == null || n['fileName'] == fileName)
          .map((n) {
            final idx = (n['index'] as num).toInt();
            return {
              ...n,
              'active': switchedNode == null ? n['active'] == true : switchedNode == idx,
            };
          })
          .toList(growable: false);
    }
    final selectedFile = fileName ?? activeFile;
    final backup = selectedFile == 'backup.yml';
    return List.generate(
      nodeCount,
      (index) => {
        'index': index,
        'name': '${backup ? '备用' : '测试'}节点 $index',
        'group': backup ? '备用订阅' : '测试订阅',
        'fileName': selectedFile,
        'subIndex': index,
        'type': 'vless',
        'latency': 0,
        'active': switchedNode == index,
      },
    );
  }

  @override
  Future<List<Map<String, dynamic>>> getSuppliers() async =>
      duplicateSuppliers
          ? [
            {'name': '无效分组', 'fileName': 'dup.yml', 'active': false},
            {'name': '无效分组', 'fileName': 'dup.yml', 'active': false},
          ]
          : [
            {
              'name': '测试订阅',
              'fileName': 'test.yml',
              'active': activeFile == 'test.yml',
            },
            {
              'name': '备用订阅',
              'fileName': 'backup.yml',
              'active': activeFile == 'backup.yml',
            },
          ];

  @override
  Future<Map<String, dynamic>> deleteSupplier(String fileName) async => {
    'ok': true,
  };

  @override
  Future<Map<String, dynamic>> importSubscription(String input) async => {
    'ok': true,
  };

  @override
  Future<Map<String, dynamic>> editSupplier(
    String fileName,
    String url,
    int updateIntervalMinutes,
  ) async => {'ok': true};

  @override
  Future<String> getSupplierUrl(String fileName) async =>
      'https://example.com/subscription';

  @override
  Future<Map<String, dynamic>> resetRules() async => {
    'ok': true,
    'groups': <Object>[],
  };

  @override
  Future<Map<String, dynamic>> saveDns(Map<String, dynamic> config) async => {
    'ok': true,
  };

  @override
  Future<Map<String, dynamic>> saveRules(
    List<Map<String, dynamic>> groups,
  ) async => {'ok': true};

  @override
  Future<Map<String, dynamic>> setGlobalMode(bool global) async => {'ok': true};

  @override
  Future<Map<String, dynamic>> switchNode(Map<String, dynamic> node) async {
    switchedNode = (node['index'] as num).toInt();
    return {'ok': true};
  }

  @override
  Future<Map<String, dynamic>> switchSupplier(String fileName) async {
    switchSupplierCalls++;
    activeFile = fileName;
    return {'ok': true};
  }

  @override
  Future<Map<String, dynamic>> testSites({String? targetId}) async {
    final activeIdx = switchedNode ?? 0;
    final ok = !failingSiteNodeIndices.contains(activeIdx);
    return {
      'ok': true,
      'results': [
        {
          'id': targetId ?? 'preset_chatgpt',
          'name': 'ChatGPT',
          'ok': ok,
          'latencyMs': ok ? 120 : 0,
        },
      ],
    };
  }

  @override
  Future<Map<String, dynamic>?> getAutoSelectConfig() async =>
      savedAutoSelectConfig == null
          ? null
          : Map<String, dynamic>.from(savedAutoSelectConfig!);

  @override
  Future<void> saveAutoSelectConfig(Map<String, dynamic> config) async {
    savedAutoSelectConfig = Map<String, dynamic>.from(config);
  }

  @override
  Future<List<Map<String, dynamic>>> getSiteTargets() async => [
    {
      'id': 'preset_chatgpt',
      'name': 'ChatGPT',
      'category': 'AI',
      'url': 'https://chatgpt.com/',
      'preset': true,
    },
  ];

  @override
  Future<void> testAllNodes() async {}

  @override
  Future<int> testNode(Map<String, dynamic> node) async {
    final idx = (node['index'] as num).toInt();
    return customLatencies[idx] ?? (500 - idx);
  }

  @override
  Future<Map<String, dynamic>> updateSupplier(String fileName) async => {
    'ok': true,
  };
}
