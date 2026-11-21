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
}

class _FakeWingApi implements WingApi {
  _FakeWingApi({
    this.nodeCount = 120,
    this.duplicateSuppliers = false,
    this.routingRulesCount = 0,
  });

  final int nodeCount;
  final bool duplicateSuppliers;
  final int routingRulesCount;
  int? switchedNode;
  String activeFile = 'test.yml';
  String? lastRequestedFile;
  int switchSupplierCalls = 0;
  int statusCalls = 0;
  int statsCalls = 0;

  @override
  Future<Map<String, dynamic>> getStatus() async {
    statusCalls++;
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
  Future<Map<String, dynamic>> testSites() async => {
    'ok': true,
    'results': <Object>[],
  };

  @override
  Future<void> testAllNodes() async {}

  @override
  Future<int> testNode(Map<String, dynamic> node) async =>
      500 - (node['index'] as num).toInt();

  @override
  Future<Map<String, dynamic>> updateSupplier(String fileName) async => {
    'ok': true,
  };
}
