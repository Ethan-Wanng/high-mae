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

  testWidgets('Android automatic selection switches to the fastest node', (
    tester,
  ) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('com.highmae.wing/vpn'),
          (call) async => call.method == 'getVpnStatus' ? false : true,
        );

    final api = _FakeWingApi(autoSelectEnabled: true, nodeCount: 12);
    await tester.pumpWidget(WingAndroidApp(api: api));
    await tester.pumpAndSettle();

    expect(api.switchedNode, 11);
  });
}

class _FakeWingApi implements WingApi {
  _FakeWingApi({this.autoSelectEnabled = false, this.nodeCount = 120});

  final bool autoSelectEnabled;
  final int nodeCount;
  int? switchedNode;

  @override
  Future<Map<String, dynamic>> getStatus() async => {
    'mode': 'Rule',
    'activeNodeName': '测试节点',
    'speedIn': '1.0 KB/s',
    'speedOut': '512 B/s',
  };

  @override
  Future<Map<String, dynamic>> getStats() async => {
    'totalIn': 2048,
    'totalOut': 1024,
  };

  @override
  Future<Map<String, dynamic>> getDns() async => {
    'servers': <Object>[],
    'rules': <Object>[],
    'default': '',
  };

  @override
  Future<Map<String, dynamic>> getAutoSelectConfig() async => {
    'enabled': autoSelectEnabled,
    'scope': 'all',
    'rules': <Object>[],
  };

  @override
  Future<List<Map<String, dynamic>>> getRules() async => [
    {'id': 'direct', 'name': '直连', 'action': 'direct', 'rules': <Object>[]},
  ];

  @override
  Future<List<Map<String, dynamic>>> getNodes() async => List.generate(
    nodeCount,
    (index) => {
      'index': index,
      'name': '测试节点 $index',
      'group': '测试订阅',
      'type': 'vless',
      'latency': 0,
      'active': switchedNode == index,
    },
  );

  @override
  Future<List<Map<String, dynamic>>> getSuppliers() async => [];

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
  Future<Map<String, dynamic>> saveAutoSelectConfig(
    Map<String, dynamic> config,
  ) async => {'ok': true};

  @override
  Future<Map<String, dynamic>> saveRules(
    List<Map<String, dynamic>> groups,
  ) async => {'ok': true};

  @override
  Future<Map<String, dynamic>> setGlobalMode(bool global) async => {'ok': true};

  @override
  Future<Map<String, dynamic>> switchNode(int index) async {
    switchedNode = index;
    return {'ok': true};
  }

  @override
  Future<Map<String, dynamic>> switchSupplier(String fileName) async => {
    'ok': true,
  };

  @override
  Future<Map<String, dynamic>> testSites() async => {
    'ok': true,
    'results': <Object>[],
  };

  @override
  Future<void> testAllNodes() async {}

  @override
  Future<int> testNode(int index) async => 500 - index;

  @override
  Future<Map<String, dynamic>> updateSupplier(String fileName) async => {
    'ok': true,
  };
}
