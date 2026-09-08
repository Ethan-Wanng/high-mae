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
    expect(api.switchedNode, isNull);

    await tester.tap(find.text('节点'));
    await tester.pumpAndSettle();

    expect(api.switchedNode, 11);
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

    expect(api.activeFile, 'backup.yml');
    expect(find.text('备用节点 0'), findsOneWidget);
    expect(find.text('测试节点 0'), findsNothing);
    expect(tester.takeException(), isNull);
  });
}

class _FakeWingApi implements WingApi {
  _FakeWingApi({this.autoSelectEnabled = false, this.nodeCount = 120});

  final bool autoSelectEnabled;
  final int nodeCount;
  int? switchedNode;
  String activeFile = 'test.yml';

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
  Future<List<Map<String, dynamic>>> getNodes({String? fileName}) async {
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
  Future<List<Map<String, dynamic>>> getSuppliers() async => [
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
  Future<Map<String, dynamic>> switchNode(Map<String, dynamic> node) async {
    switchedNode = (node['index'] as num).toInt();
    return {'ok': true};
  }

  @override
  Future<Map<String, dynamic>> switchSupplier(String fileName) async {
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
