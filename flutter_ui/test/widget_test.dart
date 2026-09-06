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

      await tester.pumpWidget(WingAndroidApp(api: _FakeWingApi()));
      await tester.pumpAndSettle();

      expect(find.text('wing'), findsOneWidget);
      expect(find.text('未连接'), findsOneWidget);
      expect(find.text('规则分流'), findsOneWidget);
      expect(find.text('节点'), findsOneWidget);
      expect(find.text('订阅'), findsOneWidget);
      expect(find.text('工具'), findsOneWidget);
      expect(find.textContaining('127.0.0.1'), findsNothing);
      expect(find.byType(WingWebView), findsNothing);
    },
  );
}

class _FakeWingApi implements WingApi {
  @override
  Future<Map<String, dynamic>> getStatus() async => {
    'mode': 'Rule',
    'activeNodeName': '测试节点',
    'speedIn': 1024,
    'speedOut': 512,
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
  Future<List<Map<String, dynamic>>> getRules() async => [];

  @override
  Future<List<Map<String, dynamic>>> getNodes() async => [];

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
  Future<Map<String, dynamic>> setGlobalMode(bool global) async => {'ok': true};

  @override
  Future<Map<String, dynamic>> switchNode(int index) async => {'ok': true};

  @override
  Future<Map<String, dynamic>> testSites() async => {
    'ok': true,
    'results': <Object>[],
  };

  @override
  Future<void> testAllNodes() async {}

  @override
  Future<int> testNode(int index) async => 42;

  @override
  Future<Map<String, dynamic>> updateSupplier(String fileName) async => {
    'ok': true,
  };
}
