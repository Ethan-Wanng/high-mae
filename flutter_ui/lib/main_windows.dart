import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webview_windows/webview_windows.dart';
import 'package:window_manager/window_manager.dart';

const _defaultWebUIURL = 'http://127.0.0.1:10809/';

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();

  const windowOptions = WindowOptions(
    size: Size(1280, 800),
    minimumSize: Size(980, 620),
    center: true,
    title: 'wing',
    backgroundColor: Color(0xFF111827),
  );

  runApp(WingApp(initialUrl: _webUIURLFromArgs(args)));

  await windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.show();
    await windowManager.focus();
  });
}

String _webUIURLFromArgs(List<String> args) {
  for (final arg in args) {
    if (arg.startsWith('--wing-url=')) {
      final value = arg.substring('--wing-url='.length).trim();
      if (value.isNotEmpty) {
        return value;
      }
    }
  }
  return _defaultWebUIURL;
}

class WingApp extends StatelessWidget {
  const WingApp({super.key, required this.initialUrl});

  final String initialUrl;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'wing',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF2DD4BF),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: WingWebView(initialUrl: initialUrl),
    );
  }
}

class WingWebView extends StatefulWidget {
  const WingWebView({
    super.key,
    required this.initialUrl,
    this.autoConnect = true,
  });

  final String initialUrl;
  final bool autoConnect;

  @override
  State<WingWebView> createState() => _WingWebViewState();
}

class _WingWebViewState extends State<WingWebView> {
  final WebviewController _controller = WebviewController();
  final List<StreamSubscription<Object?>> _subscriptions = [];

  bool _webViewReady = false;
  bool _connecting = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    if (widget.autoConnect) {
      _openWebUI();
    }
  }

  Future<void> _openWebUI() async {
    setState(() {
      _connecting = true;
      _error = null;
    });

    try {
      await _waitForBackend(widget.initialUrl);
      await _controller.initialize();
      _subscriptions.add(
        _controller.containsFullScreenElementChanged.listen((isFullScreen) {
          windowManager.setFullScreen(isFullScreen);
        }),
      );

      await _controller.setBackgroundColor(const Color(0xFF111827));
      await _controller.setPopupWindowPolicy(
        WebviewPopupWindowPolicy.sameWindow,
      );
      await _controller.loadUrl(widget.initialUrl);

      if (!mounted) {
        return;
      }
      setState(() {
        _webViewReady = true;
        _connecting = false;
      });
    } on PlatformException catch (e) {
      _showError(e.message ?? e.code);
    } catch (e) {
      _showError(e.toString());
    }
  }

  Future<void> _waitForBackend(String url) async {
    final uri = Uri.parse(url);
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 1);
    try {
      for (var attempt = 1; attempt <= 24; attempt++) {
        if (!mounted) {
          return;
        }

        try {
          final request = await client.getUrl(uri);
          request.headers.set(HttpHeaders.cacheControlHeader, 'no-cache');
          final response = await request.close();
          await response.drain<void>();
          if (response.statusCode < HttpStatus.internalServerError) {
            return;
          }
        } catch (_) {
          await Future<void>.delayed(const Duration(milliseconds: 120));
        }
      }
      throw TimeoutException('Go 后端暂时没有响应');
    } finally {
      client.close(force: true);
    }
  }

  void _showError(String message) {
    if (!mounted) {
      return;
    }
    setState(() {
      _connecting = false;
      _error = message;
    });
  }

  Future<WebviewPermissionDecision> _onPermissionRequested(
    String url,
    WebviewPermissionKind kind,
    bool isUserInitiated,
  ) async {
    return WebviewPermissionDecision.deny;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF111827),
      body: Stack(
        children: [
          if (_webViewReady)
            Webview(_controller, permissionRequested: _onPermissionRequested)
          else
            _ConnectionStateView(
              connecting: _connecting,
              error: _error,
              onRetry: _openWebUI,
            ),
          if (_webViewReady)
            StreamBuilder<LoadingState>(
              stream: _controller.loadingState,
              builder: (context, snapshot) {
                if (snapshot.data == LoadingState.loading) {
                  return const Align(
                    alignment: Alignment.topCenter,
                    child: LinearProgressIndicator(minHeight: 2),
                  );
                }
                return const SizedBox.shrink();
              },
            ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    for (final subscription in _subscriptions) {
      subscription.cancel();
    }
    if (_controller.value.isInitialized) {
      _controller.dispose();
    }
    super.dispose();
  }
}

class _ConnectionStateView extends StatelessWidget {
  const _ConnectionStateView({
    required this.connecting,
    required this.error,
    required this.onRetry,
  });

  final bool connecting;
  final String? error;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 420),
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox.square(
                dimension: 44,
                child:
                    connecting
                        ? const CircularProgressIndicator(strokeWidth: 3)
                        : Icon(
                          Icons.signal_wifi_connected_no_internet_4,
                          color: theme.colorScheme.error,
                          size: 40,
                        ),
              ),
              const SizedBox(height: 20),
              Text(
                connecting ? '正在打开控制面板' : '控制面板启动失败',
                textAlign: TextAlign.center,
                style: theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 10),
              Text(
                connecting ? '请稍候，正在准备本地服务。' : (error ?? '未知错误'),
                textAlign: TextAlign.center,
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: Colors.white70,
                ),
              ),
              if (!connecting) ...[
                const SizedBox(height: 22),
                FilledButton.icon(
                  onPressed: onRetry,
                  icon: const Icon(Icons.refresh),
                  label: const Text('重试'),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
