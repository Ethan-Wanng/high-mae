import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

const _androidDefaultWebUIURL = 'http://10.0.2.2:10809/';
const _iosDefaultWebUIURL = 'http://127.0.0.1:10809/';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(WingMobileApp(initialUrl: _defaultMobileWebUIURL()));
}

String _defaultMobileWebUIURL() {
  if (Platform.isAndroid) return _androidDefaultWebUIURL;
  return _iosDefaultWebUIURL;
}

class WingMobileApp extends StatelessWidget {
  const WingMobileApp({super.key, required this.initialUrl});

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
  late final TextEditingController _urlController;
  WebViewController? _controller;
  bool _webViewReady = false;
  bool _connecting = true;
  String? _error;
  double _progress = 0;

  @override
  void initState() {
    super.initState();
    _urlController = TextEditingController(text: widget.initialUrl);
    if (widget.autoConnect) {
      _openWebUI();
    }
  }

  WebViewController _ensureController() {
    final existing = _controller;
    if (existing != null) return existing;

    final controller =
        WebViewController()
          ..setJavaScriptMode(JavaScriptMode.unrestricted)
          ..setBackgroundColor(const Color(0xFF111827))
          ..setNavigationDelegate(
            NavigationDelegate(
              onNavigationRequest: (request) {
                if (_isAllowedControlPanelURL(request.url)) {
                  return NavigationDecision.navigate;
                }
                if (mounted) {
                  setState(() {
                    _connecting = false;
                    _webViewReady = false;
                    _error = '仅允许打开本机、模拟器或私有局域网控制面板地址。';
                  });
                }
                return NavigationDecision.prevent;
              },
              onProgress: (progress) {
                if (mounted) setState(() => _progress = progress / 100);
              },
              onPageStarted: (_) {
                if (mounted) {
                  setState(() {
                    _connecting = true;
                    _error = null;
                    _progress = 0;
                  });
                }
              },
              onPageFinished: (_) {
                if (mounted) {
                  setState(() {
                    _webViewReady = true;
                    _connecting = false;
                    _progress = 1;
                  });
                }
              },
              onWebResourceError: (error) {
                if (!mounted || _webViewReady) return;
                setState(() {
                  _connecting = false;
                  _error = error.description;
                });
              },
            ),
          );
    _controller = controller;
    return controller;
  }

  Future<void> _openWebUI() async {
    final normalized = _normalizeURL(_urlController.text);
    _urlController.text = normalized;
    if (!_isAllowedControlPanelURL(normalized)) {
      setState(() {
        _connecting = false;
        _webViewReady = false;
        _error = '请输入本机、Android 模拟器或私有局域网地址。';
        _progress = 0;
      });
      return;
    }

    final controller = _ensureController();
    setState(() {
      _connecting = true;
      _webViewReady = false;
      _error = null;
      _progress = 0;
    });

    try {
      await controller.loadRequest(Uri.parse(normalized));
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _connecting = false;
        _error = e.toString();
      });
    }
  }

  String _normalizeURL(String raw) {
    final value = raw.trim();
    if (value.isEmpty) return widget.initialUrl;
    if (value.startsWith('http://') || value.startsWith('https://')) {
      return value.endsWith('/') ? value : '$value/';
    }
    return 'http://$value/';
  }

  bool _isAllowedControlPanelURL(String raw) {
    final uri = Uri.tryParse(raw);
    if (uri == null || uri.host.isEmpty) return false;
    if (uri.scheme != 'http' && uri.scheme != 'https') return false;
    return _isLocalOrPrivateHost(uri.host);
  }

  bool _isLocalOrPrivateHost(String host) {
    final value = host.toLowerCase();
    if (value == 'localhost' || value == '10.0.2.2' || value == '10.0.3.2') {
      return true;
    }

    final ip = InternetAddress.tryParse(value);
    if (ip == null) {
      return value.endsWith('.local');
    }
    if (ip.type == InternetAddressType.IPv4) {
      final parts = value.split('.').map(int.tryParse).toList(growable: false);
      if (parts.length != 4 || parts.any((part) => part == null)) {
        return false;
      }
      final first = parts[0]!;
      final second = parts[1]!;
      return first == 10 ||
          first == 127 ||
          (first == 172 && second >= 16 && second <= 31) ||
          (first == 192 && second == 168) ||
          (first == 169 && second == 254);
    }
    if (ip.type == InternetAddressType.IPv6) {
      return value == '::1' ||
          value.startsWith('fc') ||
          value.startsWith('fd') ||
          value.startsWith('fe80:');
    }
    return false;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF111827),
      appBar: AppBar(
        titleSpacing: 12,
        title: TextField(
          controller: _urlController,
          autocorrect: false,
          enableSuggestions: false,
          keyboardType: TextInputType.url,
          textInputAction: TextInputAction.go,
          onSubmitted: (_) => _openWebUI(),
          style: const TextStyle(fontSize: 13),
          decoration: const InputDecoration(
            isDense: true,
            hintText: '控制面板地址，如 192.168.1.8:10809',
            border: InputBorder.none,
          ),
        ),
        actions: [
          IconButton(
            tooltip: '打开',
            onPressed: _openWebUI,
            icon: const Icon(Icons.arrow_forward),
          ),
          IconButton(
            tooltip: '刷新',
            onPressed: () {
              final controller = _controller;
              if (controller == null) {
                _openWebUI();
                return;
              }
              controller.reload();
            },
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: Stack(
        children: [
          if (_webViewReady && _controller != null)
            WebViewWidget(controller: _controller!),
          if (!_webViewReady)
            _ConnectionStateView(
              connecting: _connecting,
              error: _error,
              onRetry: _openWebUI,
            ),
          if (_connecting && _progress < 1)
            Align(
              alignment: Alignment.topCenter,
              child: LinearProgressIndicator(
                value: _progress == 0 ? null : _progress,
              ),
            ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _urlController.dispose();
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
        constraints: const BoxConstraints(maxWidth: 440),
        child: Padding(
          padding: const EdgeInsets.all(28),
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
                connecting ? '正在打开控制面板' : '无法连接控制面板',
                textAlign: TextAlign.center,
                style: theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 10),
              Text(
                connecting
                    ? 'Android 模拟器默认使用 10.0.2.2；真机需显式开放后端并填写局域网 IP。'
                    : (error ?? '请确认 wing 后端已启动，且手机可以访问该地址。'),
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
