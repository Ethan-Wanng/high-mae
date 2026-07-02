import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webview_windows/webview_windows.dart';
import 'package:window_manager/window_manager.dart';

const _defaultWebUIURL = 'http://127.0.0.1:10809/';
const _desktopScrollFallbackDelay = Duration(milliseconds: 30);
const _backendWatchInterval = Duration(seconds: 15);
const _backendWatchTimeout = Duration(seconds: 4);
const _backendWatchMaxMisses = 4;
const _desktopScrollFallbackScript = r'''
(() => {
  if (window.__wingDesktopScrollFallbackInstalled) return true;
  window.__wingDesktopScrollFallbackInstalled = true;
  window.__wingDesktopLastScrollAt = 0;
  window.__wingDesktopScrollAnimations = new WeakMap();
  const fallbackScale = 0.24;

  const scrollableOverflow = value => /(auto|scroll|overlay)/.test(value || '');
  const canScroll = (element, axis, delta) => {
    if (!element) return false;
    const root = document.scrollingElement || document.documentElement;
    const isRoot = element === root || element === document.documentElement || element === document.body;
    if (!isRoot) {
      const style = getComputedStyle(element);
      const overflow = axis === 'y' ? style.overflowY : style.overflowX;
      if (!scrollableOverflow(overflow)) return false;
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

  const findScrollTarget = (start, axis, delta) => {
    let element = start;
    while (element && element !== document.body) {
      if (canScroll(element, axis, delta)) return element;
      element = element.parentElement;
    }

    const root = document.scrollingElement || document.documentElement;
    return canScroll(root, axis, delta) ? root : null;
  };

  const currentScroll = (element, axis) => axis === 'y' ? element.scrollTop : element.scrollLeft;
  const maxScroll = (element, axis) => axis === 'y'
    ? element.scrollHeight - element.clientHeight
    : element.scrollWidth - element.clientWidth;
  const setScroll = (element, axis, value) => {
    if (axis === 'x') {
      element.scrollLeft = value;
    } else {
      element.scrollTop = value;
    }
  };

  const animateScroll = (element, axis, delta) => {
    const current = currentScroll(element, axis);
    const state = window.__wingDesktopScrollAnimations.get(element) || {};
    const active = state[axis];
    const target = Math.max(0, Math.min(maxScroll(element, axis), (active?.target ?? current) + delta));
    if (Math.abs(target - current) < 0.5) return true;
    if (active?.frame) cancelAnimationFrame(active.frame);

    const from = current;
    const start = performance.now();
    const duration = Math.min(190, Math.max(120, Math.abs(target - from) * 0.85));
    const animation = { target, frame: 0 };
    state[axis] = animation;
    window.__wingDesktopScrollAnimations.set(element, state);

    const tick = now => {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      setScroll(element, axis, from + (target - from) * eased);
      if (progress < 1) {
        animation.frame = requestAnimationFrame(tick);
        return;
      }
      setScroll(element, axis, target);
      if (state[axis] === animation) delete state[axis];
    };
    animation.frame = requestAnimationFrame(tick);
    return true;
  };

  document.addEventListener('scroll', () => {
    window.__wingDesktopLastScrollAt = performance.now();
  }, true);

  window.__wingDesktopScrollFallback = ({ x, y, dx, dy }) => {
    const now = performance.now();
    if (now - (window.__wingDesktopLastScrollAt || 0) < 120) return false;

    const target = document.elementFromPoint(x, y);
    if (!target) return false;
    if (target.closest('input, textarea, select, [contenteditable="true"]')) return false;

    const horizontalIntent = Math.abs(dx) > Math.abs(dy);
    const axis = horizontalIntent ? 'x' : 'y';
    const amount = (horizontalIntent ? dx : dy) * fallbackScale;
    if (Math.abs(amount) < 1) return false;

    const scrollTarget = findScrollTarget(target, axis, amount);
    if (!scrollTarget) return false;

    animateScroll(scrollTarget, axis, amount);
    window.__wingDesktopLastScrollAt = performance.now();
    return true;
  };
  return true;
})();
''';

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
    if (!_startupHiddenFromArgs(args)) {
      await windowManager.show();
      await windowManager.focus();
    }
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

bool _startupHiddenFromArgs(List<String> args) {
  return args.contains('--startup-hidden');
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

  Timer? _backendWatchTimer;
  int _backendWatchMisses = 0;
  bool _closingForBackendExit = false;
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
      await _installDesktopScrollFallback();
      await _controller.loadUrl(widget.initialUrl);

      if (!mounted) {
        return;
      }
      setState(() {
        _webViewReady = true;
        _connecting = false;
      });
      _startBackendWatchdog();
    } on PlatformException catch (e) {
      _showError(e.message ?? e.code);
    } catch (e) {
      _showError(e.toString());
    }
  }

  void _startBackendWatchdog() {
    _backendWatchTimer?.cancel();
    _backendWatchMisses = 0;
    _backendWatchTimer = Timer.periodic(_backendWatchInterval, (_) {
      unawaited(_checkBackendAlive());
    });
  }

  Future<void> _checkBackendAlive() async {
    if (!_webViewReady || _closingForBackendExit) {
      return;
    }
    final alive = await _probeBackend();
    if (!mounted || _closingForBackendExit) {
      return;
    }
    if (alive) {
      _backendWatchMisses = 0;
      return;
    }

    _backendWatchMisses += 1;
    if (_backendWatchMisses >= _backendWatchMaxMisses) {
      _closingForBackendExit = true;
      await windowManager.close();
    }
  }

  Future<bool> _probeBackend() async {
    final client = HttpClient()..connectionTimeout = _backendWatchTimeout;
    try {
      final statusUri = Uri.parse(widget.initialUrl).resolve('/healthz');
      final request = await client
          .getUrl(statusUri)
          .timeout(_backendWatchTimeout);
      final response = await request.close().timeout(_backendWatchTimeout);
      await response.drain<void>();
      return response.statusCode == HttpStatus.noContent;
    } catch (_) {
      return false;
    } finally {
      client.close(force: true);
    }
  }

  Future<void> _installDesktopScrollFallback() async {
    await _controller.addScriptToExecuteOnDocumentCreated(
      _desktopScrollFallbackScript,
    );
  }

  void _handlePointerSignal(PointerSignalEvent event) {
    if (event is! PointerScrollEvent || !_controller.value.isInitialized) {
      return;
    }
    final position = event.localPosition;
    final delta = event.scrollDelta;
    Timer(_desktopScrollFallbackDelay, () {
      _runDesktopScrollFallback(position, delta);
    });
  }

  Future<void> _runDesktopScrollFallback(Offset position, Offset delta) async {
    if (!_controller.value.isInitialized) {
      return;
    }
    final payload = jsonEncode({
      'x': position.dx,
      'y': position.dy,
      'dx': delta.dx,
      'dy': delta.dy,
    });
    try {
      await _controller.executeScript(
        'window.__wingDesktopScrollFallback && '
        'window.__wingDesktopScrollFallback($payload);',
      );
    } catch (_) {
      // Ignore transient navigation/disposal races; native WebView scrolling
      // still gets the original pointer event.
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
            Listener(
              onPointerSignal: _handlePointerSignal,
              child: Webview(
                _controller,
                permissionRequested: _onPermissionRequested,
              ),
            )
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
    _backendWatchTimer?.cancel();
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
    if (connecting) {
      return const SizedBox.expand();
    }

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
                child: Icon(
                  Icons.signal_wifi_connected_no_internet_4,
                  color: theme.colorScheme.error,
                  size: 40,
                ),
              ),
              const SizedBox(height: 20),
              Text(
                '控制面板启动失败',
                textAlign: TextAlign.center,
                style: theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 10),
              Text(
                error ?? '未知错误',
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
