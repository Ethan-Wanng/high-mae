part of 'android_app.dart';

Map<String, dynamic> _defaultAutoSelectConfig() => {
  'enabled': false,
  'scope': 'subscription',
  'subscriptionFiles': <String>[],
  'aggregateFiles': <String>[],
  'siteCheck': {
    'mode': 'none',
    'ids': <String>[],
    'defaultSelectionApplied': false,
  },
  'ignoreTimeout': true,
  'excludedNodeKeys': <String>[],
  'discardedRules': <Object>[],
  'rules': <Object>[],
};

class _AutoSelectSettingsPage extends StatefulWidget {
  const _AutoSelectSettingsPage({required this.api});

  final WingApi api;

  @override
  State<_AutoSelectSettingsPage> createState() =>
      _AutoSelectSettingsPageState();
}

class _AutoSelectSettingsPageState extends State<_AutoSelectSettingsPage> {
  Map<String, dynamic> _config = _defaultAutoSelectConfig();
  List<Map<String, dynamic>> _suppliers = const [];
  List<Map<String, dynamic>> _nodes = const [];
  final _excludedKeywords = TextEditingController();
  final _excludedProtocols = TextEditingController();
  bool _loading = true;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final values = await Future.wait<Object>([
        widget.api.getAutoSelectConfig(),
        widget.api.getSuppliers(),
        widget.api.getNodes(),
      ]);
      final config = {
        ..._defaultAutoSelectConfig(),
        ...Map<String, dynamic>.from(values[0] as Map),
      };
      final rules = _mapList(config['rules']);
      _excludedKeywords.text = _ruleValues(rules, 'exclude_keyword').join(', ');
      _excludedProtocols.text = _ruleValues(
        rules,
        'exclude_protocol',
      ).join(', ');
      if (!mounted) return;
      setState(() {
        _config = config;
        _suppliers = List<Map<String, dynamic>>.from(values[1] as List);
        _nodes = List<Map<String, dynamic>>.from(values[2] as List);
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() => _loading = false);
      _snack(context, error.toString());
    }
  }

  List<Map<String, dynamic>> get _aggregateSources {
    final supplierFiles =
        _suppliers.map((item) => item['fileName']?.toString() ?? '').toSet();
    final sources = <String, Map<String, dynamic>>{};
    for (final node in _nodes) {
      final file = node['fileName']?.toString() ?? '';
      if (file.isEmpty ||
          file == 'custom_nodes.yml' ||
          supplierFiles.contains(file)) {
        continue;
      }
      sources.putIfAbsent(
        file,
        () => {'fileName': file, 'name': node['group']},
      );
    }
    return sources.values.toList(growable: false);
  }

  Future<void> _save() async {
    if (_saving) return;
    setState(() => _saving = true);
    try {
      final rules =
          _mapList(_config['rules'])
              .where(
                (rule) =>
                    rule['type'] != 'exclude_keyword' &&
                    rule['type'] != 'exclude_protocol',
              )
              .toList();
      void addRule(String type, String label, TextEditingController input) {
        final values = _splitValues(input.text);
        if (values.isNotEmpty) {
          rules.add({
            'id': 'android_${type}_${DateTime.now().millisecondsSinceEpoch}',
            'type': type,
            'label': label,
            'values': values,
            'value': values.join(','),
          });
        }
      }

      addRule('exclude_keyword', '排除关键字', _excludedKeywords);
      addRule('exclude_protocol', '排除协议', _excludedProtocols);
      _config['rules'] = rules;
      final response = await widget.api.saveAutoSelectConfig(_config);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '保存自动选择设置失败');
      }
      if (mounted) Navigator.pop(context, _config['enabled'] == true);
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    final scope = _config['scope']?.toString() ?? 'subscription';
    final selectedSubscriptions = _stringSet(_config['subscriptionFiles']);
    final selectedAggregates = _stringSet(_config['aggregateFiles']);
    final siteCheck = Map<String, dynamic>.from(
      _config['siteCheck'] as Map? ?? const {},
    );
    return Scaffold(
      appBar: AppBar(
        title: const Text('自动选择'),
        actions: [
          TextButton(
            onPressed: _saving ? null : _save,
            child: Text(_saving ? '保存中' : '保存'),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        children: [
          SwitchListTile(
            value: _config['enabled'] == true,
            onChanged: (value) => setState(() => _config['enabled'] = value),
            title: const Text('启用自动选择'),
            subtitle: const Text('进入节点页时立即选优，并在应用运行期间定期检查'),
            secondary: const Icon(Icons.auto_awesome_rounded),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            value: scope,
            decoration: const InputDecoration(labelText: '候选节点范围'),
            items: const [
              DropdownMenuItem(value: 'all', child: Text('全部节点')),
              DropdownMenuItem(value: 'subscription', child: Text('指定订阅')),
              DropdownMenuItem(value: 'aggregate', child: Text('指定聚合组')),
            ],
            onChanged:
                (value) => setState(() => _config['scope'] = value ?? 'all'),
          ),
          if (scope == 'subscription') ...[
            const SizedBox(height: 18),
            const Text('订阅范围（不选则使用当前订阅）'),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 6,
              children:
                  _suppliers.map((supplier) {
                    final file = supplier['fileName']?.toString() ?? '';
                    return FilterChip(
                      selected: selectedSubscriptions.contains(file),
                      label: Text(supplier['name']?.toString() ?? file),
                      onSelected: (selected) {
                        setState(() {
                          selected
                              ? selectedSubscriptions.add(file)
                              : selectedSubscriptions.remove(file);
                          _config['subscriptionFiles'] =
                              selectedSubscriptions.toList();
                        });
                      },
                    );
                  }).toList(),
            ),
          ],
          if (scope == 'aggregate') ...[
            const SizedBox(height: 18),
            const Text('聚合组范围'),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 6,
              children:
                  _aggregateSources.map((source) {
                    final file = source['fileName']?.toString() ?? '';
                    return FilterChip(
                      selected: selectedAggregates.contains(file),
                      label: Text(source['name']?.toString() ?? file),
                      onSelected: (selected) {
                        setState(() {
                          selected
                              ? selectedAggregates.add(file)
                              : selectedAggregates.remove(file);
                          _config['aggregateFiles'] =
                              selectedAggregates.toList();
                        });
                      },
                    );
                  }).toList(),
            ),
          ],
          const SizedBox(height: 18),
          DropdownButtonFormField<String>(
            value: siteCheck['mode']?.toString() ?? 'none',
            decoration: const InputDecoration(labelText: '网站可用性筛选'),
            items: const [
              DropdownMenuItem(value: 'none', child: Text('不检查网站')),
              DropdownMenuItem(value: 'any', child: Text('任一网站可用')),
              DropdownMenuItem(value: 'all', child: Text('全部网站可用')),
            ],
            onChanged: (value) {
              setState(() {
                _config['siteCheck'] = {...siteCheck, 'mode': value ?? 'none'};
              });
            },
          ),
          const SizedBox(height: 18),
          TextField(
            controller: _excludedKeywords,
            decoration: const InputDecoration(
              labelText: '排除关键字',
              hintText: '例如：香港, 到期, 流量',
              helperText: '用逗号分隔，匹配节点名、来源组和文件名',
            ),
          ),
          const SizedBox(height: 18),
          TextField(
            controller: _excludedProtocols,
            decoration: const InputDecoration(
              labelText: '排除协议',
              hintText: '例如：ss, trojan',
              helperText: '用逗号分隔；Windows 端保存的其他筛选规则也会继续生效',
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _excludedKeywords.dispose();
    _excludedProtocols.dispose();
    super.dispose();
  }
}

Future<Map<String, dynamic>> _performAutoSelect(
  WingApi api,
  Map<String, dynamic> config, {
  ValueChanged<String>? onProgress,
}) async {
  var nodes = await api.getNodes();
  if (nodes.isEmpty) throw const WingApiException('没有可用于自动选择的节点');
  final suppliers = await api.getSuppliers();
  final supplierFiles =
      suppliers
          .map((item) => item['fileName']?.toString() ?? '')
          .where((value) => value.isNotEmpty)
          .toSet();
  final scope = config['scope']?.toString() ?? 'subscription';
  var targets = <String>{};
  if (scope == 'subscription') {
    targets = _stringSet(config['subscriptionFiles']);
    if (targets.isEmpty) {
      final active = suppliers.where((item) => item['active'] == true);
      final fallback =
          active.isNotEmpty
              ? active.first
              : suppliers.isNotEmpty
              ? suppliers.first
              : null;
      final file = fallback?['fileName']?.toString() ?? '';
      if (file.isNotEmpty) targets.add(file);
    }
  } else if (scope == 'aggregate') {
    targets = _stringSet(config['aggregateFiles']);
  }
  var candidates =
      nodes.where((node) {
        final file = node['fileName']?.toString() ?? '';
        if (scope == 'subscription' && !targets.contains(file)) return false;
        if (scope == 'aggregate' && !targets.contains(file)) return false;
        if (scope == 'subscription' && !supplierFiles.contains(file)) {
          return false;
        }
        return _nodePassesAutoRules(node, config, checkTimeout: false);
      }).toList();
  if (candidates.isEmpty) {
    throw const WingApiException('自动选择范围内没有符合规则的候选节点');
  }

  onProgress?.call('正在并发测试 ${candidates.length} 个候选节点…');
  var cursor = 0;
  Future<void> worker() async {
    while (cursor < candidates.length) {
      final position = cursor++;
      final node = candidates[position];
      var latency = -1;
      try {
        latency = await api.testNode((node['index'] as num).toInt());
      } catch (_) {}
      candidates[position] = {...node, 'latency': latency};
    }
  }

  final workerCount = candidates.length < 8 ? candidates.length : 8;
  await Future.wait(List.generate(workerCount, (_) => worker()));
  candidates =
      candidates
          .where(
            (node) =>
                ((node['latency'] as num?)?.toInt() ?? -1) > 0 &&
                _nodePassesAutoRules(node, config, checkTimeout: true),
          )
          .toList()
        ..sort((a, b) => (a['latency'] as num).compareTo(b['latency'] as num));
  if (candidates.isEmpty) {
    throw const WingApiException('自动选择没有找到可用节点');
  }

  final siteCheck = Map<String, dynamic>.from(
    config['siteCheck'] as Map? ?? const {},
  );
  final siteMode = siteCheck['mode']?.toString() ?? 'none';
  final selectedSiteIds = _stringSet(siteCheck['ids']);
  for (final candidate in candidates) {
    final response = await api.switchNode((candidate['index'] as num).toInt());
    if (response['ok'] != true) continue;
    if (siteMode == 'none') return candidate;
    try {
      final result = await api.testSites();
      var checks = _mapList(result['results']);
      if (selectedSiteIds.isNotEmpty) {
        checks =
            checks
                .where(
                  (item) => selectedSiteIds.contains(item['id']?.toString()),
                )
                .toList();
      }
      if (checks.isEmpty) return candidate;
      final passed = checks.where((item) => item['ok'] == true).length;
      if ((siteMode == 'any' && passed > 0) ||
          (siteMode == 'all' && passed == checks.length)) {
        return candidate;
      }
    } catch (_) {}
  }
  throw const WingApiException('没有节点满足网站可用性规则');
}

bool _nodePassesAutoRules(
  Map<String, dynamic> node,
  Map<String, dynamic> config, {
  required bool checkTimeout,
}) {
  if (_stringSet(config['excludedNodeKeys']).contains(_autoNodeKey(node))) {
    return false;
  }
  if (checkTimeout &&
      config['ignoreTimeout'] == true &&
      (node['latency'] as num?)?.toInt() == -1) {
    return false;
  }
  final text =
      [
        node['name'],
        node['sourceName'],
        node['group'],
        node['type'],
        node['fileName'],
        node['sourceFile'],
      ].join(' ').toLowerCase();
  final protocol = node['type']?.toString().toLowerCase() ?? '';
  final source =
      [
        node['sourceFile'],
        node['fileName'],
        node['group'],
      ].join(' ').toLowerCase();
  for (final rule in _mapList(config['rules'])) {
    final values = _valuesFromRule(rule);
    if (values.isEmpty) continue;
    final type = rule['type']?.toString();
    bool matches(String target) =>
        values.any((value) => target.contains(value.toLowerCase()));
    switch (type) {
      case 'exclude_keyword':
        if (matches(text)) return false;
      case 'include_region':
      case 'include_node':
        if (!matches(text)) return false;
      case 'include_subscription':
      case 'include_aggregate_group':
        if (!matches(source)) return false;
      case 'include_protocol':
        if (!matches(protocol)) return false;
      case 'exclude_protocol':
        if (matches(protocol)) return false;
    }
  }
  return true;
}

String _autoNodeKey(Map<String, dynamic> node) => [
  node['fileName'] ?? '',
  node['sourceFile'] ?? '',
  node['subIndex'] ?? '',
  node['sourceName'] ?? '',
  node['name'] ?? '',
  node['type'] ?? '',
].join('\u001f');

List<Map<String, dynamic>> _mapList(Object? value) =>
    (value as List? ?? const [])
        .whereType<Map>()
        .map((item) => Map<String, dynamic>.from(item))
        .toList();

Set<String> _stringSet(Object? value) =>
    (value as List? ?? const [])
        .map((item) => item.toString().trim())
        .where((item) => item.isNotEmpty)
        .toSet();

List<String> _splitValues(String value) =>
    value
        .split(RegExp(r'[,，\n]'))
        .map((item) => item.trim())
        .where((item) => item.isNotEmpty)
        .toSet()
        .toList();

List<String> _valuesFromRule(Map<String, dynamic> rule) {
  final values = _stringSet(rule['values']).toList();
  if (values.isNotEmpty) return values;
  return _splitValues(rule['value']?.toString() ?? '');
}

List<String> _ruleValues(List<Map<String, dynamic>> rules, String type) =>
    rules
        .where((rule) => rule['type'] == type)
        .expand(_valuesFromRule)
        .toSet()
        .toList();
