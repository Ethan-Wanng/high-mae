part of 'android_app.dart';

const autoSelectRuleTypes = <String, String>{
  'exclude_keyword': '不使用包含',
  'include_region': '只选择地区',
  'include_protocol': '只使用协议',
  'exclude_protocol': '不使用协议',
  'include_node': '只选择节点',
  'include_subscription': '只选择订阅组',
};

const _allKnownAutoSelectRuleTypes = <String, String>{
  ...autoSelectRuleTypes,
  'include_aggregate_group': '只选择聚合组',
};

const _commonAutoSelectProtocols = <String>[
  'vless',
  'vmess',
  'trojan',
  'ss',
  'hysteria2',
  'tuic',
  'anytls',
];

List<String> splitAutoSelectValues(String raw) {
  final seen = <String>{};
  final result = <String>[];
  for (final part in raw.split(RegExp(r'[,\n，、]'))) {
    final trimmed = part.trim();
    if (trimmed.isEmpty || !seen.add(trimmed)) continue;
    result.add(trimmed);
  }
  return result;
}

String autoSelectRuleTypeLabel(String type) =>
    _allKnownAutoSelectRuleTypes[type] ?? autoSelectRuleTypes['exclude_keyword']!;

String _normalizeAutoSelectProtocol(String raw) {
  switch (raw.trim().toLowerCase()) {
    case 'hy2':
    case 'hysteria2':
      return 'hysteria2';
    case 'shadowsocks':
    case 'ss':
      return 'ss';
    case 'socks':
    case 'socks5':
      return 'socks5';
    default:
      return raw.trim().toLowerCase();
  }
}

List<String> _normalizedUniqueStrings(Iterable<Object?> values) {
  final seen = <String>{};
  final out = <String>[];
  for (final raw in values) {
    final text = raw?.toString().trim() ?? '';
    if (text.isEmpty || !seen.add(text)) continue;
    out.add(text);
  }
  return out;
}

List<String> _normalizedFileNames(Iterable<Object?> values) {
  final seen = <String>{};
  final out = <String>[];
  for (final raw in values) {
    var file = raw?.toString().trim() ?? '';
    if (file.isEmpty) continue;
    try {
      file = Uri.decodeComponent(file);
    } catch (_) {}
    if (file.isEmpty || !seen.add(file)) continue;
    out.add(file);
  }
  return out;
}

class AutoSelectRule {
  const AutoSelectRule({
    required this.id,
    required this.type,
    required this.value,
    this.values = const [],
    this.label = '',
  });

  final String id;
  final String type;
  final String value;
  final List<String> values;
  final String label;

  List<String> get effectiveValues {
    if (values.isNotEmpty) {
      return _normalizedUniqueStrings(values);
    }
    return splitAutoSelectValues(value);
  }

  factory AutoSelectRule.fromJson(Map<String, dynamic> json, {int fallbackIndex = 0}) {
    final rawType = json['type']?.toString().trim() ?? 'exclude_keyword';
    final type =
        _allKnownAutoSelectRuleTypes.containsKey(rawType)
            ? rawType
            : 'exclude_keyword';
    final rawValue = json['value']?.toString() ?? '';
    final rawValues =
        (json['values'] as List? ?? const [])
            .map((e) => e?.toString() ?? '')
            .where((e) => e.trim().isNotEmpty)
            .toList(growable: false);
    final effective =
        rawValues.isNotEmpty
            ? _normalizedUniqueStrings(rawValues)
            : splitAutoSelectValues(rawValue);
    final id = json['id']?.toString().trim() ?? '';
    return AutoSelectRule(
      id: id.isEmpty ? 'rule_${fallbackIndex + 1}' : id,
      type: type,
      value: effective.isNotEmpty ? effective.join(',') : rawValue.trim(),
      values: effective,
      label: json['label']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() {
    final effective = effectiveValues;
    return {
      'id': id,
      'type': type,
      'value': effective.isNotEmpty ? effective.join(',') : value.trim(),
      if (effective.isNotEmpty) 'values': effective,
      if (label.isNotEmpty) 'label': label,
    };
  }
}

class AutoSelectSiteCheck {
  const AutoSelectSiteCheck({
    this.mode = 'none',
    this.ids = const [],
    this.defaultSelectionApplied = false,
  });

  final String mode;
  final List<String> ids;
  final bool defaultSelectionApplied;

  factory AutoSelectSiteCheck.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const AutoSelectSiteCheck();
    final rawMode = json['mode']?.toString() ?? 'none';
    final mode = const {'none', 'any', 'all'}.contains(rawMode) ? rawMode : 'none';
    return AutoSelectSiteCheck(
      mode: mode,
      ids: _normalizedUniqueStrings(json['ids'] as List? ?? const []),
      defaultSelectionApplied: json['defaultSelectionApplied'] == true,
    );
  }

  AutoSelectSiteCheck copyWith({
    String? mode,
    List<String>? ids,
    bool? defaultSelectionApplied,
  }) => AutoSelectSiteCheck(
    mode: mode ?? this.mode,
    ids: ids ?? this.ids,
    defaultSelectionApplied:
        defaultSelectionApplied ?? this.defaultSelectionApplied,
  );

  Map<String, dynamic> toJson() => {
    'mode': mode,
    'ids': ids,
    'defaultSelectionApplied': defaultSelectionApplied,
  };
}

class AutoSelectConfig {
  const AutoSelectConfig({
    this.enabled = false,
    this.scope = 'subscription',
    this.subscriptionFiles = const [],
    this.aggregateFiles = const [],
    this.siteCheck = const AutoSelectSiteCheck(),
    this.ignoreTimeout = true,
    this.excludedNodeKeys = const [],
    this.discardedRules = const [],
    this.rules = const [],
  });

  final bool enabled;
  final String scope;
  final List<String> subscriptionFiles;
  final List<String> aggregateFiles;
  final AutoSelectSiteCheck siteCheck;
  final bool ignoreTimeout;
  final List<String> excludedNodeKeys;
  final List<Map<String, dynamic>> discardedRules;
  final List<AutoSelectRule> rules;

  factory AutoSelectConfig.defaults() => const AutoSelectConfig(
    enabled: false,
    scope: 'subscription',
    rules: [
      AutoSelectRule(
        id: 'preset_no_hk',
        type: 'exclude_keyword',
        value: '香港',
        values: ['香港'],
        label: '不使用香港的节点',
      ),
    ],
  );

  factory AutoSelectConfig.fromJson(Map<String, dynamic>? json) {
    if (json == null) return AutoSelectConfig.defaults();
    final rawScope = json['scope']?.toString() ?? 'subscription';
    final scope =
        const {'all', 'subscription', 'aggregate'}.contains(rawScope)
            ? rawScope
            : 'subscription';

    final rawSubFiles = <Object?>[
      ...(json['subscriptionFiles'] as List? ?? const []),
      if (json['subscriptionFile'] != null) json['subscriptionFile'],
    ];
    final rawAggFiles = <Object?>[
      ...(json['aggregateFiles'] as List? ?? const []),
      if (json['aggregateFile'] != null) json['aggregateFile'],
    ];

    final rawSiteCheck = json['siteCheck'];
    final siteCheck = AutoSelectSiteCheck.fromJson(
      rawSiteCheck is Map ? Map<String, dynamic>.from(rawSiteCheck) : null,
    );

    final rawDiscarded = <Map<String, dynamic>>[];
    for (final item in (json['discardedRules'] as List? ?? const [])) {
      if (item is Map) {
        rawDiscarded.add(Map<String, dynamic>.from(item));
        if (rawDiscarded.length >= 5) break;
      }
    }

    final rawRules = <AutoSelectRule>[];
    final jsonRules = json['rules'] as List? ?? const [];
    for (var i = 0; i < jsonRules.length; i++) {
      final item = jsonRules[i];
      if (item is Map) {
        rawRules.add(
          AutoSelectRule.fromJson(
            Map<String, dynamic>.from(item),
            fallbackIndex: i,
          ),
        );
      }
    }

    return AutoSelectConfig(
      enabled: json['enabled'] == true,
      scope: scope,
      subscriptionFiles: _normalizedFileNames(rawSubFiles),
      aggregateFiles: _normalizedFileNames(rawAggFiles),
      siteCheck: siteCheck,
      ignoreTimeout: true,
      excludedNodeKeys: _normalizedUniqueStrings(
        json['excludedNodeKeys'] as List? ?? const [],
      ),
      discardedRules: rawDiscarded,
      rules: rawRules,
    );
  }

  AutoSelectConfig copyWith({
    bool? enabled,
    String? scope,
    List<String>? subscriptionFiles,
    List<String>? aggregateFiles,
    AutoSelectSiteCheck? siteCheck,
    List<String>? excludedNodeKeys,
    List<Map<String, dynamic>>? discardedRules,
    List<AutoSelectRule>? rules,
  }) => AutoSelectConfig(
    enabled: enabled ?? this.enabled,
    scope: scope ?? this.scope,
    subscriptionFiles: subscriptionFiles ?? this.subscriptionFiles,
    aggregateFiles: aggregateFiles ?? this.aggregateFiles,
    siteCheck: siteCheck ?? this.siteCheck,
    ignoreTimeout: true,
    excludedNodeKeys: excludedNodeKeys ?? this.excludedNodeKeys,
    discardedRules: discardedRules ?? this.discardedRules,
    rules: rules ?? this.rules,
  );

  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'scope': scope,
    'subscriptionFiles': subscriptionFiles,
    'aggregateFiles': aggregateFiles,
    'siteCheck': siteCheck.toJson(),
    'ignoreTimeout': ignoreTimeout,
    'excludedNodeKeys': excludedNodeKeys,
    'discardedRules': discardedRules,
    'rules': rules.map((r) => r.toJson()).toList(growable: false),
  };
}

String autoSelectNodeKey(Map<String, dynamic> node) => [
  node['fileName']?.toString() ?? '',
  node['sourceFile']?.toString() ?? '',
  node['subIndex']?.toString() ?? '',
  node['sourceName']?.toString() ?? '',
  node['name']?.toString() ?? '',
  node['type']?.toString() ?? '',
].join('\u001f');

String _supplierNameForAutoSelectNode(
  Map<String, dynamic> node,
  List<Map<String, dynamic>> suppliers,
) {
  final sourceFile =
      (node['sourceFile']?.toString() ?? '').isNotEmpty
          ? node['sourceFile'].toString()
          : (node['fileName']?.toString() ?? '');
  for (final s in suppliers) {
    if (s['fileName']?.toString() == sourceFile) {
      return s['name']?.toString() ?? '';
    }
  }
  return '';
}

bool _valuesMatchText(List<String> values, String text) {
  final haystack = text.toLowerCase();
  for (final value in values) {
    final needle = value.trim().toLowerCase();
    if (needle.isNotEmpty && haystack.contains(needle)) {
      return true;
    }
  }
  return false;
}

bool _protocolValuesMatch(List<String> values, String nodeType) {
  final normalizedNode = _normalizeAutoSelectProtocol(nodeType);
  if (normalizedNode.isEmpty) return false;
  for (final value in values) {
    final normalizedRule = _normalizeAutoSelectProtocol(value);
    if (normalizedRule.isEmpty) continue;
    if (normalizedNode == normalizedRule) {
      return true;
    }
  }
  return false;
}

bool nodePassesAutoSelectRules(
  Map<String, dynamic> node,
  AutoSelectConfig config,
  List<Map<String, dynamic>> suppliers, {
  bool ignoreTimeout = true,
}) {
  if (config.excludedNodeKeys.contains(autoSelectNodeKey(node))) {
    return false;
  }
  final latency = (node['latency'] as num?)?.toInt() ?? 0;
  if (ignoreTimeout && latency == -1) {
    return false;
  }
  if (config.rules.isEmpty) return true;

  final supplierName = _supplierNameForAutoSelectNode(node, suppliers);
  final fileName = node['fileName']?.toString() ?? '';
  final sourceFile = node['sourceFile']?.toString() ?? '';
  final nodeType = node['type']?.toString() ?? '';
  final groupName = node['group']?.toString() ?? '';
  final searchText = [
    node['name']?.toString() ?? '',
    node['sourceName']?.toString() ?? '',
    groupName,
    nodeType,
    fileName,
    sourceFile,
    supplierName,
  ].join(' ');
  final supplierText = [
    sourceFile.isNotEmpty ? sourceFile : fileName,
    supplierName,
    groupName,
  ].join(' ');
  final aggregateText = [fileName, groupName].join(' ');

  for (final rule in config.rules) {
    final values = rule.effectiveValues;
    if (values.isEmpty) continue;
    final passed = switch (rule.type) {
      'exclude_keyword' => !_valuesMatchText(values, searchText),
      'include_region' || 'include_node' => _valuesMatchText(values, searchText),
      'include_subscription' => _valuesMatchText(values, supplierText),
      'include_aggregate_group' => _valuesMatchText(values, aggregateText),
      'include_protocol' => _protocolValuesMatch(values, nodeType),
      'exclude_protocol' => !_protocolValuesMatch(values, nodeType),
      _ => true,
    };
    if (!passed) return false;
  }
  return true;
}

List<Map<String, dynamic>> filterAutoSelectCandidates(
  List<Map<String, dynamic>> allNodes,
  AutoSelectConfig config,
  List<Map<String, dynamic>> suppliers, {
  bool ignoreTimeout = true,
}) {
  Iterable<Map<String, dynamic>> scoped;
  switch (config.scope) {
    case 'all':
      scoped = allNodes;
    case 'aggregate':
      final aggFiles = config.aggregateFiles;
      if (aggFiles.isEmpty) {
        scoped = const [];
      } else {
        scoped = allNodes.where(
          (n) => aggFiles.contains(n['fileName']?.toString() ?? ''),
        );
      }
    default:
      final targets = <String>[...config.subscriptionFiles];
      if (targets.isEmpty && suppliers.isNotEmpty) {
        final active = suppliers.where((s) => s['active'] == true);
        final fallback =
            active.isNotEmpty
                ? active.first['fileName']?.toString()
                : suppliers.first['fileName']?.toString();
        if (fallback != null && fallback.isNotEmpty) {
          targets.add(fallback);
        }
      }
      if (targets.isEmpty) {
        scoped = const [];
      } else {
        scoped = allNodes.where(
          (n) => targets.contains(n['fileName']?.toString() ?? ''),
        );
      }
  }
  return scoped
      .where(
        (node) => nodePassesAutoSelectRules(
          node,
          config,
          suppliers,
          ignoreTimeout: ignoreTimeout,
        ),
      )
      .toList(growable: false);
}

class _AutoSelectPane extends StatelessWidget {
  const _AutoSelectPane({
    required this.config,
    required this.loading,
    required this.running,
    required this.statusText,
    required this.progress,
    required this.candidates,
    required this.allNodes,
    required this.suppliers,
    required this.siteTargets,
    required this.switchingNodeKey,
    required this.onRefresh,
    required this.onToggleEnabled,
    required this.onRunNow,
    required this.onStop,
    required this.onConfigChanged,
    required this.onSwitchNode,
  });

  final AutoSelectConfig config;
  final bool loading;
  final bool running;
  final String? statusText;
  final double? progress;
  final List<Map<String, dynamic>> candidates;
  final List<Map<String, dynamic>> allNodes;
  final List<Map<String, dynamic>> suppliers;
  final List<Map<String, dynamic>> siteTargets;
  final String? switchingNodeKey;
  final Future<void> Function() onRefresh;
  final ValueChanged<bool> onToggleEnabled;
  final VoidCallback onRunNow;
  final VoidCallback onStop;
  final Future<void> Function(AutoSelectConfig next, {bool reselect})
  onConfigChanged;
  final Future<void> Function(Map<String, dynamic> node) onSwitchNode;

  Future<void> _addOrEditRule(
    BuildContext context, {
    int? editIndex,
  }) async {
    final initial = editIndex == null ? null : config.rules[editIndex];
    final result = await showDialog<AutoSelectRule>(
      context: context,
      builder:
          (_) => _AutoSelectRuleDialog(
            initialRule: initial,
            allNodes: allNodes,
            suppliers: suppliers,
          ),
    );
    if (result == null) return;
    final nextRules = [...config.rules];
    if (editIndex == null) {
      nextRules.add(result);
    } else {
      nextRules[editIndex] = result;
    }
    await onConfigChanged(
      config.copyWith(rules: nextRules),
      reselect: config.enabled,
    );
  }

  Future<void> _deleteRule(int index) async {
    final nextRules = [...config.rules];
    final removed = nextRules.removeAt(index);
    final nextDiscarded = [
      removed.toJson(),
      ...config.discardedRules,
    ].take(5).toList(growable: false);
    await onConfigChanged(
      config.copyWith(rules: nextRules, discardedRules: nextDiscarded),
      reselect: config.enabled,
    );
  }

  Future<void> _clearRules(BuildContext context) async {
    if (config.rules.isEmpty) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('清空规则'),
            content: const Text('确定清空全部筛选规则吗？'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('清空'),
              ),
            ],
          ),
    );
    if (confirmed != true) return;
    final nextDiscarded = [
      ...config.rules.map((r) => r.toJson()),
      ...config.discardedRules,
    ].take(5).toList(growable: false);
    await onConfigChanged(
      config.copyWith(rules: const [], discardedRules: nextDiscarded),
      reselect: config.enabled,
    );
  }

  Future<void> _excludeNode(
    BuildContext context,
    Map<String, dynamic> node,
  ) async {
    final name = node['name']?.toString() ?? '该节点';
    final confirmed = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('排除节点'),
            content: Text('仅从自动选择候选中排除「$name」'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('排除'),
              ),
            ],
          ),
    );
    if (confirmed != true) return;
    final key = autoSelectNodeKey(node);
    final nextExcluded = _normalizedUniqueStrings([
      ...config.excludedNodeKeys,
      key,
    ]);
    await onConfigChanged(
      config.copyWith(excludedNodeKeys: nextExcluded),
      reselect: config.enabled,
    );
  }

  Future<void> _restoreExcluded(BuildContext context) async {
    if (config.excludedNodeKeys.isEmpty) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('恢复排除'),
            content: const Text('确定恢复全部已排除节点吗？'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('恢复'),
              ),
            ],
          ),
    );
    if (confirmed != true) return;
    await onConfigChanged(
      config.copyWith(excludedNodeKeys: const []),
      reselect: config.enabled,
    );
  }

  String _nodeKey(Map<String, dynamic> node) =>
      '${node['fileName'] ?? ''}:${node['subIndex'] ?? node['index']}:${node['name'] ?? ''}';

  @override
  Widget build(BuildContext context) {
    if (loading && allNodes.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    final effectiveSubFiles = <String>{...config.subscriptionFiles};
    if (effectiveSubFiles.isEmpty && suppliers.isNotEmpty) {
      final active = suppliers.where((s) => s['active'] == true);
      final fallback =
          active.isNotEmpty
              ? active.first['fileName']?.toString()
              : suppliers.first['fileName']?.toString();
      if (fallback != null && fallback.isNotEmpty) {
        effectiveSubFiles.add(fallback);
      }
    }

    final scopeItems = <DropdownMenuItem<String>>[
      const DropdownMenuItem(value: 'all', child: Text('全部节点')),
      const DropdownMenuItem(value: 'subscription', child: Text('指定订阅组')),
      if (config.scope == 'aggregate')
        const DropdownMenuItem(value: 'aggregate', child: Text('指定聚合组')),
    ];

    return RefreshIndicator(
      onRefresh: onRefresh,
      child: CustomScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        slivers: [
          SliverPadding(
            padding: const EdgeInsets.fromLTRB(16, 10, 16, 0),
            sliver: SliverToBoxAdapter(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(14, 10, 14, 12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Row(
                            children: [
                              Switch(
                                value: config.enabled,
                                onChanged: onToggleEnabled,
                              ),
                              const SizedBox(width: 8),
                              const Expanded(
                                child: Text(
                                  '自动选择',
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: TextStyle(fontWeight: FontWeight.w600),
                                ),
                              ),
                              if (running)
                                OutlinedButton.icon(
                                  onPressed: onStop,
                                  icon: const Icon(Icons.stop_rounded),
                                  label: const Text('停止'),
                                )
                              else
                                FilledButton.icon(
                                  onPressed: onRunNow,
                                  icon: const Icon(Icons.auto_awesome_rounded),
                                  label: Text(
                                    config.enabled ? '重新选择' : '立即选择',
                                  ),
                                ),
                            ],
                          ),
                          if (running || (statusText ?? '').isNotEmpty) ...[
                            const SizedBox(height: 8),
                            if (running)
                              LinearProgressIndicator(value: progress),
                            if ((statusText ?? '').isNotEmpty) ...[
                              if (running) const SizedBox(height: 6),
                              Text(
                                statusText!,
                                style: const TextStyle(
                                  color: Colors.white70,
                                  fontSize: 13,
                                ),
                              ),
                            ],
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(14, 10, 14, 12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Row(
                            children: [
                              const Expanded(
                                child: Text(
                                  '筛选规则',
                                  style: TextStyle(fontWeight: FontWeight.w600),
                                ),
                              ),
                              if (config.rules.isNotEmpty)
                                TextButton(
                                  onPressed: () => _clearRules(context),
                                  child: const Text('清空'),
                                ),
                              FilledButton.tonalIcon(
                                onPressed: () => _addOrEditRule(context),
                                icon: const Icon(Icons.add_rounded, size: 18),
                                label: const Text('添加规则'),
                              ),
                            ],
                          ),
                          const SizedBox(height: 6),
                          if (config.rules.isEmpty)
                            const Padding(
                              padding: EdgeInsets.symmetric(vertical: 10),
                              child: Text(
                                '暂无规则',
                                textAlign: TextAlign.center,
                                style: TextStyle(color: Colors.white54),
                              ),
                            )
                          else
                            for (var i = 0; i < config.rules.length; i++)
                              ListTile(
                                dense: true,
                                visualDensity: VisualDensity.compact,
                                contentPadding: EdgeInsets.zero,
                                onTap:
                                    () => _addOrEditRule(context, editIndex: i),
                                title: Text(
                                  autoSelectRuleTypeLabel(config.rules[i].type),
                                ),
                                subtitle: Text(
                                  config.rules[i].effectiveValues.join('、'),
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                trailing: Row(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    IconButton(
                                      tooltip: '编辑',
                                      icon: const Icon(
                                        Icons.edit_outlined,
                                        size: 20,
                                      ),
                                      onPressed:
                                          () => _addOrEditRule(
                                            context,
                                            editIndex: i,
                                          ),
                                    ),
                                    IconButton(
                                      tooltip: '删除',
                                      icon: const Icon(
                                        Icons.delete_outline,
                                        size: 20,
                                      ),
                                      onPressed: () => _deleteRule(i),
                                    ),
                                  ],
                                ),
                              ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(14),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          DropdownButtonFormField<String>(
                            key: ValueKey('scope:${config.scope}'),
                            value: config.scope,
                            isExpanded: true,
                            decoration: const InputDecoration(
                              labelText: '选择范围',
                            ),
                            items: scopeItems,
                            onChanged: (value) {
                              if (value == null || value == config.scope) return;
                              onConfigChanged(
                                config.copyWith(scope: value),
                                reselect: config.enabled,
                              );
                            },
                          ),
                          if (config.scope == 'subscription' &&
                              suppliers.isNotEmpty) ...[
                            const SizedBox(height: 10),
                            Wrap(
                              spacing: 8,
                              runSpacing: 6,
                              children: suppliers
                                  .map((supplier) {
                                    final file =
                                        supplier['fileName']?.toString() ?? '';
                                    final name =
                                        supplier['name']?.toString() ?? file;
                                    final selected = effectiveSubFiles.contains(
                                      file,
                                    );
                                    return FilterChip(
                                      label: Text(name),
                                      selected: selected,
                                      onSelected: (checked) {
                                        final next = <String>{
                                          ...effectiveSubFiles,
                                        };
                                        if (checked) {
                                          next.add(file);
                                        } else {
                                          next.remove(file);
                                        }
                                        onConfigChanged(
                                          config.copyWith(
                                            subscriptionFiles: next.toList(
                                              growable: false,
                                            ),
                                          ),
                                          reselect: config.enabled,
                                        );
                                      },
                                    );
                                  })
                                  .toList(growable: false),
                            ),
                          ],
                          const SizedBox(height: 12),
                          DropdownButtonFormField<String>(
                            key: ValueKey('siteMode:${config.siteCheck.mode}'),
                            value: config.siteCheck.mode,
                            isExpanded: true,
                            decoration: const InputDecoration(
                              labelText: '网站可用性',
                            ),
                            items: const [
                              DropdownMenuItem(
                                value: 'none',
                                child: Text('不要求'),
                              ),
                              DropdownMenuItem(
                                value: 'any',
                                child: Text('任一可用'),
                              ),
                              DropdownMenuItem(
                                value: 'all',
                                child: Text('全部可用'),
                              ),
                            ],
                            onChanged: (value) {
                              if (value == null ||
                                  value == config.siteCheck.mode) {
                                return;
                              }
                              var nextIds = config.siteCheck.ids;
                              var defaultApplied =
                                  config.siteCheck.defaultSelectionApplied;
                              if (value != 'none' &&
                                  nextIds.isEmpty &&
                                  !defaultApplied &&
                                  siteTargets.isNotEmpty) {
                                nextIds =
                                    siteTargets
                                        .map((e) => e['id']?.toString() ?? '')
                                        .where((id) => id.isNotEmpty)
                                        .toList(growable: false);
                                defaultApplied = true;
                              }
                              onConfigChanged(
                                config.copyWith(
                                  siteCheck: config.siteCheck.copyWith(
                                    mode: value,
                                    ids: nextIds,
                                    defaultSelectionApplied: defaultApplied,
                                  ),
                                ),
                                reselect: config.enabled,
                              );
                            },
                          ),
                          if (config.siteCheck.mode != 'none' &&
                              siteTargets.isNotEmpty) ...[
                            const SizedBox(height: 10),
                            Wrap(
                              spacing: 8,
                              runSpacing: 6,
                              children: siteTargets
                                  .map((target) {
                                    final id = target['id']?.toString() ?? '';
                                    final name =
                                        target['name']?.toString() ?? id;
                                    final selected = config.siteCheck.ids
                                        .contains(id);
                                    return FilterChip(
                                      label: Text(name),
                                      selected: selected,
                                      onSelected: (checked) {
                                        final next = <String>[
                                          ...config.siteCheck.ids,
                                        ];
                                        if (checked) {
                                          if (!next.contains(id)) next.add(id);
                                        } else {
                                          next.remove(id);
                                        }
                                        onConfigChanged(
                                          config.copyWith(
                                            siteCheck: config.siteCheck
                                                .copyWith(
                                                  ids: next,
                                                  defaultSelectionApplied: true,
                                                ),
                                          ),
                                          reselect: config.enabled,
                                        );
                                      },
                                    );
                                  })
                                  .toList(growable: false),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          '候选节点 (${candidates.length})',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                      ),
                      if (config.excludedNodeKeys.isNotEmpty)
                        TextButton(
                          onPressed: () => _restoreExcluded(context),
                          child: Text(
                            '恢复排除 (${config.excludedNodeKeys.length})',
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 6),
                ],
              ),
            ),
          ),
          if (candidates.isEmpty)
            const SliverToBoxAdapter(
              child: Padding(
                padding: EdgeInsets.symmetric(vertical: 28, horizontal: 16),
                child: Text(
                  '暂无符合规则的节点',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.white54),
                ),
              ),
            )
          else
            SliverPadding(
              padding: const EdgeInsets.fromLTRB(12, 0, 12, 28),
              sliver: SliverFixedExtentList(
                itemExtent: 102,
                delegate: SliverChildBuilderDelegate(
                  (context, index) {
                    final node = candidates[index];
                    final active = node['active'] == true;
                    final latency = (node['latency'] as num?)?.toInt() ?? 0;
                    final nodeKey = _nodeKey(node);
                    final nodeType = node['type']?.toString() ?? '';
                    final latencyLabel =
                        latency == 0
                            ? '未测速'
                            : latency < 0
                            ? '超时'
                            : '$latency ms';
                    return Padding(
                      key: ValueKey('auto:$nodeKey:$index'),
                      padding: const EdgeInsets.only(bottom: 6),
                      child: Card(
                        color: active ? const Color(0xFF173D37) : null,
                        child: ListTile(
                          visualDensity: VisualDensity.compact,
                          contentPadding: const EdgeInsets.symmetric(
                            horizontal: 14,
                            vertical: 2,
                          ),
                          onTap: () => onSwitchNode(node),
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
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          trailing: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              if (switchingNodeKey == nodeKey)
                                const SizedBox.square(
                                  dimension: 20,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                )
                              else
                                Text(
                                  latencyLabel,
                                  style: TextStyle(
                                    color:
                                        latency > 0
                                            ? const Color(0xFF55E7CB)
                                            : Colors.white54,
                                    fontSize: 13,
                                  ),
                                ),
                              IconButton(
                                tooltip: '排除节点',
                                icon: const Icon(Icons.close_rounded, size: 18),
                                onPressed: () => _excludeNode(context, node),
                              ),
                            ],
                          ),
                        ),
                      ),
                    );
                  },
                  childCount: candidates.length,
                  addAutomaticKeepAlives: false,
                  addSemanticIndexes: false,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _AutoSelectRuleDialog extends StatefulWidget {
  const _AutoSelectRuleDialog({
    required this.initialRule,
    required this.allNodes,
    required this.suppliers,
  });

  final AutoSelectRule? initialRule;
  final List<Map<String, dynamic>> allNodes;
  final List<Map<String, dynamic>> suppliers;

  @override
  State<_AutoSelectRuleDialog> createState() => _AutoSelectRuleDialogState();
}

class _AutoSelectRuleDialogState extends State<_AutoSelectRuleDialog> {
  late String _type;
  late final TextEditingController _textController;
  late final TextEditingController _nodeSearchController;
  final Set<String> _selectedValues = <String>{};
  String? _validationError;

  @override
  void initState() {
    super.initState();
    final initial = widget.initialRule;
    _type = initial?.type ?? 'exclude_keyword';
    final initialValues = initial?.effectiveValues ?? const [];
    _textController = TextEditingController(text: initialValues.join(', '));
    _nodeSearchController = TextEditingController();
    _selectedValues.addAll(initialValues);
  }

  @override
  void dispose() {
    _textController.dispose();
    _nodeSearchController.dispose();
    super.dispose();
  }

  List<String> _availableProtocols() {
    final byNormalized = <String, String>{};
    for (final proto in _commonAutoSelectProtocols) {
      byNormalized[_normalizeAutoSelectProtocol(proto)] = proto;
    }
    for (final node in widget.allNodes) {
      final raw = node['type']?.toString().trim() ?? '';
      if (raw.isEmpty) continue;
      final norm = _normalizeAutoSelectProtocol(raw);
      byNormalized[norm] = raw;
    }
    for (final v in _selectedValues) {
      final norm = _normalizeAutoSelectProtocol(v);
      if (norm.isNotEmpty) {
        byNormalized.putIfAbsent(norm, () => v);
      }
    }
    return byNormalized.values.toList(growable: false)..sort();
  }

  List<String> _availableNodeNames() {
    final seen = <String>{};
    final out = <String>[];
    for (final node in widget.allNodes) {
      final name = node['name']?.toString().trim() ?? '';
      if (name.isEmpty || !seen.add(name)) continue;
      out.add(name);
    }
    return out;
  }

  List<String> _availableSupplierNames() {
    final seen = <String>{};
    final out = <String>[];
    for (final s in widget.suppliers) {
      final label =
          (s['name']?.toString().trim() ?? '').isNotEmpty
              ? s['name'].toString().trim()
              : (s['fileName']?.toString().trim() ?? '');
      if (label.isEmpty || !seen.add(label)) continue;
      out.add(label);
    }
    return out;
  }

  bool get _isProtocolType =>
      _type == 'include_protocol' || _type == 'exclude_protocol';

  void _syncSelectedFromText() {
    _selectedValues
      ..clear()
      ..addAll(splitAutoSelectValues(_textController.text));
  }

  void _toggleChipValue(String val, bool checked) {
    setState(() {
      _validationError = null;
      if (_isProtocolType) {
        final normTarget = _normalizeAutoSelectProtocol(val);
        _selectedValues.removeWhere(
          (item) => _normalizeAutoSelectProtocol(item) == normTarget,
        );
        if (checked) {
          _selectedValues.add(val);
        }
      } else {
        if (checked) {
          _selectedValues.add(val);
        } else {
          _selectedValues.remove(val);
        }
      }
      _textController.text = _selectedValues.join(', ');
    });
  }

  void _submit() {
    final values = switch (_type) {
      'include_node' => _normalizedUniqueStrings(
        _selectedValues.isNotEmpty
            ? _selectedValues
            : splitAutoSelectValues(_textController.text),
      ),
      'include_subscription' when _availableSupplierNames().isNotEmpty =>
        _normalizedUniqueStrings(_selectedValues),
      _ => splitAutoSelectValues(_textController.text),
    };
    if (values.isEmpty) {
      setState(() => _validationError = '请至少填写或选择一项');
      return;
    }
    final id =
        widget.initialRule?.id ??
        'rule_${DateTime.now().microsecondsSinceEpoch}';
    Navigator.pop(
      context,
      AutoSelectRule(
        id: id,
        type: _type,
        value: values.join(','),
        values: values,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final typeEntries = <String, String>{
      ...autoSelectRuleTypes,
      if (_type == 'include_aggregate_group')
        'include_aggregate_group': '只选择聚合组',
    };
    final protocols = _isProtocolType ? _availableProtocols() : const <String>[];
    final supplierNames =
        _type == 'include_subscription'
            ? _availableSupplierNames()
            : const <String>[];
    final nodeNames =
        _type == 'include_node' ? _availableNodeNames() : const <String>[];
    final nodeQuery = _nodeSearchController.text.trim().toLowerCase();
    final filteredNodeNames =
        nodeQuery.isEmpty
            ? nodeNames
            : nodeNames
                .where((n) => n.toLowerCase().contains(nodeQuery))
                .toList(growable: false);

    return AlertDialog(
      title: Text(widget.initialRule == null ? '添加规则' : '编辑规则'),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              DropdownButtonFormField<String>(
                key: ValueKey('ruleType:$_type'),
                value: _type,
                isExpanded: true,
                decoration: const InputDecoration(labelText: '规则类型'),
                items: typeEntries.entries
                    .map(
                      (entry) => DropdownMenuItem(
                        value: entry.key,
                        child: Text(entry.value),
                      ),
                    )
                    .toList(growable: false),
                onChanged: (value) {
                  if (value == null || value == _type) return;
                  setState(() {
                    _type = value;
                    _validationError = null;
                    _selectedValues.clear();
                    _textController.clear();
                    _nodeSearchController.clear();
                  });
                },
              ),
              const SizedBox(height: 12),
              if (_isProtocolType) ...[
                Wrap(
                  spacing: 8,
                  runSpacing: 6,
                  children: protocols
                      .map((proto) {
                        final normProto = _normalizeAutoSelectProtocol(proto);
                        final selected = _selectedValues.any(
                          (item) =>
                              _normalizeAutoSelectProtocol(item) == normProto,
                        );
                        return FilterChip(
                          label: Text(proto),
                          selected: selected,
                          onSelected: (checked) => _toggleChipValue(proto, checked),
                        );
                      })
                      .toList(growable: false),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _textController,
                  decoration: const InputDecoration(
                    labelText: '协议',
                    hintText: 'vless, hysteria2',
                  ),
                  onChanged: (_) {
                    _validationError = null;
                    _syncSelectedFromText();
                    setState(() {});
                  },
                ),
              ] else if (_type == 'include_subscription' &&
                  supplierNames.isNotEmpty) ...[
                Wrap(
                  spacing: 8,
                  runSpacing: 6,
                  children: supplierNames
                      .map(
                        (name) => FilterChip(
                          label: Text(name),
                          selected: _selectedValues.contains(name),
                          onSelected:
                              (checked) => _toggleChipValue(name, checked),
                        ),
                      )
                      .toList(growable: false),
                ),
              ] else if (_type == 'include_node' && nodeNames.isNotEmpty) ...[
                TextField(
                  controller: _nodeSearchController,
                  decoration: const InputDecoration(
                    prefixIcon: Icon(Icons.search_rounded),
                    hintText: '搜索节点',
                  ),
                  onChanged: (_) => setState(() {}),
                ),
                const SizedBox(height: 8),
                SizedBox(
                  height: 200,
                  child: ListView.builder(
                    itemCount: filteredNodeNames.length,
                    itemBuilder: (context, index) {
                      final name = filteredNodeNames[index];
                      return CheckboxListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        value: _selectedValues.contains(name),
                        title: Text(
                          name,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        onChanged:
                            (checked) =>
                                _toggleChipValue(name, checked == true),
                      );
                    },
                  ),
                ),
              ] else ...[
                TextField(
                  controller: _textController,
                  autofocus: widget.initialRule == null,
                  decoration: InputDecoration(
                    labelText:
                        _type == 'include_region'
                            ? '地区关键字'
                            : _type == 'include_subscription'
                            ? '订阅组'
                            : _type == 'include_aggregate_group'
                            ? '聚合组'
                            : _type == 'include_node'
                            ? '节点名称'
                            : '排除关键字',
                    hintText: '香港, 日本',
                  ),
                  onChanged: (_) {
                    if (_validationError != null) {
                      setState(() => _validationError = null);
                    }
                  },
                ),
              ],
              if (_validationError != null) ...[
                const SizedBox(height: 8),
                Text(
                  _validationError!,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.error,
                    fontSize: 13,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: _submit,
          child: Text(widget.initialRule == null ? '添加' : '保存'),
        ),
      ],
    );
  }
}
