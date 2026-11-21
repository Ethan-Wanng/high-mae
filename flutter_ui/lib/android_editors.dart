part of 'android_app.dart';

class _DnsEditorPage extends StatefulWidget {
  const _DnsEditorPage({required this.api});

  final WingApi api;

  @override
  State<_DnsEditorPage> createState() => _DnsEditorPageState();
}

class _DnsEditorPageState extends State<_DnsEditorPage> {
  Map<String, dynamic> _config = const {};
  bool _loading = true;
  bool _saving = false;

  List<Map<String, dynamic>> get _servers =>
      (_config['servers'] as List? ?? const [])
          .map((item) => Map<String, dynamic>.from(item as Map))
          .toList();

  List<Map<String, dynamic>> get _rules =>
      (_config['rules'] as List? ?? const [])
          .map((item) => Map<String, dynamic>.from(item as Map))
          .toList();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final config = await widget.api.getDns();
      if (!mounted) return;
      setState(() {
        _config = {
          ...config,
          'servers': _copyMaps(config['servers']),
          'rules': _copyMaps(config['rules']),
        };
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() => _loading = false);
      _snack(context, error.toString());
    }
  }

  Future<void> _save() async {
    if (_saving) return;
    final servers = _servers;
    if (servers.isEmpty) {
      _snack(context, '请至少添加一个 DNS 服务器');
      return;
    }
    if (!servers.any((server) => server['id'] == _config['default'])) {
      _config['default'] = servers.first['id'];
    }
    setState(() => _saving = true);
    try {
      final response = await widget.api.saveDns(_config);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? 'DNS 保存失败');
      }
      if (mounted) _snack(context, 'DNS 配置已保存并应用');
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _editServer([int? index]) async {
    final current = index == null ? null : _servers[index];
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => _DnsServerDialog(current: current),
    );
    if (result == null || !mounted) return;
    final servers = _servers;
    if (index == null) {
      servers.add(result);
    } else {
      servers[index] = result;
    }
    setState(() {
      _config['servers'] = servers;
      _config['default'] ??= result['id'];
    });
  }

  void _deleteServer(int index) {
    final servers = _servers;
    final removed = servers.removeAt(index);
    final rules =
        _rules.where((rule) => rule['serverId'] != removed['id']).toList();
    setState(() {
      _config['servers'] = servers;
      _config['rules'] = rules;
      if (_config['default'] == removed['id']) {
        _config['default'] = servers.isEmpty ? '' : servers.first['id'];
      }
    });
  }

  Future<void> _editRule([int? index]) async {
    final servers = _servers;
    if (servers.isEmpty) {
      _snack(context, '请先添加 DNS 服务器');
      return;
    }
    final current = index == null ? null : _rules[index];
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => _DnsRuleDialog(servers: servers, current: current),
    );
    if (result == null || !mounted) return;
    final rules = _rules;
    if (index == null) {
      rules.add(result);
    } else {
      rules[index] = result;
    }
    setState(() => _config['rules'] = rules);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    final servers = _servers;
    final rules = _rules;
    final defaultId =
        servers.any((server) => server['id'] == _config['default'])
            ? _config['default']?.toString()
            : (servers.isEmpty ? null : servers.first['id'].toString());
    return Scaffold(
      appBar: AppBar(
        title: const Text('DNS 分流'),
        actions: [
          TextButton.icon(
            onPressed: _saving ? null : _save,
            icon:
                _saving
                    ? const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                    : const Icon(Icons.save_outlined),
            label: const Text('保存'),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 40),
        children: [
          Card(
            child: SwitchListTile(
              value: _config['autoOverwrite'] == true,
              onChanged:
                  (value) => setState(() => _config['autoOverwrite'] = value),
              title: const Text('自动覆写系统 DNS'),
              subtitle: const Text('连接时将 DNS 请求交给 wing 分流'),
            ),
          ),
          const SizedBox(height: 12),
          if (servers.isNotEmpty)
            DropdownButtonFormField<String>(
              value: defaultId,
              decoration: const InputDecoration(labelText: '默认 DNS 服务器'),
              items:
                  servers
                      .map(
                        (server) => DropdownMenuItem(
                          value: server['id'].toString(),
                          child: Text(server['name']?.toString() ?? '未命名'),
                        ),
                      )
                      .toList(),
              onChanged:
                  (value) => setState(() => _config['default'] = value ?? ''),
            ),
          const SizedBox(height: 20),
          _EditorSectionHeader(
            title: 'DNS 服务器',
            count: servers.length,
            onAdd: _editServer,
          ),
          if (servers.isEmpty)
            const _EditorEmpty(message: '暂无 DNS 服务器')
          else
            ...servers.asMap().entries.map(
              (entry) => Card(
                margin: const EdgeInsets.only(bottom: 8),
                child: ListTile(
                  onTap: () => _editServer(entry.key),
                  leading: const Icon(Icons.dns_outlined),
                  title: Text(entry.value['name']?.toString() ?? '未命名'),
                  subtitle: Text(entry.value['address']?.toString() ?? ''),
                  trailing: IconButton(
                    tooltip: '删除',
                    onPressed: () => _deleteServer(entry.key),
                    icon: const Icon(Icons.delete_outline),
                  ),
                ),
              ),
            ),
          const SizedBox(height: 20),
          _EditorSectionHeader(
            title: 'DNS 规则',
            count: rules.length,
            onAdd: _editRule,
          ),
          if (rules.isEmpty)
            const _EditorEmpty(message: '暂无 DNS 分流规则')
          else
            ...rules.asMap().entries.map((entry) {
              final server = servers.cast<Map<String, dynamic>?>().firstWhere(
                (item) => item?['id'] == entry.value['serverId'],
                orElse: () => null,
              );
              return Card(
                margin: const EdgeInsets.only(bottom: 8),
                child: ListTile(
                  onTap: () => _editRule(entry.key),
                  title: Text(entry.value['value']?.toString() ?? ''),
                  subtitle: Text(
                    '${_ruleTypeLabel(entry.value['type'])} → ${server?['name'] ?? '未知服务器'}',
                  ),
                  trailing: IconButton(
                    tooltip: '删除',
                    onPressed: () {
                      final next = _rules..removeAt(entry.key);
                      setState(() => _config['rules'] = next);
                    },
                    icon: const Icon(Icons.delete_outline),
                  ),
                ),
              );
            }),
        ],
      ),
    );
  }
}

class _RoutingEditorPage extends StatefulWidget {
  const _RoutingEditorPage({required this.api});

  final WingApi api;

  @override
  State<_RoutingEditorPage> createState() => _RoutingEditorPageState();
}

class _RoutingEditorPageState extends State<_RoutingEditorPage> {
  List<Map<String, dynamic>> _groups = const [];
  bool _loading = true;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final groups = await widget.api.getRules();
      if (!mounted) return;
      setState(() {
        _groups =
            groups
                .map((group) => {...group, 'rules': _copyMaps(group['rules'])})
                .toList();
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() => _loading = false);
      _snack(context, error.toString());
    }
  }

  Future<void> _save() async {
    if (_saving) return;
    setState(() => _saving = true);
    try {
      final response = await widget.api.saveRules(_groups);
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '路由规则保存失败');
      }
      if (mounted) _snack(context, '路由规则已保存并立即应用');
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _reset() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('恢复默认规则？'),
            content: const Text('当前域名路由规则组会被默认配置覆盖。'),
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
    try {
      final response = await widget.api.resetRules();
      if (response['ok'] != true) {
        throw WingApiException(response['msg']?.toString() ?? '恢复默认规则失败');
      }
      await _load();
      if (mounted) _snack(context, '默认路由规则已恢复');
    } catch (error) {
      if (mounted) _snack(context, error.toString());
    }
  }

  Future<void> _editGroup([int? index]) async {
    final current = index == null ? null : _groups[index];
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => _RoutingGroupDialog(current: current),
    );
    if (result == null || !mounted) return;
    setState(() {
      final next = [..._groups];
      if (index == null) {
        next.add(result);
      } else {
        next[index] = result;
      }
      _groups = next;
    });
  }

  Future<void> _openGroupRules(int groupIndex) async {
    final group = _groups[groupIndex];
    await Navigator.of(context).push<void>(
      MaterialPageRoute(
        builder:
            (_) => _RoutingGroupRulesPage(
              groupName: group['name']?.toString() ?? '未命名规则组',
              initialRules: _copyMaps(group['rules']),
              onRulesChanged: (rules) {
                if (!mounted || groupIndex >= _groups.length) return;
                setState(() {
                  final next = [..._groups];
                  next[groupIndex] = {...next[groupIndex], 'rules': rules};
                  _groups = next;
                });
              },
            ),
      ),
    );
  }

  void _deleteGroup(int index) {
    setState(() => _groups = [..._groups]..removeAt(index));
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    return Scaffold(
      appBar: AppBar(
        title: const Text('路由规则'),
        actions: [
          IconButton(
            tooltip: '恢复默认',
            onPressed: _reset,
            icon: const Icon(Icons.restore_rounded),
          ),
          TextButton.icon(
            onPressed: _saving ? null : _save,
            icon:
                _saving
                    ? const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                    : const Icon(Icons.save_outlined),
            label: const Text('保存'),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _editGroup,
        icon: const Icon(Icons.create_new_folder_outlined),
        label: const Text('添加规则组'),
      ),
      body:
          _groups.isEmpty
              ? const _EditorEmpty(message: '暂无路由规则组')
              : ListView.builder(
                padding: const EdgeInsets.fromLTRB(12, 10, 12, 96),
                itemCount: _groups.length,
                itemBuilder: (context, groupIndex) {
                  final group = _groups[groupIndex];
                  final ruleCount = (group['rules'] as List?)?.length ?? 0;
                  return Card(
                    margin: const EdgeInsets.only(bottom: 10),
                    child: ListTile(
                      onTap: () => _openGroupRules(groupIndex),
                      leading: Icon(_actionIcon(group['action'])),
                      title: Text(group['name']?.toString() ?? '未命名规则组'),
                      subtitle: Text(
                        '${_actionLabel(group['action'])} · $ruleCount 条规则',
                      ),
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          PopupMenuButton<String>(
                            onSelected: (value) {
                              if (value == 'edit') _editGroup(groupIndex);
                              if (value == 'delete') _deleteGroup(groupIndex);
                            },
                            itemBuilder:
                                (_) => const [
                                  PopupMenuItem(
                                    value: 'edit',
                                    child: Text('编辑规则组'),
                                  ),
                                  PopupMenuItem(
                                    value: 'delete',
                                    child: Text('删除规则组'),
                                  ),
                                ],
                          ),
                          const Icon(Icons.chevron_right_rounded),
                        ],
                      ),
                    ),
                  );
                },
              ),
    );
  }
}

class _RoutingGroupRulesPage extends StatefulWidget {
  const _RoutingGroupRulesPage({
    required this.groupName,
    required this.initialRules,
    required this.onRulesChanged,
  });

  final String groupName;
  final List<Map<String, dynamic>> initialRules;
  final ValueChanged<List<Map<String, dynamic>>> onRulesChanged;

  @override
  State<_RoutingGroupRulesPage> createState() => _RoutingGroupRulesPageState();
}

class _RoutingGroupRulesPageState extends State<_RoutingGroupRulesPage> {
  late List<Map<String, dynamic>> _rules;
  List<int> _filteredIndices = const [];
  final _search = TextEditingController();

  @override
  void initState() {
    super.initState();
    _rules = _copyMaps(widget.initialRules);
    _rebuildFiltered();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  void _rebuildFiltered() {
    final query = _search.text.trim().toLowerCase();
    if (query.isEmpty) {
      _filteredIndices = List<int>.generate(_rules.length, (i) => i);
      return;
    }
    final matches = <int>[];
    for (var i = 0; i < _rules.length; i++) {
      final value = _rules[i]['value']?.toString().toLowerCase() ?? '';
      if (value.contains(query)) {
        matches.add(i);
      }
    }
    _filteredIndices = matches;
  }

  Future<void> _editRule([int? ruleIndex]) async {
    final current = ruleIndex == null ? null : _rules[ruleIndex];
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => _RoutingRuleDialog(current: current),
    );
    if (result == null || !mounted) return;
    setState(() {
      if (ruleIndex == null) {
        _rules.add(result);
      } else {
        _rules[ruleIndex] = result;
      }
      _rebuildFiltered();
    });
    widget.onRulesChanged(_copyMaps(_rules));
  }

  void _deleteRule(int ruleIndex) {
    setState(() {
      _rules.removeAt(ruleIndex);
      _rebuildFiltered();
    });
    widget.onRulesChanged(_copyMaps(_rules));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.groupName)),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _editRule(),
        icon: const Icon(Icons.add_rounded),
        label: const Text('添加规则'),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 10, 16, 8),
            child: TextField(
              controller: _search,
              onChanged: (_) => setState(_rebuildFiltered),
              decoration: const InputDecoration(
                hintText: '搜索域名规则',
                prefixIcon: Icon(Icons.search_rounded),
              ),
            ),
          ),
          Expanded(
            child:
                _filteredIndices.isEmpty
                    ? const _EditorEmpty(message: '暂无路由规则')
                    : ListView.builder(
                      padding: const EdgeInsets.fromLTRB(12, 4, 12, 96),
                      itemExtent: 72,
                      addRepaintBoundaries: true,
                      itemCount: _filteredIndices.length,
                      itemBuilder: (context, index) {
                        final ruleIndex = _filteredIndices[index];
                        final rule = _rules[ruleIndex];
                        return Card(
                          margin: const EdgeInsets.only(bottom: 6),
                          child: ListTile(
                            onTap: () => _editRule(ruleIndex),
                            leading: const Icon(Icons.rule_rounded),
                            title: Text(
                              rule['value']?.toString() ?? '',
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            subtitle: Text(_ruleTypeLabel(rule['type'])),
                            trailing: IconButton(
                              tooltip: '删除',
                              onPressed: () => _deleteRule(ruleIndex),
                              icon: const Icon(Icons.delete_outline),
                            ),
                          ),
                        );
                      },
                    ),
          ),
        ],
      ),
    );
  }
}

class _DnsServerDialog extends StatefulWidget {
  const _DnsServerDialog({this.current});

  final Map<String, dynamic>? current;

  @override
  State<_DnsServerDialog> createState() => _DnsServerDialogState();
}

class _DnsServerDialogState extends State<_DnsServerDialog> {
  late final TextEditingController _name;
  late final TextEditingController _address;

  @override
  void initState() {
    super.initState();
    _name = TextEditingController(text: widget.current?['name']?.toString());
    _address = TextEditingController(
      text: widget.current?['address']?.toString() ?? '1.1.1.1:53',
    );
  }

  @override
  void dispose() {
    _name.dispose();
    _address.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.current == null ? '添加 DNS 服务器' : '编辑 DNS 服务器'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: _name,
            autofocus: true,
            decoration: const InputDecoration(labelText: '名称'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _address,
            keyboardType: TextInputType.url,
            decoration: const InputDecoration(
              labelText: '地址',
              hintText: '1.1.1.1:53',
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () {
            if (_name.text.trim().isEmpty || _address.text.trim().isEmpty) {
              return;
            }
            Navigator.pop(context, {
              'id':
                  widget.current?['id'] ??
                  'dns_${DateTime.now().microsecondsSinceEpoch}',
              'name': _name.text.trim(),
              'address': _address.text.trim(),
              'type': 'udp',
            });
          },
          child: const Text('确定'),
        ),
      ],
    );
  }
}

class _DnsRuleDialog extends StatefulWidget {
  const _DnsRuleDialog({required this.servers, this.current});

  final List<Map<String, dynamic>> servers;
  final Map<String, dynamic>? current;

  @override
  State<_DnsRuleDialog> createState() => _DnsRuleDialogState();
}

class _DnsRuleDialogState extends State<_DnsRuleDialog> {
  late final TextEditingController _value;
  late String _type;
  late String _serverId;

  @override
  void initState() {
    super.initState();
    _value = TextEditingController(text: widget.current?['value']?.toString());
    final rawType = widget.current?['type']?.toString() ?? 'domain_suffix';
    _type =
        _ruleTypeItems().any((item) => item.value == rawType)
            ? rawType
            : 'domain_suffix';
    final rawServer = widget.current?['serverId']?.toString();
    _serverId =
        widget.servers.any((s) => s['id']?.toString() == rawServer)
            ? rawServer!
            : widget.servers.first['id'].toString();
  }

  @override
  void dispose() {
    _value.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.current == null ? '添加 DNS 规则' : '编辑 DNS 规则'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          DropdownButtonFormField<String>(
            value: _type,
            decoration: const InputDecoration(labelText: '匹配方式'),
            items: _ruleTypeItems(),
            onChanged: (next) => setState(() => _type = next ?? _type),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _value,
            decoration: const InputDecoration(
              labelText: '域名内容',
              hintText: 'example.com',
            ),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            value: _serverId,
            decoration: const InputDecoration(labelText: 'DNS 服务器'),
            items:
                widget.servers
                    .map(
                      (server) => DropdownMenuItem(
                        value: server['id'].toString(),
                        child: Text(server['name']?.toString() ?? '未命名'),
                      ),
                    )
                    .toList(),
            onChanged: (next) => setState(() => _serverId = next ?? _serverId),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () {
            if (_value.text.trim().isEmpty) return;
            Navigator.pop(context, {
              'type': _type,
              'value': _value.text.trim(),
              'serverId': _serverId,
            });
          },
          child: const Text('确定'),
        ),
      ],
    );
  }
}

class _RoutingGroupDialog extends StatefulWidget {
  const _RoutingGroupDialog({this.current});

  final Map<String, dynamic>? current;

  @override
  State<_RoutingGroupDialog> createState() => _RoutingGroupDialogState();
}

class _RoutingGroupDialogState extends State<_RoutingGroupDialog> {
  late final TextEditingController _name;
  late String _action;

  @override
  void initState() {
    super.initState();
    _name = TextEditingController(text: widget.current?['name']?.toString());
    final rawAction = widget.current?['action']?.toString() ?? 'direct';
    _action =
        (rawAction == 'direct' || rawAction == 'proxy' || rawAction == 'reject')
            ? rawAction
            : 'direct';
  }

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.current == null ? '添加规则组' : '编辑规则组'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: _name,
            autofocus: true,
            decoration: const InputDecoration(labelText: '规则组名称'),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            value: _action,
            decoration: const InputDecoration(labelText: '匹配后的动作'),
            items: const [
              DropdownMenuItem(value: 'direct', child: Text('直连')),
              DropdownMenuItem(value: 'proxy', child: Text('代理')),
              DropdownMenuItem(value: 'reject', child: Text('拒绝')),
            ],
            onChanged: (next) => setState(() => _action = next ?? _action),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () {
            if (_name.text.trim().isEmpty) return;
            Navigator.pop(context, {
              'id':
                  widget.current?['id'] ??
                  'group_${DateTime.now().microsecondsSinceEpoch}',
              'name': _name.text.trim(),
              'action': _action,
              'rules': widget.current?['rules'] ?? <Map<String, dynamic>>[],
            });
          },
          child: const Text('确定'),
        ),
      ],
    );
  }
}

class _RoutingRuleDialog extends StatefulWidget {
  const _RoutingRuleDialog({this.current});

  final Map<String, dynamic>? current;

  @override
  State<_RoutingRuleDialog> createState() => _RoutingRuleDialogState();
}

class _RoutingRuleDialogState extends State<_RoutingRuleDialog> {
  late final TextEditingController _value;
  late String _type;

  @override
  void initState() {
    super.initState();
    _value = TextEditingController(text: widget.current?['value']?.toString());
    final rawType = widget.current?['type']?.toString() ?? 'domain_suffix';
    _type =
        _ruleTypeItems().any((item) => item.value == rawType)
            ? rawType
            : 'domain_suffix';
  }

  @override
  void dispose() {
    _value.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.current == null ? '添加路由规则' : '编辑路由规则'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          DropdownButtonFormField<String>(
            value: _type,
            decoration: const InputDecoration(labelText: '匹配方式'),
            items: _ruleTypeItems(),
            onChanged: (next) => setState(() => _type = next ?? _type),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _value,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: '域名内容',
              hintText: 'example.com',
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () {
            if (_value.text.trim().isEmpty) return;
            Navigator.pop(context, {'type': _type, 'value': _value.text.trim()});
          },
          child: const Text('确定'),
        ),
      ],
    );
  }
}

class _EditorSectionHeader extends StatelessWidget {
  const _EditorSectionHeader({
    required this.title,
    required this.count,
    required this.onAdd,
  });

  final String title;
  final int count;
  final VoidCallback onAdd;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          Expanded(
            child: Text(
              '$title ($count)',
              style: Theme.of(context).textTheme.titleMedium,
            ),
          ),
          TextButton.icon(
            onPressed: onAdd,
            icon: const Icon(Icons.add_rounded),
            label: const Text('添加'),
          ),
        ],
      ),
    );
  }
}

class _EditorEmpty extends StatelessWidget {
  const _EditorEmpty({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 16),
      child: Center(
        child: Text(
          message,
          textAlign: TextAlign.center,
          style: const TextStyle(color: Colors.white54),
        ),
      ),
    );
  }
}

List<Map<String, dynamic>> _copyMaps(Object? value) =>
    (value as List? ?? const [])
        .map((item) => Map<String, dynamic>.from(item as Map))
        .toList();

List<DropdownMenuItem<String>> _ruleTypeItems() => const [
  DropdownMenuItem(value: 'domain', child: Text('完整域名')),
  DropdownMenuItem(value: 'domain_suffix', child: Text('域名后缀')),
  DropdownMenuItem(value: 'domain_keyword', child: Text('域名关键字')),
];

String _ruleTypeLabel(Object? value) {
  switch (value) {
    case 'domain':
      return '完整域名';
    case 'domain_keyword':
      return '域名关键字';
    default:
      return '域名后缀';
  }
}

String _actionLabel(Object? value) {
  switch (value) {
    case 'proxy':
      return '代理';
    case 'reject':
      return '拒绝';
    default:
      return '直连';
  }
}

IconData _actionIcon(Object? value) {
  switch (value) {
    case 'proxy':
      return Icons.vpn_lock_outlined;
    case 'reject':
      return Icons.block_rounded;
    default:
      return Icons.lan_outlined;
  }
}
