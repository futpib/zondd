import 'package:flutter/material.dart';

import 'control.dart';
import 'json_yaml.dart';
import 'ui.dart';

// Use the rich layout only when it can display every review field. Other
// formats remain reviewable as the complete proposal rendered in YAML.
bool _isTextReview(Object? value) {
  bool fields(Object? object, Set<String> names) =>
      object is Map &&
      object.length == names.length &&
      names.every(object.containsKey);
  bool text(Object? value) => value is String && value.trim().isNotEmpty;
  if (!fields(value, {'version', 'title', 'sections'})) return false;
  final review = value as Map;
  if (review['version'] is! int ||
      review['version'] != 1 ||
      !text(review['title']) ||
      review['sections'] is! List) {
    return false;
  }
  final sections = review['sections'] as List;
  if (sections.isEmpty) return false;
  for (final section in sections) {
    if (!fields(section, {'title', 'fields'}) ||
        !text(section['title']) ||
        section['fields'] is! List) {
      return false;
    }
    final items = section['fields'] as List;
    if (items.isEmpty) return false;
    for (final item in items) {
      if (!fields(item, {'label', 'value'}) ||
          !text(item['label']) ||
          !text(item['value'])) {
        return false;
      }
    }
  }
  return true;
}

class RuleProposalCard extends StatefulWidget {
  const RuleProposalCard({
    super.key,
    required this.proposal,
    required this.enabled,
    required this.resolve,
  });
  final Map<String, dynamic> proposal;
  final bool enabled;
  final Future<void> Function(bool approve, int? seconds) resolve;

  @override
  State<RuleProposalCard> createState() => _RuleProposalCardState();
}

class _RuleProposalCardState extends State<RuleProposalCard> {
  int lifetime = 3600;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Reusable rule proposal',
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 12),
          RuleDefinition(proposal: widget.proposal),
          const SizedBox(height: 12),
          DropdownButtonFormField<int>(
            initialValue: lifetime,
            decoration: const InputDecoration(labelText: 'Grant lifetime'),
            items: const [
              DropdownMenuItem(value: 3600, child: Text('1 hour')),
              DropdownMenuItem(value: 86400, child: Text('24 hours')),
              DropdownMenuItem(value: 0, child: Text('Until revoked')),
            ],
            onChanged: widget.enabled
                ? (value) => setState(() => lifetime = value!)
                : null,
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: OutlinedButton(
                  onPressed: widget.enabled
                      ? () => widget.resolve(false, null)
                      : null,
                  child: const Text('Reject rule'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: FilledButton(
                  onPressed: widget.enabled
                      ? () => widget.resolve(
                          true,
                          lifetime == 0 ? null : lifetime,
                        )
                      : null,
                  child: const Text('Approve rule'),
                ),
              ),
            ],
          ),
        ],
      ),
    ),
  );
}

class RuleDefinition extends StatelessWidget {
  const RuleDefinition({super.key, required this.proposal});
  final Map<String, dynamic> proposal;

  @override
  Widget build(BuildContext context) {
    final source = proposal['source'];
    final raw = proposal['review'];
    final review = _isTextReview(raw) ? raw as Map : null;
    final yaml = SelectableText(
      jsonAsYaml(proposal),
      key: ValueKey('rule-yaml-${proposal['id']}'),
      style: mono,
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          '${proposal['principal']} · ${review?['title'] ?? proposal['id']}',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 12),
        if (source is String && source.isNotEmpty) ...[
          Text('Rule source', style: Theme.of(context).textTheme.titleSmall),
          const Text('As received by the daemon'),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerLowest,
              borderRadius: BorderRadius.circular(8),
            ),
            child: SelectableText(
              source,
              key: ValueKey('rule-source-${proposal['id']}'),
              style: mono,
              textDirection: TextDirection.ltr,
            ),
          ),
          const SizedBox(height: 12),
        ],
        if (review == null) ...[
          Text(
            'Complete rule data (YAML)',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 8),
          yaml,
        ] else
          for (final section in review['sections'] as List) ...[
            const SizedBox(height: 12),
            Text(
              section['title'] as String,
              style: Theme.of(context).textTheme.titleSmall,
            ),
            for (final field in section['fields'] as List)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: SelectableText('${field['label']}: ${field['value']}'),
              ),
          ],
        if (review != null)
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            title: const Text('Rule details (YAML)'),
            children: [yaml],
          ),
      ],
    );
  }
}

enum _RuleFilter { current, history, all }

class RulesPage extends StatefulWidget {
  const RulesPage({super.key, required this.api});
  final ControlApi api;
  @override
  State<RulesPage> createState() => _RulesPageState();
}

class _RulesPageState extends State<RulesPage> {
  final search = TextEditingController();
  final expandedRules = <String>{};
  _RuleFilter filter = _RuleFilter.current;
  List<dynamic>? rules;
  String? error;
  bool busy = false, needsRecovery = false;
  int connectionGeneration = 0;
  ControlConnection? get connection =>
      widget.api is ControlConnection ? widget.api as ControlConnection : null;
  bool get unavailable => connection?.disconnected ?? false;
  void connectionChanged() {
    if (!mounted) return;
    if (connection!.generation != connectionGeneration) {
      connectionGeneration = connection!.generation;
      needsRecovery = true;
    }
    setState(() {});
    if (needsRecovery) refresh();
  }

  Future<void> reconnect() async {
    try {
      await connection!.reconnect();
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    }
  }

  @override
  void initState() {
    super.initState();
    connection?.addListener(connectionChanged);
    refresh();
  }

  @override
  void dispose() {
    connection?.removeListener(connectionChanged);
    search.dispose();
    super.dispose();
  }

  Future<void> refresh() async {
    if (busy || unavailable) return;
    needsRecovery = false;
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final result = await widget.api.request({'method': 'rules'});
      if (mounted) setState(() => rules = result['rules'] as List);
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) {
        setState(() => busy = false);
        if (needsRecovery) refresh();
      }
    }
  }

  Future<void> revoke(Map<String, dynamic> proposal) async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await widget.api.request({
        'method': 'revoke_rule',
        'grant_id': proposal['id'],
      });
    } catch (e) {
      if (mounted) setState(() => error = '$e');
      return;
    } finally {
      if (mounted) {
        setState(() => busy = false);
        if (needsRecovery) refresh();
      }
    }
    if (mounted) await refresh();
  }

  @override
  Widget build(BuildContext context) {
    final query = search.text.trim().toLowerCase();
    final all = rules ?? [];
    final scoped = [
      if (filter != _RuleFilter.history) ...[
        ...all.where((state) => state['status'] == 'active'),
        ...all.where((state) => state['status'] == 'pending'),
      ],
      if (filter != _RuleFilter.current)
        ...all.where(
          (state) => !['active', 'pending'].contains(state['status']),
        ),
    ];
    final matching = scoped
        .where(
          (state) =>
              query.isEmpty || jsonAsYaml(state).toLowerCase().contains(query),
        )
        .toList();
    return Scaffold(
      appBar: AppBar(
        title: const Text('Caller rules'),
        actions: [
          IconButton(
            onPressed: busy || unavailable ? null : refresh,
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh rules',
          ),
        ],
      ),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 12, 20, 8),
            child: TextField(
              controller: search,
              onChanged: (_) => setState(() {}),
              onSubmitted: (_) => FocusScope.of(context).unfocus(),
              textInputAction: TextInputAction.search,
              decoration: InputDecoration(
                labelText: 'Search rules',
                hintText: 'Name, caller, status, or rule text',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: search.text.isEmpty
                    ? null
                    : IconButton(
                        tooltip: 'Clear search',
                        icon: const Icon(Icons.clear),
                        onPressed: () => setState(search.clear),
                      ),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
            child: SegmentedButton<_RuleFilter>(
              segments: const [
                ButtonSegment(
                  value: _RuleFilter.current,
                  label: Text('Current'),
                ),
                ButtonSegment(
                  value: _RuleFilter.history,
                  label: Text('History'),
                ),
                ButtonSegment(value: _RuleFilter.all, label: Text('All')),
              ],
              selected: {filter},
              onSelectionChanged: (selection) =>
                  setState(() => filter = selection.single),
            ),
          ),
          if (unavailable)
            ListTile(
              leading: const Icon(Icons.cloud_off),
              title: Text(connection!.connectionStatus),
              trailing: TextButton(
                onPressed: connection!.reconnecting ? null : reconnect,
                child: const Text('Reconnect'),
              ),
            ),
          if (error != null &&
              (!unavailable ||
                  (error != const ConnectionLost().toString() &&
                      error != '${connection?.reconnectError}')))
            ErrorBox(error!),
          if (busy) const LinearProgressIndicator(),
          if (rules != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
              child: Text(
                query.isEmpty
                    ? '${scoped.length} ${scoped.length == 1 ? 'rule' : 'rules'}'
                    : '${matching.length} of ${scoped.length} rules',
              ),
            ),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
              keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
              children: [
                if (rules != null && scoped.isEmpty && query.isEmpty)
                  Text(switch (filter) {
                    _RuleFilter.current =>
                      'No current rule proposals or grants.',
                    _RuleFilter.history => 'No historical rules.',
                    _RuleFilter.all => 'No rule proposals or grants.',
                  })
                else if (rules != null && matching.isEmpty)
                  const Text('No rules match your search.'),
                for (final raw in matching)
                  ruleCard(raw as Map<String, dynamic>),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget ruleCard(Map<String, dynamic> state) {
    final proposal = state['proposal'] as Map<String, dynamic>;
    final id = proposal['id'] as String;
    final review = proposal['review'];
    final title = review is Map ? review['title'] : null;
    final expiry = state['grant_expires_unix_ms'] as int?;
    return Card(
      key: ValueKey('rule-state-$id'),
      child: ExpansionTile(
        key: ValueKey('rule-expand-$id'),
        initiallyExpanded: expandedRules.contains(id),
        onExpansionChanged: (expanded) =>
            expanded ? expandedRules.add(id) : expandedRules.remove(id),
        title: Text(title is String && title.trim().isNotEmpty ? title : id),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Caller: ${proposal['principal']}'),
            Text('Status: ${state['status']}'),
            if (state['status'] == 'active')
              Text(
                expiry == null
                    ? 'Valid until revoked'
                    : 'Expires ${DateTime.fromMillisecondsSinceEpoch(expiry).toLocal()}',
              ),
          ],
        ),
        expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
        childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
        children: [
          Text(state['reason'] as String),
          const SizedBox(height: 12),
          RuleDefinition(proposal: proposal),
          if (state['status'] == 'active')
            OutlinedButton(
              onPressed: busy || unavailable ? null : () => revoke(proposal),
              child: const Text('Revoke rule'),
            ),
        ],
      ),
    );
  }
}
