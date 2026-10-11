import 'dart:convert';
import 'package:flutter/material.dart';
import 'control.dart';
import 'ui.dart';

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
          const Text(
            'Approval permits repeated invocations by this principal (including every assigned key) without another prompt. Commands run as your Unix user without gaining new privileges.',
          ),
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
    final bound = proposal['bound'] as Map;
    final rule = bound['rule'] as Map;
    final parameters = rule['parameters'] as List;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          '${proposal['principal']} · ${rule['name']}',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 12),
        SelectableText(proposal['source'] as String, style: mono),
        const SizedBox(height: 12),
        Text('Executable: ${jsonEncode(rule['program'])}'),
        Text('Working directory: ${jsonEncode(bound['cwd'])}'),
        Text('Server HOME: ${jsonEncode(bound['home'])}'),
        if (parameters.isNotEmpty) ...[
          const SizedBox(height: 8),
          Text(
            'Parameters: ${parameters.map((p) => '${p['name']}: ${p['kind']}').join(', ')}',
          ),
          const Text(
            'repo-name: 1–100 ASCII letters, digits, dots, underscores or hyphens; starts with a letter or digit. Values are literal text.',
          ),
        ],
        if (rule['create_new'] != null) ...[
          const SizedBox(height: 8),
          const Text(
            'create-new publishes a directory only after success and only if its destination is still absent.',
          ),
        ],
        ExpansionTile(
          tilePadding: EdgeInsets.zero,
          title: const Text('Rule details'),
          children: [
            SelectableText(
              const JsonEncoder.withIndent('  ').convert(proposal),
              style: mono,
            ),
          ],
        ),
      ],
    );
  }
}

class RulesPage extends StatefulWidget {
  const RulesPage({super.key, required this.api});
  final ControlApi api;
  @override
  State<RulesPage> createState() => _RulesPageState();
}

class _RulesPageState extends State<RulesPage> {
  List<dynamic>? rules;
  String? error;
  bool busy = false;
  @override
  void initState() {
    super.initState();
    refresh();
  }

  Future<void> refresh() async {
    if (busy) return;
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
      if (mounted) setState(() => busy = false);
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
      if (mounted) setState(() => busy = false);
    }
    if (mounted) await refresh();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('Caller rules'),
      actions: [
        IconButton(
          onPressed: busy ? null : refresh,
          icon: const Icon(Icons.refresh),
          tooltip: 'Refresh rules',
        ),
      ],
    ),
    body: ListView(
      padding: const EdgeInsets.all(20),
      children: [
        if (error != null) ErrorBox(error!),
        if (busy) const LinearProgressIndicator(),
        if (rules?.isEmpty == true) const Text('No rule proposals or grants.'),
        for (final raw in rules ?? []) ruleCard(raw as Map<String, dynamic>),
      ],
    ),
  );

  Widget ruleCard(Map<String, dynamic> state) {
    final proposal = state['proposal'] as Map<String, dynamic>;
    final expiry = state['grant_expires_unix_ms'] as int?;
    return Card(
      key: ValueKey('rule-state-${proposal['id']}'),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Status: ${state['status']}',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            Text(state['reason'] as String),
            if (state['status'] == 'active')
              Text(
                expiry == null
                    ? 'Valid until revoked'
                    : 'Expires ${DateTime.fromMillisecondsSinceEpoch(expiry).toLocal()}',
              ),
            const SizedBox(height: 12),
            RuleDefinition(proposal: proposal),
            if (state['status'] == 'active')
              OutlinedButton(
                onPressed: busy ? null : () => revoke(proposal),
                child: const Text('Revoke rule'),
              ),
          ],
        ),
      ),
    );
  }
}
