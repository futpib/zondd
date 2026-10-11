import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'control.dart';
import 'ui.dart';
import 'json_yaml.dart';
import 'search.dart';

const activeStatuses = {
  'received',
  'pending',
  'approved',
  'allowed',
  'running',
};
String statusLabel(String status) => switch (status) {
  'pending' => 'Needs approval',
  'approved' => 'Approved',
  'allowed' => 'Allowed',
  'completed' => 'Finished',
  'denied' => 'Denied',
  'expired' => 'Expired',
  'cancelled' => 'Cancelled',
  'interrupted' => 'Interrupted',
  'rejected' => 'Rejected',
  'failed' => 'Failed',
  'running' => 'Running',
  _ => 'Received',
};
String timestamp(dynamic value) => DateTime.fromMillisecondsSinceEpoch(
  value as int,
).toLocal().toString().split('.').first;
String commandText(Map<String, dynamic> record) =>
    jsonAsYaml(record['command'] ?? record['input']);

IconData statusIcon(String status) => switch (status) {
  'completed' => Icons.check_circle_outline,
  'running' || 'allowed' || 'approved' => Icons.play_circle_outline,
  'pending' => Icons.pending_outlined,
  'expired' => Icons.timer_off_outlined,
  'cancelled' || 'interrupted' => Icons.stop_circle_outlined,
  _ => Icons.block,
};

class HistoryPage extends StatefulWidget {
  const HistoryPage({super.key, required this.api});
  final ControlApi api;
  @override
  State<HistoryPage> createState() => HistoryPageState();
}

class HistoryPageState extends State<HistoryPage> with WidgetsBindingObserver {
  List<Map<String, dynamic>> rows = [];
  int? before;
  bool activity = false, loading = false, loaded = false, paged = false;
  String? error;
  Timer? timer;
  Timer? searchTimer;
  final search = TextEditingController();
  final expandedActions = <int>{};
  String query = '';
  int generation = 0;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    fetch();
    timer = Timer.periodic(const Duration(seconds: 2), (_) => fetch());
  }

  @override
  void dispose() {
    timer?.cancel();
    searchTimer?.cancel();
    search.dispose();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    timer?.cancel();
    if (state == AppLifecycleState.resumed) {
      fetch();
      timer = Timer.periodic(const Duration(seconds: 2), (_) => fetch());
    }
  }

  Future<void> fetch({bool more = false}) async {
    if (!mounted || loading || searchTimer?.isActive == true) return;
    setState(() => loading = true);
    final selectedActivity = activity;
    final selectedGeneration = generation;
    try {
      final result = await widget.api.request({
        'method': activity ? 'actions' : 'history',
        'limit': 30,
        if (more) 'before': before,
        if (query.isNotEmpty) 'query': query,
      });
      if (!mounted || generation != selectedGeneration) return;
      final head = (result[activity ? 'actions' : 'requests'] as List)
          .cast<Map<String, dynamic>>();
      final incoming = [...head];
      final updatedSequences = <int>{};
      if (!selectedActivity) {
        final sequences = head.map((row) => row['sequence']).toSet();
        final waiting = rows
            .where(
              (row) =>
                  activeStatuses.contains(row['status']) &&
                  !sequences.contains(row['sequence']),
            )
            .toList();
        for (final row in waiting) {
          final update = await widget.api.request({
            'method': 'history',
            'before': (row['sequence'] as int) + 1,
            'limit': 1,
            if (query.isNotEmpty) 'query': query,
          });
          if (!mounted || generation != selectedGeneration) return;
          updatedSequences.add(row['sequence'] as int);
          incoming.addAll(
            (update['requests'] as List).cast<Map<String, dynamic>>().where(
              (updated) => updated['sequence'] == row['sequence'],
            ),
          );
        }
      }
      setState(() {
        final gap =
            rows.isNotEmpty &&
            head.isNotEmpty &&
            (head.last['sequence'] as int) > (rows.first['sequence'] as int);
        final merged = <int, Map<String, dynamic>>{
          for (final row in rows)
            if (!updatedSequences.contains(row['sequence']))
              row['sequence'] as int: row,
          for (final row in incoming) row['sequence'] as int: row,
        };
        rows = merged.values.toList()
          ..sort(
            (a, b) => (b['sequence'] as int).compareTo(a['sequence'] as int),
          );
        if (more || !paged || gap) before = result['next_before'] as int?;
        if (more) paged = true;
        if (gap) paged = false;
        loaded = true;
        error = null;
      });
    } catch (e) {
      if (mounted && generation == selectedGeneration) {
        setState(() => error = '$e');
      }
    } finally {
      if (mounted) {
        setState(() => loading = false);
        if (generation != selectedGeneration) fetch();
      }
    }
  }

  void resetResults() {
    generation++;
    rows = [];
    before = null;
    loaded = false;
    paged = false;
    error = null;
  }

  void searchChanged(String text) {
    searchTimer?.cancel();
    setState(() {});
    searchTimer = Timer(const Duration(milliseconds: 300), () {
      final value = search.text.trim();
      if (value == query) return;
      setState(() {
        query = value;
        resetResults();
      });
      fetch();
    });
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('History', style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 16),
            SegmentedButton<bool>(
              segments: const [
                ButtonSegment(
                  value: false,
                  label: Text('Requests'),
                  icon: Icon(Icons.history),
                ),
                ButtonSegment(
                  value: true,
                  label: Text('Activity'),
                  icon: Icon(Icons.receipt_long),
                ),
              ],
              selected: {activity},
              onSelectionChanged: (value) {
                searchTimer?.cancel();
                setState(() {
                  activity = value.single;
                  query = search.text.trim();
                  resetResults();
                });
                fetch();
              },
            ),
            const SizedBox(height: 12),
            ListSearchField(
              controller: search,
              label: activity ? 'Search activity' : 'Search requests',
              hint: activity
                  ? 'Action or details'
                  : 'Command, caller, status, or reason',
              onChanged: searchChanged,
            ),
          ],
        ),
      ),
      Expanded(
        child: RefreshIndicator(
          onRefresh: fetch,
          child: ListView(
            physics: const AlwaysScrollableScrollPhysics(),
            keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              if (error != null) ErrorBox(error!),
              if (!loaded && error == null)
                const Center(child: CircularProgressIndicator()),
              if (loaded && rows.isEmpty && query.isNotEmpty)
                const Text('No history matches your search.'),
              if (loaded && rows.isEmpty && query.isEmpty)
                EmptyState(
                  Icons.history,
                  activity ? 'No activity yet' : 'No requests yet',
                  activity
                      ? 'Daemon actions are kept here.'
                      : 'Requests and their outcomes are kept here, including rejected and expired requests.',
                ),
              for (final row in rows)
                if (activity)
                  ActionTile(
                    key: ValueKey(row['sequence']),
                    action: row,
                    initiallyExpanded: expandedActions.contains(
                      row['sequence'],
                    ),
                    onExpansionChanged: (expanded) => expanded
                        ? expandedActions.add(row['sequence'] as int)
                        : expandedActions.remove(row['sequence']),
                  )
                else
                  Card(
                    child: ListTile(
                      contentPadding: const EdgeInsets.all(16),
                      leading: Icon(statusIcon(row['status'] as String)),
                      title: Text(
                        '${statusLabel(row['status'] as String)} · ${row['principal']}',
                      ),
                      subtitle: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const SizedBox(height: 8),
                          Text(
                            commandText(row),
                            style: mono,
                            maxLines: 3,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(height: 8),
                          Text(timestamp(row['created_unix_ms'])),
                          if ((row['reason'] as String).isNotEmpty)
                            Text(
                              row['reason'] as String,
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                          if (row['authorization'] == 'approval')
                            const Text('Approved once'),
                          if (row['retry_of'] != null)
                            const Text('Run again from an earlier request'),
                        ],
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () async {
                        await Navigator.push(
                          context,
                          MaterialPageRoute<void>(
                            builder: (_) => RequestDetailsPage(
                              api: widget.api,
                              requestId: row['request_id'] as String,
                            ),
                          ),
                        );
                        fetch();
                      },
                    ),
                  ),
              if (before != null)
                TextButton(
                  onPressed: loading ? null : () => fetch(more: true),
                  child: const Text('Load earlier'),
                ),
            ],
          ),
        ),
      ),
    ],
  );
}

class ActionTile extends StatelessWidget {
  const ActionTile({
    super.key,
    required this.action,
    this.initiallyExpanded = false,
    this.onExpansionChanged,
  });
  final Map<String, dynamic> action;
  final bool initiallyExpanded;
  final ValueChanged<bool>? onExpansionChanged;
  @override
  Widget build(BuildContext context) => Card(
    child: ExpansionTile(
      initiallyExpanded: initiallyExpanded,
      onExpansionChanged: onExpansionChanged,
      title: Text((action['action'] as String).replaceAll('_', ' ')),
      subtitle: Text(timestamp(action['time_unix_ms'])),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Align(
          alignment: Alignment.centerLeft,
          child: SelectableText(jsonAsYaml(action['detail']), style: mono),
        ),
      ],
    ),
  );
}

class RequestDetailsPage extends StatefulWidget {
  const RequestDetailsPage({
    super.key,
    required this.api,
    required this.requestId,
  });
  final ControlApi api;
  final String requestId;
  @override
  State<RequestDetailsPage> createState() => _RequestDetailsPageState();
}

class _RequestDetailsPageState extends State<RequestDetailsPage> {
  Map<String, dynamic>? record;
  List<Map<String, dynamic>> actions = [];
  int? before;
  String? error;
  bool loading = false, acting = false, paged = false;
  Timer? timer;
  int fetchGeneration = 0;
  ControlConnection? get connection =>
      widget.api is ControlConnection ? widget.api as ControlConnection : null;
  bool get unavailable =>
      connection?.disconnected == true || connection?.reconnecting == true;
  int connectionGeneration = 0;
  bool needsRecovery = false;
  void connectionChanged() {
    if (!mounted) return;
    if (unavailable) {
      fetchGeneration++;
      loading = false;
    }
    if (connection!.generation != connectionGeneration) {
      connectionGeneration = connection!.generation;
      needsRecovery = true;
    }
    setState(() {});
    if (needsRecovery) unawaited(fetch());
  }

  Future<void> reconnect() async {
    if (acting || connection!.reconnecting) return;
    setState(() {
      acting = true;
      error = null;
      fetchGeneration++;
      loading = false;
    });
    try {
      await connection!.reconnect();
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => acting = false);
    }
    if (mounted && !unavailable) await fetch();
  }

  @override
  void initState() {
    super.initState();
    connection?.addListener(connectionChanged);
    fetch();
    timer = Timer.periodic(const Duration(seconds: 2), (_) {
      if (needsRecovery ||
          record == null ||
          activeStatuses.contains(record!['status'])) {
        fetch();
      }
    });
  }

  @override
  void dispose() {
    timer?.cancel();
    connection?.removeListener(connectionChanged);
    super.dispose();
  }

  Future<void> fetch() async {
    if (loading || acting || unavailable) return;
    needsRecovery = false;
    final generation = ++fetchGeneration;
    setState(() => loading = true);
    try {
      final result = await widget.api.request({
        'method': 'request_detail',
        'request_id': widget.requestId,
      });
      if (mounted && generation == fetchGeneration) {
        setState(() {
          record = result['request'] as Map<String, dynamic>;
          final incoming = (result['actions'] as List)
              .cast<Map<String, dynamic>>();
          final gap =
              actions.isNotEmpty &&
              incoming.isNotEmpty &&
              (incoming.last['sequence'] as int) >
                  (actions.first['sequence'] as int);
          if (!paged || gap) {
            before = result['next_before'] as int?;
          }
          if (gap) paged = false;
          final merged = <int, Map<String, dynamic>>{
            for (final row in actions) row['sequence'] as int: row,
            for (final row in incoming) row['sequence'] as int: row,
          };
          actions = merged.values.toList()
            ..sort(
              (a, b) => (b['sequence'] as int).compareTo(a['sequence'] as int),
            );
          error = null;
        });
      }
    } catch (e) {
      if (mounted && generation == fetchGeneration) {
        setState(() => error = '$e');
      }
    } finally {
      if (mounted && generation == fetchGeneration) {
        setState(() => loading = false);
      }
    }
  }

  Future<void> earlier() async {
    if (loading || acting || unavailable) return;
    setState(() => acting = true);
    try {
      final result = await widget.api.request({
        'method': 'actions',
        'request_id': widget.requestId,
        'before': before,
        'limit': 30,
      });
      if (mounted) {
        setState(() {
          actions.addAll(
            (result['actions'] as List).cast<Map<String, dynamic>>(),
          );
          before = result['next_before'] as int?;
          paged = true;
        });
      }
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => acting = false);
    }
  }

  Future<void> resolve(bool approve) async {
    setState(() => acting = true);
    try {
      await widget.api.request({
        'method': 'resolve',
        'approval_id': record!['approval_id'],
        'approve': approve,
      });
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => acting = false);
    }
    await fetch();
  }

  Future<void> retry() async {
    setState(() => acting = true);
    try {
      final result = await widget.api.request({
        'method': 'retry',
        'request_id': widget.requestId,
      });
      if (!mounted) return;
      await Navigator.pushReplacement(
        context,
        MaterialPageRoute<void>(
          builder: (_) => RequestDetailsPage(
            api: widget.api,
            requestId: result['request_id'] as String,
          ),
        ),
      );
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => acting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final r = record;
    final result = r?['result'] as Map?;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Request history'),
        actions: [
          if (connection != null)
            IconButton(
              tooltip: 'Reconnect',
              onPressed: acting || connection!.reconnecting ? null : reconnect,
              icon: const Icon(Icons.sync),
            ),
          IconButton(
            tooltip: 'Refresh',
            onPressed: acting || loading || unavailable ? null : fetch,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          if (unavailable)
            ListTile(
              leading: const Icon(Icons.cloud_off),
              title: Text(connection!.connectionStatus),
              trailing: TextButton(
                onPressed: acting || connection!.reconnecting
                    ? null
                    : reconnect,
                child: const Text('Reconnect'),
              ),
            ),
          if (error != null &&
              (!unavailable ||
                  (error != const ConnectionLost().toString() &&
                      error != '${connection?.reconnectError}')))
            ErrorBox(error!),
          if (acting) const LinearProgressIndicator(),
          if (r == null && error == null && !unavailable)
            const Center(child: CircularProgressIndicator()),
          if (r != null) ...[
            Row(
              children: [
                Icon(statusIcon(r['status'] as String)),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    statusLabel(r['status'] as String),
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text('${r['principal']} · ${timestamp(r['created_unix_ms'])}'),
            const SizedBox(height: 20),
            SelectableText(commandText(r), style: mono),
            if (r['cwd'] != null) ...[
              const SizedBox(height: 12),
              SelectableText(jsonAsYaml({'cwd': r['cwd']}), style: mono),
            ],
            const SizedBox(height: 12),
            Text(r['reason'] as String),
            const SizedBox(height: 20),
            if (r['status'] == 'pending')
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: acting || loading || unavailable
                          ? null
                          : () => resolve(false),
                      child: const Text('Reject'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: FilledButton(
                      onPressed: acting || loading || unavailable
                          ? null
                          : () => resolve(true),
                      child: const Text('Approve once'),
                    ),
                  ),
                ],
              ),
            if (!activeStatuses.contains(r['status'])) ...[
              FilledButton.icon(
                onPressed: acting || loading || unavailable ? null : retry,
                icon: const Icon(Icons.replay),
                label: const Text('Run again'),
              ),
              const SizedBox(height: 8),
              const Text(
                'Creates a new request under current policy. Earlier approvals do not carry over.',
              ),
            ],
            if (r['retry_of'] != null)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: TextButton(
                  onPressed: () => Navigator.push(
                    context,
                    MaterialPageRoute<void>(
                      builder: (_) => RequestDetailsPage(
                        api: widget.api,
                        requestId: r['retry_of'] as String,
                      ),
                    ),
                  ),
                  child: const Text('View original request'),
                ),
              ),
            if (result != null) ...[
              const SizedBox(height: 24),
              if (result['code'] != null || result['signal'] != null)
                Text(
                  'Exit code: ${result['code'] ?? '—'} · Signal: ${result['signal'] ?? '—'}',
                ),
              for (final field in ['stdout', 'stderr'])
                if (result[field] is String &&
                    (result[field] as String).isNotEmpty) ...[
                  const SizedBox(height: 16),
                  Text(field, style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 8),
                  SelectableText(
                    utf8.decode(
                      base64Decode(result[field] as String),
                      allowMalformed: true,
                    ),
                    style: mono,
                  ),
                ],
            ],
            ExpansionTile(
              title: const Text('Request details'),
              children: [
                ListTile(
                  title: const Text('Request ID'),
                  subtitle: SelectableText(
                    r['request_id'] as String,
                    style: mono,
                  ),
                ),
                ListTile(
                  title: const Text('Last update'),
                  subtitle: Text(timestamp(r['updated_unix_ms'])),
                ),
              ],
            ),
            ExpansionTile(
              title: const Text('Original request'),
              children: [SelectableText(jsonAsYaml(r['input']), style: mono)],
            ),
            if (result != null)
              ExpansionTile(
                title: const Text('Raw result'),
                children: [SelectableText(jsonAsYaml(result), style: mono)],
              ),
            const SizedBox(height: 24),
            Text('Activity', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 12),
            for (final action in actions)
              ActionTile(key: ValueKey(action['sequence']), action: action),
            if (before != null)
              TextButton(
                onPressed: acting || loading || unavailable ? null : earlier,
                child: const Text('Load earlier activity'),
              ),
          ],
        ],
      ),
    );
  }
}
