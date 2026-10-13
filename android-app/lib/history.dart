import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'control.dart';
import 'ui.dart';
import 'json_yaml.dart';
import 'search.dart';
import 'audit.dart';

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
  bool includeReads = false, grouped = true, exporting = false;
  bool auditUnsupported = false;
  AuditVerifier? verifier;
  String? auditError;
  ControlConnection? get connection =>
      widget.api is ControlConnection ? widget.api as ControlConnection : null;
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
    connection?.addListener(connectionChanged);
    fetch();
    timer = Timer.periodic(const Duration(seconds: 2), (_) => fetch());
  }

  @override
  void dispose() {
    timer?.cancel();
    searchTimer?.cancel();
    search.dispose();
    WidgetsBinding.instance.removeObserver(this);
    connection?.removeListener(connectionChanged);
    super.dispose();
  }

  void connectionChanged() {
    if (!mounted) return;
    if (connection!.disconnected || connection!.reconnecting) {
      setState(
        () => error =
            '${connection!.connectionStatus} Showing previously loaded history.',
      );
    } else {
      fetch();
    }
  }

  Future<void> exportAudit() async {
    if (verifier == null || exporting) return;
    setState(() => exporting = true);
    try {
      final bundle = await verifier!.export(SshControl.auditDevice);
      final bytes = Uint8List.fromList(
        utf8.encode(const JsonEncoder.withIndent('  ').convert(bundle)),
      );
      final result = await FilePicker.saveFile(
        fileName: 'zond-audit-${verifier!.checkpoint!['sequence']}.json',
        bytes: bytes,
        mimeType: 'application/json',
      );
      if (mounted && result != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Audit history exported.')),
        );
      }
    } catch (e) {
      if (mounted) setState(() => auditError = '$e');
    } finally {
      if (mounted) setState(() => exporting = false);
    }
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
      final nextVerifier = widget.api is AuditPeer
          ? (widget.api as AuditPeer).historyVerifier
          : null;
      if (verifier != nextVerifier) {
        verifier = nextVerifier;
        auditUnsupported = false;
      }
      if (verifier != null && !auditUnsupported) {
        try {
          await verifier!.sync();
          if (!mounted || generation != selectedGeneration) return;
          auditError = null;
        } on StateError catch (e) {
          if (e.message == 'invalid control request') {
            if (await verifier!.hasSavedCheckpoint()) {
              throw StateError(
                'Receiver stopped supporting audit verification. The phone checkpoint is preserved.',
              );
            }
            auditUnsupported = true;
          } else {
            auditError = '$e';
            rethrow;
          }
        }
      }
      final result = await widget.api.request({
        'method': activity ? 'actions' : 'history',
        'limit': 30,
        if (more) 'before': before,
        if (query.isNotEmpty) 'query': query,
        if (activity && verifier != null && !auditUnsupported)
          'include_reads': includeReads,
      });
      if (!mounted || generation != selectedGeneration) return;
      final head = (result[activity ? 'actions' : 'requests'] as List)
          .cast<Map<String, dynamic>>();
      if (selectedActivity && verifier != null && !auditUnsupported) {
        // The receiver can add events between verification and this page.
        // Verify the newer checkpoint before accepting those displayed bytes.
        if (head.any((r) => !verifier!.events.containsKey(r['sequence']))) {
          await verifier!.sync();
        }
        for (final row in head) {
          verifier!.verifyDisplayed(row);
        }
      }
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
        setState(() {
          error = '$e';
          if (verifier != null && !auditUnsupported) auditError = '$e';
        });
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
            Row(
              children: [
                Expanded(
                  child: Text(
                    'History',
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                ),
                if (verifier != null && !auditUnsupported)
                  IconButton(
                    tooltip: 'Export audit history',
                    onPressed: exporting || loading || auditError != null
                        ? null
                        : exportAudit,
                    icon: Icon(
                      exporting ? Icons.hourglass_top : Icons.download,
                    ),
                  ),
              ],
            ),
            if (auditUnsupported)
              const Text(
                'Receiver has no audit verification. History is unverified.',
              ),
            if ((verifier?.checkpoint != null || auditError != null) &&
                !auditUnsupported)
              Text(
                auditError == null
                    ? 'Activity matches phone checkpoint · event ${verifier!.checkpoint!['sequence']}'
                    : 'Audit check failed. Previous phone checkpoint preserved.',
              ),
            if (verifier?.checkpoint != null && !auditUnsupported)
              const Text(
                'Checks detect changes since phone observations. Outcomes are reports from the receiver or application.',
              ),
            if ((verifier?.unrecordedReceipts ?? 0) > 0)
              Text(
                '${verifier!.unrecordedReceipts} device decisions are not recorded by the receiver. Their outcomes are unknown.',
              ),
            if (verifier?.legacyThrough != null &&
                verifier!.legacyThrough > 0 &&
                !auditUnsupported)
              Text(
                'Events through ${verifier!.legacyThrough} were imported before integrity tracking began.',
              ),
            if (verifier != null && !verifier!.online)
              const Text(
                'Daemon offline. Management changes can still be recorded.',
              ),
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
            if (activity)
              Wrap(
                spacing: 8,
                children: [
                  FilterChip(
                    label: const Text('Include reads'),
                    selected: includeReads,
                    onSelected: (value) {
                      setState(() {
                        includeReads = value;
                        resetResults();
                      });
                      fetch();
                    },
                  ),
                  FilterChip(
                    label: const Text('Group related events'),
                    selected: grouped,
                    onSelected: (value) => setState(() => grouped = value),
                  ),
                ],
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
              if (auditError != null && auditError != error)
                ErrorBox(auditError!),
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
              if (activity && grouped && !auditUnsupported)
                ...activityGroups(rows, widget.api, includeReads),
              for (final row in rows)
                if (activity &&
                    (!grouped ||
                        auditUnsupported ||
                        eventSubject(row) == null) &&
                    (includeReads || row['category'] != 'read'))
                  ActionTile(
                    key: ValueKey(row['sequence']),
                    action: row,
                    api: widget.api,
                    verified:
                        verifier != null &&
                        !auditUnsupported &&
                        auditError == null,
                    initiallyExpanded: expandedActions.contains(
                      row['sequence'],
                    ),
                    onExpansionChanged: (expanded) => expanded
                        ? expandedActions.add(row['sequence'] as int)
                        : expandedActions.remove(row['sequence']),
                  )
                else if (!activity)
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
    this.api,
    this.verified = false,
  });
  final Map<String, dynamic> action;
  final bool initiallyExpanded;
  final ValueChanged<bool>? onExpansionChanged;
  final ControlApi? api;
  final bool verified;
  @override
  Widget build(BuildContext context) => Card(
    child: ExpansionTile(
      initiallyExpanded: initiallyExpanded,
      onExpansionChanged: onExpansionChanged,
      title: Text(eventTitle(action)),
      subtitle: Text(
        [
          timestamp(action['time_unix_ms']),
          if (eventSummary(action).isNotEmpty) eventSummary(action),
        ].join('\n'),
      ),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        if (action['detail'] is Map &&
            (action['detail'] as Map)['actor'] is Map)
          ActorInfo(
            verified: verified,
            actor: Map<String, dynamic>.from(
              (action['detail'] as Map)['actor'] as Map,
            ),
          ),
        if (api != null && action['request_id'] is String)
          TextButton(
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute<void>(
                builder: (_) => RequestDetailsPage(
                  api: api!,
                  requestId: action['request_id'] as String,
                ),
              ),
            ),
            child: const Text('View request'),
          ),
        Align(
          alignment: Alignment.centerLeft,
          child: SelectableText(jsonAsYaml(action['detail']), style: mono),
        ),
      ],
    ),
  );
}

String eventTitle(Map<String, dynamic> row) {
  final detail = row['detail'] as Map? ?? const {};
  return switch (row['action']) {
    'request_received' => 'Request submitted',
    'policy_evaluated' => 'Policy evaluated',
    'execution_started' => 'Command started',
    'request_finished' => 'Command finished',
    'request_rejected' => 'Request rejected',
    'approval_granted' => 'Approved once',
    'approval_denied' => 'Approval denied',
    'approval_expired' => 'Approval expired',
    'request_withdrawn' => 'Caller withdrew request',
    'request_cancelled' => 'Command cancelled',
    'interrupted' => 'Command interrupted',
    'signed_decision' => 'Device signed decision',
    'interaction_requested' => 'Application requested input',
    'interaction_decision' =>
      detail['provided'] == true ? 'Response submitted' : 'Response declined',
    'interaction_ended' => switch (detail['status']) {
      'answered' => 'Response submitted for recipient',
      'withdrawn' => 'Application withdrew its request',
      'expired' => 'Input request expired',
      'rejected' => 'Input request declined',
      _ => 'Input request ended',
    },
    'interaction_response_queued' => 'Response queued for recipient',
    'interaction_delivery_failed' => 'Private delivery failed',
    'interaction_result' => switch (detail['outcome']) {
      'succeeded' => 'Application reported success',
      'failed' => 'Application reported failure',
      'cancelled' => 'Application reported cancellation',
      _ => 'Application result unknown after interruption',
    },
    'credential_session_opened' => 'Recipient connected',
    'credential_session_closed' => 'Recipient disconnected',
    'credential_answered' =>
      detail['provided'] == true
          ? 'Sudo response submitted'
          : 'Sudo response declined',
    'daemon_started' => 'Daemon started',
    'daemon_stopping' => 'Daemon stopping',
    'policy_reloaded' => 'Policy applied',
    'control.save_config_requested' => 'Configuration save requested',
    'control.save_config' =>
      detail['ok'] == true
          ? 'Configuration saved'
          : 'Configuration save failed',
    'control.service_requested' => 'Daemon service action requested',
    'control.service_finished' =>
      detail['ok'] == true
          ? 'Daemon service action completed'
          : 'Daemon service action failed',
    _ => (row['action'] as String).replaceAll('_', ' '),
  };
}

String eventSummary(Map<String, dynamic> row) {
  final d = row['detail'] as Map? ?? const {};
  final parts = <String>[];
  if (d['principal'] is String) parts.add('Caller: ${d['principal']}');
  if (d['recipient'] is Map) {
    final recipient = d['recipient'] as Map;
    parts.add('Recipient: ${recipient['label'] ?? recipient['name']}');
  } else if (d['recipient'] is String) {
    parts.add('Recipient: ${d['recipient']}');
  }
  if (d['reason'] is String) parts.add(d['reason'] as String);
  if (d['code'] != null) parts.add('Exit ${d['code']}');
  if (d['provider_origin'] is String) parts.add(d['provider_origin'] as String);
  if (d['rule'] is Map) {
    final rule = d['rule'] as Map;
    final name = (rule['bound'] as Map?)?['rule'];
    if (name is Map && name['name'] is String) {
      parts.add('Rule: ${name['name']}');
    }
  }
  return parts.join(' · ');
}

String? eventSubject(Map<String, dynamic> row) {
  final d = row['detail'] as Map? ?? const {};
  if (row['request_id'] is String) return row['request_id'] as String;
  if (d['challenge_id'] is String) return d['challenge_id'] as String;
  if (d['proposal_id'] is String) return d['proposal_id'] as String;
  if (d['grant_id'] is String) return d['grant_id'] as String;
  if (d['proposal'] is Map && (d['proposal'] as Map)['id'] is String) {
    return (d['proposal'] as Map)['id'] as String;
  }
  if (d['session_id'] is String) return d['session_id'] as String;
  if (d['recipient'] is Map &&
      (d['recipient'] as Map)['session_id'] is String) {
    return (d['recipient'] as Map)['session_id'] as String;
  }
  if (row['category'] != 'read' && d['actor'] is Map) {
    final actor = d['actor'] as Map;
    return (actor['receipt_id'] ?? actor['operation_id']) as String?;
  }
  return null;
}

List<Widget> activityGroups(
  List<Map<String, dynamic>> rows,
  ControlApi api,
  bool includeReads,
) {
  final groups = <String, List<Map<String, dynamic>>>{};
  for (final row in rows) {
    if (!includeReads && row['category'] == 'read') continue;
    final key = eventSubject(row);
    if (key == null) continue;
    groups.putIfAbsent(key, () => []).add(row);
  }
  return [
    for (final entry in groups.entries)
      ActivityGroup(
        key: ValueKey(entry.key),
        events: entry.value,
        api: api,
        subject: entry.key,
      ),
  ];
}

class ActivityGroup extends StatelessWidget {
  const ActivityGroup({
    super.key,
    required this.events,
    required this.api,
    required this.subject,
  });
  final List<Map<String, dynamic>> events;
  final ControlApi api;
  final String subject;
  @override
  Widget build(BuildContext context) {
    final latest = events.first;
    final request = events.any((e) => e['request_id'] == subject);
    return Card(
      child: ListTile(
        leading: Icon(request ? Icons.terminal : Icons.receipt_long),
        title: Text(eventTitle(latest)),
        subtitle: Text(
          [
            timestamp(latest['time_unix_ms']),
            if (eventSummary(latest).isNotEmpty) eventSummary(latest),
            if ([
              'signed_decision',
              'control.save_config_requested',
              'control.service_requested',
            ].contains(latest['action']))
              'Outcome not yet recorded',
            'View timeline · ${subject.substring(0, subject.length < 8 ? subject.length : 8)}',
          ].join('\n'),
        ),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute<void>(
            builder: (_) => request
                ? RequestDetailsPage(api: api, requestId: subject)
                : TimelinePage(api: api, subject: subject),
          ),
        ),
      ),
    );
  }
}

class ActorInfo extends StatelessWidget {
  const ActorInfo({super.key, required this.actor, this.verified = false});
  final Map<String, dynamic> actor;
  final bool verified;
  @override
  Widget build(BuildContext context) {
    final transport = actor['transport'] as Map? ?? const {};
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Unix account: ${actor['unix_uid'] ?? 'unknown'}'),
          if (transport['ssh_key_fingerprint'] is String)
            SelectableText(
              'SSH key: ${transport['ssh_key_fingerprint']}',
              style: mono,
            )
          else
            const Text('SSH key attribution unavailable'),
          if (transport['evidence'] is String &&
              transport['ssh_key_fingerprint'] != null)
            Text('Account-side evidence: ${transport['evidence']}'),
          if (actor['device_signing_key'] is String) ...[
            SelectableText(
              'Device signing key: ${actor['device_signing_key']}',
              style: mono,
            ),
            Text(
              verified
                  ? 'Device signature checked. It proves key possession; it does not identify a person.'
                  : 'Receiver-reported device key. Check the signed receipt in Activity.',
            ),
          ] else
            const Text('No device-signed decision receipt'),
        ],
      ),
    );
  }
}

class TimelinePage extends StatefulWidget {
  const TimelinePage({super.key, required this.api, required this.subject});
  final ControlApi api;
  final String subject;
  @override
  State<TimelinePage> createState() => _TimelinePageState();
}

class _TimelinePageState extends State<TimelinePage>
    with WidgetsBindingObserver {
  final rows = <int, Map<String, dynamic>>{};
  int? before;
  String? error;
  bool loading = false;
  bool verified = false;
  Timer? timer;
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
    if (loading) return;
    setState(() => loading = true);
    try {
      final verifier = widget.api is AuditPeer
          ? (widget.api as AuditPeer).historyVerifier
          : null;
      await verifier?.sync();
      final result = await widget.api.request({
        'method': 'actions',
        'subject_id': widget.subject,
        'include_reads': false,
        'limit': 30,
        if (more) 'before': before,
      });
      final incoming = (result['actions'] as List).cast<Map<String, dynamic>>();
      if (verifier != null) {
        if (incoming.any((e) => !verifier.events.containsKey(e['sequence']))) {
          await verifier.sync();
        }
        for (final row in incoming) {
          verifier.verifyDisplayed(row);
        }
      }
      if (!mounted) return;
      setState(() {
        verified = verifier != null;
        final gap =
            rows.isNotEmpty &&
            incoming.isNotEmpty &&
            (incoming.last['sequence'] as int) >
                rows.keys.reduce((a, b) => a > b ? a : b);
        if (more || before == null || gap) {
          before = result['next_before'] as int?;
        }
        for (final row in incoming) {
          rows[row['sequence'] as int] = row;
        }
        error = null;
      });
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ordered = rows.values.toList()
      ..sort((a, b) => (a['sequence'] as int).compareTo(b['sequence'] as int));
    return Scaffold(
      appBar: AppBar(title: const Text('Activity timeline')),
      body: RefreshIndicator(
        onRefresh: fetch,
        child: ListView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.all(20),
          children: [
            SelectableText(widget.subject, style: mono),
            if (error != null) ErrorBox(error!),
            if (loading) const LinearProgressIndicator(),
            if (before != null)
              TextButton(
                onPressed: loading ? null : () => fetch(more: true),
                child: const Text('Load earlier activity'),
              ),
            for (final row in ordered)
              ActionTile(
                key: ValueKey(row['sequence']),
                action: row,
                api: widget.api,
                verified: verified && error == null,
              ),
          ],
        ),
      ),
    );
  }
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
  bool verified = false;
  Future<void> verifyActions(
    List<Map<String, dynamic>> incoming,
    Map<String, dynamic>? request,
  ) async {
    final verifier = widget.api is AuditPeer
        ? (widget.api as AuditPeer).historyVerifier
        : null;
    verified = false;
    if (verifier == null) return;
    try {
      await verifier.sync();
    } on StateError catch (e) {
      if (e.message == 'invalid control request' &&
          !await verifier.hasSavedCheckpoint()) {
        return;
      }
      rethrow;
    }
    if (incoming.any((e) => !verifier.events.containsKey(e['sequence']))) {
      await verifier.sync();
    }
    for (final row in incoming) {
      verifier.verifyDisplayed(row);
    }
    if (request != null) verifier.verifyRequestAttribution(request);
    verified = true;
  }

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
      final incoming = (result['actions'] as List).cast<Map<String, dynamic>>();
      final nextRecord = result['request'] as Map<String, dynamic>;
      await verifyActions(incoming, nextRecord);
      if (mounted && generation == fetchGeneration) {
        setState(() {
          record = nextRecord;
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
      final incoming = (result['actions'] as List).cast<Map<String, dynamic>>();
      await verifyActions(incoming, null);
      if (mounted) {
        setState(() {
          final merged = <int, Map<String, dynamic>>{
            for (final row in actions) row['sequence'] as int: row,
            for (final row in incoming) row['sequence'] as int: row,
          };
          actions = merged.values.toList()
            ..sort(
              (a, b) => (b['sequence'] as int).compareTo(a['sequence'] as int),
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
                if (r['submitted_by'] is Map)
                  ListTile(
                    title: const Text('Recorded submitter'),
                    subtitle: ActorInfo(
                      actor: Map<String, dynamic>.from(
                        r['submitted_by'] as Map,
                      ),
                      verified: verified,
                    ),
                  ),
                if (r['reviewed_by'] is Map)
                  ListTile(
                    title: const Text('Recorded reviewer'),
                    subtitle: ActorInfo(
                      actor: Map<String, dynamic>.from(r['reviewed_by'] as Map),
                      verified: verified,
                    ),
                  ),
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
            Text(
              'Activity timeline',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            Text(
              verified
                  ? 'Activity checked against the phone checkpoint. Command output is receiver-reported.'
                  : 'Activity verification unavailable.',
            ),
            const SizedBox(height: 12),
            if (before != null)
              TextButton(
                onPressed: acting || loading || unavailable ? null : earlier,
                child: const Text('Load earlier activity'),
              ),
            for (final action in actions.reversed)
              ActionTile(
                key: ValueKey(action['sequence']),
                action: action,
                verified: verified && error == null,
              ),
          ],
        ],
      ),
    );
  }
}
