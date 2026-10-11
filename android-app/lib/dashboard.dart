import 'policy_overview.dart';
import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:toml/toml.dart';
import 'control.dart';
import 'ui.dart';
import 'history.dart';
import 'rules.dart';

class Dashboard extends StatefulWidget {
  const Dashboard({
    super.key,
    required this.api,
    required this.name,
    this.connection = 'SSH',
  });
  final ControlApi api;
  final String name, connection;
  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> with WidgetsBindingObserver {
  Timer? timer;
  ControlConnection? get connection =>
      widget.api is ControlConnection ? widget.api as ControlConnection : null;
  bool get reconnecting => connection?.reconnecting ?? false;
  bool get disconnected => connection?.disconnected ?? false;

  void connectionChanged() {
    if (mounted) setState(() {});
  }

  Future<void> reconnect() async {
    if (acting || reconnecting) return;
    await action(() async {
      await connection!.reconnect();
    });
    if (!mounted || disconnected) return;
    if (tab == 0) await refresh();
    if (loadedConfig != null) {
      await action(() async {
        await reconcilePolicy();
      });
    }
    if (tab == 1 && loadedConfig == null) await loadConfig();
    if (tab == 2) await service('status');
    if (tab == 3) await historyKey.currentState?.fetch();
  }

  List<dynamic> queue = [];
  List<dynamic> credentials = [];
  List<dynamic> proposals = [];
  String? error, message;
  bool polling = false, acting = false;
  int tab = 0;
  String? revision;
  final config = TextEditingController();
  final historyKey = GlobalKey<HistoryPageState>();
  String? loadedConfig, attemptedSave;
  String configPath = '';
  bool editing = false, loaded = false;
  Map<String, String> serviceState = {};
  Map defaultPrincipals = {};
  bool applyRequired = false;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    connection?.addListener(connectionChanged);
    refresh();
    timer = Timer.periodic(const Duration(seconds: 2), (_) => refresh());
  }

  @override
  void dispose() {
    timer?.cancel();
    connection?.removeListener(connectionChanged);
    config.dispose();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    timer?.cancel();
    if (state == AppLifecycleState.resumed) {
      refresh();
      timer = Timer.periodic(const Duration(seconds: 2), (_) => refresh());
    }
  }

  Future<void> refresh() async {
    if (polling || acting || disconnected || tab != 0) return;
    polling = true;
    try {
      final result = await widget.api.request({'method': 'pending'});
      if (mounted) {
        setState(() {
          queue = result['requests'] as List;
          credentials = result['credentials'] as List? ?? [];
          proposals = result['proposals'] as List? ?? [];
          loaded = true;
          error = null;
        });
      }
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      polling = false;
    }
  }

  Future<void> action(Future<void> Function() work) async {
    if (acting) return;
    setState(() {
      acting = true;
      error = null;
      message = null;
    });
    try {
      await work();
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => acting = false);
    }
  }

  Future<void> resolve(Map<String, dynamic> request, bool approve) async {
    await action(() async {
      await widget.api.request({
        'method': 'resolve',
        'approval_id': request['approval_id'],
        'approve': approve,
      });
      if (mounted) {
        setState(() {
          queue.removeWhere(
            (item) => item['approval_id'] == request['approval_id'],
          );
          message = approve
              ? 'Approved once. The caller can now run this command.'
              : 'Rejected. The caller has been notified.';
        });
      }
    });
    await refresh();
  }

  Future<void> resolveRule(
    Map<String, dynamic> proposal,
    bool approve,
    int? seconds,
  ) async {
    await action(() async {
      await widget.api.request({
        'method': 'resolve_rule',
        'proposal_id': proposal['id'],
        'digest': proposal['digest'],
        'approve': approve,
        'expires_in_secs': seconds,
      });
      if (mounted) {
        setState(() {
          proposals.removeWhere((item) => item['id'] == proposal['id']);
          message = approve
              ? 'Rule approved. Matching invocations can run without another prompt.'
              : 'Rule proposal rejected.';
        });
      }
    });
    await refresh();
  }

  Future<void> resolveCredential(
    Map<String, dynamic> challenge,
    bool provide,
  ) async {
    String? password;
    if (provide) {
      password = await showDialog<String>(
        context: context,
        builder: (context) =>
            _SudoPasswordDialog(prompt: challenge['prompt'] as String),
      );
      if (password == null) return;
    }
    await action(() async {
      await widget.api.request({
        'method': 'credential',
        'challenge_id': challenge['challenge_id'],
        'password': password,
      });
      if (mounted) {
        setState(() {
          credentials.removeWhere(
            (item) => item['challenge_id'] == challenge['challenge_id'],
          );
          message = provide
              ? 'Password sent to the waiting sudo prompt.'
              : 'Sudo prompt rejected.';
        });
      }
    });
    await refresh();
  }

  Future<bool> confirm(String title, String detail) async =>
      await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(title),
          content: Text(detail),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Continue'),
            ),
          ],
        ),
      ) ??
      false;
  Future<void> loadConfig() async {
    if (loadedConfig != null &&
        config.text != loadedConfig &&
        !await confirm(
          'Discard unsaved edits?',
          'Reload the configuration from the server.',
        )) {
      return;
    }
    await action(() async {
      final result = await widget.api.request({'method': 'read_config'});
      String? activeRevision;
      try {
        activeRevision =
            (await widget.api.request({'method': 'status'}))['revision']
                as String?;
      } catch (_) {
        /* Editing remains available while the daemon is stopped. */
      }
      if (!mounted) return;
      setState(() {
        defaultPrincipals =
            TomlDocument.parse(
                  result['defaults'] as String? ?? '',
                ).toMap()['principals']
                as Map? ??
            {};
        config.text = result['content'] as String;
        loadedConfig = config.text;
        attemptedSave = null;
        revision = result['revision'] as String;
        configPath = result['path'] as String;
        applyRequired = activeRevision != revision;
      });
    });
  }

  Future<void> service(String verb) async {
    if (verb != 'status' &&
        !await confirm(
          '$verb zondd?',
          verb == 'start'
              ? 'Start the systemd user service.'
              : 'This stops active commands and clears pending approvals.',
        )) {
      return;
    }
    await action(() async {
      final result = await widget.api.request({
        'method': 'service',
        'action': verb,
      });
      final status = verb == 'status'
          ? result
          : await widget.api.request({'method': 'service', 'action': 'status'});
      if (mounted) {
        setState(() {
          serviceState = {
            for (final line in (status['output'] as String).split('\n'))
              if (line.contains('='))
                line.substring(0, line.indexOf('=')): line.substring(
                  line.indexOf('=') + 1,
                ),
          };
          if (verb != 'status') message = 'Service $verb completed.';
        });
      }
    });
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop:
        !reconnecting && (loadedConfig == null || config.text == loadedConfig),
    onPopInvokedWithResult: (didPop, _) async {
      if (!didPop &&
          !reconnecting &&
          await confirm(
            'Discard unsaved edits?',
            'Disconnect from ${widget.name}.',
          ) &&
          context.mounted) {
        setState(() => loadedConfig = config.text);
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (context.mounted) Navigator.pop(context);
        });
      }
    },
    child: Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.name, maxLines: 1, overflow: TextOverflow.ellipsis),
            Text(
              widget.connection,
              style: Theme.of(context).textTheme.labelSmall?.copyWith(
                color: Theme.of(context).colorScheme.primary,
              ),
            ),
          ],
        ),
        actions: [
          if (connection != null)
            IconButton(
              tooltip: 'Reconnect',
              onPressed: acting || reconnecting ? null : reconnect,
              icon: const Icon(Icons.sync),
            ),
          IconButton(
            tooltip: 'Refresh',
            onPressed: acting || disconnected
                ? null
                : () {
                    if (tab == 0) {
                      refresh();
                    } else if (tab == 1) {
                      loadConfig();
                    } else if (tab == 2) {
                      service('status');
                    } else {
                      historyKey.currentState?.fetch();
                    }
                  },
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: tab,
        onDestinationSelected: (value) {
          setState(() {
            tab = value;
            error = null;
            message = null;
          });
          if (value == 1 && revision == null) loadConfig();
          if (value == 2) service('status');
          if (value == 0) refresh();
        },
        destinations: [
          NavigationDestination(
            icon: Badge(
              isLabelVisible: queue.isNotEmpty,
              label: Text('${queue.length}'),
              child: const Icon(Icons.inbox_outlined),
            ),
            selectedIcon: const Icon(Icons.inbox),
            label: 'Approvals',
          ),
          const NavigationDestination(icon: Icon(Icons.tune), label: 'Policy'),
          const NavigationDestination(
            icon: Icon(Icons.settings_power),
            label: 'Service',
          ),
          const NavigationDestination(
            icon: Icon(Icons.history),
            label: 'History',
          ),
        ],
      ),
      body: Column(
        children: [
          if (acting) const LinearProgressIndicator(),
          if (disconnected)
            Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                children: [
                  const Icon(Icons.cloud_off),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      reconnecting
                          ? 'Reconnecting…'
                          : 'Connection lost. Reconnect to continue.',
                    ),
                  ),
                  TextButton(
                    onPressed: acting || reconnecting ? null : reconnect,
                    child: const Text('Reconnect'),
                  ),
                ],
              ),
            ),
          if (error != null &&
              (!disconnected || error != const ConnectionLost().toString()))
            ErrorBox(error!),
          if (message != null)
            Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                children: [
                  Icon(
                    Icons.check_circle_outline,
                    size: 20,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(width: 12),
                  Expanded(child: Text(message!)),
                ],
              ),
            ),
          Expanded(
            child: tab == 0
                ? approvals()
                : tab == 1
                ? policy()
                : tab == 2
                ? servicePanel()
                : HistoryPage(key: historyKey, api: widget.api),
          ),
        ],
      ),
    ),
  );
  Widget approvals() => RefreshIndicator(
    onRefresh: refresh,
    child: ListView(
      physics: const AlwaysScrollableScrollPhysics(),
      padding: const EdgeInsets.all(20),
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                'Pending commands',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
            ),
            if (queue.isNotEmpty ||
                credentials.isNotEmpty ||
                proposals.isNotEmpty)
              Chip(
                label: Text(
                  '${queue.length + credentials.length + proposals.length}',
                ),
              ),
          ],
        ),
        const SizedBox(height: 8),
        const Text('Review requests that need your permission.'),
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton.icon(
            onPressed: disconnected
                ? null
                : () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => RulesPage(api: widget.api),
                    ),
                  ),
            icon: const Icon(Icons.rule),
            label: const Text('Caller rules'),
          ),
        ),
        const SizedBox(height: 24),
        if (!loaded && error == null && !disconnected)
          const Center(child: CircularProgressIndicator()),
        if (loaded &&
            queue.isEmpty &&
            credentials.isEmpty &&
            proposals.isEmpty &&
            error == null &&
            !disconnected)
          const EmptyState(
            Icons.task_alt,
            'All caught up',
            'No pending approvals. New requests appear here automatically.',
          ),
        for (final raw in proposals)
          RuleProposalCard(
            key: ValueKey('rule-${raw['id']}'),
            proposal: raw as Map<String, dynamic>,
            enabled: !acting && !disconnected,
            resolve: (approve, seconds) => resolveRule(raw, approve, seconds),
          ),
        for (final raw in queue) approvalCard(raw as Map<String, dynamic>),
        for (final raw in credentials)
          credentialCard(raw as Map<String, dynamic>),
      ],
    ),
  );
  Widget approvalCard(Map<String, dynamic> request) {
    final command = request['command'] as Map<String, dynamic>;
    final program = command['program'] as String;
    final arguments = (command['args'] as List).cast<String>();
    final remaining =
        ((request['expires_unix_ms'] as int) -
            DateTime.now().millisecondsSinceEpoch) ~/
        1000;
    final time = remaining <= 0
        ? 'Expiring…'
        : remaining >= 60
        ? '${remaining ~/ 60}m ${remaining % 60}s left'
        : '${remaining}s left';
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                const Icon(Icons.person_outline, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    request['principal'] as String,
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
                const Icon(Icons.timer_outlined, size: 16),
                const SizedBox(width: 4),
                Text(time, style: Theme.of(context).textTheme.labelMedium),
              ],
            ),
            const SizedBox(height: 20),
            Text(
              request['operation'] as String? ?? program.split('/').last,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surface,
                borderRadius: BorderRadius.circular(12),
              ),
              child: SelectableText(
                [jsonEncode(program), ...arguments.map(jsonEncode)].join(' '),
                style: mono,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              request['reason'] as String,
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            if (request['sudo_password'] == true) ...[
              const SizedBox(height: 8),
              const Text(
                'Approval permits sudo password prompts and privileged child processes.',
              ),
            ],
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              dense: true,
              title: const Text('Request details'),
              children: [
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Request ID'),
                  subtitle: SelectableText(
                    request['approval_id'] as String,
                    style: mono,
                  ),
                ),
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Exact arguments'),
                  subtitle: SelectableText(
                    const JsonEncoder.withIndent('  ').convert(arguments),
                    style: mono,
                  ),
                ),
                if (request['cwd'] != null)
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Working directory'),
                    subtitle: SelectableText(
                      jsonEncode(request['cwd']),
                      style: mono,
                    ),
                  ),
                const Text(
                  'Approval applies once to this exact request. It does not change policy.',
                ),
                const SizedBox(height: 12),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: acting || disconnected
                        ? null
                        : () => resolve(request, false),
                    child: const Text('Reject'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: acting || disconnected
                        ? null
                        : () => resolve(request, true),
                    child: const Text('Approve once'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget credentialCard(Map<String, dynamic> challenge) {
    final command = challenge['command'] as Map<String, dynamic>;
    return Card(
      key: ValueKey('credential-${challenge['challenge_id']}'),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Sudo password requested',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text('${challenge['principal']} · ${challenge['operation']}'),
            const SizedBox(height: 8),
            SelectableText(
              [
                jsonEncode(command['program']),
                ...(command['args'] as List).map(jsonEncode),
              ].join(' '),
              style: mono,
            ),
            const SizedBox(height: 8),
            Text(challenge['prompt'] as String),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: acting || disconnected
                        ? null
                        : () => resolveCredential(challenge, false),
                    child: const Text('Reject'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: acting || disconnected
                        ? null
                        : () => resolveCredential(challenge, true),
                    child: const Text('Enter password'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> validate() => action(() async {
    await widget.api.request({
      'method': 'validate_config',
      'content': config.text,
    });
    if (mounted) setState(() => message = 'Configuration is valid.');
  });
  Future<bool> reconcilePolicy({bool reviewConflict = false}) async {
    final remote = await widget.api.request({'method': 'read_config'});
    if (!mounted) return false;
    final content = remote['content'] as String;
    final remoteRevision = remote['revision'] as String;
    if (content != loadedConfig && content != attemptedSave) {
      if (!reviewConflict) {
        setState(
          () => error =
              'The server policy changed. Your draft is preserved. '
              'Save to review the server version before replacing it.',
        );
        return false;
      }
      final replace = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Replace changed server policy?'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Another version is saved on the server. Replace it with your current draft? '
                  'Cancel keeps both versions unchanged. Server policy:',
                ),
                const SizedBox(height: 12),
                SelectableText(content, style: mono),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Replace with draft'),
            ),
          ],
        ),
      );
      if (replace != true || !mounted) return false;
    }
    setState(() {
      if (revision != remoteRevision) applyRequired = true;
      revision = remoteRevision;
      loadedConfig = content;
      attemptedSave = null;
    });
    return true;
  }

  Future<void> savePolicy() => action(() async {
    if (!await reconcilePolicy(reviewConflict: true) || !mounted) return;
    final draft = config.text;
    attemptedSave = draft;
    final result = await widget.api.request({
      'method': 'save_config',
      'content': draft,
      'revision': revision,
    });
    if (mounted) {
      setState(() {
        revision = result['revision'] as String;
        loadedConfig = draft;
        attemptedSave = null;
        applyRequired = true;
        message = 'Saved. Apply to activate this policy.';
      });
    }
    await applySaved();
  });
  Future<void> applySaved() async {
    final result = await widget.api.request({
      'method': 'reload_config',
      'revision': revision,
    });
    final cancelled = result['cancelled_approvals'] as int;
    final retained = result['retained_approvals'] as int? ?? 0;
    final allowed = result['allowed_approvals'] as int? ?? 0;
    final refreshed = result['refreshed_approvals'] as int? ?? 0;
    if (mounted) {
      setState(() {
        applyRequired = false;
        message = cancelled + retained + allowed + refreshed == 0
            ? 'Policy applied.'
            : 'Policy applied. $retained waiting, $allowed allowed, $refreshed need fresh review, $cancelled rejected or expired.';
      });
    }
  }

  Widget policy() {
    Map<String, dynamic>? parsed;
    try {
      parsed = parsePolicyOverview(loadedConfig ?? '');
    } catch (_) {
      /* Keep invalid drafts editable. */
    }
    final principals = parsed?['principals'] as Map? ?? defaultPrincipals;
    final operations = parsed?['operations'] as Map? ?? {};
    final approvals = parsed?['approvals'] as Map? ?? {};
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(20, 12, 12, 8),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  editing ? 'Edit policy' : 'Policy',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
              ),
              TextButton.icon(
                onPressed: revision == null
                    ? null
                    : () => setState(() => editing = !editing),
                icon: Icon(editing ? Icons.view_agenda_outlined : Icons.code),
                label: Text(editing ? 'Overview' : 'Edit TOML'),
              ),
            ],
          ),
        ),
        if (editing) ...[
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            child: Text(
              config.text != loadedConfig
                  ? 'Unsaved changes'
                  : 'Saved configuration',
              style: Theme.of(context).textTheme.labelMedium,
            ),
          ),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 12),
              child: TextField(
                controller: config,
                enabled: revision != null && !acting,
                onChanged: (_) => setState(() {}),
                expands: true,
                minLines: null,
                maxLines: null,
                textAlignVertical: TextAlignVertical.top,
                style: mono,
                autocorrect: false,
                enableSuggestions: false,
                keyboardType: TextInputType.multiline,
                decoration: const InputDecoration(
                  labelText: 'Configuration',
                  alignLabelWithHint: true,
                ),
              ),
            ),
          ),
          SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 0, 20, 12),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: acting || revision == null ? null : validate,
                      child: const Text('Validate'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: FilledButton(
                      onPressed: acting || revision == null ? null : savePolicy,
                      child: const Text('Save & apply'),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ] else
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              children: [
                if (revision == null)
                  const Padding(
                    padding: EdgeInsets.all(24),
                    child: Center(child: Text('Loading configuration…')),
                  )
                else ...[
                  if (config.text != loadedConfig)
                    const Padding(
                      padding: EdgeInsets.only(bottom: 12),
                      child: Text(
                        'Showing saved policy. Your unsaved draft is in the editor.',
                      ),
                    ),
                  if (parsed == null)
                    const ErrorBox(
                      'This configuration cannot be displayed. Open Edit TOML to repair it, then validate and apply your changes.',
                    ),
                  if (applyRequired)
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            Text(
                              'Apply saved policy',
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                            const SizedBox(height: 8),
                            const Text(
                              'Running commands continue. Waiting requests are re-evaluated under the new policy.',
                            ),
                            const SizedBox(height: 12),
                            FilledButton.icon(
                              onPressed: acting
                                  ? null
                                  : () => action(applySaved),
                              icon: const Icon(Icons.sync),
                              label: const Text('Apply now'),
                            ),
                          ],
                        ),
                      ),
                    ),
                  if (parsed != null) ...[
                    Card(
                      child: ListTile(
                        leading: Icon(
                          approvals['enabled'] != false
                              ? Icons.verified_user_outlined
                              : Icons.block,
                        ),
                        title: Text(
                          approvals['enabled'] != false
                              ? 'Manual approvals enabled'
                              : 'Manual approvals disabled',
                        ),
                        subtitle: Text(
                          approvals['enabled'] != false
                              ? 'Requests expire after ${approvals['timeout_secs'] ?? 300} seconds'
                              : 'Commands cannot wait for manual review',
                        ),
                      ),
                    ),
                    SectionHeading('Callers · ${principals.length}'),
                    for (final entry in principals.entries)
                      Card(
                        child: ExpansionTile(
                          leading: const Icon(Icons.person_outline),
                          title: Text('${entry.key}'),
                          subtitle: Text(
                            entry.value['allow_exec'] == true
                                ? 'Commands · default ${entry.value['default'] ?? 'deny'}'
                                : 'Named operations only',
                          ),
                          childrenPadding: const EdgeInsets.fromLTRB(
                            16,
                            0,
                            16,
                            16,
                          ),
                          children: [
                            ListTile(
                              contentPadding: EdgeInsets.zero,
                              title: const Text('Working directory'),
                              subtitle: SelectableText(
                                '${entry.value['cwd']}',
                                style: mono,
                              ),
                            ),
                            ListTile(
                              contentPadding: EdgeInsets.zero,
                              title: const Text('Operations'),
                              subtitle: Text(
                                (entry.value['operations'] as List? ?? [])
                                        .join(', ')
                                        .isEmpty
                                    ? 'None'
                                    : (entry.value['operations'] as List).join(
                                        ', ',
                                      ),
                              ),
                            ),
                            for (final rule
                                in entry.value['rules'] as List? ?? [])
                              ListTile(
                                contentPadding: EdgeInsets.zero,
                                title: Text(
                                  '${rule['decision']}'.toUpperCase(),
                                  style: Theme.of(
                                    context,
                                  ).textTheme.labelMedium,
                                ),
                                subtitle: SelectableText(
                                  '${rule['program']}\n${rule.containsKey('args') ? jsonEncode(rule['args']) : 'Any arguments'}\nWorking directory: ${rule['cwd'] ?? entry.value['cwd']}',
                                  style: mono,
                                ),
                              ),
                          ],
                        ),
                      ),
                    SectionHeading('Operations · ${operations.length}'),
                    for (final entry in operations.entries)
                      Card(
                        child: ExpansionTile(
                          leading: const Icon(Icons.terminal),
                          title: Text('${entry.key}'),
                          subtitle: Text(
                            '${entry.value['description'] ?? entry.value['program']}',
                          ),
                          childrenPadding: const EdgeInsets.all(16),
                          children: [
                            ListTile(
                              contentPadding: EdgeInsets.zero,
                              title: Text(
                                '${entry.value['decision'] ?? 'deny'}'
                                    .toUpperCase(),
                              ),
                              subtitle: SelectableText(
                                [
                                  jsonEncode(entry.value['program']),
                                  ...(entry.value['fixed_args'] as List? ?? [])
                                      .map(jsonEncode),
                                ].join(' '),
                                style: mono,
                              ),
                            ),
                            for (final argument
                                in entry.value['arguments'] as List? ?? [])
                              ListTile(
                                contentPadding: EdgeInsets.zero,
                                title: Text('${argument['name']}'),
                                subtitle: Text(
                                  'Choices: ${(argument['choices'] as List? ?? []).map(jsonEncode).join(', ')}',
                                ),
                              ),
                          ],
                        ),
                      ),
                  ],
                  const SectionHeading('Configuration file'),
                  SelectableText(configPath, style: mono),
                  const SizedBox(height: 24),
                ],
              ],
            ),
          ),
      ],
    );
  }

  Widget servicePanel() {
    final active = serviceState['ActiveState'] == 'active';
    final missing = serviceState['LoadState'] == 'not-found';
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text('Service', style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 24),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              children: [
                CircleAvatar(
                  radius: 30,
                  child: Icon(
                    active
                        ? Icons.check_circle_outline
                        : Icons.power_settings_new,
                    size: 30,
                  ),
                ),
                const SizedBox(height: 16),
                Text(
                  serviceState.isEmpty
                      ? 'Checking status…'
                      : missing
                      ? 'Service not installed'
                      : active
                      ? 'Running'
                      : 'Stopped',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 8),
                const Text('zondd.service · user service'),
                if (serviceState['SubState'] != null)
                  Text(
                    serviceState['SubState']!,
                    style: Theme.of(context).textTheme.labelMedium,
                  ),
              ],
            ),
          ),
        ),
        if (missing)
          const Padding(
            padding: EdgeInsets.only(bottom: 20),
            child: Text(
              'Install the zondd user unit on this server to control it here.',
            ),
          ),
        if (applyRequired)
          const Padding(
            padding: EdgeInsets.only(bottom: 20),
            child: Text('Apply the saved policy from the Policy tab.'),
          ),
        FilledButton.icon(
          onPressed: acting || serviceState.isEmpty || missing
              ? null
              : () => service(active ? 'restart' : 'start'),
          icon: Icon(active ? Icons.restart_alt : Icons.play_arrow),
          label: Text(active ? 'Restart' : 'Start'),
        ),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: acting || !active ? null : () => service('stop'),
          icon: const Icon(Icons.stop_outlined),
          label: const Text('Stop'),
        ),
        const SectionHeading('Details'),
        for (final entry in serviceState.entries)
          ListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(entry.key),
            trailing: Text(entry.value),
          ),
      ],
    );
  }
}

class _SudoPasswordDialog extends StatefulWidget {
  const _SudoPasswordDialog({required this.prompt});
  final String prompt;

  @override
  State<_SudoPasswordDialog> createState() => _SudoPasswordDialogState();
}

class _SudoPasswordDialogState extends State<_SudoPasswordDialog> {
  final controller = TextEditingController();

  @override
  void dispose() {
    controller.clear();
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    scrollable: true,
    title: const Text('Sudo password'),
    content: Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(widget.prompt),
        const SizedBox(height: 12),
        TextField(
          controller: controller,
          obscureText: true,
          enableSuggestions: false,
          autocorrect: false,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'Password'),
        ),
      ],
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(
        onPressed: () => Navigator.pop(context, controller.text),
        child: const Text('Send password'),
      ),
    ],
  );
}
