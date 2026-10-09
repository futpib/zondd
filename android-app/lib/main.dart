import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';

import 'control.dart';

void main() => runApp(const ZonddApp());

class ZonddApp extends StatelessWidget {
  const ZonddApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'zondd',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      colorSchemeSeed: const Color(0xff38685b),
      useMaterial3: true,
    ),
    darkTheme: ThemeData(
      colorSchemeSeed: const Color(0xff38685b),
      brightness: Brightness.dark,
      useMaterial3: true,
    ),
    home: const ConnectionsPage(),
  );
}

class ConnectionsPage extends StatefulWidget {
  const ConnectionsPage({super.key});
  @override
  State<ConnectionsPage> createState() => _ConnectionsPageState();
}

class _ConnectionsPageState extends State<ConnectionsPage> {
  final store = const ProfileStore();
  List<Profile> profiles = [];
  String? error;
  bool busy = true;
  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    try {
      profiles = await store.load();
    } catch (e) {
      error = '$e';
    }
    if (mounted) setState(() => busy = false);
  }

  Future<void> edit([Profile? original]) async {
    final result = await Navigator.of(context).push<Profile>(
      MaterialPageRoute(builder: (_) => ProfilePage(profile: original)),
    );
    if (result == null) return;
    try {
      final updated = [...profiles];
      if (original == null) {
        updated.add(result);
      } else {
        updated[updated.indexOf(original)] = result;
      }
      await store.save(updated);
      if (mounted) setState(() => profiles = updated);
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    }
  }

  Future<void> connect(Profile profile) async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final api = await SshControl.connect(profile, (type, fingerprint) async {
        final saved = await store.hostKey(profile.hostIdentity);
        final key = '$type $fingerprint';
        if (saved != null) {
          if (saved != key) {
            throw StateError(
              'SSH host key changed for ${profile.host}. Saved: $saved; received: $key',
            );
          }
          return true;
        }
        if (!mounted) return false;
        final trusted =
            await showDialog<bool>(
              context: context,
              builder: (context) => AlertDialog(
                title: const Text('Trust SSH host key?'),
                content: SelectableText(
                  '${profile.host}\n$type\n$fingerprint\n\nCompare this fingerprint with the server before trusting it.',
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(context, false),
                    child: const Text('Cancel'),
                  ),
                  FilledButton(
                    onPressed: () => Navigator.pop(context, true),
                    child: const Text('Trust'),
                  ),
                ],
              ),
            ) ??
            false;
        if (trusted) await store.trust(profile.hostIdentity, key);
        return trusted;
      });
      if (!mounted) {
        await api.close();
        return;
      }
      try {
        await Navigator.of(context).push<void>(
          MaterialPageRoute(
            builder: (_) => Dashboard(api: api, name: profile.name),
          ),
        );
      } finally {
        await api.close();
      }
    } catch (e) {
      error = '$e';
    }
    if (mounted) setState(() => busy = false);
  }

  Future<void> forget(Profile profile, bool keyOnly) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          keyOnly ? 'Forget trusted host key?' : 'Delete saved connection?',
        ),
        content: Text(
          keyOnly
              ? 'The next connection will ask you to verify the server fingerprint again.'
              : 'The saved credentials for ${profile.name} will be removed.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Forget'),
          ),
        ],
      ),
    );
    if (yes != true) return;
    try {
      if (keyOnly) {
        await store.forget(profile.hostIdentity);
      } else {
        final updated = [...profiles]..remove(profile);
        await store.save(updated);
        if (mounted) setState(() => profiles = updated);
      }
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('zondd')),
    floatingActionButton: FloatingActionButton.extended(
      onPressed: busy ? null : () => edit(),
      icon: const Icon(Icons.add),
      label: const Text('Connection'),
    ),
    body: ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(
          'Manage your user daemon',
          style: Theme.of(context).textTheme.headlineSmall,
        ),
        const Padding(
          padding: EdgeInsets.symmetric(vertical: 12),
          child: Text(
            'Use a normal SSH login with the same rights as the account running zondd. Choose direct SSH or SSH over Iroh.',
          ),
        ),
        if (busy) const LinearProgressIndicator(),
        if (error != null) ErrorBox(error!),
        if (!busy && profiles.isEmpty)
          const Padding(
            padding: EdgeInsets.all(24),
            child: Text(
              'Add a connection to review approvals and edit policy.',
            ),
          ),
        for (final profile in profiles)
          Card(
            child: ListTile(
              leading: Icon(
                profile.iroh ? Icons.hub_outlined : Icons.dns_outlined,
              ),
              title: Text(profile.name),
              subtitle: Text(
                '${profile.user}@${profile.host}\n${profile.iroh ? 'SSH over Iroh' : 'SSH • port ${profile.port}'}',
              ),
              onTap: busy ? null : () => connect(profile),
              trailing: PopupMenuButton<String>(
                enabled: !busy,
                onSelected: (action) {
                  if (action == 'edit') {
                    edit(profile);
                  } else {
                    forget(profile, action == 'key');
                  }
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'edit', child: Text('Edit')),
                  PopupMenuItem(value: 'key', child: Text('Forget host key')),
                  PopupMenuItem(value: 'delete', child: Text('Delete')),
                ],
              ),
            ),
          ),
        const SizedBox(height: 88),
      ],
    ),
  );
}

class ProfilePage extends StatefulWidget {
  const ProfilePage({super.key, this.profile});
  final Profile? profile;
  @override
  State<ProfilePage> createState() => _ProfilePageState();
}

class _ProfilePageState extends State<ProfilePage> {
  final form = GlobalKey<FormState>();
  late final Map<String, TextEditingController> fields;
  late bool iroh;
  @override
  void initState() {
    super.initState();
    final p = widget.profile;
    iroh = p?.iroh ?? false;
    fields = {
      for (final entry in <String, String>{
        'Name': p?.name ?? '',
        'Host': p?.host ?? '',
        'User': p?.user ?? '',
        'Port': '${p?.port ?? 22}',
        'Private key': p?.privateKey ?? '',
        'Key passphrase': p?.passphrase ?? '',
        'Password': p?.password ?? '',
        'Relays': p?.relays.join('\n') ?? '',
        'Executable': p?.executable ?? '.cargo/bin/zondctl',
        'Runtime': p?.runtime ?? '',
        'Config': p?.config ?? '',
      }.entries)
        entry.key: TextEditingController(text: entry.value),
    };
  }

  @override
  void dispose() {
    for (final f in fields.values) {
      f.dispose();
    }
    super.dispose();
  }

  String value(String key) => fields[key]!.text;
  Widget field(
    String key, {
    String? label,
    bool required = false,
    bool secret = false,
    int lines = 1,
    String? hint,
  }) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 8),
    child: TextFormField(
      controller: fields[key],
      obscureText: secret,
      maxLines: lines,
      autocorrect: false,
      enableSuggestions: false,
      decoration: InputDecoration(
        labelText: label ?? key,
        helperText: hint,
        border: const OutlineInputBorder(),
      ),
      validator: (text) {
        if (required && (text == null || text.trim().isEmpty)) {
          return 'Required';
        }
        if (key == 'Port' &&
            !iroh &&
            (int.tryParse(text ?? '') == null ||
                int.parse(text!) < 1 ||
                int.parse(text) > 65535)) {
          return 'Port must be 1–65535';
        }
        if (key == 'Host' &&
            iroh &&
            !RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(text ?? '')) {
          return 'Enter a 64-character Iroh endpoint ID';
        }
        return null;
      },
    ),
  );
  void save() {
    if (!form.currentState!.validate()) return;
    Navigator.pop(
      context,
      Profile(
        name: value('Name').trim(),
        host: value('Host').trim(),
        user: value('User').trim(),
        port: int.tryParse(value('Port')) ?? 22,
        iroh: iroh,
        privateKey: value('Private key'),
        passphrase: value('Key passphrase'),
        password: value('Password'),
        executable: value('Executable').trim(),
        runtime: value('Runtime').trim(),
        config: value('Config').trim(),
        relays: value(
          'Relays',
        ).split(RegExp(r'\s+')).where((v) => v.isNotEmpty).toList(),
      ),
    );
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('SSH connection')),
    body: Form(
      key: form,
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            field('Name', required: true),
            SwitchListTile(
              title: const Text('Use Iroh transport'),
              value: iroh,
              onChanged: (v) => setState(() => iroh = v),
            ),
            field(
              'Host',
              label: iroh ? 'Iroh endpoint ID' : 'SSH hostname or IP',
              required: true,
            ),
            if (!iroh) field('Port'),
            field('User', label: 'SSH username', required: true),
            const Text(
              'Use an unrestricted SSH key or password, not a forced-command caller key.',
            ),
            field(
              'Private key',
              lines: 4,
              hint: 'Paste a PEM or OpenSSH private key',
            ),
            field('Key passphrase', secret: true),
            field('Password', secret: true),
            ExpansionTile(
              title: const Text('Advanced'),
              children: [
                field(
                  'Executable',
                  label: 'Remote zondctl executable',
                  required: true,
                  hint:
                      'Absolute path, path relative to home, or executable on PATH',
                ),
                field('Runtime', label: 'Runtime directory (optional)'),
                field('Config', label: 'Config file (optional)'),
                if (iroh)
                  field(
                    'Relays',
                    lines: 3,
                    hint: 'Relay URLs, one per line. Empty uses Iroh defaults.',
                  ),
              ],
            ),
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 16),
              child: Text(
                'Saved credentials are encrypted in Android storage.',
              ),
            ),
            FilledButton(onPressed: save, child: const Text('Save connection')),
          ],
        ),
      ),
    ),
  );
}

class Dashboard extends StatefulWidget {
  const Dashboard({super.key, required this.api, required this.name});
  final ControlApi api;
  final String name;
  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> with WidgetsBindingObserver {
  Timer? timer;
  List<dynamic> queue = [];
  String? error, message;
  bool polling = false, acting = false;
  int tab = 0;
  String? revision;
  final config = TextEditingController();
  String? loadedConfig;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    refresh();
    timer = Timer.periodic(const Duration(seconds: 2), (_) => refresh());
  }

  @override
  void dispose() {
    timer?.cancel();
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
    if (polling || acting || tab != 0) return;
    polling = true;
    try {
      final result = await widget.api.request({'method': 'pending'});
      if (mounted) {
        setState(() {
          queue = result['requests'] as List;
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
      if (!mounted) return;
      setState(() {
        config.text = result['content'] as String;
        loadedConfig = config.text;
        revision = result['revision'] as String;
        message = result['path'] as String;
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
      if (mounted) {
        setState(
          () => message = (result['output'] as String).isEmpty
              ? 'Service $verb completed.'
              : result['output'] as String,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: loadedConfig == null || config.text == loadedConfig,
    onPopInvokedWithResult: (didPop, _) async {
      if (!didPop &&
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
        title: Text(widget.name),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            onPressed: acting
                ? null
                : () {
                    if (tab == 0) {
                      refresh();
                    } else if (tab == 1) {
                      loadConfig();
                    } else {
                      service('status');
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
        destinations: const [
          NavigationDestination(icon: Icon(Icons.rule), label: 'Approvals'),
          NavigationDestination(icon: Icon(Icons.tune), label: 'Policy'),
          NavigationDestination(
            icon: Icon(Icons.settings_power),
            label: 'Service',
          ),
        ],
      ),
      body: Column(
        children: [
          if (acting) const LinearProgressIndicator(),
          if (error != null) ErrorBox(error!),
          if (message != null)
            Padding(
              padding: const EdgeInsets.all(12),
              child: SelectableText(message!),
            ),
          Expanded(
            child: tab == 0
                ? approvals()
                : tab == 1
                ? policy()
                : ListView(
                    padding: const EdgeInsets.all(16),
                    children: [
                      const Text('systemd user service • zondd.service'),
                      const SizedBox(height: 16),
                      for (final verb in ['start', 'stop', 'restart'])
                        Padding(
                          padding: const EdgeInsets.all(8),
                          child: FilledButton.tonal(
                            onPressed: acting ? null : () => service(verb),
                            child: Text(
                              '${verb[0].toUpperCase()}${verb.substring(1)}',
                            ),
                          ),
                        ),
                    ],
                  ),
          ),
        ],
      ),
    ),
  );
  Widget approvals() => RefreshIndicator(
    onRefresh: refresh,
    child: ListView(
      physics: const AlwaysScrollableScrollPhysics(),
      padding: const EdgeInsets.all(16),
      children: [
        Text(
          'Pending commands',
          style: Theme.of(context).textTheme.headlineSmall,
        ),
        const Text(
          'Decisions apply once to the exact request shown. Updates every two seconds while this screen is open.',
        ),
        if (queue.isEmpty && error == null)
          const Padding(
            padding: EdgeInsets.all(32),
            child: Text('No pending approvals'),
          ),
        for (final raw in queue) approvalCard(raw as Map<String, dynamic>),
      ],
    ),
  );
  Widget approvalCard(Map<String, dynamic> request) {
    final command = request['command'] as Map<String, dynamic>;
    final expires = DateTime.fromMillisecondsSinceEpoch(
      request['expires_unix_ms'] as int,
    ).toLocal();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              request['principal'] as String,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            if (request['operation'] != null)
              Text('Operation: ${request['operation']}'),
            const SizedBox(height: 8),
            SelectableText(
              const JsonEncoder.withIndent('  ').convert(command),
              style: const TextStyle(fontFamily: 'monospace'),
            ),
            Text('${request['reason']}\nExpires: $expires'),
            SelectableText(
              request['approval_id'] as String,
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              children: [
                OutlinedButton(
                  onPressed: acting ? null : () => resolve(request, false),
                  child: const Text('Reject'),
                ),
                FilledButton(
                  onPressed: acting ? null : () => resolve(request, true),
                  child: const Text('Approve once'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget policy() => ListView(
    padding: const EdgeInsets.all(16),
    children: [
      const Text(
        'Edit the TOML policy. Saving validates the file; restart the service to apply changes.',
      ),
      const SizedBox(height: 12),
      TextField(
        controller: config,
        enabled: revision != null && !acting,
        onChanged: (_) => setState(() {}),
        minLines: 12,
        maxLines: null,
        style: const TextStyle(fontFamily: 'monospace'),
        autocorrect: false,
        enableSuggestions: false,
        decoration: const InputDecoration(
          border: OutlineInputBorder(),
          labelText: 'Configuration',
        ),
      ),
      const SizedBox(height: 16),
      Wrap(
        spacing: 12,
        children: [
          OutlinedButton(
            onPressed: acting || revision == null
                ? null
                : () => action(() async {
                    await widget.api.request({
                      'method': 'validate_config',
                      'content': config.text,
                    });
                    if (mounted) {
                      setState(() => message = 'Configuration is valid.');
                    }
                  }),
            child: const Text('Validate'),
          ),
          FilledButton(
            onPressed: acting || revision == null
                ? null
                : () => action(() async {
                    final result = await widget.api.request({
                      'method': 'save_config',
                      'content': config.text,
                      'revision': revision,
                    });
                    if (mounted) {
                      setState(() {
                        revision = result['revision'] as String;
                        loadedConfig = config.text;
                        message = 'Saved. Restart zondd to apply this policy.';
                      });
                    }
                  }),
            child: const Text('Save policy'),
          ),
        ],
      ),
    ],
  );
}

class ErrorBox extends StatelessWidget {
  const ErrorBox(this.message, {super.key});
  final String message;
  @override
  Widget build(BuildContext context) => Card(
    color: Theme.of(context).colorScheme.errorContainer,
    child: ConstrainedBox(
      constraints: const BoxConstraints(maxHeight: 180),
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(12),
        child: SelectableText(message),
      ),
    ),
  );
}
