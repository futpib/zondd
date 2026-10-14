import 'dart:async';
import 'package:flutter/material.dart';
import 'json_yaml.dart';
import 'credential_save_panel.dart';
import 'saved_credentials.dart';

class InteractionCard extends StatelessWidget {
  const InteractionCard({
    super.key,
    required this.challenge,
    required this.server,
    required this.enabled,
    required this.resolve,
  });
  final Map<String, dynamic> challenge;
  final String server;
  final bool enabled;
  final Future<void> Function(bool) resolve;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Application input requested',
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 12),
          InteractionContext(challenge: challenge, server: server),
          const SizedBox(height: 12),
          const Text('Application-supplied prompt'),
          Text(challenge['prompt'] as String),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: OutlinedButton(
                  onPressed: enabled ? () => resolve(false) : null,
                  child: const Text('Reject'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: FilledButton(
                  onPressed: enabled ? () => resolve(true) : null,
                  child: const Text('Respond'),
                ),
              ),
            ],
          ),
        ],
      ),
    ),
  );
}

class InteractionContext extends StatelessWidget {
  const InteractionContext({
    super.key,
    required this.challenge,
    required this.server,
  });
  final Map<String, dynamic> challenge;
  final String server;

  @override
  Widget build(BuildContext context) {
    final recipient = challenge['recipient'] as Map<String, dynamic>;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Configured recipient',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
        Text('$server · ${recipient['label']}'),
        Text('Origin: ${recipient['origin']}'),
        if (challenge['provider_origin'] != null)
          Text('Permitted provider origin: ${challenge['provider_origin']}'),
        ExpansionTile(
          title: const Text('Recipient details'),
          tilePadding: EdgeInsets.zero,
          children: [SelectableText(jsonAsYaml(recipient))],
        ),
      ],
    );
  }
}

class InteractionDialog extends StatefulWidget {
  const InteractionDialog({
    super.key,
    required this.challenge,
    required this.server,
    required this.isCurrent,
    this.binding,
    this.vault = const AndroidCredentialVault(),
  });
  final Map<String, dynamic> challenge;
  final String server;
  final bool Function() isCurrent;
  final CredentialBinding? binding;
  final CredentialVault vault;

  @override
  State<InteractionDialog> createState() => _InteractionDialogState();
}

class _InteractionDialogState extends State<InteractionDialog>
    with WidgetsBindingObserver {
  final form = GlobalKey<FormState>();
  final controllers = <String, TextEditingController>{};
  final choices = <String, String>{};
  final memory = GlobalKey<CredentialSavePanelState>();
  bool sending = false;
  bool loadedSavedValues = false;
  bool get busy => sending || (memory.currentState?.busy ?? false);
  late final Timer timer;
  List<Map<String, dynamic>> get fields =>
      (widget.challenge['fields'] as List).cast<Map<String, dynamic>>();
  bool get current =>
      widget.isCurrent() &&
      DateTime.now().millisecondsSinceEpoch <
          (widget.challenge['expires_unix_ms'] as int);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    for (final field in fields) {
      controllers[field['id'] as String] = TextEditingController();
    }
    timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    timer.cancel();
    for (final controller in controllers.values) {
      controller.clear();
      controller.dispose();
    }
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      for (final controller in controllers.values) {
        controller.clear();
      }
      choices.clear();
      loadedSavedValues = false;
    }
  }

  void edited(Map<String, dynamic> field) {
    if (!loadedSavedValues ||
        (!['text', 'choice', 'confirmation'].contains(field['kind']) &&
            (field['choices'] as List? ?? []).isEmpty)) {
      return;
    }
    for (final item in fields) {
      if (item['kind'] != 'text') controllers[item['id']]!.clear();
    }
    loadedSavedValues = false;
  }

  Future<void> send() async {
    if (!current || busy || !form.currentState!.validate()) return;
    setState(() => sending = true);
    final values = <String, String>{
      for (final field in fields)
        field['id'] as String:
            choices[field['id']] ?? controllers[field['id']]!.text,
    };
    try {
      if (memory.currentState != null &&
          !await memory.currentState!.save(values)) {
        return;
      }
      if (mounted && current) {
        Navigator.pop(context, Map<String, String>.from(values));
      }
    } finally {
      values.clear();
      if (mounted) setState(() => sending = false);
    }
  }

  Widget fieldInput(Map<String, dynamic> field) {
    final id = field['id'] as String;
    final kind = field['kind'] as String;
    final options = (field['choices'] as List? ?? []).cast<String>();
    final required = field['required'] != false;
    String? validate(String? value) =>
        required && (value == null || value.isEmpty) ? 'Required' : null;
    if (options.isNotEmpty || kind == 'confirmation') {
      final items = options.isNotEmpty ? options : ['yes', 'no'];
      return DropdownButtonFormField<String>(
        key: ValueKey('interaction-field-$id'),
        decoration: InputDecoration(labelText: field['label'] as String),
        items: items
            .toSet()
            .map((v) => DropdownMenuItem(value: v, child: Text(v)))
            .toList(),
        onChanged: current && !busy
            ? (value) {
                edited(field);
                setState(() => choices[id] = value ?? '');
              }
            : null,
        validator: validate,
      );
    }
    final known = ['text', 'secret', 'password', 'otp'].contains(kind);
    return TextFormField(
      key: ValueKey('interaction-field-$id'),
      controller: controllers[id],
      enabled: current && !busy,
      obscureText: kind != 'text',
      autocorrect: false,
      enableSuggestions: false,
      maxLength: 4096,
      decoration: InputDecoration(
        labelText: field['label'] as String,
        helperText: known
            ? null
            : 'Field type: $kind. Review its YAML details below.',
        counterText: '',
      ),
      validator: validate,
      onChanged: (_) => edited(field),
    );
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('Respond to application'),
    content: SizedBox(
      width: 500,
      child: SingleChildScrollView(
        child: Form(
          key: form,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              InteractionContext(
                challenge: widget.challenge,
                server: widget.server,
              ),
              const SizedBox(height: 12),
              const Text('Application-supplied prompt'),
              Text(widget.challenge['prompt'] as String),
              for (final field in fields)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: fieldInput(field),
                ),
              ExpansionTile(
                title: const Text('Application-supplied details (YAML)'),
                children: [
                  SelectableText(
                    jsonAsYaml({
                      'prompt': widget.challenge['prompt'],
                      'fields': widget.challenge['fields'],
                      'context': widget.challenge['context'],
                    }),
                  ),
                ],
              ),
              if (widget.binding != null)
                CredentialSavePanel(
                  key: memory,
                  binding: widget.binding!.forAnswers(choices),
                  vault: widget.vault,
                  isCurrent: () => current,
                  apply: (values) {
                    for (final field in fields) {
                      final id = field['id'] as String;
                      if (field['kind'] == 'text' &&
                          controllers[id]!.text.isNotEmpty &&
                          values.containsKey(id) &&
                          controllers[id]!.text != values[id]) {
                        return false;
                      }
                    }
                    for (final entry in values.entries) {
                      controllers[entry.key]?.text = entry.value;
                    }
                    loadedSavedValues = true;
                    return true;
                  },
                  changed: () {
                    if (mounted) setState(() {});
                  },
                ),
              if (!current)
                const Text(
                  'This request is no longer available. Reconnect or refresh the queue.',
                ),
            ],
          ),
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: busy ? null : () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(
        onPressed: !current || busy ? null : send,
        child: const Text('Send response'),
      ),
    ],
  );
}
