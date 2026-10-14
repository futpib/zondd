import 'dart:async';
import 'package:flutter/material.dart';
import 'credential_save_panel.dart';
import 'saved_credentials.dart';

class SudoPasswordDialog extends StatefulWidget {
  const SudoPasswordDialog({
    super.key,
    required this.challenge,
    required this.isCurrent,
    this.binding,
    this.vault = const AndroidCredentialVault(),
  });
  final Map<String, dynamic> challenge;
  final bool Function() isCurrent;
  final CredentialBinding? binding;
  final CredentialVault vault;
  @override
  State<SudoPasswordDialog> createState() => _SudoPasswordDialogState();
}

class _SudoPasswordDialogState extends State<SudoPasswordDialog>
    with WidgetsBindingObserver {
  final controller = TextEditingController();
  final memory = GlobalKey<CredentialSavePanelState>();
  late final Timer timer;
  bool sending = false;
  bool get current =>
      widget.isCurrent() &&
      DateTime.now().millisecondsSinceEpoch <
          (widget.challenge['expires_unix_ms'] as int);
  bool get busy => sending || (memory.currentState?.busy ?? false);
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      controller.clear();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    timer.cancel();
    controller.clear();
    controller.dispose();
    super.dispose();
  }

  Future<void> send() async {
    if (!current || busy || controller.text.isEmpty) return;
    setState(() => sending = true);
    final values = {'password': controller.text};
    try {
      if (memory.currentState != null &&
          !await memory.currentState!.save(values)) {
        return;
      }
      if (mounted && current) Navigator.pop(context, values['password']);
    } finally {
      values.clear();
      if (mounted) setState(() => sending = false);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    scrollable: true,
    title: const Text('Sudo password'),
    content: Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(widget.challenge['prompt'] as String),
        const SizedBox(height: 12),
        TextField(
          controller: controller,
          enabled: current && !busy,
          obscureText: true,
          enableSuggestions: false,
          autocorrect: false,
          autofocus: true,
          onChanged: (_) => setState(() {}),
          decoration: const InputDecoration(labelText: 'Password'),
        ),
        if (widget.binding != null)
          CredentialSavePanel(
            key: memory,
            binding: widget.binding!,
            vault: widget.vault,
            isCurrent: () => current,
            apply: (values) {
              controller.text = values['password'] ?? '';
              return true;
            },
            changed: () {
              if (mounted) setState(() {});
            },
          ),
        if (!current)
          const Text('This password request is no longer available.'),
      ],
    ),
    actions: [
      TextButton(
        onPressed: busy ? null : () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(
        onPressed: !current || busy || controller.text.isEmpty ? null : send,
        child: const Text('Send password'),
      ),
    ],
  );
}
