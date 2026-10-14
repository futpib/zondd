import 'package:flutter/material.dart';
import 'saved_credentials.dart';

class CredentialSavePanel extends StatefulWidget {
  const CredentialSavePanel({
    super.key,
    required this.binding,
    required this.vault,
    required this.apply,
    required this.isCurrent,
    required this.changed,
  });
  final CredentialBinding binding;
  final CredentialVault vault;
  final bool Function(Map<String, String>) apply;
  final bool Function() isCurrent;
  final VoidCallback changed;
  @override
  State<CredentialSavePanel> createState() => CredentialSavePanelState();
}

class CredentialSavePanelState extends State<CredentialSavePanel>
    with WidgetsBindingObserver {
  int lifecycleGeneration = 0;
  bool ready = false,
      available = false,
      saved = false,
      busy = false,
      remember = true;
  CredentialLifetime lifetime = CredentialLifetime.hour;
  String? error;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    load();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden ||
        state == AppLifecycleState.detached) {
      lifecycleGeneration++;
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didUpdateWidget(CredentialSavePanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.binding.id != widget.binding.id) {
      ready = false;
      saved = false;
      remember = false;
      error = null;
      load();
    }
  }

  Future<void> load() async {
    final id = widget.binding.id;
    try {
      final available = await widget.vault.available();
      final entries = await widget.vault.list();
      if (mounted && widget.binding.id == id) {
        setState(() {
          this.available = available;
          saved = entries.any((entry) => entry.id == widget.binding.id);
          ready = true;
          remember = available;
        });
      }
    } catch (_) {
      if (mounted && widget.binding.id == id) {
        setState(() {
          ready = true;
          remember = false;
        });
      }
    }
    if (mounted) widget.changed();
  }

  Future<bool> save(Map<String, String> values) async {
    if (!ready) return false;
    if (!remember || !available) return true;
    if (busy || !widget.isCurrent()) return false;
    final generation = lifecycleGeneration;
    final binding = widget.binding;
    setState(() {
      busy = true;
      error = null;
    });
    widget.changed();
    try {
      await widget.vault.save(binding, values, lifetime);
      return mounted &&
          widget.isCurrent() &&
          lifecycleGeneration == generation &&
          widget.binding.id == binding.id;
    } catch (_) {
      if (mounted) {
        setState(
          () => error =
              'Credentials were not saved. Try again, or turn off saving to send without saving.',
        );
      }
      return false;
    } finally {
      if (mounted) {
        setState(() => busy = false);
        widget.changed();
      }
    }
  }

  Future<void> unlock() async {
    if (busy || !widget.isCurrent()) return;
    final generation = lifecycleGeneration;
    final binding = widget.binding;
    setState(() {
      busy = true;
      error = null;
    });
    widget.changed();
    Map<String, String>? values;
    try {
      values = await widget.vault.unlock(binding);
      if (!mounted ||
          !widget.isCurrent() ||
          lifecycleGeneration != generation ||
          widget.binding.id != binding.id) {
        return;
      }
      if (!widget.apply(values)) {
        setState(
          () => error =
              'Saved credentials do not match the entered account. Enter credentials manually, or clear the account field first.',
        );
        return;
      }
      setState(() => remember = false);
    } catch (_) {
      if (mounted) {
        setState(
          () => error =
              'Saved credentials could not be unlocked. You can enter them manually.',
        );
      }
    } finally {
      values?.clear();
      if (mounted) {
        setState(() => busy = false);
        widget.changed();
      }
    }
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      if (saved)
        OutlinedButton.icon(
          key: const ValueKey('unlock-saved-credentials'),
          onPressed: busy || !available || !widget.isCurrent() ? null : unlock,
          icon: const Icon(Icons.fingerprint),
          label: const Text('Use saved credentials'),
        ),
      if (!ready || busy) const LinearProgressIndicator(),
      if (ready && !available)
        const Text(
          'Set up strong biometrics on Android 11 or newer to save credentials.',
        ),
      if (available) ...[
        CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Save credentials on this device'),
          subtitle: Text(
            'Biometric unlock required. Saves: ${widget.binding.fieldIds.join(', ')}.',
          ),
          value: remember,
          onChanged: busy || !widget.isCurrent()
              ? null
              : (value) => setState(() => remember = value!),
        ),
        if (remember)
          DropdownButtonFormField<CredentialLifetime>(
            initialValue: lifetime,
            decoration: const InputDecoration(
              labelText: 'Keep saved credentials for',
            ),
            items: CredentialLifetime.values
                .map(
                  (value) =>
                      DropdownMenuItem(value: value, child: Text(value.label)),
                )
                .toList(),
            onChanged: busy
                ? null
                : (value) => setState(() => lifetime = value!),
          ),
      ],
      if (error != null)
        Text(
          error!,
          style: TextStyle(color: Theme.of(context).colorScheme.error),
        ),
    ],
  );
}
