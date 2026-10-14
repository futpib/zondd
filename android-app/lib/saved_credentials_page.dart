import 'package:flutter/material.dart';
import 'saved_credentials.dart';

class SavedCredentialsPage extends StatefulWidget {
  const SavedCredentialsPage({
    super.key,
    this.vault = const AndroidCredentialVault(),
  });
  final CredentialVault vault;
  @override
  State<SavedCredentialsPage> createState() => _SavedCredentialsPageState();
}

class _SavedCredentialsPageState extends State<SavedCredentialsPage> {
  List<SavedCredential> entries = [];
  bool busy = true;
  String? error;
  @override
  void initState() {
    super.initState();
    refresh();
  }

  Future<void> refresh() async {
    try {
      final entries = await widget.vault.list();
      entries.sort((a, b) => b.created.compareTo(a.created));
      if (mounted) {
        setState(() {
          this.entries = entries;
          error = null;
        });
      }
    } catch (_) {
      if (mounted) setState(() => error = 'Could not read saved credentials.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> remove(SavedCredential? entry) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          entry == null
              ? 'Remove all saved credentials?'
              : 'Remove saved credentials?',
        ),
        content: Text(
          entry == null
              ? 'You will need to enter credentials again.'
              : '${entry.metadata['server']} · ${entry.metadata['recipient']}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    setState(() {
      busy = true;
      error = null;
    });
    try {
      if (entry == null) {
        await widget.vault.removeAll();
      } else {
        await widget.vault.remove(entry.id);
      }
      await refresh();
    } catch (_) {
      if (mounted) {
        setState(() {
          busy = false;
          error = 'Could not remove saved credentials.';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('Saved credentials'),
      actions: [
        IconButton(
          tooltip: 'Refresh',
          onPressed: busy ? null : refresh,
          icon: const Icon(Icons.refresh),
        ),
        IconButton(
          tooltip: 'Remove all saved credentials',
          onPressed: busy ? null : () => remove(null),
          icon: const Icon(Icons.delete_sweep_outlined),
        ),
      ],
    ),
    body: Column(
      children: [
        if (busy) const LinearProgressIndicator(),
        if (error != null)
          Padding(padding: const EdgeInsets.all(16), child: Text(error!)),
        const Padding(
          padding: EdgeInsets.all(16),
          child: Text(
            'Saved values stay on this device and require biometric unlock. Expired credentials are removed when checked.',
          ),
        ),
        Expanded(
          child: entries.isEmpty
              ? const Center(child: Text('No saved credentials'))
              : ListView.builder(
                  itemCount: entries.length,
                  itemBuilder: (context, index) {
                    final entry = entries[index];
                    final metadata = entry.metadata;
                    final expiry = entry.expires == 0
                        ? 'Forever'
                        : 'Expires ${DateTime.fromMillisecondsSinceEpoch(entry.expires).toLocal()}';
                    return ListTile(
                      key: ValueKey('saved-credential-${entry.id}'),
                      leading: const Icon(Icons.lock_outline),
                      title: Text(
                        '${metadata['server']} · ${metadata['recipient']}',
                      ),
                      subtitle: Text(
                        '${metadata['purpose']}\n$expiry\nFields: ${(metadata['fields'] as List).join(', ')}',
                      ),
                      isThreeLine: true,
                      trailing: IconButton(
                        tooltip: 'Remove saved credentials',
                        onPressed: busy ? null : () => remove(entry),
                        icon: const Icon(Icons.delete_outline),
                      ),
                    );
                  },
                ),
        ),
      ],
    ),
  );
}
