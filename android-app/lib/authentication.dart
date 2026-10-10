import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';

class AuthenticationDialog {
  AuthenticationDialog(this.context, this.target);
  final BuildContext context;
  final String target;
  DialogRoute<List<String>>? _route;
  bool _closed = false;

  Future<List<String>?> request(SSHUserInfoRequest request, bool retry) async {
    if (_closed || !context.mounted) return null;
    final route = DialogRoute<List<String>>(
      context: context,
      barrierDismissible: false,
      builder: (_) =>
          _AuthenticationForm(target: target, request: request, retry: retry),
    );
    _route = route;
    try {
      return await Navigator.of(context).push(route);
    } finally {
      if (_route == route) _route = null;
    }
  }

  void close() {
    _closed = true;
    final route = _route;
    _route = null;
    if (route != null && route.isActive) route.navigator?.removeRoute(route);
  }
}

class _AuthenticationForm extends StatefulWidget {
  const _AuthenticationForm({
    required this.target,
    required this.request,
    required this.retry,
  });
  final String target;
  final SSHUserInfoRequest request;
  final bool retry;

  @override
  State<_AuthenticationForm> createState() => _AuthenticationFormState();
}

class _AuthenticationFormState extends State<_AuthenticationForm> {
  late final fields = [
    for (final _ in widget.request.prompts) TextEditingController(),
  ];

  @override
  void dispose() {
    for (final field in fields) {
      field.dispose();
    }
    super.dispose();
  }

  void submit() => Navigator.pop(context, [for (final f in fields) f.text]);

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(
      widget.request.name.isEmpty ? 'SSH authentication' : widget.request.name,
    ),
    content: SingleChildScrollView(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(widget.target),
          if (widget.retry) ...[
            const SizedBox(height: 12),
            const Text('Authentication failed. Try again.'),
          ],
          if (widget.request.instruction.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(widget.request.instruction),
          ],
          for (var i = 0; i < fields.length; i++) ...[
            const SizedBox(height: 16),
            TextField(
              controller: fields[i],
              autofocus: i == 0,
              obscureText: !widget.request.prompts[i].echo,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: widget.request.prompts[i].promptText,
              ),
              textInputAction: i == fields.length - 1
                  ? TextInputAction.done
                  : TextInputAction.next,
              onSubmitted: i == fields.length - 1 ? (_) => submit() : null,
            ),
          ],
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(onPressed: submit, child: const Text('Continue')),
    ],
  );
}
