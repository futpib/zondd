import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_test/flutter_test.dart';

// Caller SSH channels speak the daemon protocol directly. Negotiate before
// sending a command, and retain the same iterator for all subsequent events.
Future<StreamIterator<String>> callerEvents(SSHSession session) async {
  final events = StreamIterator(
    session.stdout
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter()),
  );
  try {
    session.stdin.add(
      Uint8List.fromList(
        utf8.encode(
          '${jsonEncode({
            'handshake': 1,
            'protocols': [2],
            'capabilities': [],
          })}\n',
        ),
      ),
    );
    expect(
      await events.moveNext().timeout(const Duration(seconds: 10)),
      isTrue,
      reason: 'Caller channel closed before protocol negotiation',
    );
    final welcome = jsonDecode(events.current) as Map;
    expect(welcome['error'], isNull, reason: jsonEncode(welcome));
    expect(welcome['handshake'], 1, reason: jsonEncode(welcome));
    expect(welcome['protocol'], 2, reason: jsonEncode(welcome));
    expect(welcome['capabilities'], isEmpty, reason: jsonEncode(welcome));
    return events;
  } catch (_) {
    await events.cancel();
    session.close();
    rethrow;
  }
}
