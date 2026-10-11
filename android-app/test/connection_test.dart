import 'dart:async';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';

class Transport implements ControlApi, ConnectionEvents {
  final ended = Completer<void>();
  final requests = <Map<String, dynamic>>[];
  bool lost = false, closed = false;
  @override
  Future<void> get done => ended.future;
  @override
  Future<void> close() async {
    closed = true;
    if (!ended.isCompleted) ended.complete();
  }

  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    requests.add(body);
    if (lost) throw const ConnectionLost();
    return {};
  }
}

void main() {
  testWidgets('reconnects with capped backoff without replaying a mutation', (
    tester,
  ) async {
    final old = Transport()..lost = true;
    final replacement = Transport();
    var attempts = 0;
    final api = ControlConnection(old, () async {
      attempts++;
      if (attempts < 7) throw TimeoutException('offline');
      return replacement;
    });
    addTearDown(api.dispose);
    await expectLater(
      api.request({'method': 'resolve', 'approve': true}),
      throwsA(isA<ConnectionLost>()),
    );
    expect(attempts, 0);
    for (final delay in [1, 2, 4, 8, 16, 30, 30]) {
      final before = attempts;
      await tester.pump(Duration(milliseconds: delay * 1000 - 1));
      expect(attempts, before);
      await tester.pump(const Duration(milliseconds: 1));
      expect(attempts, before + 1);
    }
    expect(api.disconnected, isFalse);
    expect(api.generation, 1);
    expect(old.requests, [
      {'method': 'resolve', 'approve': true},
    ]);
    expect(replacement.requests, isEmpty);
    expect(old.closed, isTrue);
  });

  testWidgets('idle drops recover on resume and pause retries in background', (
    tester,
  ) async {
    final old = Transport();
    var attempts = 0;
    final api = ControlConnection(old, () async {
      attempts++;
      return Transport();
    });
    addTearDown(api.dispose);
    api.didChangeAppLifecycleState(AppLifecycleState.paused);
    old.ended.complete();
    await tester.pump(const Duration(minutes: 1));
    expect(api.disconnected, isTrue);
    expect(attempts, 0);
    api.didChangeAppLifecycleState(AppLifecycleState.resumed);
    await tester.pump(const Duration(milliseconds: 1));
    expect(attempts, 1);
    expect(api.disconnected, isFalse);
  });

  testWidgets('resuming detects a stale session with a read-only probe', (
    tester,
  ) async {
    final old = Transport()..lost = true;
    final api = ControlConnection(old, () async => Transport());
    addTearDown(api.dispose);
    api.didChangeAppLifecycleState(AppLifecycleState.resumed);
    await tester.pump();
    expect(old.requests, [
      {'method': 'status'},
    ]);
    await tester.pump(const Duration(seconds: 1));
    expect(api.disconnected, isFalse);
  });

  for (final failure in [
    const AuthenticationCancelled(),
    SSHHostkeyError('host key changed'),
    SSHAuthAbortError('handshake failed', SSHHostkeyError('untrusted host')),
    SSHAuthFailError('key rejected'),
    SSHAuthAbortError(
      'signing stopped',
      SSHInternalError(PlatformException(code: 'cancelled')),
    ),
  ]) {
    testWidgets('$failure pauses automatic retries until requested', (
      tester,
    ) async {
      final old = Transport();
      var attempts = 0;
      final api = ControlConnection(old, () async {
        attempts++;
        if (attempts == 1) throw failure;
        return Transport();
      });
      addTearDown(api.dispose);
      old.ended.complete();
      await tester.pump();
      await tester.pump(const Duration(seconds: 1));
      expect(attempts, 1);
      expect(api.connectionStatus, contains('$failure'));
      await tester.pump(const Duration(minutes: 1));
      api.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await tester.pump();
      expect(attempts, 1);
      await api.reconnect();
      expect(api.disconnected, isFalse);
    });
  }

  testWidgets('manual retry coalesces and closing releases a late connection', (
    tester,
  ) async {
    final old = Transport(), late = Transport();
    final opening = Completer<ControlApi>();
    var attempts = 0, cancellations = 0;
    final api = ControlConnection(old, () {
      attempts++;
      return opening.future;
    }, onClose: () => cancellations++);
    addTearDown(api.dispose);
    old.ended.complete();
    await tester.pump();
    final pending = api.reconnect();
    final failure = expectLater(pending, throwsA(isA<ConnectionLost>()));
    expect(identical(pending, api.reconnect()), isTrue);
    await tester.pump(const Duration(seconds: 31));
    expect(attempts, 1);
    await api.close();
    opening.complete(late);
    await failure;
    expect(late.closed, isTrue);
    expect(cancellations, 1);
    await tester.pump(const Duration(minutes: 1));
    expect(attempts, 1);
  });
}
