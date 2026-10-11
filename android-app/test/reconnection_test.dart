import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/dashboard.dart';

class TestControl implements ControlApi {
  bool lost = false;
  int closes = 0;
  final calls = <Map<String, dynamic>>[];
  Future<Map<String, dynamic>> Function()? respond;

  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    calls.add(body);
    if (lost) throw const ConnectionLost();
    if (respond != null) return respond!();
    return switch (body['method']) {
      'pending' || 'history' => {'requests': []},
      'read_config' => {
        'content': '[principals.demo]\ncwd = "/"\n',
        'revision': 'original',
        'path': 'config.toml',
      },
      'status' => {'revision': 'original'},
      'save_config' => throw StateError(
        'configuration changed; reload before saving',
      ),
      _ => {},
    };
  }

  @override
  Future<void> close() async => closes++;
}

void main() {
  test(
    'lost mutations are never replayed and concurrent reconnects share a session',
    () async {
      final old = TestControl()..lost = true;
      final next = TestControl();
      final connecting = Completer<ControlApi>();
      var attempts = 0;
      final api = ControlConnection(old, () {
        attempts++;
        return connecting.future;
      });
      await expectLater(
        api.request({'method': 'resolve'}),
        throwsA(isA<ConnectionLost>()),
      );
      expect(api.disconnected, isTrue);
      final first = api.reconnect();
      final second = api.reconnect();
      expect(identical(first, second), isTrue);
      await expectLater(
        api.request({'method': 'resolve'}),
        throwsA(isA<ConnectionLost>()),
      );
      connecting.complete(next);
      await first;
      expect(attempts, 1);
      expect(old.closes, 1);
      expect(next.calls, isEmpty);
      expect(api.disconnected, isFalse);
      await api.request({'method': 'pending'});
      expect(next.calls.single['method'], 'pending');
      await api.close();
      expect(next.closes, 1);
      api.dispose();
    },
  );

  test(
    'late failures from an old session do not break its replacement',
    () async {
      final pending = Completer<Map<String, dynamic>>();
      final old = TestControl()..respond = () => pending.future;
      final api = ControlConnection(old, () async => TestControl());
      final request = api.request({'method': 'pending'});
      final failed = expectLater(request, throwsA(isA<ConnectionLost>()));
      await api.reconnect();
      pending.completeError(const ConnectionLost());
      await failed;
      expect(api.disconnected, isFalse);
      await api.close();
      api.dispose();
    },
  );

  test('closing during reconnect disposes the late transport', () async {
    final connecting = Completer<ControlApi>();
    final next = TestControl();
    final api = ControlConnection(TestControl(), () => connecting.future);
    final attempt = api.reconnect();
    final failed = expectLater(attempt, throwsA(isA<ConnectionLost>()));
    await Future<void>.delayed(Duration.zero);
    await api.close();
    api.dispose();
    connecting.complete(next);
    await failed;
    expect(next.closes, 1);
  });

  test('daemon errors do not mark the SSH connection disconnected', () async {
    final old = TestControl()
      ..respond = () async => throw StateError('Daemon is stopped');
    final api = ControlConnection(old, () async => TestControl());
    await expectLater(api.request({'method': 'pending'}), throwsStateError);
    expect(api.disconnected, isFalse);
    await api.close();
    api.dispose();
  });

  testWidgets(
    'closed connection recovers in place after failure and cancellation',
    (tester) async {
      final old = TestControl()..lost = true;
      var attempts = 0;
      final api = ControlConnection(old, () async {
        attempts++;
        if (attempts == 1) throw StateError('Server unavailable');
        if (attempts == 2) throw const AuthenticationCancelled();
        return TestControl();
      });
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'test'),
        ),
      );
      await tester.pumpAndSettle();
      expect(
        find.text('Connection lost. Retrying automatically…'),
        findsOneWidget,
      );
      for (final error in ['Server unavailable', 'Authentication cancelled']) {
        await tester.tap(find.widgetWithText(TextButton, 'Reconnect'));
        await tester.pumpAndSettle();
        expect(find.textContaining(error), findsOneWidget);
        expect(find.byType(Dashboard), findsOneWidget);
      }
      await tester.tap(find.widgetWithText(TextButton, 'Reconnect'));
      await tester.pumpAndSettle();
      expect(find.text('All caught up'), findsOneWidget);
      expect(
        find.text('Connection lost. Retrying automatically…'),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox.shrink());
      await api.close();
      api.dispose();
    },
  );

  testWidgets(
    'reconnect checks server revision without replacing or saving the draft',
    (tester) async {
      final old = TestControl(), next = TestControl();
      final connecting = Completer<ControlApi>();
      final api = ControlConnection(old, () => connecting.future);
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'test'),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Policy'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit TOML'));
      await tester.pumpAndSettle();
      const draft = '[principals.demo]\ncwd = "/tmp"\n';
      await tester.enterText(find.byType(TextField), draft);
      await tester.tap(find.byTooltip('Reconnect'));
      await tester.pump();
      expect(find.text('Reconnecting…'), findsOneWidget);
      expect(
        tester
            .widget<IconButton>(find.widgetWithIcon(IconButton, Icons.sync))
            .onPressed,
        isNull,
      );
      connecting.complete(next);
      await tester.pumpAndSettle();
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        draft,
      );
      expect(next.calls.map((c) => c['method']), ['read_config']);
      await tester.tap(find.text('Save & apply'));
      await tester.pumpAndSettle();
      final save = next.calls.singleWhere((c) => c['method'] == 'save_config');
      expect(save['revision'], 'original');
      expect(save['content'], draft);
      expect(find.textContaining('configuration changed'), findsOneWidget);
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        draft,
      );
      await tester.pumpWidget(const SizedBox.shrink());
      await api.close();
      api.dispose();
    },
  );

  testWidgets('history failures expose dashboard recovery', (tester) async {
    final old = TestControl(), next = TestControl();
    final api = ControlConnection(old, () async => next);
    await tester.pumpWidget(
      MaterialApp(
        home: Dashboard(api: api, name: 'test'),
      ),
    );
    await tester.pumpAndSettle();
    old.lost = true;
    await tester.tap(find.text('History'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(TextButton, 'Reconnect'));
    await tester.pumpAndSettle();
    expect(api.disconnected, isFalse);
    expect(next.calls.any((call) => call['method'] == 'history'), isTrue);
    await tester.pumpWidget(const SizedBox.shrink());
    await api.close();
    api.dispose();
  });
}
