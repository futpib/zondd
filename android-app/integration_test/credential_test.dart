import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;

  testWidgets('approve a named operation and answer repeated sudo prompts', (
    tester,
  ) async {
    tester.testTextInput.register();
    final profile = Profile(
      name: 'Credential test',
      host: fixture['host'],
      port: fixture['port'],
      user: fixture['user'],
      privateKey: fixture['key'],
      executable: fixture['executable'],
      runtime: fixture['runtime'],
      config: fixture['config'],
    );
    final api = await SshControl.connect(
      profile,
      (_, fingerprint) async => fingerprint == fixture['fingerprint'],
    );
    final original = await api.request({'method': 'read_config'});
    SSHClient? caller;
    SSHSession? session;
    StreamIterator<String>? events;
    String? requestId;

    Future<void> waitFor(Finder finder) async {
      for (var i = 0; i < 400 && finder.evaluate().isEmpty; i++) {
        await tester.pump(const Duration(milliseconds: 100));
      }
      expect(finder, findsOneWidget);
      await tester.ensureVisible(finder);
      await tester.pump(const Duration(milliseconds: 300));
    }

    try {
      final oldPolicy = original['content'] as String;
      expect(oldPolicy, contains('default = "ask"'));
      final policy =
          '${oldPolicy.replaceFirst('default = "ask"', 'default = "ask"\noperations = ["privileged"]').replaceFirst('command_timeout_secs = 2', 'command_timeout_secs = 120')}\n[operations.privileged]\nprogram = ${jsonEncode(fixture['probe'])}\nfixed_args = ["askpass"]\ndecision = "ask"\nsudo_password = true\n';
      final saved = await api.request({
        'method': 'save_config',
        'content': policy,
        'revision': original['revision'],
      });
      await api.request({
        'method': 'reload_config',
        'revision': saved['revision'],
      });

      caller = SSHClient(
        await SSHSocket.connect(fixture['host'], fixture['port']),
        username: fixture['user'],
        identities: SSHKeyPair.fromPem(fixture['callerKey']),
        onVerifyHostKey: (_, fingerprint) =>
            utf8.decode(fingerprint) == fixture['fingerprint'],
      );
      session = await caller.execute('');
      events = StreamIterator(
        session.stdout
            .cast<List<int>>()
            .transform(utf8.decoder)
            .transform(const LineSplitter()),
      );
      session.stdin.add(
        Uint8List.fromList(
          utf8.encode(
            '${jsonEncode({
              'version': 1,
              'id': 7,
              'body': {'method': 'invoke', 'operation': 'privileged', 'args': []},
            })}\n',
          ),
        ),
      );
      expect(await events.moveNext(), isTrue);
      final pending = jsonDecode(events.current)['body'];
      expect(pending['type'], 'pending');
      requestId = pending['request']['request_id'] as String;

      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: profile.name),
        ),
      );
      await waitFor(find.text('Approve once'));
      await tester.tap(find.text('Approve once'));
      String? previousChallenge;
      for (final password in ['test-password-one', 'test-password-two']) {
        String? challengeId;
        for (var i = 0; i < 400 && challengeId == null; i++) {
          final queue =
              (await api.request({'method': 'pending'}))['credentials'] as List;
          if (queue.isNotEmpty &&
              queue.first['challenge_id'] != previousChallenge) {
            challengeId = queue.first['challenge_id'] as String;
          } else {
            await tester.pump(const Duration(milliseconds: 100));
          }
        }
        expect(challengeId, isNotNull);
        previousChallenge = challengeId;
        await waitFor(find.byKey(ValueKey('credential-$challengeId')));
        await tester.tap(find.text('Enter password'));
        await waitFor(find.byType(TextField));
        expect(
          tester.widget<TextField>(find.byType(TextField)).obscureText,
          true,
        );
        await tester.enterText(find.byType(TextField), password);
        await tester.tap(find.text('Send password'));
        await tester.pump(const Duration(milliseconds: 500));
      }

      expect(
        await events.moveNext().timeout(const Duration(seconds: 20)),
        isTrue,
      );
      final completed = jsonDecode(events.current)['body'];
      expect(completed['type'], 'completed');
      expect(
        utf8.decode(base64Decode(completed['stdout'] as String)),
        'two prompts answered\n',
      );
      final history = await api.request({'method': 'history'});
      final actions = await api.request({'method': 'actions'});
      for (final secret in ['test-password-one', 'test-password-two']) {
        expect(jsonEncode(history), isNot(contains(secret)));
        expect(jsonEncode(actions), isNot(contains(secret)));
      }
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      await events?.cancel();
      session?.close();
      if (requestId != null && caller != null) {
        try {
          final stop = await caller.execute('');
          stop.stdin.add(
            Uint8List.fromList(
              utf8.encode(
                '${jsonEncode({
                  'version': 1,
                  'id': 8,
                  'body': {'method': 'cancel', 'request_id': requestId},
                })}\n',
              ),
            ),
          );
          await stop.stdout.first.timeout(const Duration(seconds: 3));
          stop.close();
        } catch (_) {
          // A completed or disconnected job needs no further cleanup.
        }
      }
      caller?.close();
      final current = await api.request({'method': 'read_config'});
      if (current['content'] != original['content']) {
        final restored = await api.request({
          'method': 'save_config',
          'content': original['content'],
          'revision': current['revision'],
        });
        await api.request({
          'method': 'reload_config',
          'revision': restored['revision'],
        });
      }
      await api.close();
    }
  }, timeout: const Timeout(Duration(minutes: 4)));
}
