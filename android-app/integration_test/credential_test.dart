import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:yaml/yaml.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;

  for (final persistent in [false, true]) {
    testWidgets(
      'approve ${persistent ? 'a persistent sudo rule over Iroh' : 'a named operation over SSH'} and answer repeated sudo prompts',
      (tester) async {
        tester.testTextInput.register();
        final profile = Profile(
          name: 'Credential test',
          host: fixture[persistent ? 'endpoint' : 'host'],
          iroh: persistent,
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
        String? proposalId;

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
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: profile.name),
            ),
          );
          if (persistent) {
            final proposalSession = await caller.execute('');
            final proposalEvents = StreamIterator(
              proposalSession.stdout
                  .cast<List<int>>()
                  .transform(utf8.decoder)
                  .transform(const LineSplitter()),
            );
            try {
              proposalSession.stdin.add(
                Uint8List.fromList(
                  utf8.encode(
                    '${jsonEncode({
                      'version': 1,
                      'id': 6,
                      'body': {'method': 'propose_rule', 'source': 'rule persistent-sudo() { run --allow-privilege-escalation "${fixture['probe']}" askpass }'},
                    })}\n',
                  ),
                ),
              );
              expect(await proposalEvents.moveNext(), isTrue);
              final proposed = jsonDecode(proposalEvents.current)['body'];
              expect(proposed['type'], 'rule_proposed');
              proposalId = proposed['proposal']['id'] as String;
              await waitFor(find.text('Reusable rule proposal'));
              expect(
                find.textContaining('no_new_privs is disabled'),
                findsOneWidget,
              );
              await waitFor(find.byType(DropdownButtonFormField<int>));
              await tester.tap(find.byType(DropdownButtonFormField<int>));
              await tester.pumpAndSettle();
              await tester.tap(find.text('Until revoked').last);
              await tester.pumpAndSettle();
              await waitFor(find.text('Approve rule'));
              await tester.tap(find.text('Approve rule'));
              await waitFor(
                find.text(
                  'Rule approved. Matching invocations can run without another prompt.',
                ),
              );
              final rules =
                  (await api.request({'method': 'rules'}))['rules'] as List;
              final grant = rules.singleWhere(
                (r) => r['proposal']['id'] == proposalId,
              );
              expect(grant['status'], 'active');
              expect(grant['grant_expires_unix_ms'], isNull);
            } finally {
              await proposalEvents.cancel();
              proposalSession.close();
            }
          }
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
                  'body': {'method': 'invoke', 'operation': persistent ? 'persistent-sudo' : 'privileged', 'args': []},
                })}\n',
              ),
            ),
          );
          if (!persistent) {
            expect(await events.moveNext(), isTrue);
            final pending = jsonDecode(events.current)['body'];
            expect(pending['type'], 'pending');
            requestId = pending['request']['request_id'] as String;

            await waitFor(find.text('Approve once'));
            expect(
              loadYaml(
                tester
                    .widget<SelectableText>(
                      find.byWidgetPredicate(
                        (w) =>
                            w is SelectableText &&
                            RegExp(r'(^|\n)program:').hasMatch(w.data ?? ''),
                      ),
                    )
                    .data!,
              ),
              pending['request']['command'],
            );
            await tester.tap(find.text('Approve once'));
          }
          String? previousChallenge;
          for (final password in ['test-password-one', 'test-password-two']) {
            String? challengeId;
            for (var i = 0; i < 400 && challengeId == null; i++) {
              final queue =
                  (await api.request({'method': 'pending'}))['credentials']
                      as List;
              if (queue.isNotEmpty &&
                  queue.first['challenge_id'] != previousChallenge) {
                challengeId = queue.first['challenge_id'] as String;
                requestId ??= queue.first['request_id'] as String;
              } else {
                await tester.pump(const Duration(milliseconds: 100));
              }
            }
            expect(challengeId, isNotNull);
            previousChallenge = challengeId;
            await waitFor(find.byKey(ValueKey('credential-$challengeId')));
            expect(
              loadYaml(
                tester
                    .widget<SelectableText>(
                      find.byWidgetPredicate(
                        (w) =>
                            w is SelectableText &&
                            RegExp(r'(^|\n)program:').hasMatch(w.data ?? ''),
                      ),
                    )
                    .data!,
              ),
              {
                'program': fixture['probe'],
                'args': ['askpass'],
              },
            );
            await tester.tap(find.text('Enter password'));
            await waitFor(find.byType(TextField));
            expect(
              tester.widget<TextField>(find.byType(TextField)).obscureText,
              true,
            );
            await tester.enterText(find.byType(TextField), password);
            await tester.pumpAndSettle();
            final saving = find.widgetWithText(
              CheckboxListTile,
              'Save credentials on this device',
            );
            if (saving.evaluate().isNotEmpty &&
                tester.widget<CheckboxListTile>(saving).value == true) {
              await tester.ensureVisible(saving);
              await tester.tap(saving);
              await tester.pumpAndSettle();
            }
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
          if (proposalId != null) {
            await api.request({
              'method': 'revoke_rule',
              'grant_id': proposalId,
            });
          }
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
      },
      timeout: const Timeout(Duration(minutes: 4)),
    );
  }
}
