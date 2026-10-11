import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';
import 'package:zondd_control/identities.dart';
import 'package:zondd_control/history.dart';

// Let the real server commit, then lose the response before the UI receives it.
class LostSaveReply implements ControlApi {
  LostSaveReply(this.transport);
  final SshControl transport;
  @override
  Future<void> close() => transport.close();
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    final result = await transport.request(body);
    if (body['method'] == 'save_config') {
      await transport.close();
      throw const ConnectionLost();
    }
    return result;
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;
  Profile profile(bool iroh, {bool restricted = false}) => Profile(
    name: iroh ? 'Iroh test' : 'SSH test',
    host: (iroh ? fixture['endpoint'] : fixture['host']) as String,
    port: fixture['port'] as int,
    user: fixture['user'] as String,
    iroh: iroh,
    privateKey: fixture[restricted ? 'callerKey' : 'key'] as String,
    executable: fixture['executable'] as String,
    runtime: fixture['runtime'] as String,
    config: fixture['config'] as String,
  );

  testWidgets(
    'repair malformed remote policy through the editor',
    (tester) async {
      final p = Profile(
        name: 'Policy review',
        host: fixture['host'],
        port: fixture['port'],
        user: fixture['user'],
        privateKey: fixture['key'],
        executable: fixture['executable'],
        runtime: fixture['runtime'],
        config: fixture['config'],
      );
      final api = await SshControl.connect(
        p,
        (_, fp) async => fp == fixture['fingerprint'],
      );
      final original = await api.request({'method': 'read_config'});
      final ssh = SSHClient(
        await SSHSocket.connect(p.host, p.port),
        username: p.user,
        identities: SSHKeyPair.fromPem(p.privateKey),
        onVerifyHostKey: (_, fp) => utf8.decode(fp) == fixture['fingerprint'],
      );
      await ssh.authenticated;
      Future<void> write(String content) async {
        await ssh.run(
          'printf %s ${shellQuote(content)} > ${shellQuote(p.config)}',
        );
      }

      try {
        await write('approvals = false\n');
        expect(
          (await api.request({'method': 'read_config'}))['content'],
          'approvals = false\n',
        );
        await tester.pumpWidget(
          MaterialApp(
            home: Dashboard(api: api, name: p.name),
          ),
        );
        await tester.pump(const Duration(seconds: 1));
        await tester.tap(find.text('Policy'));
        for (
          var i = 0;
          i < 100 &&
              find
                  .textContaining('This configuration cannot be displayed')
                  .evaluate()
                  .isEmpty;
          i++
        ) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(tester.takeException(), isNull);
        expect(
          find.textContaining('This configuration cannot be displayed'),
          findsOneWidget,
        );
        await tester.tap(find.text('Edit TOML'));
        await tester.pump(const Duration(milliseconds: 500));
        await tester.enterText(find.byType(TextField), original['content']);
        await tester.tap(find.text('Save & apply'));
        for (
          var i = 0;
          i < 100 && find.text('Policy applied.').evaluate().isEmpty;
          i++
        ) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(find.text('Policy applied.'), findsOneWidget);
        expect(
          (await api.request({'method': 'read_config'}))['content'],
          original['content'],
        );
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        await write(original['content']);
        ssh.close();
        await api.close();
      }
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  for (final iroh in [false, true]) {
    testWidgets(
      'reconcile a lost policy-save reply over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        Future<SshControl> open() => SshControl.connect(
          profile(iroh),
          (_, fp) async => fp == fixture['fingerprint'],
        );
        final first = await open();
        final original = await first.request({'method': 'read_config'});
        final allowReconnect = Completer<void>();
        final api = ControlConnection(LostSaveReply(first), () async {
          await allowReconnect.future;
          return open();
        });
        // Integration binding otherwise keeps the real IME attached. Injected
        // enterText values do not update that IME's buffer, which can send its
        // old value when the editor disables during reconnect.
        tester.testTextInput.register();
        Future<void> waitFor(Finder finder) async {
          for (var i = 0; i < 400 && finder.evaluate().isEmpty; i++) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(finder, findsWidgets);
          await tester.pump(const Duration(milliseconds: 350));
        }

        try {
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: 'Lost save'),
            ),
          );
          await waitFor(find.text('All caught up'));
          await tester.tap(find.text('Policy'));
          await waitFor(find.text('Edit TOML'));
          for (
            var i = 0;
            i < 200 &&
                tester
                        .widget<TextButton>(
                          find.widgetWithText(TextButton, 'Edit TOML'),
                        )
                        .onPressed ==
                    null;
            i++
          ) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          await tester.tap(find.text('Edit TOML'));
          await waitFor(find.byType(TextField));
          final draft = '${original['content']}\n# saved with lost response\n';
          await tester.enterText(find.byType(TextField), draft);
          await tester.pumpAndSettle();
          await tester.tap(find.text('Save & apply'));
          await waitFor(find.widgetWithText(TextButton, 'Reconnect'));
          final newer = '$draft# edited while disconnected\n';
          await tester.enterText(find.byType(TextField), newer);
          await tester.pumpAndSettle();
          expect(
            tester.widget<TextField>(find.byType(TextField)).controller!.text,
            newer,
          );
          allowReconnect.complete();
          for (
            var i = 0;
            i < 400 && (api.disconnected || api.reconnecting);
            i++
          ) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          // Reconciliation also reads the server after authentication completes.
          for (
            var i = 0;
            i < 200 &&
                tester
                        .widget<FilledButton>(
                          find.widgetWithText(FilledButton, 'Save & apply'),
                        )
                        .onPressed ==
                    null;
            i++
          ) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(
            tester.widget<TextField>(find.byType(TextField)).controller!.text,
            newer,
          );
          await tester.tap(find.text('Save & apply'));
          await waitFor(find.text('Policy applied.'));
          expect(
            (await api.request({'method': 'read_config'}))['content'],
            newer,
          );
        } finally {
          await tester.pumpWidget(const SizedBox.shrink());
          tester.testTextInput.unregister();
          await api.close();
          api.dispose();
          final cleanup = await open();
          try {
            final current = await cleanup.request({'method': 'read_config'});
            final saved = await cleanup.request({
              'method': 'save_config',
              'content': original['content'],
              'revision': current['revision'],
            });
            await cleanup.request({
              'method': 'reload_config',
              'revision': saved['revision'],
            });
          } finally {
            await cleanup.close();
          }
        }
      },
    );
    testWidgets(
      'automatically recover a closed ${iroh ? 'Iroh' : 'SSH'} session in place',
      (tester) async {
        var connections = 0;
        Future<SshControl> open() async {
          connections++;
          return SshControl.connect(
            profile(iroh),
            (_, fp) async => fp == fixture['fingerprint'],
          );
        }

        final transport = await open();
        final api = ControlConnection(transport, open);
        try {
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: 'Recovery'),
            ),
          );
          for (
            var i = 0;
            i < 200 && find.text('All caught up').evaluate().isEmpty;
            i++
          ) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(find.text('All caught up'), findsOneWidget);
          await transport.close();
          for (
            var i = 0;
            i < 200 && find.text('Reconnect').evaluate().isEmpty;
            i++
          ) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(
            find.text('Connection lost. Retrying automatically…'),
            findsOneWidget,
          );
          for (
            var i = 0;
            i < 400 &&
                (api.disconnected ||
                    find.text('All caught up').evaluate().isEmpty);
            i++
          ) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(api.disconnected, isFalse);
          expect(find.text('All caught up'), findsOneWidget);
          expect(connections, 2);
          expect(
            (await api.request({'method': 'pending'}))['requests'],
            isEmpty,
          );
        } finally {
          await tester.pumpWidget(const SizedBox.shrink());
          await api.close();
          api.dispose();
        }
      },
    );
  }

  testWidgets(
    'saved credentials connect through the normal SSH management UI',
    (tester) async {
      const store = ProfileStore();
      final previous = await store.load();
      final previousKeys = await IdentityStore().load();
      final p = profile(false);
      try {
        await store.save([p]);
        final migrated = (await store.load()).single;
        expect(migrated.privateKey, isEmpty);
        expect((await IdentityStore().get(migrated.keyId)).pem, p.privateKey);
        await tester.pumpWidget(const ZonddApp());
        for (var i = 0; i < 100 && find.text(p.name).evaluate().isEmpty; i++) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        await tester.tap(find.text(p.name));
        for (
          var i = 0;
          i < 200 && find.text('Trust SSH host key?').evaluate().isEmpty;
          i++
        ) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(
          find.textContaining(fixture['fingerprint'] as String),
          findsOneWidget,
        );
        await tester.tap(find.text('Trust'));
        for (
          var i = 0;
          i < 200 && find.text('Pending commands').evaluate().isEmpty;
          i++
        ) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(find.text('Pending commands'), findsOneWidget);
        expect(
          await store.hostKey(p.hostIdentity),
          contains(fixture['fingerprint']),
        );
        await tester.pageBack();
        for (var i = 0; i < 20; i++) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        await tester.pumpWidget(const SizedBox.shrink());
      } finally {
        await store.save(previous);
        await IdentityStore().save(previousKeys);
        await store.forget(p.hostIdentity);
      }
    },
  );

  testWidgets(
    'built-in policy and omitted defaults are visible over real SSH',
    (tester) async {
      final api = await SshControl.connect(
        profile(false),
        (_, fp) async => fp == fixture['fingerprint'],
      );
      final original = await api.request({'method': 'read_config'});
      try {
        for (final content in ['', '[approvals]\nenabled = false\n']) {
          final current = await api.request({'method': 'read_config'});
          final saved = await api.request({
            'method': 'save_config',
            'content': content,
            'revision': current['revision'],
          });
          await api.request({
            'method': 'reload_config',
            'revision': saved['revision'],
          });
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(key: UniqueKey(), api: api, name: 'Defaults'),
            ),
          );
          await tester.pump();
          await tester.tap(find.text('Policy'));
          final label = content.isEmpty
              ? 'Manual approvals enabled'
              : 'Manual approvals disabled';
          for (var i = 0; i < 200 && find.text(label).evaluate().isEmpty; i++) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(find.text(label), findsOneWidget);
          expect(find.text('Callers · 1'), findsOneWidget);
          expect(find.text('default'), findsOneWidget);
          await tester.pumpWidget(const SizedBox.shrink());
        }
      } finally {
        final current = await api.request({'method': 'read_config'});
        final saved = await api.request({
          'method': 'save_config',
          'content': original['content'],
          'revision': current['revision'],
        });
        await api.request({
          'method': 'reload_config',
          'revision': saved['revision'],
        });
        await api.close();
      }
    },
  );

  testWidgets(
    'approve and reject through real Android SSH and Iroh transports',
    (tester) async {
      for (final iroh in [false, true]) {
        var verified = false;
        final api = await SshControl.connect(profile(iroh), (
          type,
          fingerprint,
        ) async {
          expect(fingerprint, fixture['fingerprint']);
          verified = true;
          return true;
        });
        expect(verified, isTrue);
        try {
          for (final approve in [true, false]) {
            final socket = await SSHSocket.connect(
              fixture['host'] as String,
              fixture['port'] as int,
            );
            final caller = SSHClient(
              socket,
              username: fixture['user'] as String,
              identities: SSHKeyPair.fromPem(fixture['callerKey'] as String),
              onVerifyHostKey: (_, fingerprint) =>
                  utf8.decode(fingerprint) == fixture['fingerprint'],
            );
            try {
              final session = await caller.execute('');
              final events = StreamIterator(
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
                      'body': {
                        'method': 'run',
                        'command': {
                          'program': '/usr/bin/printf',
                          'args': ['%s', 'android-approved'],
                        },
                      },
                    })}\n',
                  ),
                ),
              );
              expect(
                await events.moveNext().timeout(const Duration(seconds: 10)),
                isTrue,
              );
              expect(jsonDecode(events.current)['body']['type'], 'pending');
              if (approve) {
                final pending = jsonDecode(events.current)['body']['request'];
                final config = await api.request({'method': 'read_config'});
                final saved = await api.request({
                  'method': 'save_config',
                  'content':
                      '${config['content']}\n# Keep the caller connected\n',
                  'revision': config['revision'],
                });
                final applied = await api.request({
                  'method': 'reload_config',
                  'revision': saved['revision'],
                });
                expect(applied['retained_approvals'], 1);
                final queue =
                    (await api.request({'method': 'pending'}))['requests']
                        as List;
                expect(queue.single['approval_id'], pending['approval_id']);
                expect(
                  queue.single['expires_unix_ms'],
                  pending['expires_unix_ms'],
                );
              }

              await tester.pumpWidget(
                MaterialApp(
                  home: Dashboard(api: api, name: profile(iroh).name),
                ),
              );
              for (
                var i = 0;
                i < 100 && find.text('Approve once').evaluate().isEmpty;
                i++
              ) {
                await tester.pump(const Duration(milliseconds: 100));
              }
              expect(find.text('Approve once'), findsOneWidget);
              expect(find.textContaining('android-approved'), findsOneWidget);
              await tester.ensureVisible(
                find.text(approve ? 'Approve once' : 'Reject'),
              );
              await tester.tap(find.text(approve ? 'Approve once' : 'Reject'));
              for (var i = 0; i < 30; i++) {
                await tester.pump(const Duration(milliseconds: 100));
              }
              expect(
                await events.moveNext().timeout(const Duration(seconds: 10)),
                isTrue,
              );
              final result = jsonDecode(events.current)['body'];
              expect(result['type'], approve ? 'completed' : 'rejected');
              if (approve) {
                expect(
                  utf8.decode(base64Decode(result['stdout'] as String)),
                  'android-approved',
                );
              }
              await events.cancel();
              session.close();
              await tester.pumpWidget(const SizedBox.shrink());
            } finally {
              caller.close();
            }
          }
          final config = await api.request({'method': 'read_config'});
          await expectLater(
            api.request({
              'method': 'save_config',
              'content': 'invalid',
              'revision': config['revision'],
            }),
            throwsA(isA<StateError>()),
          );
          final edited =
              '${config['content']}\n# Android E2E ${iroh ? 'iroh' : 'ssh'}\n';
          final saved = await api.request({
            'method': 'save_config',
            'content': edited,
            'revision': config['revision'],
          });
          expect(saved['restart_required'], isFalse);
          expect(saved['apply_required'], isTrue);
          final applied = await api.request({
            'method': 'reload_config',
            'revision': saved['revision'],
          });
          expect(applied['revision'], saved['revision']);
          expect(
            (await api.request({'method': 'status'}))['revision'],
            saved['revision'],
          );
          expect(
            (await api.request({'method': 'read_config'}))['content'],
            edited,
          );
          await expectLater(
            api.request({
              'method': 'save_config',
              'content': config['content'],
              'revision': config['revision'],
            }),
            throwsA(isA<StateError>()),
          );
          final service = await api.request({
            'method': 'service',
            'action': 'status',
          });
          expect(service['output'], contains('LoadState='));
          final history =
              (await api.request({'method': 'history'}))['requests'] as List;
          expect(history.any((r) => r['status'] == 'completed'), isTrue);
          expect(history.any((r) => r['status'] == 'denied'), isTrue);
          final original = history.firstWhere(
            (r) => r['status'] == 'completed',
          );
          final retry = await api.request({
            'method': 'retry',
            'request_id': original['request_id'],
          });
          Map<String, dynamic>? queued;
          for (var i = 0; i < 100 && queued == null; i++) {
            final entries =
                (await api.request({'method': 'pending'}))['requests'] as List;
            for (final entry in entries) {
              if (entry['request_id'] == retry['request_id']) {
                queued = entry as Map<String, dynamic>;
              }
            }
            if (queued == null) {
              await tester.pump(const Duration(milliseconds: 100));
            }
          }
          expect(queued, isNotNull);
          expect(queued!['approval_id'], isNot(original['approval_id']));
          await api.request({
            'method': 'resolve',
            'approval_id': queued['approval_id'],
            'approve': false,
          });
          final detail = await api.request({
            'method': 'request_detail',
            'request_id': retry['request_id'],
          });
          expect(detail['request']['retry_of'], original['request_id']);
          expect(detail['request']['status'], 'denied');
          final actions =
              (await api.request({'method': 'actions'}))['actions'] as List;
          expect(actions.any((a) => a['action'] == 'approval_denied'), isTrue);
          final recovery = ControlConnection(
            api,
            () => SshControl.connect(
              profile(iroh),
              (_, fp) async => fp == fixture['fingerprint'],
            ),
          );
          try {
            await tester.pumpWidget(
              MaterialApp(
                home: RequestDetailsPage(
                  api: recovery,
                  requestId: retry['request_id'] as String,
                ),
              ),
            );
            for (
              var i = 0;
              i < 200 && find.text('Run again').evaluate().isEmpty;
              i++
            ) {
              await tester.pump(const Duration(milliseconds: 100));
            }
            expect(find.text('Run again'), findsOneWidget);
            await api.close();
            for (var i = 0; i < 200 && !recovery.disconnected; i++) {
              await tester.pump(const Duration(milliseconds: 100));
            }
            await tester.pump();
            for (var i = 0; i < 400 && recovery.disconnected; i++) {
              await tester.pump(const Duration(milliseconds: 100));
            }
            expect(recovery.disconnected, isFalse);
            expect(recovery.generation, 1);
            expect(find.text('Run again'), findsOneWidget);
            expect(
              (await recovery.request({
                'method': 'request_detail',
                'request_id': retry['request_id'],
              }))['request']['status'],
              'denied',
            );
          } finally {
            await tester.pumpWidget(const SizedBox.shrink());
            await recovery.close();
            recovery.dispose();
          }
        } finally {
          await api.close();
        }
        await expectLater(
          SshControl.connect(profile(iroh), (_, _) async => false),
          throwsA(anything),
        );
        final restricted = await SshControl.connect(
          profile(iroh, restricted: true),
          (_, fp) async => fp == fixture['fingerprint'],
        );
        try {
          await expectLater(
            restricted.request({'method': 'pending'}),
            throwsA(isA<StateError>()),
          );
        } finally {
          await restricted.close();
        }
      }
    },
  );
}
