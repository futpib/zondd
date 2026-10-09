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
