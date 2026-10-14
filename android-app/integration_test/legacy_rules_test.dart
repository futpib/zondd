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
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))['legacy']
          as Map<String, dynamic>;
  for (final iroh in [false, true]) {
    testWidgets(
      'approve a rule with 207493 imported events over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        final api = await SshControl.connect(
          Profile(
            name: 'Imported history',
            host: fixture[iroh ? 'endpoint' : 'host'],
            port: fixture['port'],
            user: fixture['user'],
            iroh: iroh,
            privateKey: fixture['key'],
            executable: fixture['executable'],
            runtime: fixture['runtime'],
            config: fixture['config'],
          ),
          (_, fingerprint) async => fingerprint == fixture['fingerprint'],
        );
        final caller = SSHClient(
          await SSHSocket.connect(fixture['host'], fixture['port']),
          username: fixture['user'],
          identities: SSHKeyPair.fromPem(fixture['callerKey']),
          onVerifyHostKey: (_, fingerprint) =>
              utf8.decode(fingerprint) == fixture['fingerprint'],
        );
        Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
          final session = await caller.execute('');
          final responses = StreamIterator(
            session.stdout
                .cast<List<int>>()
                .transform(utf8.decoder)
                .transform(const LineSplitter()),
          );
          try {
            session.stdin.add(
              Uint8List.fromList(
                utf8.encode(
                  '${jsonEncode({'version': 1, 'id': 7, 'body': body})}\n',
                ),
              ),
            );
            expect(
              await responses.moveNext().timeout(const Duration(seconds: 10)),
              isTrue,
            );
            return jsonDecode(responses.current)['body']
                as Map<String, dynamic>;
          } finally {
            await responses.cancel();
            session.close();
          }
        }

        Future<void> visible(Finder finder) async {
          for (var i = 0; i < 200 && finder.evaluate().isEmpty; i++) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(finder, findsOneWidget);
          await tester.ensureVisible(finder);
          await tester.pump(const Duration(milliseconds: 100));
        }

        String? proposalId;
        try {
          final snapshot = await api.request({'method': 'audit_snapshot'});
          expect(snapshot['legacy_through_sequence'], 207493);
          final name = 'legacy-${iroh ? 'iroh' : 'ssh'}';
          final proposed = await request({
            'method': 'propose_rule',
            'source':
                'rule $name() { run /usr/bin/printf "%s" "legacy-approved" }',
          });
          proposalId = proposed['proposal']['id'] as String;
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: 'Imported history'),
            ),
          );
          if (iroh) {
            await visible(find.text('History'));
            await tester.tap(find.text('History'));
            await tester.pump(const Duration(milliseconds: 300));
            expect(find.byType(CircularProgressIndicator), findsOneWidget);
            await tester.tap(find.text('Approvals'));
            await tester.pump(const Duration(milliseconds: 100));
          }
          await visible(find.text('Approve rule'));
          await tester.tap(find.text('Approve rule'));
          await visible(
            find.text(
              'Rule approved. Matching invocations can run without another prompt.',
            ),
          );
          expect(api.historyVerifier.legacyThrough, 207493);
          expect(api.historyVerifier.events.length, lessThan(100));
          expect(
            api.historyVerifier.events.keys.every(
              (sequence) => sequence >= 207493,
            ),
            isTrue,
          );
          final result = await request({
            'method': 'invoke',
            'operation': name,
            'args': <String>[],
          });
          expect(result['code'], 0);
          expect(
            utf8.decode(base64Decode(result['stdout'] as String)),
            'legacy-approved',
          );
          await api.historyVerifier.sync(includeLegacy: false);
          expect(api.historyVerifier.unrecordedReceipts, 0);
          expect(
            api.historyVerifier.events.values.any(
              (event) => event['action'] == 'signed_decision',
            ),
            isTrue,
          );
        } finally {
          if (proposalId != null) {
            await api.request({
              'method': 'revoke_rule',
              'grant_id': proposalId,
            });
          }
          await tester.pumpWidget(const SizedBox.shrink());
          await api.close();
          caller.close();
          await caller.done;
        }
      },
    );
  }
}
