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
  for (final iroh in [false, true]) {
    testWidgets(
      'review and revoke a caller rule over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        final api = await SshControl.connect(
          Profile(
            name: 'Rule review',
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
                  '${jsonEncode({'version': 1, 'id': 7, 'body': body})}\n',
                ),
              ),
            );
            expect(await events.moveNext(), isTrue);
            return jsonDecode(events.current)['body'] as Map<String, dynamic>;
          } finally {
            await events.cancel();
            session.close();
          }
        }

        Future<void> visible(Finder finder) async {
          for (var i = 0; i < 300 && finder.evaluate().isEmpty; i++) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(finder, findsOneWidget);
          await tester.ensureVisible(finder);
          await tester.pump(const Duration(milliseconds: 300));
        }

        final name = 'android-rule-${iroh ? 'iroh' : 'ssh'}';
        final source =
            'rule $name(x: repo-name) {\n  create-new "${fixture['runtime']}/\$x" as dest {\n    run mkdir "\$dest"\n  }\n}';
        String? proposalId;
        try {
          final proposed = await request({
            'method': 'propose_rule',
            'source': source,
          });
          expect(proposed['type'], 'rule_proposed');
          final proposal = proposed['proposal'] as Map;
          proposalId = proposal['id'] as String;
          expect(
            (await request({'method': 'rules'}))['rules'],
            contains(
              predicate(
                (dynamic s) =>
                    s['proposal']['id'] == proposalId &&
                    s['status'] == 'pending',
              ),
            ),
          );
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: 'Rule review'),
            ),
          );
          await visible(find.text('Reusable rule proposal'));
          expect(find.text(source), findsOneWidget);
          expect(find.textContaining('repo-name: 1–100 ASCII'), findsOneWidget);
          await visible(find.text('Approve rule'));
          await tester.tap(find.text('Approve rule'));
          await visible(
            find.text(
              'Rule approved. Matching invocations can run without another prompt.',
            ),
          );
          final states = (await request({'method': 'rules'}))['rules'] as List;
          expect(
            states
                .where((s) => s['proposal']['id'] == proposalId)
                .single['status'],
            'active',
          );
          expect(
            (await request({
              'method': 'invoke',
              'operation': name,
              'args': ['../escape'],
            }))['type'],
            'error',
          );
          expect(
            (await request({
              'method': 'invoke',
              'operation': name,
              'args': [name],
            }))['code'],
            0,
          );
          expect(
            (await request({
              'method': 'invoke',
              'operation': name,
              'args': [name],
            }))['type'],
            'error',
          );
          await visible(find.text('Caller rules'));
          await tester.tap(find.text('Caller rules'));
          await visible(find.text('Revoke rule'));
          await tester.tap(find.text('Revoke rule'));
          await visible(
            find.descendant(
              of: find.byKey(ValueKey('rule-state-$proposalId')),
              matching: find.text('Status: revoked'),
            ),
          );
          final after =
              (await request({'method': 'permissions'}))['permissions']['rules']
                  as List;
          expect(
            after
                .where((s) => s['proposal']['id'] == proposalId)
                .single['status'],
            'revoked',
          );
          expect(
            (await request({
              'method': 'invoke',
              'operation': name,
              'args': ['other'],
            }))['type'],
            'error',
          );
        } finally {
          await tester.pumpWidget(const SizedBox.shrink());
          if (proposalId != null) {
            final states =
                (await api.request({'method': 'rules'}))['rules'] as List;
            for (final state in states.where(
              (s) => s['proposal']['id'] == proposalId,
            )) {
              if (state['status'] == 'active') {
                await api.request({
                  'method': 'revoke_rule',
                  'grant_id': proposalId,
                });
              }
              if (state['status'] == 'pending') {
                await api.request({
                  'method': 'resolve_rule',
                  'proposal_id': proposalId,
                  'digest': state['proposal']['digest'],
                  'approve': false,
                });
              }
            }
          }
          caller.close();
          await api.close();
        }
      },
      timeout: const Timeout(Duration(minutes: 3)),
    );
  }
}
