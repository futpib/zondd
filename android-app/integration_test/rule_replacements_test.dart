import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';

// Change the real receiver baseline after review, just before its decision.
class RevokeBeforeApproval implements ControlApi {
  RevokeBeforeApproval(this.transport);
  final ControlApi transport;
  String? baseline;
  @override
  Future<void> close() => transport.close();
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    if (body['method'] == 'resolve_rule' &&
        body['approve'] == true &&
        baseline != null) {
      final id = baseline;
      baseline = null;
      await transport.request({'method': 'revoke_rule', 'grant_id': id});
    }
    return transport.request(body);
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture = jsonDecode(
    const String.fromEnvironment('ZONDD_FIXTURE'),
  ) as Map<String, dynamic>;
  for (final iroh in [false, true]) {
    testWidgets(
      'replacement additions, removals, branch changes and stale review over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        final transport = await SshControl.connect(
          Profile(
            name: 'Replacement review',
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
        final api = RevokeBeforeApproval(transport);
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
                  '${jsonEncode({
                    'handshake': 1,
                    'protocols': [2],
                    'capabilities': [],
                  })}\n',
                ),
              ),
            );
            expect(await events.moveNext(), isTrue);
            final welcome = jsonDecode(events.current) as Map;
            expect(welcome['protocol'], 2, reason: jsonEncode(welcome));
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

        final name = 'replace-${iroh ? 'iroh' : 'ssh'}';
        String source({bool zond = true, String? eka}) {
          final rows = [
            'snakes = (repo="futpib/snakes-telegram", path="/home/publisher/code/snakes-telegram", src="refs/heads/master", dst="refs/heads/master")',
            if (zond) 'zond = (repo="futpib/zondd", path="/home/publisher/code/zondd", src="refs/heads/master", dst="refs/heads/master")',
            if (eka != null)
              'eka = (repo="futpib/EKA2L1", path="/home/publisher/code/EKA2L1", src="refs/heads/$eka", dst="refs/heads/$eka")',
          ];
          return 'type target = choice(fields=(repo, path, src, dst)) {\n${rows.join('\n')}\n}\nrule $name(t: target) { run printf "%s|%s" "\${t.repo}" "\${t.dst}" }';
        }

        Future<Map<String, dynamic>> propose(String source) async {
          final event = await request({
            'method': 'propose_rule',
            'source': source,
          });
          expect(event['type'], 'rule_proposed', reason: jsonEncode(event));
          return event['proposal'] as Map<String, dynamic>;
        }

        Future<Map> state(Map proposal) async =>
            ((await request({'method': 'rules'}))['rules'] as List).singleWhere(
              (s) => s['proposal']['id'] == proposal['id'],
            ) as Map;
        try {
          final original = await propose(source());
          expect(original['replaces'], isNull);
          await api.request({
            'method': 'resolve_rule',
            'proposal_id': original['id'],
            'digest': original['digest'],
            'approve': true,
          });
          var baseline = original;
          for (final change in [
            (
              source: source(eka: 'wasm-port'),
              label: 'Added Choice target.eka',
              summary: '1 added, 0 removed, 0 changed.',
              repo: 'futpib/EKA2L1',
            ),
            (
              source: source(zond: false, eka: 'wasm-port'),
              label: 'Removed Choice target.zond',
              summary: '0 added, 1 removed, 0 changed.',
              repo: 'futpib/zondd',
            ),
            (
              source: source(zond: false, eka: 'release'),
              label: 'Changed Choice target.eka',
              summary: '0 added, 0 removed, 1 changed.',
              repo: 'futpib/EKA2L1',
            ),
          ]) {
            final proposal = await propose(change.source);
            expect(proposal['replaces']['id'], baseline['id']);
            final fields = proposal['review']['sections'][0]['fields'] as List;
            final changed = fields.singleWhere(
              (f) => f['label'] == change.label,
            );
            expect(changed['value'], contains(change.repo));
            expect(jsonEncode(fields), isNot(contains('snakes-telegram')));
            await tester.pumpWidget(const SizedBox.shrink());
            await tester.pumpWidget(
              MaterialApp(
                home: Dashboard(api: api, name: 'Replacement review'),
              ),
            );
            await visible(find.text('Changes from approved rule'));
            expect(find.textContaining(change.summary), findsOneWidget);
            final row = find.text('${change.label}: ${changed['value']}');
            await visible(row);
            expect(find.textContaining('snakes-telegram'), findsNothing);
            expect(
              find.byKey(ValueKey('rule-source-${proposal['id']}')),
              findsNothing,
            );
            if (change.label.startsWith('Added')) {
              expect(changed['value'], contains('refs/heads/wasm-port'));
              expect(jsonEncode(fields), isNot(contains('futpib/zondd')));
            }
            if (change.label.startsWith('Changed')) {
              expect(changed['value'], contains('Before:'));
              expect(changed['value'], contains('refs/heads/wasm-port'));
              expect(changed['value'], contains('After:'));
              expect(changed['value'], contains('refs/heads/release'));
            }
            await visible(find.text('Full proposed rule'));
            await tester.tap(find.text('Full proposed rule'));
            await visible(
              find.byKey(ValueKey('rule-source-${proposal['id']}')),
            );
            expect(
              tester
                  .widget<SelectableText>(
                    find.byKey(ValueKey('rule-source-${proposal['id']}')),
                  )
                  .data,
              change.source,
            );
            await visible(find.text('Full proposed rule'));
            await tester.tap(find.text('Full proposed rule'));
            await visible(find.text('Approve rule'));
            await tester.tap(find.text('Approve rule'));
            await visible(
              find.text(
                'Rule approved. Matching invocations can run without another prompt.',
              ),
            );
            expect((await state(proposal))['status'], 'active');
            expect((await state(proposal))['proposal'], proposal);
            expect((await state(baseline))['status'], 'revoked');
            baseline = proposal;
          }
          final result = await request({
            'method': 'invoke',
            'operation': name,
            'args': ['eka'],
          });
          expect(result['type'], 'completed');
          expect(
            utf8.decode(base64Decode(result['stdout'] as String)),
            'futpib/EKA2L1|refs/heads/release',
          );
          expect(
            (await request({
              'method': 'invoke',
              'operation': name,
              'args': ['zond'],
            }))['type'],
            'error',
          );
          final stale = await propose(source(eka: 'wasm-port'));
          await tester.pumpWidget(const SizedBox.shrink());
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: 'Replacement review'),
            ),
          );
          await visible(find.text('Changes from approved rule'));
          api.baseline = baseline['id'] as String;
          await visible(find.text('Approve rule'));
          await tester.tap(find.text('Approve rule'));
          await visible(find.textContaining('approved rule baseline changed'));
          expect((await state(stale))['status'], 'invalidated');
          expect((await state(baseline))['status'], 'revoked');
        } finally {
          await tester.pumpWidget(const SizedBox.shrink());
          final rules =
              (await transport.request({'method': 'rules'}))['rules'] as List;
          for (final state in rules.where(
            (s) => s['proposal']['bound']['rule']['name'] == name,
          )) {
            final p = state['proposal'];
            if (state['status'] == 'active') {
              await transport.request({
                'method': 'revoke_rule',
                'grant_id': p['id'],
              });
            } else if (state['status'] == 'pending') {
              await transport.request({
                'method': 'resolve_rule',
                'proposal_id': p['id'],
                'digest': p['digest'],
                'approve': false,
              });
            }
          }
          caller.close();
          await api.close();
        }
      },
      timeout: const Timeout(Duration(minutes: 4)),
    );
  }
}
