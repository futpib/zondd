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
  for (final scenario in [
    (iroh: false, service: false, typed: false),
    (iroh: true, service: false, typed: false),
    (iroh: false, service: true, typed: false),
    (iroh: true, service: true, typed: false),
    (iroh: false, service: false, typed: true),
    (iroh: true, service: false, typed: true),
  ]) {
    final iroh = scenario.iroh;
    testWidgets(
      'review and revoke a ${scenario.typed
          ? 'typed'
          : scenario.service
          ? 'service'
          : 'directory'} rule over ${iroh ? 'Iroh' : 'SSH'}',
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

        final name =
            'android-${scenario.typed
                ? 'typed'
                : scenario.service
                ? 'service'
                : 'rule'}-${iroh ? 'iroh' : 'ssh'}';
        final source = scenario.typed
            ? r'''type view = choice(resource, market) {
  balances = ("balances", "portfolio")
  accounts = ("accounts", "portfolio")
  positions = ("positions", "usdm")
}
type selected = view
type number = integer(min_inclusive=1, max_exclusive=11)
type big-count = integer(min_inclusive=0, max_exclusive=2**128)
type category = enum { daily, weekly }
type symbol = text('[A-Z]+', 2, 10)
rule RULE_NAME(v: selected, n: number, c: category, s: symbol, b: big-count) {
  run printf "%s:%s:%s:%s:%s:%s" "${v.resource}" "${v.market}" "$n" "$c" "$s" "$b"
}'''
                  .replaceAll('RULE_NAME', name)
            : scenario.service
            ? 'rule $name(x: repo-name) {\n  require user-service-active-or-enabled "zond-test-\$x.service"\n  run systemctl --user restart -- "zond-test-\$x.service"\n}'
            : 'rule $name(x: repo-name) {\n  create-new-dir "${fixture['runtime']}/\$x" as dest {\n    run mkdir "\$dest"\n  }\n}';
        String? proposalId;
        try {
          final proposed = await request({
            'method': 'propose_rule',
            'source': source,
          });
          expect(proposed['type'], 'rule_proposed');
          final proposal = proposed['proposal'] as Map;
          expect(proposal['review']['version'], 1);
          expect(proposal['source'], source);
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
          expect(
            tester
                .widget<SelectableText>(
                  find.byKey(ValueKey('rule-source-$proposalId')),
                )
                .data,
            proposal['source'],
          );
          final definition =
              'Definition: ${proposal['review']['sections'][0]['fields'][0]['value']}';
          expect(find.text(definition), findsOneWidget);
          if (scenario.typed) {
            expect(find.text('Local type definitions'), findsOneWidget);
            expect(
              proposal['bound']['rule']['types'][3]['definition']['max_exclusive'],
              '340282366920938463463374607431768211456',
            );
            expect(
              find.textContaining(
                '0 <= value < 340282366920938463463374607431768211456',
              ),
              findsWidgets,
            );
            expect(
              find.textContaining('No other combinations are permitted.'),
              findsWidgets,
            );
          } else {
            expect(
              find.textContaining('repo-name: 1–100 ASCII'),
              findsOneWidget,
            );
          }
          for (final section in proposal['review']['sections'] as List) {
            expect(find.text(section['title'] as String), findsOneWidget);
            for (final field in section['fields'] as List) {
              expect(
                find.text('${field['label']}: ${field['value']}'),
                findsOneWidget,
              );
            }
          }
          await visible(find.text('Rule details (YAML)'));
          await tester.tap(find.text('Rule details (YAML)'));
          final yamlView = find.byKey(ValueKey('rule-yaml-$proposalId'));
          await visible(yamlView);
          expect(
            loadYaml(tester.widget<SelectableText>(yamlView).data!),
            equals(proposal),
          );
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
          final invoked = await request({
            'method': 'invoke',
            'operation': name,
            'args': scenario.typed
                ? [
                    'positions',
                    '2',
                    'daily',
                    'ETHUSDT',
                    '340282366920938463463374607431768211455',
                  ]
                : [name],
          });
          if (scenario.service) {
            expect(invoked['type'], 'error');
            expect(
              invoked['message'],
              contains('require user-service-active-or-enabled'),
            );
          } else {
            expect(invoked['code'], 0);
          }
          if (scenario.typed) {
            expect(
              utf8.decode(base64Decode(invoked['stdout'] as String)),
              'positions:usdm:2:daily:ETHUSDT:340282366920938463463374607431768211455',
            );
            for (final args in [
              ['positions', '11', 'daily', 'ETHUSDT', '0'],
              ['positions', '02', 'daily', 'ETHUSDT', '0'],
              ['positions', '2', 'other', 'ETHUSDT', '0'],
              ['positions', '2', 'daily', 'ethusdt', '0'],
              ['positions', 'portfolio', '2', 'daily', 'ETHUSDT', '0'],

              [
                'positions',
                '2',
                'daily',
                'ETHUSDT',
                '340282366920938463463374607431768211456',
              ],
            ]) {
              expect(
                (await request({
                  'method': 'invoke',
                  'operation': name,
                  'args': args,
                }))['type'],
                'error',
              );
            }
          } else {
            expect(
              (await request({
                'method': 'invoke',
                'operation': name,
                'args': [name],
              }))['type'],
              'error',
            );
          }
          await visible(find.text('Caller rules'));
          await tester.tap(find.text('Caller rules'));
          final ruleCard = find.byKey(ValueKey('rule-state-$proposalId'));
          await visible(find.byType(TextField));
          await tester.enterText(find.byType(TextField), 'NO-MATCH-$name');
          await visible(find.text('No rules match your search.'));
          await tester.enterText(find.byType(TextField), name.toUpperCase());
          await tester.testTextInput.receiveAction(TextInputAction.search);
          await visible(ruleCard);
          expect(find.text(source), findsNothing);
          expect(find.text('Revoke rule'), findsNothing);
          await tester.tap(find.text(name));
          await visible(find.byKey(ValueKey('rule-source-$proposalId')));
          expect(find.text(source), findsOneWidget);
          await visible(find.text(definition));
          await visible(find.text('Revoke rule'));
          await tester.tap(find.text('Revoke rule'));
          await tester.pump();
          for (
            var i = 0;
            i < 300 &&
                find.byType(LinearProgressIndicator).evaluate().isNotEmpty;
            i++
          ) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(find.byType(LinearProgressIndicator), findsNothing);
          final after =
              (await request({'method': 'permissions'}))['permissions']['rules']
                  as List;
          expect(
            after
                .where((s) => s['proposal']['id'] == proposalId)
                .single['status'],
            'revoked',
          );
          expect(find.byKey(ValueKey('rule-state-$proposalId')), findsNothing);
          await tester.tap(find.text('History'));
          await tester.pump(const Duration(milliseconds: 300));
          // Scroll back to the historical card if its preserved expansion is
          // taller than the viewport.
          await tester.drag(find.byType(ListView), const Offset(0, 10000));
          await tester.pump(const Duration(milliseconds: 300));
          await visible(
            find.descendant(
              of: find.byKey(ValueKey('rule-state-$proposalId')),
              matching: find.text('Status: revoked'),
            ),
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
