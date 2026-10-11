import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';
import 'package:zondd_control/rules.dart';
import 'package:zondd_control/ui.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;
  testWidgets(
    'capture reusable rule review and YAML fallback',
    (tester) async {
      final api = await SshControl.connect(
        Profile(
          name: 'Rule review',
          host: fixture['host'],
          port: fixture['port'],
          user: fixture['user'],
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
      Future<void> settle() async {
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 700));
      }

      Future<void> visible(Finder finder) async {
        for (var i = 0; i < 300 && finder.evaluate().isEmpty; i++) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(finder, findsOneWidget);
        await tester.ensureVisible(finder);
        await settle();
      }

      Future<void> capture(String name) async {
        const port = String.fromEnvironment('CAPTURE_PORT');
        if (port.isEmpty) return;
        FocusManager.instance.primaryFocus?.unfocus();
        await settle();
        final socket = await Socket.connect(
          '10.0.2.2',
          int.parse(port),
          timeout: const Duration(seconds: 10),
        );
        try {
          socket.write('GET /$name HTTP/1.0\r\nHost: localhost\r\n\r\n');
          await socket.flush();
          final response = await utf8.decoder
              .bind(socket)
              .join()
              .timeout(const Duration(seconds: 30));
          expect(response, contains('200 OK'));
        } finally {
          socket.destroy();
        }
      }

      Widget app(Widget home) => MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: appTheme(Brightness.dark),
        home: home,
      );

      Map<String, dynamic>? proposal;
      try {
        const source = r'''rule clone-futpib(x: repo-name) {
  require is-dir "$HOME/code"
  create-new-dir "$HOME/code/$x" as dest {
    run git clone -- "https://github.com/futpib/$x.git" "$dest"
  }
}''';
        final session = await caller.execute('');
        try {
          session.stdin.add(
            Uint8List.fromList(
              utf8.encode(
                '${jsonEncode({
                  'version': 1,
                  'id': 1,
                  'body': {'method': 'propose_rule', 'source': source},
                })}\n',
              ),
            ),
          );
          final response = await session.stdout
              .cast<List<int>>()
              .transform(utf8.decoder)
              .transform(const LineSplitter())
              .first;
          final body = jsonDecode(response)['body'] as Map;
          expect(body['type'], 'rule_proposed');
          proposal = body['proposal'] as Map<String, dynamic>;
        } finally {
          session.close();
        }

        await tester.pumpWidget(app(Dashboard(api: api, name: 'Rule review')));
        await visible(find.text('Reusable rule proposal'));
        await capture('01-rule-proposal');
        await visible(find.text('Parameters (positional order)'));
        await capture('02-rule-checks');
        await visible(find.text('Approve rule'));
        await capture('03-rule-approval');
        await tester.tap(find.text('1 hour'));
        await settle();
        await capture('04-grant-lifetime');
        await tester.tap(find.text('24 hours').last);
        await settle();
        await tester.tap(find.text('Rule details (YAML)'));
        await visible(find.text('Rule details (YAML)'));
        await capture('05-rule-yaml');
        await tester.tap(find.text('Rule details (YAML)'));
        await visible(find.text('Approve rule'));
        await tester.tap(find.text('Approve rule'));
        await visible(
          find.text(
            'Rule approved. Matching invocations can run without another prompt.',
          ),
        );
        final states =
            (await api.request({'method': 'rules'}))['rules'] as List;
        expect(
          states.singleWhere(
            (s) => s['proposal']['id'] == proposal!['id'],
          )['status'],
          'active',
        );
        await visible(find.text('Caller rules'));
        await tester.tap(find.text('Caller rules'));
        await visible(find.text('Status: active'));
        await capture('06-active-rule');
        await visible(find.text('Revoke rule'));
        await tester.tap(find.text('Revoke rule'));
        await tester.pump();
        for (
          var i = 0;
          i < 300 && find.byType(LinearProgressIndicator).evaluate().isNotEmpty;
          i++
        ) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(find.byType(LinearProgressIndicator), findsNothing);
        await tester.drag(find.byType(ListView), const Offset(0, 10000));
        await settle();
        await visible(find.text('Status: revoked'));
        await capture('07-revoked-rule');

        // A future review format is a presentation fixture, not a daemon grant.
        // Keep the real proposal fields and use the production approval widget.
        final futureProposal = <String, dynamic>{
          ...proposal,
          'review': {
            'version': 2,
            'title': 'clone-futpib',
            'checks': {
              'destination': 'must not exist',
              'parameter': 'repo-name',
            },
          },
        };
        bool? approved;
        await tester.pumpWidget(const SizedBox.shrink());
        await tester.pumpWidget(
          app(
            Scaffold(
              appBar: AppBar(title: const Text('Future-format demo')),
              body: ListView(
                padding: const EdgeInsets.all(20),
                children: [
                  RuleProposalCard(
                    proposal: futureProposal,
                    enabled: true,
                    resolve: (value, seconds) async {
                      approved = value;
                      expect(seconds, 3600);
                    },
                  ),
                ],
              ),
            ),
          ),
        );
        await visible(find.text('Complete rule data (YAML)'));
        await capture('08-future-format-yaml');
        await visible(find.text('Approve rule'));
        await capture('09-future-format-approval');
        await tester.tap(find.text('Approve rule'));
        expect(approved, isTrue);
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        if (proposal != null) {
          final states =
              (await api.request({'method': 'rules'}))['rules'] as List;
          for (final state in states.where(
            (s) => s['proposal']['id'] == proposal!['id'],
          )) {
            if (state['status'] == 'active') {
              await api.request({
                'method': 'revoke_rule',
                'grant_id': proposal['id'],
              });
            } else if (state['status'] == 'pending') {
              await api.request({
                'method': 'resolve_rule',
                'proposal_id': proposal['id'],
                'digest': proposal['digest'],
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
