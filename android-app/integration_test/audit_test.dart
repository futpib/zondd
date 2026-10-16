import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/history.dart';
import 'package:zondd_control/main.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;
  for (final iroh in [false, true]) {
    testWidgets(
      'signed decisions, native export and tamper detection over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        debugPrint('Audit E2E ${iroh ? 'Iroh' : 'SSH'}: connecting');
        final profile = Profile(
          name: 'Audit server',
          host: fixture[iroh ? 'endpoint' : 'host'],
          iroh: iroh,
          port: fixture['port'],
          user: fixture['user'],
          privateKey: fixture['key'],
          executable: fixture['executable'],
          runtime: fixture['runtime'],
          config: fixture['config'],
        );
        var api = await SshControl.connect(
          profile,
          (_, fp) async => fp == fixture['fingerprint'],
        );
        final management = SSHClient(
          await SSHSocket.connect(fixture['host'], fixture['port']),
          username: fixture['user'],
          identities: SSHKeyPair.fromPem(fixture['key']),
          onVerifyHostKey: (_, fp) => utf8.decode(fp) == fixture['fingerprint'],
        );
        final caller = SSHClient(
          await SSHSocket.connect(fixture['host'], fixture['port']),
          username: fixture['user'],
          identities: SSHKeyPair.fromPem(fixture['callerKey']),
          onVerifyHostKey: (_, fp) => utf8.decode(fp) == fixture['fingerprint'],
        );
        SSHSession? session;
        var tampered = false;
        Future<void> visible(Finder finder) async {
          for (var i = 0; i < 500 && finder.evaluate().isEmpty; i++) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(finder, findsWidgets);
          await tester.ensureVisible(finder.first);
          await tester.pump(const Duration(milliseconds: 100));
        }

        String quote(String text) => "'${text.replaceAll("'", "'\\''")}'";
        Future<void> remotePython(String source) async {
          final command =
              'python3 -c ${quote(source)} ${quote(fixture['config'])}';
          final process = await management.execute(command);
          final errors = process.stderr
              .cast<List<int>>()
              .transform(utf8.decoder)
              .join();
          await process.done.timeout(const Duration(seconds: 20));
          expect(process.exitCode, 0, reason: await errors);
          process.close();
        }

        const tamper = '''
import sqlite3,sys,pathlib,json
p=pathlib.Path(sys.argv[1]).with_suffix('.history.sqlite3')
db=sqlite3.connect(p)
row=db.execute('SELECT sequence,detail FROM actions ORDER BY sequence DESC LIMIT 1').fetchone()
undo=p.with_suffix('.audit-undo.json')
undo.touch(mode=0o600)
undo.write_text(json.dumps(row))
detail=json.loads(row[1]); detail['forged']='changed receiver history'
db.execute('UPDATE actions SET detail=? WHERE sequence=?',(json.dumps(detail),row[0]))
db.commit()
''';
        const restore = '''
import sqlite3,sys,pathlib,json
p=pathlib.Path(sys.argv[1]).with_suffix('.history.sqlite3')
undo=p.with_suffix('.audit-undo.json')
row=json.loads(undo.read_text())
db=sqlite3.connect(p)
db.execute('UPDATE actions SET detail=? WHERE sequence=?',(row[1],row[0]))
db.commit();undo.unlink()
''';
        try {
          session = await caller.execute('');
          final responses = StreamIterator(
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
                  'id': 99,
                  'transport': {'ssh_key_fingerprint': 'SPOOFED-KEY', 'evidence': 'client_claim'},
                  'body': {
                    'method': 'run',
                    'command': {
                      'program': '/usr/bin/printf',
                      'args': ['%s', 'audited-output'],
                    },
                  },
                })}\n',
              ),
            ),
          );
          expect(
            await responses.moveNext().timeout(const Duration(seconds: 20)),
            true,
          );
          final pending =
              jsonDecode(responses.current)['body']['request'] as Map;
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: profile.name),
            ),
          );
          await visible(find.text('Approve once'));
          await tester.tap(find.text('Approve once'));
          expect(
            await responses.moveNext().timeout(const Duration(seconds: 20)),
            true,
          );
          expect(jsonDecode(responses.current)['body']['type'], 'completed');
          debugPrint('Audit E2E ${iroh ? 'Iroh' : 'SSH'}: approval completed');
          await responses.cancel();
          session.close();
          session = null;
          await api.historyVerifier.sync();
          final events = api.historyVerifier.events.values.toList();
          final received = events.singleWhere(
            (e) =>
                e['request_id'] == pending['request_id'] &&
                e['action'] == 'request_received',
          );
          expect(
            received['detail']['actor']['transport']['evidence'],
            'forced_command_key_binding',
          );
          expect(
            received['detail']['actor']['transport']['ssh_key_fingerprint'],
            startsWith('SHA256:'),
          );
          expect(jsonEncode(events), isNot(contains('SPOOFED-KEY')));
          final decision = events.singleWhere(
            (e) =>
                e['request_id'] == pending['request_id'] &&
                e['action'] == 'approval_granted',
          );
          expect(
            decision['detail']['actor']['device_key_evidence'],
            'signature_verified',
          );
          expect(
            decision['detail']['actor']['transport']['evidence'],
            'openssh_auth_info',
          );
          final receipts = await SshControl.auditDevice.receipts(
            api.auditScope,
          );
          expect(
            receipts.any(
              (r) =>
                  r['proof']['nonce'] ==
                  decision['detail']['actor']['receipt_id'],
            ),
            true,
          );
          final policy = await api.request({'method': 'read_config'});
          final saved = await api.request({
            'method': 'save_config',
            'revision': policy['revision'],
            'content': '${policy['content']}\n# auditable management edit\n',
          });
          await api.historyVerifier.sync();
          final edit = api.historyVerifier.events.values.lastWhere(
            (e) =>
                e['action'] == 'control.save_config' &&
                e['detail']['revision'] == saved['revision'],
          );
          final editId = edit['detail']['actor']['receipt_id'] as String;
          await tester.tap(find.text('History'));
          await visible(
            find.textContaining('Activity matches phone checkpoint'),
          );
          await tester.tap(find.text('Activity'));
          final group = find.descendant(
            of: find.byWidgetPredicate(
              (w) => w is ActivityGroup && w.subject == pending['request_id'],
            ),
            matching: find.text('Command finished'),
          );
          await visible(group);
          await tester.tap(group);
          await visible(find.text('Activity timeline'));
          await visible(find.text('Request details'));
          await tester.tap(find.text('Request details'));
          await visible(find.text('Recorded reviewer'));
          expect(
            find.textContaining('Device signature checked.'),
            findsOneWidget,
          );
          await tester.pageBack();
          await tester.pump(const Duration(milliseconds: 500));
          final editGroup = find.descendant(
            of: find.byWidgetPredicate(
              (w) => w is ActivityGroup && w.subject == editId,
            ),
            matching: find.text('Configuration saved'),
          );
          await tester.scrollUntilVisible(
            editGroup,
            -200,
            scrollable: find.byType(Scrollable).last,
          );
          await visible(editGroup);
          await tester.tap(editGroup);
          await visible(find.text('Activity timeline'));
          await visible(find.text('Device signed decision'));
          await visible(find.text('Configuration save requested'));
          await visible(find.text('Configuration saved'));
          await tester.pageBack();
          await tester.pump(const Duration(milliseconds: 500));
          final export = find.byWidgetPredicate(
            (w) => w is IconButton && w.tooltip == 'Export audit history',
          );
          await visible(export);
          debugPrint('Audit E2E ${iroh ? 'Iroh' : 'SSH'}: export ready');
          for (var i = 0; i < 500; i++) {
            final button = tester.widget<IconButton>(export);
            if (button.onPressed != null) break;
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(tester.widget<IconButton>(export).onPressed, isNotNull);
          await tester.tap(export);
          debugPrint(
            'Audit E2E ${iroh ? 'Iroh' : 'SSH'}: native save requested',
          );
          // The host driver completes the real Android document saver, pulls the
          // saved bytes, checks them with zondctl, and removes the exported fixture.
          await visible(find.text('Audit history exported.'));
          debugPrint(
            'Audit E2E ${iroh ? 'Iroh' : 'SSH'}: native save completed',
          );
          await tester.pumpWidget(const SizedBox.shrink());
          await api.close();
          api = await SshControl.connect(
            profile,
            (_, fp) async => fp == fixture['fingerprint'],
          );
          await api.request({
            'method': 'save_config',
            'revision': saved['revision'],
            'content': policy['content'],
          });
          await api.historyVerifier.sync();
          final key = 'audit:checkpoint:${api.auditScope}';
          const storage = FlutterSecureStorage();
          final anchor = await storage.read(key: key);
          expect(anchor, isNotNull);
          await api.close();
          await remotePython(tamper);
          tampered = true;
          api = await SshControl.connect(
            profile,
            (_, fp) async => fp == fixture['fingerprint'],
          );
          await tester.pumpWidget(
            MaterialApp(
              home: Scaffold(body: HistoryPage(api: api)),
            ),
          );
          await visible(
            find.text(
              'Audit check failed. Previous phone checkpoint preserved.',
            ),
          );
          expect(await storage.read(key: key), anchor);
          await expectLater(
            api.request({
              'method': 'retry',
              'request_id': pending['request_id'],
            }),
            throwsA(anything),
          );
          expect(await storage.read(key: key), anchor);
          await remotePython(restore);
          tampered = false;
          await api.historyVerifier.sync();
          expect(
            api.historyVerifier.checkpoint!['sequence'],
            greaterThanOrEqualTo(jsonDecode(anchor!)['checkpoint']['sequence']),
          );
        } finally {
          if (tampered) await remotePython(restore);
          await tester.pumpWidget(const SizedBox.shrink());
          session?.close();
          caller.close();
          management.close();
          await api.close();
          await tester.pump(const Duration(seconds: 2));
        }
      },
      timeout: const Timeout(Duration(minutes: 8)),
    );
  }
}
