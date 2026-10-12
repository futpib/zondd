import 'dart:convert';
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
      'application form delivers secrets privately over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        tester.testTextInput.register();
        final profile = Profile(
          name: 'Trusted test server',
          host: fixture[iroh ? 'endpoint' : 'host'],
          iroh: iroh,
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
        SSHClient? serviceConnection;
        SSHSession? service;
        final original = await api.request({'method': 'read_config'});
        Future<void> waitFor(Finder finder) async {
          for (var i = 0; i < 400 && finder.evaluate().isEmpty; i++) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(finder, findsOneWidget);
          await tester.ensureVisible(finder);
          await tester.pump(const Duration(milliseconds: 100));
        }

        try {
          final saved = await api.request({
            'method': 'save_config',
            'revision': original['revision'],
            'content':
                '${original['content']}\n[credential_recipients.testapp]\nlabel = "Configured test application"\nkey_sha256 = ${jsonEncode(fixture['credentialKeyDigest'])}\nfield_ids = ["username", "password"]\norigins = ["https://example.test"]\n',
          });
          await api.request({
            'method': 'reload_config',
            'revision': saved['revision'],
          });
          serviceConnection = SSHClient(
            await SSHSocket.connect(fixture['host'], fixture['port']),
            username: fixture['user'],
            identities: SSHKeyPair.fromPem(fixture['key']),
            onVerifyHostKey: (_, fingerprint) =>
                utf8.decode(fingerprint) == fixture['fingerprint'],
          );
          String quote(String value) => "'${value.replaceAll("'", "'\\''")}'";
          service = await serviceConnection.execute(
            [
              fixture['executable'],
              '--runtime-dir',
              fixture['runtime'],
              'credential-adapter',
              '--recipient',
              'testapp',
              '--key-file',
              fixture['credentialKeyFile'],
              '--origin',
              'https://example.test',
              '--',
              fixture['probe'],
              'interaction',
            ].cast<String>().map(quote).join(' '),
          );
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: profile.name),
            ),
          );
          await waitFor(find.text('Application input requested'));
          expect(
            find.text('Trusted test server · Configured test application'),
            findsOneWidget,
          );
          await tester.tap(find.text('Respond'));
          await waitFor(
            find.byKey(const ValueKey('interaction-field-username')),
          );
          await tester.enterText(
            find.byKey(const ValueKey('interaction-field-username')),
            'test-user',
          );
          await tester.enterText(
            find.byKey(const ValueKey('interaction-field-password')),
            'test-application-password',
          );
          final password = find.descendant(
            of: find.byKey(const ValueKey('interaction-field-password')),
            matching: find.byType(TextField),
          );
          expect(tester.widget<TextField>(password).obscureText, true);
          await tester.tap(find.text('Send response'));
          await waitFor(
            find.text('Response sent to the configured application.'),
          );
          await waitFor(find.text('Credential request: idle'));
          expect(find.text('Retry'), findsNothing);
          final audit = jsonEncode(
            await api.request({'method': 'actions', 'limit': 100}),
          );
          expect(audit, contains('interaction_result'));
          expect(audit, contains('succeeded'));
          expect(audit, isNot(contains('test-application-password')));
          expect(audit, isNot(contains('test-user')));
        } finally {
          service?.close();
          serviceConnection?.close();
          await tester.pumpWidget(const SizedBox.shrink());
          final latest = await api.request({'method': 'read_config'});
          final saved = await api.request({
            'method': 'save_config',
            'revision': latest['revision'],
            'content': original['content'],
          });
          await api.request({
            'method': 'reload_config',
            'revision': saved['revision'],
          });
          await api.close();
        }
      },
    );
  }
}
