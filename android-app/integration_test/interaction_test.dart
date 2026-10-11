import 'dart:convert';
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
                '${original['content']}\n[credential_adapters.testapp]\nlabel = "Configured test application"\nprogram = ${jsonEncode(fixture['probe'])}\nargs = ["interaction"]\ncwd = "/"\n',
          });
          await api.request({
            'method': 'reload_config',
            'revision': saved['revision'],
          });
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
          await waitFor(find.text('Application status: ready'));
          final audit = jsonEncode(
            await api.request({'method': 'actions', 'limit': 100}),
          );
          expect(audit, contains('interaction_result'));
          expect(audit, contains('succeeded'));
          expect(audit, isNot(contains('test-application-password')));
          expect(audit, isNot(contains('test-user')));
        } finally {
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
