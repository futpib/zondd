import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/identities.dart';
import 'package:zondd_control/main.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;

  Future<void> waitFor(WidgetTester tester, Finder finder) async {
    for (var i = 0; i < 400 && finder.evaluate().isEmpty; i++) {
      await tester.pump(const Duration(milliseconds: 100));
    }
    expect(finder, findsOneWidget);
    await tester.pump(const Duration(milliseconds: 300));
  }

  for (final iroh in [false, true]) {
    testWidgets(
      'interactive authentication over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        const store = ProfileStore();
        final previous = await store.load();
        final identities = await IdentityStore().load();
        final base = Profile(
          name: 'Authentication test',
          host: fixture[iroh ? 'authEndpoint' : 'host'] as String,
          port: fixture['authPort'] as int,
          iroh: iroh,
          user: 'password',
          executable: fixture['executable'] as String,
          runtime: fixture['runtime'] as String,
          config: fixture['config'] as String,
        );
        final previousHost = await store.hostKey(base.hostIdentity);
        Future<void> open(Profile profile) async {
          await tester.pumpWidget(const SizedBox.shrink());
          await store.save([profile]);
          await tester.pumpWidget(const ZonddApp());
          await waitFor(tester, find.text(profile.name));
          await tester.tap(find.text(profile.name));
        }

        Future<void> answer(List<String> answers) async {
          final fields = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.byType(TextField),
          );
          expect(fields, findsNWidgets(answers.length));
          for (var i = 0; i < answers.length; i++) {
            await tester.enterText(fields.at(i), answers[i]);
          }
          await tester.tap(find.text('Continue'));
        }

        Future<void> connected() async {
          await waitFor(tester, find.text('All caught up'));
          expect(find.byType(AlertDialog), findsNothing);
          expect(
            (await store.load()).single.password,
            isNot('android test password'),
          );
          await tester.pageBack();
          await tester.pump(const Duration(seconds: 1));
        }

        try {
          await store.trust(
            base.hostIdentity,
            'ssh-ed25519 ${fixture['fingerprint']}',
          );
          // Quick connect must reach authentication without opening profile setup.
          await store.save([]);
          await IdentityStore().save([]);
          await tester.pumpWidget(const ZonddApp());
          await tester.pump(const Duration(seconds: 1));
          if (!iroh) await tester.tap(find.text('SSH'));
          await tester.enterText(
            find.widgetWithText(TextField, 'Target'),
            'password@${base.host}${iroh ? '' : ':${base.port}'}',
          );
          await tester.tap(find.text('Connect'));
          await waitFor(tester, find.text('SSH password'));
          await tester.tap(find.text('Cancel'));
          await waitFor(tester, find.text('Connect'));
          expect(await store.load(), isEmpty);
          // No stored identity or password: cancel, reconnect, and correct a typo.
          await open(base);
          await waitFor(tester, find.text('SSH password'));
          expect(
            tester
                .widget<TextField>(
                  find.descendant(
                    of: find.byType(AlertDialog),
                    matching: find.byType(TextField),
                  ),
                )
                .obscureText,
            isTrue,
          );
          await tester.tap(find.text('Cancel'));
          await waitFor(tester, find.text('Connect'));
          expect(find.byType(AlertDialog), findsNothing);
          await tester.tap(find.text(base.name));
          await waitFor(tester, find.text('SSH password'));
          await answer(['wrong password']);
          await waitFor(tester, find.text('Authentication failed. Try again.'));
          await answer(['android test password']);
          await connected();

          // A stale saved password must be used only once before asking again.
          await open(
            Profile.fromJson({...base.toJson(), 'password': 'outdated'}),
          );
          await waitFor(tester, find.text('Authentication failed. Try again.'));
          await answer(['android test password']);
          await connected();

          // A rejected key falls back to the server's multi-round challenges.
          await open(
            Profile.fromJson({
              ...base.toJson(),
              'user': 'interactive',
              'privateKey': fixture['key'],
            }),
          );
          await waitFor(tester, find.text('Server sign-in'));
          final fields = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.byType(TextField),
          );
          expect(tester.widget<TextField>(fields.at(0)).obscureText, isFalse);
          expect(tester.widget<TextField>(fields.at(1)).obscureText, isTrue);
          expect(
            find.text('Enter the test account and password.'),
            findsOneWidget,
          );
          await answer(['test account', 'android test password']);
          await waitFor(tester, find.text('Verification'));
          await answer(['123456']);
          await connected();
        } finally {
          await tester.pumpWidget(const SizedBox.shrink());
          await store.save(previous);
          await IdentityStore().save(identities);
          if (previousHost == null) {
            await store.forget(base.hostIdentity);
          } else {
            await store.trust(base.hostIdentity, previousHost);
          }
        }
      },
      timeout: const Timeout(Duration(minutes: 6)),
    );
  }
}
