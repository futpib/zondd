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

  testWidgets(
    'host trust expires with the connection and cannot save a stale pin',
    (tester) async {
      const store = ProfileStore();
      final p = Profile(
        name: 'Trust timeout',
        host: fixture['host'],
        port: fixture['authPort'],
        user: 'password',
      );
      final previous = await store.load();
      final pin = await store.hostKey(p.hostIdentity);
      try {
        await store.save([p]);
        await store.forget(p.hostIdentity);
        await tester.pumpWidget(const ZonddApp());
        await waitFor(tester, find.text(p.name));
        await tester.tap(find.text(p.name));
        await waitFor(tester, find.text('Trust SSH host key?'));
        await tester.pump(const Duration(seconds: 125));
        expect(find.byType(AlertDialog), findsNothing);
        expect(await store.hostKey(p.hostIdentity), isNull);
        expect(find.textContaining('TimeoutException'), findsOneWidget);
        await tester.tap(find.text(p.name));
        await waitFor(tester, find.text('Trust SSH host key?'));
        await tester.tap(find.text('Trust'));
        await waitFor(tester, find.text('SSH password'));
        expect(
          await store.hostKey(p.hostIdentity),
          'ssh-ed25519 ${fixture['fingerprint']}',
        );
        await tester.tap(find.text('Cancel'));
        await waitFor(tester, find.text('Connect'));
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        await store.save(previous);
        if (pin == null) {
          await store.forget(p.hostIdentity);
        } else {
          await store.trust(p.hostIdentity, pin);
        }
      }
    },
    timeout: const Timeout(Duration(minutes: 4)),
  );

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
          await IdentityStore().import('Test identity', fixture['key']);
          await tester.pumpWidget(const ZonddApp());
          await tester.pump(const Duration(seconds: 1));
          await waitFor(tester, find.byType(DropdownButtonFormField<String>));
          await tester.tap(find.byType(DropdownButtonFormField<String>));
          await tester.pump(const Duration(milliseconds: 500));
          await tester.tap(find.text('Password / no SSH key').last);
          await tester.pump(const Duration(milliseconds: 500));
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
          // Editing an existing profile must preserve changes on Back.
          await tester.pumpWidget(const SizedBox.shrink());
          await store.save([base]);
          await tester.pumpWidget(const ZonddApp());
          await waitFor(tester, find.text(base.name));
          await tester.tap(find.byType(PopupMenuButton<String>));
          await waitFor(tester, find.text('Edit'));
          await tester.tap(find.text('Edit'));
          await waitFor(tester, find.text('Connection options'));
          await tester.enterText(
            find.widgetWithText(TextFormField, 'Display name (optional)'),
            'Edited name',
          );
          await tester.pump();
          await tester.pageBack();
          await waitFor(tester, find.text('Discard connection changes?'));
          await tester.tap(find.text('Keep editing'));
          await waitFor(tester, find.text('Edited name'));
          await tester.tap(find.text('Save connection'));
          await waitFor(tester, find.text('Connect'));
          await waitFor(tester, find.widgetWithText(ListTile, 'Edited name'));
          expect((await store.load()).single.name, 'Edited name');

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
          await waitFor(tester, find.text('All caught up'));
          // Reconnection must create a fresh prompt, preserve the dashboard on
          // cancellation, and reuse the saved host-key pin.
          await tester.tap(find.byTooltip('Reconnect'));
          await waitFor(tester, find.text('SSH password'));
          await tester.tap(find.text('Cancel'));
          await waitFor(
            tester,
            find.textContaining('Authentication cancelled'),
          );
          expect(find.byType(Dashboard), findsOneWidget);
          // Cancelling pauses automatic retries until reconnect is requested.
          final connection =
              tester.widget<Dashboard>(find.byType(Dashboard)).api
                  as ControlConnection;
          await tester.pump(const Duration(seconds: 3));
          expect(connection.disconnected, isTrue);
          expect(connection.reconnecting, isFalse);
          expect(find.byType(AlertDialog), findsNothing);
          await tester.tap(find.widgetWithText(TextButton, 'Reconnect'));
          await waitFor(tester, find.text('SSH password'));
          await answer(['android test password']);
          await connected();

          // A stale saved password must be used only once before asking again.
          await open(
            Profile.fromJson({...base.toJson(), 'password': 'outdated'}),
          );
          await waitFor(tester, find.text('Authentication failed. Try again.'));
          await answer(['android test password']);
          await connected();

          // Both keyless and rejected-key connections use the advertised method.
          for (final privateKey in ['', fixture['key']]) {
            await open(
              Profile.fromJson({
                ...base.toJson(),
                'user': 'interactive',
                'privateKey': privateKey,
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
          }

          // Password expiry uses the protocol's change request, including cancel.
          for (final cancel in [true, false]) {
            await open(Profile.fromJson({...base.toJson(), 'user': 'expired'}));
            await waitFor(tester, find.text('SSH password'));
            await answer(['android test password']);
            await waitFor(tester, find.text('Change SSH password'));
            expect(
              find.text('Your password expired. Choose a new password.'),
              findsOneWidget,
            );
            if (cancel) {
              await tester.tap(find.text('Cancel'));
              await waitFor(tester, find.text('Connect'));
            } else {
              await answer([
                'android test password',
                'new test password',
                'mismatch',
              ]);
              await waitFor(
                tester,
                find.text('The new passwords do not match.'),
              );
              await answer([
                'android test password',
                'new test password',
                'new test password',
              ]);
              await connected();
              expect((await store.load()).single.password, isEmpty);
            }
          }

          // Informational challenges are acknowledged immediately and remain
          // visible until the next challenge. Cancel closes the actual transport.
          for (final cancel in [true, false]) {
            await open(Profile.fromJson({...base.toJson(), 'user': 'push'}));
            await waitFor(tester, find.text('Push approval'));
            expect(
              find.text('Approve this login on your other device.'),
              findsOneWidget,
            );
            expect(find.text('Continue'), findsNothing);
            if (cancel) {
              await tester.tap(find.text('Cancel'));
              await waitFor(tester, find.text('Connect'));
              await tester.pump(const Duration(seconds: 5));
              expect(find.byType(AlertDialog), findsNothing);
            } else {
              await waitFor(tester, find.text('Verification'));
              expect(find.text('Push approval'), findsNothing);
              await answer(['123456']);
              await connected();
            }
          }
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
      timeout: const Timeout(Duration(minutes: 8)),
    );
  }
}
