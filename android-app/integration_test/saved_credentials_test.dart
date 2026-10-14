import 'package:flutter/material.dart';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/saved_credentials.dart';
import 'package:zondd_control/saved_credentials_page.dart';
import 'package:zondd_control/sudo_password_dialog.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'Android Keystore protects saving, repeated reuse, cancellation, removal and expiry',
    (tester) async {
      tester.testTextInput.register();
      const vault = AndroidCredentialVault();
      expect(
        await vault.available(),
        true,
        reason: 'Enroll fingerprint 1 on an isolated Android 11+ emulator.',
      );
      await vault.removeAll();
      final challenge = <String, dynamic>{
        'challenge_id': 'vault-test-one',
        'request_id': 'job-one',
        'principal': 'default',
        'operation': 'system-upgrade',
        'prompt': '[sudo] password for test-account:',
        'command': {
          'program': '/usr/bin/paru',
          'args': ['-Syu'],
        },
        'expires_unix_ms': DateTime.now().millisecondsSinceEpoch + 300000,
      };
      final binding = CredentialBinding.sudo(
        'verified-test-host-account-and-config',
        'Test VM',
        challenge,
      )!;
      String? response;
      Future<void> waitFor(bool Function() condition) async {
        for (var i = 0; i < 400 && !condition(); i++) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(condition(), true);
      }

      Future<void> open() async {
        await waitFor(() => find.byType(SudoPasswordDialog).evaluate().isEmpty);
        response = null;
        await tester.pumpWidget(
          MaterialApp(
            home: Builder(
              builder: (context) => TextButton(
                onPressed: () async {
                  response = await showDialog<String>(
                    context: context,
                    builder: (_) => SudoPasswordDialog(
                      challenge: challenge,
                      isCurrent: () => true,
                      binding: binding,
                    ),
                  );
                },
                child: const Text('Open credential prompt'),
              ),
            ),
          ),
        );
        await tester.tap(find.text('Open credential prompt'));
        await waitFor(
          () => find.byType(CheckboxListTile).evaluate().isNotEmpty,
        );
      }

      final signal = File('${Directory.systemTemp.path}/zond-vault-test-mode');
      final ready = File(
        '${Directory.systemTemp.path}/zond-vault-test-mode-ready',
      );
      debugPrint('CREDENTIAL_VAULT_SIGNAL=${signal.path}');
      Future<void> mode(String value) async {
        if (await ready.exists()) await ready.delete();
        await signal.writeAsString(value, flush: true);
        debugPrint('CREDENTIAL_VAULT_AUTH=$value');
        for (var i = 0; i < 600; i++) {
          if (await ready.exists() && await ready.readAsString() == value) {
            return;
          }
          await Future<void>.delayed(const Duration(milliseconds: 50));
        }
        fail('The biometric test driver did not acknowledge $value.');
      }

      try {
        await open();
        expect(find.text('1 hour (default)'), findsOneWidget);
        expect(
          tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
          true,
        );
        await tester.enterText(find.byType(TextField), 'test-vault-secret');
        await tester.pump();
        await mode('allow');
        await tester.tap(find.text('Send password'));
        await waitFor(() => response != null);
        expect(response, 'test-vault-secret');
        var record = (await vault.list()).single;
        expect(record.expires - record.created, 3600000);

        challenge['challenge_id'] = 'vault-test-two';
        challenge['request_id'] = 'job-two';
        await open();
        expect(
          tester.widget<TextField>(find.byType(TextField)).controller!.text,
          isEmpty,
        );
        await waitFor(
          () => find.text('Use saved credentials').evaluate().isNotEmpty,
        );
        await mode('allow');
        await tester.tap(find.text('Use saved credentials'));
        await waitFor(
          () => tester
              .widget<TextField>(find.byType(TextField))
              .controller!
              .text
              .isNotEmpty,
        );
        expect(
          tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
          false,
        );
        await tester.tap(find.text('Send password'));
        await waitFor(() => response != null);
        expect(response, 'test-vault-secret');

        final wrong = CredentialBinding.sudo(
          'other-verified-host',
          'Other VM',
          challenge,
        )!;
        await expectLater(
          vault.unlock(wrong),
          throwsA(
            isA<PlatformException>().having((e) => e.code, 'code', 'expired'),
          ),
        );
        await mode('cancel');
        await expectLater(
          vault.unlock(binding).timeout(const Duration(seconds: 20)),
          throwsA(
            isA<PlatformException>().having((e) => e.code, 'code', 'cancelled'),
          ),
        );
        await mode('allow');
        expect((await vault.unlock(binding))['password'], 'test-vault-secret');
        await mode('background');
        await expectLater(
          vault.unlock(binding).timeout(const Duration(seconds: 20)),
          throwsA(
            isA<PlatformException>().having((e) => e.code, 'code', 'cancelled'),
          ),
        );
        await mode('allow');
        await tester.pump(const Duration(seconds: 2));

        await open();
        await tester.enterText(find.byType(TextField), 'test-vault-forever');
        await tester.pump();
        await tester.tap(
          find.byType(DropdownButtonFormField<CredentialLifetime>),
        );
        await tester.pumpAndSettle();
        await tester.tap(find.text('Forever').last);
        await tester.pumpAndSettle();
        await mode('allow');
        await tester.tap(find.text('Send password'));
        await waitFor(() => response != null);
        record = (await vault.list()).single;
        expect(record.expires, 0);
        await tester.pumpWidget(
          const MaterialApp(home: SavedCredentialsPage()),
        );
        await tester.pumpAndSettle();
        expect(find.textContaining('test-vault-forever'), findsNothing);
        expect(find.textContaining('Forever'), findsOneWidget);
        await tester.tap(find.byTooltip('Remove saved credentials'));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Remove'));
        await tester.pumpAndSettle();
        expect(await vault.list(), isEmpty);
        await expectLater(
          vault.unlock(binding),
          throwsA(isA<PlatformException>()),
        );

        await mode('allow');
        await vault.save(binding, {
          'password': 'test-vault-expiring',
        }, CredentialLifetime.minutes15);
        await mode('expire');
        for (var i = 0; i < 200 && (await vault.list()).isNotEmpty; i++) {
          await tester.pump(const Duration(milliseconds: 200));
        }
        expect(await vault.list(), isEmpty);
        await expectLater(
          vault.unlock(binding),
          throwsA(
            isA<PlatformException>().having((e) => e.code, 'code', 'expired'),
          ),
        );
        await mode('restore');
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        await vault.removeAll();
        if (await signal.exists()) await signal.delete();
        if (await ready.exists()) await ready.delete();
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
