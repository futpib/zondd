import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/identities.dart';
import 'package:zondd_control/keys_page.dart';

// Select the fixture key and approve access in the real provider UI when asked.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'provider-held key authenticates over SSH and Iroh',
    (tester) async {
      final fixture =
          jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
              as Map<String, dynamic>;
      final store = IdentityStore();
      final previous = await store.load();
      try {
        await store.save([]);
        await tester.pumpWidget(const MaterialApp(home: KeysPage()));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Add from OpenKeychain'));
        Identity? key;
        for (var i = 0; i < 600; i++) {
          await tester.pump(const Duration(milliseconds: 500));
          final keys = await store.load();
          if (keys.isNotEmpty) {
            key = keys.single;
            break;
          }
        }
        expect(
          key,
          isNotNull,
          reason: 'Select and authorize the fixture key in OpenKeychain',
        );
        expect(key!.externalKey, isNotNull);
        expect(key.pem, isEmpty);
        expect(key.passphrase, isEmpty);
        expect(find.text('Copy public key'), findsOneWidget);
        await tester.tap(find.text('Close'));
        await tester.pumpAndSettle();
        for (final iroh in [false, true]) {
          final profile = Profile(
            name: 'External key',
            host: fixture[iroh ? 'endpoint' : 'host'] as String,
            port: fixture['port'] as int,
            user: fixture['user'] as String,
            keyId: key.id,
            iroh: iroh,
            executable: fixture['executable'] as String,
            runtime: fixture['runtime'] as String,
            config: fixture['config'] as String,
          );
          final control = await SshControl.connect(profile, (
            _,
            fingerprint,
          ) async {
            expect(fingerprint, fixture['fingerprint']);
            return true;
          });
          try {
            final status = await control.request({'method': 'status'});
            expect(status['revision'], isNotEmpty, reason: '$status');
          } finally {
            await control.close();
          }
        }
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        await store.save(previous);
      }
    },
    timeout: const Timeout(Duration(minutes: 8)),
  );
}
