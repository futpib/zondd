import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/connections.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/identities.dart';
import 'package:zondd_control/keys_page.dart';
import 'package:zondd_control/qr_scan.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('camera QR imports fill every supported field without submitting', (
    tester,
  ) async {
    final store = IdentityStore();
    final previous = await store.load();
    Future<void> displayQr(String contents, {bool live = false}) async {
      final client = HttpClient();
      try {
        final request = await client.postUrl(
          Uri.parse(
            'http://10.0.2.2:${const String.fromEnvironment('QR_TEST_PORT')}/${live ? 'qr-live' : 'qr'}',
          ),
        );
        final bytes = utf8.encode(contents);
        request.contentLength = bytes.length;
        request.add(bytes);
        final response = await request.close();
        expect(response.statusCode, 200);
        await response.drain<void>();
      } finally {
        client.close(force: true);
      }
    }

    QrScanButton scanButton(Finder tooltip) => tester.widget<QrScanButton>(
      find.ancestor(of: tooltip, matching: find.byType(QrScanButton)),
    );

    Future<void> scan(String label, String contents, String expected) async {
      debugPrint('Scanning $label');
      await displayQr('');
      final button = find.byTooltip('Scan $label QR code');
      await tester.ensureVisible(button);
      await tester.tap(button);
      for (
        var i = 0;
        i < 30 && find.byType(QrScanPage).evaluate().isEmpty;
        i++
      ) {
        await tester.pump(const Duration(milliseconds: 100));
      }
      expect(find.byType(QrScanPage), findsOneWidget);
      await displayQr(contents, live: true);
      for (var i = 0; i < 300; i++) {
        await tester.pump(const Duration(milliseconds: 100));
        if (find.byType(QrScanPage).evaluate().isEmpty) break;
      }
      expect(
        find.byType(QrScanPage),
        findsNothing,
        reason: '$label scan did not finish',
      );
      await tester.pumpAndSettle();
      expect(scanButton(button).controller.text, expected);
    }

    try {
      final key = await store.generate('QR fixture');
      await store.save(previous);
      await tester.pumpWidget(const MaterialApp(home: ConnectionsPage()));
      await tester.pumpAndSettle();
      await displayQr('');
      final cancelButton = find.byTooltip('Scan target QR code');
      await tester.tap(cancelButton);
      await tester.pumpAndSettle();
      expect(find.byType(QrScanPage), findsOneWidget);
      await tester.pageBack();
      await tester.pumpAndSettle();
      expect(find.byType(QrScanPage), findsNothing);
      expect(scanButton(cancelButton).controller.text, '');
      final target = 'alice@${'ab' * 32}';
      await scan('target', ' $target ', target);
      expect(find.byType(ConnectionsPage), findsOneWidget);

      await tester.pumpWidget(
        MaterialApp(
          home: ProfilePage(
            profile: Profile(
              name: 'QR test',
              host: 'server',
              user: 'alice',
              password: 'old',
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await scan('target', ' alice@server:2222 ', 'alice@server:2222');
      await scan(
        'password',
        ' space-sensitive password ',
        ' space-sensitive password ',
      );
      await tester.tap(find.text('Iroh'));
      await tester.tap(find.text('Advanced'));
      await tester.pumpAndSettle();
      await scan(
        'relays',
        'https://relay.example\nhttps://backup.example',
        'https://relay.example\nhttps://backup.example',
      );

      await tester.pumpWidget(const MaterialApp(home: KeysPage()));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Import'));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Key name'),
        'QR imported',
      );
      await scan('private key', key.pem, key.pem);
      expect((await store.load()).length, previous.length);
      await scan(
        'passphrase',
        ' passphrase with spaces ',
        ' passphrase with spaces ',
      );
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Passphrase (if encrypted)'),
        '',
      );
      final save = find.widgetWithText(FilledButton, 'Import key');
      await tester.ensureVisible(save);
      await tester.tap(save);
      for (var i = 0; i < 100; i++) {
        await tester.pump(const Duration(milliseconds: 100));
        if (find.byType(AddKeyPage).evaluate().isEmpty) break;
      }
      expect(find.byType(AddKeyPage), findsNothing);
      final imported = (await store.load()).singleWhere(
        (identity) => identity.name == 'QR imported',
      );
      expect(imported.fingerprint, key.fingerprint);
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      await store.save(previous);
    }
  });
}
