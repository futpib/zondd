import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';
import 'package:zondd_control/identities.dart';
import 'package:zondd_control/ui.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final f =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;
  testWidgets('manage identities, connections, policy and approvals', (
    tester,
  ) async {
    const store = ProfileStore();
    final previous = await store.load();
    final previousKeys = await IdentityStore().load();
    final profile = Profile(
      name: 'Home server',
      host: f['host'],
      port: f['port'],
      user: f['user'],
      privateKey: f['key'],
      executable: f['executable'],
      runtime: f['runtime'],
      config: f['config'],
    );
    Future<void> settle() async {
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 350));
      await tester.pump(const Duration(milliseconds: 400));
    }

    Future<void> waitFor(Finder finder) async {
      for (var i = 0; i < 200 && finder.evaluate().isEmpty; i++) {
        await tester.pump(const Duration(milliseconds: 100));
      }
      if (finder.evaluate().isEmpty) {
        for (final error in tester.widgetList<ErrorBox>(
          find.byType(ErrorBox),
        )) {
          debugPrint('UI error: ${error.message}');
        }
      }
      expect(finder, findsWidgets);
      await settle();
    }

    Future<void> tap(Finder finder) async {
      await tester.ensureVisible(finder.first);
      await settle();
      await tester.tap(finder.first);
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
      debugPrint('Captured $name');
    }

    Future<void> home() async {
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pumpWidget(const ZonddApp());
      await settle();
    }

    Future<void> pending(bool approve) async {
      final socket = await SSHSocket.connect(f['host'], f['port']);
      final caller = SSHClient(
        socket,
        username: f['user'],
        identities: SSHKeyPair.fromPem(f['callerKey']),
        onVerifyHostKey: (_, fp) => utf8.decode(fp) == f['fingerprint'],
      );
      try {
        final session = await caller.execute('');
        final events = StreamIterator(
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
                'id': 7,
                'body': {
                  'method': 'run',
                  'command': {
                    'program': '/usr/bin/printf',
                    'args': ['%s', 'Hello from zondd'],
                  },
                },
              })}\n',
            ),
          ),
        );
        expect(await events.moveNext(), isTrue);
        await waitFor(find.text('Approve once'));
        if (approve) {
          await capture('14-pending-approval');
          await tap(find.text('Request details'));
          await capture('15-request-details');
          await tap(find.text('Request details'));
        }
        await tap(find.text(approve ? 'Approve once' : 'Reject'));
        expect(await events.moveNext(), isTrue);
        expect(
          jsonDecode(events.current)['body']['type'],
          approve ? 'completed' : 'rejected',
        );
        await capture(approve ? '16-approved' : '17-rejected');
        await events.cancel();
        session.close();
      } finally {
        caller.close();
      }
    }

    try {
      // Avoid racing injected edits against the emulator's real IME.
      tester.testTextInput.register();
      await store.save([]);
      await IdentityStore().save([]);
      await store.forget(profile.hostIdentity);
      await home();
      await capture('01-home');
      await tap(find.byTooltip('SSH keys'));
      await capture('02-keys-empty');
      await tap(find.text('Generate'));
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Key name'),
        'Phone',
      );
      await capture('03-generate-key');
      await tap(find.text('Generate Ed25519 key'));
      await waitFor(find.text('Copy public key'));
      await capture('04-public-key');
      await tap(find.text('Copy public key'));
      await Future<void>.delayed(const Duration(seconds: 5));
      await capture('05-keys');
      await tap(find.byIcon(Icons.more_vert));
      await tap(find.text('Delete'));
      await capture('30-delete-key');
      await tap(find.text('Cancel'));
      await tap(find.text('Import'));
      await capture('06-import-key');
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Key name'),
        'Home server key',
      );
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Private key'),
        f['key'],
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await settle();
      await tap(find.widgetWithText(FilledButton, 'Import key'));
      await waitFor(find.text('Copy public key'));
      await tap(find.text('Close'));
      expect((await IdentityStore().load()).length, 2);
      await tester.pageBack();
      await settle();
      await store.save([profile]);
      await home();
      await waitFor(find.text(profile.name));
      await tester.enterText(
        find.widgetWithText(TextField, 'Target'),
        'alice@home.example',
      );
      await tap(find.text('SSH'));
      await capture('07-saved-connections');
      await tap(find.byTooltip('Add connection'));
      await tap(find.text('SSH'));
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Target'),
        'alice@home.example:22',
      );
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Display name (optional)'),
        'Home server',
      );
      await capture('08-ssh-options');
      await tap(find.text('Iroh'));
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Target'),
        'alice@${'ab' * 32}',
      );
      await capture('09-iroh-options');
      await tap(find.text('Password'));
      await capture('10-password');
      await tap(find.text('Advanced'));
      await tester.ensureVisible(find.text('Relay URLs (optional)'));
      await capture('11-advanced');
      await tap(find.text('SSH'));
      await tap(find.text('SSH key'));
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Target'),
        '${f['user']}@${f['host']}:${f['port']}',
      );
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Display name (optional)'),
        'Created in UI',
      );
      await tap(find.byType(DropdownButtonFormField<String>));
      await tap(find.text('Home server key').last);
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Remote zondctl executable'),
        f['executable'],
      );
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Runtime directory (optional)'),
        f['runtime'],
      );
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Config file (optional)'),
        f['config'],
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await settle();
      await tap(find.text('Save connection'));
      await waitFor(find.text('Created in UI'));
      final created = (await store.load()).last;
      expect(created.host, f['host']);
      expect(created.port, f['port']);
      expect(created.runtime, f['runtime']);
      expect(created.config, f['config']);
      expect((await IdentityStore().get(created.keyId)).pem, f['key']);
      await store.save([profile]);
      await home();
      await waitFor(find.text(profile.name));
      await tap(find.text(profile.name));
      await waitFor(find.text('Trust SSH host key?'));
      await capture('12-trust-host');
      await tap(find.text('Trust'));
      await waitFor(find.text('All caught up'));
      await capture('13-queue-empty');
      await pending(true);
      await pending(false);
      await tap(find.text('History'));
      await waitFor(find.text('Denied · exec'));
      await capture('32-history');
      await tap(find.text('Denied · exec').first);
      await waitFor(find.text('Run again'));
      await capture('33-denied-request');
      await tap(find.text('Run again'));
      await waitFor(find.text('Approve once'));
      await capture('34-rerun-pending');
      await tap(find.text('Approve once'));
      await waitFor(find.text('Finished'));
      expect(find.text('Hello from zondd'), findsOneWidget);
      await capture('35-rerun-completed');
      await tester.scrollUntilVisible(
        find.text('approval granted'),
        300,
        scrollable: find.byType(Scrollable).last,
      );
      await settle();
      await capture('36-request-activity');
      await tester.pageBack();
      await settle();
      await tester.scrollUntilVisible(
        find.text('Activity'),
        -300,
        scrollable: find.byType(Scrollable).first,
      );
      await tap(find.text('Activity'));
      await waitFor(find.text('admin request'));
      await capture('37-daemon-activity');
      await tap(find.text('Policy'));
      await waitFor(find.textContaining('Manual approvals enabled'));
      await capture('18-policy');
      await tap(find.text('exec'));
      await capture('19-caller-policy');
      await tap(find.text('exec'));
      await tap(find.text('greet'));
      await capture('31-operation-policy');
      await tap(find.text('Edit TOML'));
      await waitFor(find.text('Configuration'));
      final controller = tester
          .widget<TextField>(find.byType(TextField).first)
          .controller!;
      final original = controller.text;
      expect(original, contains('[principals.exec]'));
      await capture('20-policy-editor');
      await tap(find.text('Validate'));
      await waitFor(find.text('Configuration is valid.'));
      await capture('21-policy-valid');
      await tester.enterText(
        find.byType(TextField).first,
        '[principals.demo]\ncwd = "relative-path"\n',
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await settle();
      await tap(find.text('Validate'));
      await waitFor(find.textContaining('cwd must be absolute'));
      await capture('22-invalid-policy');
      await tester.enterText(
        find.byType(TextField).first,
        '$original\n# Saved from the Android controller\n',
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await settle();
      await tap(find.text('Save & apply'));
      await waitFor(find.text('Policy applied.'));
      await capture('23-policy-saved');
      final saved = controller.text;
      await tester.enterText(
        find.byType(TextField).first,
        '$saved\n# Unsaved edit\n',
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await settle();
      await tap(find.byTooltip('Refresh'));
      await capture('24-discard-edits');
      await tap(find.text('Cancel'));
      await tester.enterText(find.byType(TextField).first, saved);
      FocusManager.instance.primaryFocus?.unfocus();
      await settle();
      await tap(find.text('Service'));
      await waitFor(find.text('LoadState'));
      await capture('25-service');
      await tester.pageBack();
      await settle();
      await tap(find.byIcon(Icons.more_vert));
      await capture('26-connection-menu');
      await tap(find.text('Forget host key'));
      await capture('27-forget-host-key');
      await tap(find.text('Cancel'));
      await tap(find.byIcon(Icons.more_vert));
      await tap(find.text('Delete'));
      await capture('28-delete-connection');
      await tap(find.text('Cancel'));
      await store.trust(
        profile.hostIdentity,
        'ssh-ed25519 SHA256:changed-demo-key',
      );
      await tap(find.text(profile.name));
      await waitFor(find.textContaining('SSH host key changed'));
      await capture('29-host-key-changed');
      await tester.pumpWidget(const SizedBox.shrink());
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      tester.testTextInput.unregister();
      await store.save(previous);
      await IdentityStore().save(previousKeys);
      await store.forget(profile.hostIdentity);
    }
  });
}
