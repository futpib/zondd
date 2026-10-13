import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/identities.dart';
import 'package:zondd_control/keys_page.dart';
import 'package:zondd_control/main.dart';
import 'package:zondd_control/ui.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;
  for (final iroh in [false, true]) {
    testWidgets(
      'search saved lists, policy and older history over ${iroh ? 'Iroh' : 'SSH'}',
      (tester) async {
        tester.testTextInput.register();
        final profile = Profile(
          name: 'Search server',
          host: fixture[iroh ? 'endpoint' : 'host'],
          port: fixture['port'],
          user: fixture['user'],
          iroh: iroh,
          privateKey: fixture['key'],
          executable: fixture['executable'],
          runtime: fixture['runtime'],
          config: fixture['config'],
        );
        final api = await SshControl.connect(
          profile,
          (_, fp) async => fp == fixture['fingerprint'],
        );
        final caller = SSHClient(
          await SSHSocket.connect(fixture['host'], fixture['port']),
          username: fixture['user'],
          identities: SSHKeyPair.fromPem(fixture['callerKey']),
          onVerifyHostKey: (_, fp) => utf8.decode(fp) == fixture['fingerprint'],
        );
        const store = ProfileStore();
        final keys = IdentityStore();
        final oldProfiles = await store.load();
        final oldKeys = await keys.load();
        Future<void> settle() async {
          await tester.pump();
          await tester.pump(const Duration(milliseconds: 500));
        }

        Future<void> visible(Finder finder) async {
          for (var i = 0; i < 300 && finder.evaluate().isEmpty; i++) {
            await tester.pump(const Duration(milliseconds: 100));
          }
          expect(finder, findsWidgets);
          await tester.ensureVisible(finder.first);
          await settle();
        }

        Future<void> search(String label, String value) async {
          final field = find.widgetWithText(TextField, label);
          await visible(field);
          await tester.enterText(field, value);
          FocusManager.instance.primaryFocus?.unfocus();
          await settle();
        }

        Future<void> capture(String name) async {
          const port = String.fromEnvironment('CAPTURE_PORT');
          if (port.isEmpty || iroh) return;
          await settle();
          final socket = await Socket.connect('10.0.2.2', int.parse(port));
          try {
            socket.write('GET /$name HTTP/1.0\r\nHost: localhost\r\n\r\n');
            await socket.flush();
            expect(
              await utf8.decoder
                  .bind(socket)
                  .join()
                  .timeout(const Duration(seconds: 30)),
              contains('200 OK'),
            );
          } finally {
            socket.destroy();
          }
        }

        Future<void> app(Widget home) async {
          await tester.pumpWidget(const SizedBox.shrink());
          await tester.pumpWidget(
            MaterialApp(
              debugShowCheckedModeBanner: false,
              theme: appTheme(Brightness.dark),
              home: home,
            ),
          );
          await settle();
        }

        try {
          if (!iroh) {
            await keys.save([]);
            await keys.import('Search key', fixture['key']);
            await keys.generate('Other key');
            await app(const KeysPage());
            await search('Search SSH keys', 'SEARCH KEY');
            await visible(find.text('Search key'));
            expect(find.text('Other key'), findsNothing);
            await capture('01-search-keys');
            await search('Search SSH keys', 'no-such-key');
            await visible(find.text('No SSH keys match your search.'));
            await tester.tap(find.byTooltip('Clear search'));
            await visible(find.text('Other key'));
            await store.save([
              profile,
              Profile(
                name: 'Other server',
                host: 'example.invalid',
                user: 'other',
              ),
            ]);
            await app(const ConnectionsPage());
            await search('Search connections', 'SEARCH SERVER');
            await visible(find.text('Search server'));
            expect(find.text('Other server'), findsNothing);
            await capture('02-search-connections');
          }
          final marker = 'older-search-${iroh ? 'iroh' : 'ssh'}';
          for (var i = 0; i < 33; i++) {
            final session = await caller.execute('');
            try {
              session.stdin.add(
                Uint8List.fromList(
                  utf8.encode(
                    '${jsonEncode({
                      'version': 1,
                      'id': i,
                      'body': {
                        'method': 'run',
                        'command': {
                          'program': '/usr/bin/false',
                          'args': [i == 0 ? marker : 'recent-noise'],
                        },
                      },
                    })}\n',
                  ),
                ),
              );
              final response = await session.stdout
                  .cast<List<int>>()
                  .transform(utf8.decoder)
                  .transform(const LineSplitter())
                  .first;
              expect(jsonDecode(response)['body']['type'], 'rejected');
            } finally {
              session.close();
            }
          }
          await app(Dashboard(api: api, name: 'Search server'));
          await tester.tap(find.text('History'));
          await visible(find.text('Rejected · exec'));
          expect(find.textContaining(marker), findsNothing);
          await search('Search requests', marker.toUpperCase());
          await visible(find.textContaining(marker));
          expect(find.text('Rejected · exec'), findsOneWidget);
          expect(find.text('Load earlier'), findsNothing);
          await capture('03-search-older-requests');
          await tester.tap(find.text('Activity'));
          await visible(find.text('Group related events'));
          await tester.tap(find.text('Group related events'));
          await visible(find.text('Request submitted'));
          expect(find.byType(SelectableText), findsNothing);
          await capture('04-search-activity');
          await tester.tap(find.text('Request submitted'));
          await visible(find.textContaining(marker));
          await search('Search activity', 'no-such-history');
          await visible(find.text('No history matches your search.'));
          await tester.tap(find.text('Policy'));
          await visible(find.text('Search policy'));
          await search('Search policy', 'hello %s');
          await visible(find.text('greet'));
          expect(find.text('exec'), findsNothing);
          expect(find.textContaining('fixed_args:'), findsNothing);
          await capture('05-search-policy');
          await tester.tap(find.text('greet'));
          await visible(find.textContaining('fixed_args:'));
          await search('Search policy', 'no-such-policy');
          await visible(
            find.text('No callers or operations match your search.'),
          );
          await search('Search policy', 'hello %s');
          await visible(find.textContaining('fixed_args:'));
          await tester.tap(find.text('Edit TOML'));
          await visible(find.text('Configuration'));
          expect(
            tester.widget<TextField>(find.byType(TextField)).controller!.text,
            contains('[principals.exec]'),
          );
        } finally {
          await tester.pumpWidget(const SizedBox.shrink());
          caller.close();
          await api.close();
          await store.save(oldProfiles);
          await keys.save(oldKeys);
        }
      },
      timeout: const Timeout(Duration(minutes: 4)),
    );
  }
}
