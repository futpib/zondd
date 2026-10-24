import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zondd_control/control.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final fixture =
      jsonDecode(const String.fromEnvironment('ZONDD_FIXTURE'))
          as Map<String, dynamic>;
  for (final iroh in [false, true]) {
    testWidgets('reports installed app version over ${iroh ? 'Iroh' : 'SSH'}', (
      tester,
    ) async {
      final api = await SshControl.connect(
        Profile(
          name: 'Client version',
          host: fixture[iroh ? 'endpoint' : 'host'],
          port: fixture['port'],
          user: fixture['user'],
          iroh: iroh,
          privateKey: fixture['key'],
          executable: fixture['executable'],
          runtime: fixture['runtime'],
          config: fixture['config'],
        ),
        (_, fingerprint) async => fingerprint == fixture['fingerprint'],
      );
      try {
        expect((await api.request({'method': 'status'}))['type'], 'status');
        final snapshot = await api.request({'method': 'audit_snapshot'});
        expect(snapshot['type'], 'audit_snapshot');
        expect(
          (await api.request({
            'method': 'audit_page',
            'after': 0,
            'through': snapshot['checkpoint']['sequence'],
          }))['type'],
          'audit_page',
        );
      } finally {
        await api.close();
      }
    });
  }
}
