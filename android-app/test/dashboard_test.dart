import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';

class UnavailableControl implements ControlApi {
  final List<Map<String, dynamic>> calls = [];
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    calls.add(body);
    if (body['method'] == 'pending') throw StateError('Daemon is stopped');
    if (body['method'] == 'read_config') {
      return {
        'content': '[principals.demo]\ncwd = "/"\n',
        'revision': 'original',
        'path': 'config.toml',
      };
    }
    if (body['method'] == 'save_config') {
      throw StateError('configuration changed; reload before saving');
    }
    return {};
  }

  @override
  Future<void> close() async {}
}

void main() {
  testWidgets(
    'stopped daemon leaves policy accessible and stale-save errors preserve edits',
    (tester) async {
      final api = UnavailableControl();
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'test'),
        ),
      );
      await tester.pump();
      expect(find.textContaining('Daemon is stopped'), findsOneWidget);
      await tester.tap(find.text('Policy'));
      await tester.pumpAndSettle();
      const draft = '[principals.demo]\ncwd = "/tmp"\n';
      await tester.enterText(find.byType(TextField), draft);
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Save policy'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Save policy'));
      await tester.pumpAndSettle();
      expect(find.textContaining('configuration changed'), findsOneWidget);
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        draft,
      );
      expect(api.calls.last, {
        'method': 'save_config',
        'content': draft,
        'revision': 'original',
      });
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('connection editor validates an Iroh endpoint', (tester) async {
    await tester.pumpWidget(const MaterialApp(home: ProfilePage()));
    await tester.tap(find.text('Use Iroh transport'));
    await tester.pumpAndSettle();
    expect(find.text('Iroh endpoint ID'), findsOneWidget);
    await tester.ensureVisible(find.text('Save connection'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Save connection'));
    await tester.pumpAndSettle();
    expect(find.text('Required'), findsWidgets);
  });
}
