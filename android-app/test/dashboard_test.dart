import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
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

class EditableControl implements ControlApi {
  String content = '[principals.demo]\ncwd = "/"\n';
  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    switch (body['method']) {
      case 'pending':
        return {'requests': []};
      case 'read_config':
        return {
          'content': content,
          'revision': 'before',
          'path': 'config.toml',
        };
      case 'validate_config':
        throw StateError('cwd must be absolute');
      case 'save_config':
        content = body['content'] as String;
        return {'revision': 'after', 'restart_required': true};
      default:
        throw StateError('unexpected request');
    }
  }
}

void main() {
  testWidgets('a corrected policy can be saved after a validation error', (
    tester,
  ) async {
    final api = EditableControl();
    await tester.pumpWidget(
      MaterialApp(
        home: Dashboard(api: api, name: 'test'),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Policy'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Edit TOML'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'invalid');
    await tester.tap(find.text('Validate'));
    await tester.pumpAndSettle();
    expect(find.textContaining('cwd must be absolute'), findsOneWidget);
    const edited = '[principals.demo]\ncwd = "/tmp"\n';
    await tester.enterText(find.byType(TextField), edited);
    await tester.tap(find.text('Save policy'));
    await tester.pumpAndSettle();
    expect(api.content, edited);
    expect(
      find.text('Saved. Restart zondd to apply this policy.'),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });
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
      await tester.tap(find.text('Edit TOML'));
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
    FlutterSecureStorage.setMockInitialValues({});
    await tester.pumpWidget(const MaterialApp(home: ProfilePage()));
    await tester.pumpAndSettle();
    expect(find.text('user@endpoint_id'), findsOneWidget);
    await tester.ensureVisible(find.text('Save connection'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Save connection'));
    await tester.pumpAndSettle();
    expect(find.text('Required'), findsWidgets);
  });

  test('connection targets preserve IPv6 and reject malformed addresses', () {
    expect(Target.parse('alice@example.org', false).port, 22);
    final ipv6 = Target.parse('ssh://alice@[2001:db8::1]:2222', false);
    expect(ipv6.user, 'alice');
    expect(ipv6.host, '2001:db8::1');
    expect(ipv6.port, 2222);
    expect(Target.parse('alice@${'AB' * 32}', true).host, 'ab' * 32);
    for (final input in [
      'host',
      'alice@host:0',
      'alice@host:65536',
      'alice@host/path',
      'alice:secret@host',
    ]) {
      expect(() => Target.parse(input, false), throwsFormatException);
    }
    expect(() => Target.parse('alice@invalid', true), throwsFormatException);
  });
}
