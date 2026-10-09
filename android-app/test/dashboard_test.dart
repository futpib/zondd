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
  bool failApply = false;
  int saves = 0;
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
          'defaults':
              '[principals.default]\ncwd = "/"\nallow_exec = true\ndefault = "ask"\n',
          'revision': 'before',
          'path': 'config.toml',
        };
      case 'validate_config':
        throw StateError('cwd must be absolute');
      case 'reload_config':
        expect(body['revision'], 'after');
        if (failApply) throw StateError('Daemon unavailable');
        return {'revision': 'after', 'cancelled_approvals': 0};
      case 'save_config':
        saves++;
        content = body['content'] as String;
        return {'revision': 'after', 'apply_required': true};
      default:
        throw StateError('unexpected request');
    }
  }
}

void main() {
  testWidgets(
    'policy overview includes the built-in caller only when principals are omitted',
    (tester) async {
      for (final content in [
        '[approvals]\nenabled = false\n',
        '[principals]\n',
      ]) {
        final api = EditableControl()..content = content;
        await tester.pumpWidget(
          MaterialApp(
            home: Dashboard(api: api, name: 'test'),
          ),
        );
        await tester.pumpAndSettle();
        await tester.tap(find.text('Policy'));
        await tester.pumpAndSettle();
        expect(
          find.text(
            content.startsWith('[approvals]') ? 'Callers · 1' : 'Callers · 0',
          ),
          findsOneWidget,
        );
        expect(
          find.text(
            content.startsWith('[approvals]')
                ? 'Manual approvals disabled'
                : 'Manual approvals enabled',
          ),
          findsOneWidget,
        );
        await tester.pumpWidget(const SizedBox.shrink());
      }
    },
  );

  testWidgets('a saved policy can be applied again after a reload failure', (
    tester,
  ) async {
    final api = EditableControl()..failApply = true;
    await tester.pumpWidget(
      MaterialApp(
        home: Dashboard(api: api, name: 'test'),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Policy'));
    await tester.pumpAndSettle();
    expect(find.text('Manual approvals enabled'), findsOneWidget);
    await tester.tap(find.text('Edit TOML'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), '${api.content}\n# edited');
    await tester.tap(find.text('Save & apply'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Daemon unavailable'), findsOneWidget);
    await tester.tap(find.text('Overview'));
    await tester.pumpAndSettle();
    api.failApply = false;
    await tester.tap(find.text('Apply now'));
    await tester.pumpAndSettle();
    expect(find.text('Policy applied.'), findsOneWidget);
    expect(find.text('Apply now'), findsNothing);
    expect(api.saves, 1);
    await tester.pumpWidget(const SizedBox.shrink());
  });
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
    await tester.tap(find.text('Save & apply'));
    await tester.pumpAndSettle();
    expect(api.content, edited);
    expect(find.text('Policy applied.'), findsOneWidget);
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
      await tester.ensureVisible(find.text('Save & apply'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Save & apply'));
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
