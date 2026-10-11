import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/interactions.dart';

Map<String, dynamic> challenge() => {
  'challenge_id': 'one',
  'recipient': {
    'label': 'Configured Gateway',
    'adapter': 'ibkr',
    'session_id': 'session',
    'origin': 'configured service',
    'command': {'program': '/opt/adapter', 'args': []},
    'cwd': '/',
  },
  'prompt': 'Software-supplied prompt',
  'expires_unix_ms': DateTime.now().millisecondsSinceEpoch + 60000,
  'fields': [
    {'id': 'username', 'label': 'Username', 'kind': 'text'},
    {'id': 'password', 'label': 'Password', 'kind': 'secret'},
    {
      'id': 'future',
      'label': 'Future value',
      'kind': 'future-token',
      'required': false,
    },
    {
      'id': 'mode',
      'label': 'Mode',
      'kind': 'choice',
      'choices': ['paper', 'live'],
    },
  ],
  'context': {
    'future': {'scope': 'example.test'},
  },
};

void main() {
  testWidgets(
    'generic form separates context, masks secrets and reviews unknown fields as YAML',
    (tester) async {
      Map<String, String>? response;
      await tester.pumpWidget(
        MaterialApp(
          home: Builder(
            builder: (context) => TextButton(
              child: const Text('Open'),
              onPressed: () async {
                response = await showDialog<Map<String, String>>(
                  context: context,
                  builder: (_) => InteractionDialog(
                    challenge: challenge(),
                    server: 'Trusted server',
                    isCurrent: () => true,
                  ),
                );
              },
            ),
          ),
        ),
      );
      await tester.tap(find.text('Open'));
      await tester.pumpAndSettle();
      expect(find.text('Configured recipient'), findsOneWidget);
      expect(find.text('Trusted server · Configured Gateway'), findsOneWidget);
      expect(find.text('Application-supplied prompt'), findsOneWidget);
      final inputs = tester
          .widgetList<TextField>(find.byType(TextField))
          .toList();
      expect(inputs.map((w) => w.obscureText), [false, true, true]);
      await tester.tap(find.text('Send response'));
      await tester.pumpAndSettle();
      expect(find.text('Required'), findsWidgets);
      await tester.enterText(
        find.byKey(const ValueKey('interaction-field-username')),
        'user',
      );
      await tester.enterText(
        find.byKey(const ValueKey('interaction-field-password')),
        'private-value',
      );
      await tester.ensureVisible(
        find.byKey(const ValueKey('interaction-field-mode')),
      );
      await tester.tap(find.byKey(const ValueKey('interaction-field-mode')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('paper').last);
      await tester.pumpAndSettle();
      await tester.ensureVisible(
        find.text('Application-supplied details (YAML)'),
      );
      await tester.tap(find.text('Application-supplied details (YAML)'));
      await tester.pumpAndSettle();
      expect(find.textContaining('example.test'), findsOneWidget);
      expect(
        tester
            .widgetList<SelectableText>(find.byType(SelectableText))
            .any((w) => (w.data ?? '').contains('private-value')),
        isFalse,
      );
      await tester.tap(find.text('Send response'));
      await tester.pumpAndSettle();
      expect(response, {
        'username': 'user',
        'password': 'private-value',
        'future': '',
        'mode': 'paper',
      });
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('disconnection or withdrawal prevents sending a stale form', (
    tester,
  ) async {
    bool current = true;
    await tester.pumpWidget(
      MaterialApp(
        home: InteractionDialog(
          challenge: challenge(),
          server: 'server',
          isCurrent: () => current,
        ),
      ),
    );
    current = false;
    await tester.pump(const Duration(seconds: 1));
    expect(
      tester
          .widget<FilledButton>(
            find.widgetWithText(FilledButton, 'Send response'),
          )
          .onPressed,
      isNull,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
