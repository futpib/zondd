import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/authentication.dart';
import 'package:zondd_control/connections.dart';
import 'package:zondd_control/control.dart';

void main() {
  testWidgets('server prompts preserve answers, echo and instructions', (
    tester,
  ) async {
    late AuthenticationDialog dialog;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) {
            dialog = AuthenticationDialog(context, 'user@server');
            return const Scaffold();
          },
        ),
      ),
    );
    final response = dialog.request(
      SSHUserInfoRequest('Sign in', 'Server instructions', [
        SSHUserInfoPrompt('Account', true),
        SSHUserInfoPrompt('Secret', false),
      ]),
      true,
    );
    await tester.pumpAndSettle();
    expect(find.text('user@server'), findsOneWidget);
    expect(find.text('Server instructions'), findsOneWidget);
    expect(find.text('Authentication failed. Try again.'), findsOneWidget);
    final fields = find.byType(TextField);
    expect(tester.widget<TextField>(fields.at(0)).obscureText, isFalse);
    expect(tester.widget<TextField>(fields.at(1)).obscureText, isTrue);
    await tester.enterText(fields.at(0), 'alice');
    await tester.enterText(fields.at(1), ' secret with spaces ');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    expect(await response, ['alice', ' secret with spaces ']);
    await tester.pumpAndSettle();
  });

  testWidgets('cancel, back, and connection failure dismiss authentication', (
    tester,
  ) async {
    late AuthenticationDialog dialog;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) {
            dialog = AuthenticationDialog(context, 'user@server');
            return const Scaffold();
          },
        ),
      ),
    );
    final request = SSHUserInfoRequest('', '', [
      SSHUserInfoPrompt('Password', false),
    ]);
    for (final exit in ['cancel', 'back', 'failure']) {
      final response = dialog.request(request, false);
      await tester.pumpAndSettle();
      if (exit == 'cancel') {
        await tester.tap(find.text('Cancel'));
      } else if (exit == 'back') {
        await tester.binding.handlePopRoute();
      } else {
        dialog.close();
      }
      expect(await response, isNull);
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsNothing);
    }
    expect(await dialog.request(request, false), isNull);
  });

  testWidgets(
    'password profile may omit a saved password and remain editable',
    (tester) async {
      FlutterSecureStorage.setMockInitialValues({});
      Profile? saved;
      final profile = Profile(name: 'Server', host: 'server', user: 'alice');
      await tester.pumpWidget(
        MaterialApp(
          home: Builder(
            builder: (context) {
              return Scaffold(
                body: TextButton(
                  onPressed: () async {
                    saved = await Navigator.of(context).push<Profile>(
                      MaterialPageRoute(
                        builder: (_) => ProfilePage(profile: profile),
                      ),
                    );
                  },
                  child: const Text('Edit'),
                ),
              );
            },
          ),
        ),
      );
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();
      expect(find.text('Ask when connecting'), findsOneWidget);
      await tester.tap(find.text('Save connection'));
      await tester.pumpAndSettle();
      expect(saved?.password, isEmpty);
      expect(saved?.keyId, isEmpty);
    },
  );
}
