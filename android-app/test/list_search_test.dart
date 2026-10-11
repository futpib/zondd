import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/connections.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/dashboard.dart';
import 'package:zondd_control/identities.dart';
import 'package:zondd_control/keys_page.dart';
import 'dashboard_test.dart' show EditableControl;

void main() {
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  testWidgets(
    'policy searches hidden fields and preserves expansion by entry',
    (tester) async {
      final api = EditableControl()
        ..content = '''
[principals.alpha]
cwd = "/home/alice/code"
operations = ["deploy"]
[principals.beta]
cwd = "/tmp"
[operations.deploy]
program = "/usr/bin/printf"
fixed_args = ["hidden-needle"]
decision = "allow"
''';
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'test'),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Policy'));
      await tester.pumpAndSettle();
      expect(find.textContaining('fixed_args:'), findsNothing);
      await tester.enterText(find.byType(TextField), ' HIDDEN-NEEDLE ');
      await tester.pumpAndSettle();
      expect(find.text('Callers · 0 of 2'), findsOneWidget);
      expect(find.text('Operations · 1 of 1'), findsOneWidget);
      expect(find.text('alpha'), findsNothing);
      await tester.scrollUntilVisible(
        find.text('deploy'),
        150,
        scrollable: find
            .descendant(
              of: find.byType(ListView),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      await tester.tap(find.text('deploy'));
      await tester.pumpAndSettle();
      expect(find.textContaining('fixed_args:'), findsOneWidget);
      await tester.enterText(find.byType(TextField), '/home/alice');
      await tester.pumpAndSettle();
      expect(find.text('alpha'), findsOneWidget);
      expect(find.text('deploy'), findsNothing);
      await tester.enterText(find.byType(TextField), 'hidden-needle');
      await tester.pumpAndSettle();
      expect(find.textContaining('fixed_args:'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'nothing-matches');
      await tester.pumpAndSettle();
      expect(
        find.text('No callers or operations match your search.'),
        findsOneWidget,
      );
      await tester.tap(find.byTooltip('Clear search'));
      await tester.pumpAndSettle();
      expect(find.text('Callers · 2'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'connections search public labels without matching saved secrets',
    (tester) async {
      await const ProfileStore().save([
        Profile(
          name: 'Desktop',
          user: 'alice',
          host: 'home.example',
          password: 'password-needle',
        ),
        Profile(name: 'Build VM', user: 'builder', host: 'ab' * 32, iroh: true),
      ]);
      await tester.pumpWidget(const MaterialApp(home: ConnectionsPage()));
      await tester.pumpAndSettle();
      final search = find.widgetWithText(TextField, 'Search connections');
      await tester.ensureVisible(search);
      for (final query in [' DESKTOP ', 'ALICE', 'home.example', 'ssh']) {
        await tester.enterText(search, query);
        await tester.pumpAndSettle();
        expect(find.text('Desktop'), findsOneWidget);
        expect(find.text('Build VM'), findsNothing);
      }
      await tester.enterText(search, 'iroh');
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(
        find.text('Build VM'),
        150,
        scrollable: find
            .descendant(
              of: find.byType(ListView),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      expect(find.text('Build VM'), findsOneWidget);
      expect(find.text('Desktop'), findsNothing);
      await tester.enterText(search, 'password-needle');
      await tester.pumpAndSettle();
      expect(find.text('No connections match your search.'), findsOneWidget);
      await tester.tap(find.byTooltip('Clear search'));
      await tester.pumpAndSettle();
      expect(find.text('Desktop'), findsOneWidget);
      await tester.scrollUntilVisible(
        find.text('Build VM'),
        150,
        scrollable: find
            .descendant(
              of: find.byType(ListView),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      expect(find.text('Build VM'), findsOneWidget);
    },
  );

  testWidgets(
    'SSH keys search names and fingerprints while private keys stay excluded',
    (tester) async {
      final store = IdentityStore();
      final phone = await store.generate('Phone');
      await store.generate('Work');
      await tester.pumpWidget(const MaterialApp(home: KeysPage()));
      await tester.pumpAndSettle();
      final search = find.widgetWithText(TextField, 'Search SSH keys');
      await tester.ensureVisible(search);
      for (final query in [' PHONE ', phone.fingerprint]) {
        await tester.enterText(search, query);
        await tester.pumpAndSettle();
        expect(find.text('Phone'), findsOneWidget);
        expect(find.text('Work'), findsNothing);
      }
      await tester.enterText(search, 'PRIVATE KEY');
      await tester.pumpAndSettle();
      expect(find.text('No SSH keys match your search.'), findsOneWidget);
      await tester.tap(find.byTooltip('Clear search'));
      await tester.pumpAndSettle();
      expect(find.text('Phone'), findsOneWidget);
      expect(find.text('Work'), findsOneWidget);
    },
  );
}
