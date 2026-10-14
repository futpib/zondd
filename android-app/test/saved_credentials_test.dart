import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/audit.dart';
import 'package:zondd_control/interactions.dart';
import 'package:zondd_control/saved_credentials.dart';
import 'package:zondd_control/saved_credentials_page.dart';
import 'package:zondd_control/sudo_password_dialog.dart';

Map<String, dynamic> application() => {
  'challenge_id': 'challenge-one',
  'expires_unix_ms': DateTime.now().millisecondsSinceEpoch + 60000,
  'recipient': {
    'name': 'folio-example',
    'label': 'Example account',
    'peer_uid': 1000,
    'peer_pid': 1,
    'session_id': 'first-session',
    'configuration_revision': 'registered-key-revision',
    'identity': 'private key',
    'origin': 'configured service',
  },
  'provider_origin': 'https://example.test',
  'prompt': 'Sign in',
  'fields': <Map<String, dynamic>>[
    {'id': 'username', 'label': 'Username', 'kind': 'text'},
    {'id': 'password', 'label': 'Password', 'kind': 'secret'},
    {'id': 'otp', 'label': 'Code', 'kind': 'otp'},
  ],
  'context': <String, dynamic>{'account': 'paper', 'purpose': 'Read history'},
};
Map<String, dynamic> sudo() => {
  'challenge_id': 'sudo-one',
  'request_id': 'job-one',
  'principal': 'default',
  'operation': 'system-upgrade',
  'prompt': '[sudo] password for alice:',
  'command': {
    'program': '/usr/bin/paru',
    'args': ['-Syu'],
  },
  'expires_unix_ms': DateTime.now().millisecondsSinceEpoch + 60000,
};

class MemoryVault implements CredentialVault {
  final entries = <String, SavedCredential>{};
  final values = <String, Map<String, String>>{};
  bool enrolled = true, cancelSave = false;
  Completer<Map<String, String>>? pendingUnlock;
  int unlocks = 0;
  CredentialLifetime? savedLifetime;
  @override
  Future<bool> available() async => enrolled;
  @override
  Future<List<SavedCredential>> list() async => entries.values.toList();
  @override
  Future<Map<String, String>> unlock(CredentialBinding binding) async {
    unlocks++;
    if (pendingUnlock != null) return pendingUnlock!.future;
    return Map<String, String>.from(values[binding.id]!);
  }

  @override
  Future<void> save(
    CredentialBinding binding,
    Map<String, String> supplied,
    CredentialLifetime lifetime,
  ) async {
    if (cancelSave) throw StateError('Cancelled');
    savedLifetime = lifetime;
    values[binding.id] = binding.select(supplied);
    entries[binding.id] = SavedCredential(
      binding.id,
      1,
      lifetime.seconds,
      binding.metadata,
    );
  }

  @override
  Future<void> remove(String id) async {
    entries.remove(id);
    values.remove(id);
  }

  @override
  Future<void> removeAll() async {
    entries.clear();
    values.clear();
  }
}

void main() {
  test(
    'application cache binds all stable receiver, recipient and auth context',
    () {
      final original = application();
      String? key(
        Map<String, dynamic> c, [
        String receiver = 'verified-host',
      ]) => CredentialBinding.application(receiver, 'VM', c)?.id;
      final id = key(original);
      expect(id, isNotNull);
      for (final change in <void Function(Map<String, dynamic>)>[
        (c) => c['recipient']['name'] = 'another-app',
        (c) => c['recipient']['label'] = 'Other configured recipient',
        (c) => c['recipient']['configuration_revision'] = 'new-key',
        (c) => c['recipient']['peer_uid'] = 1001,
        (c) => c['recipient']['origin'] = 'other origin',
        (c) => c['recipient']['future-auth-scope'] = 'another tenant',
        (c) => c['provider_origin'] = 'https://other.test',
        (c) => c['context']['account'] = 'live',
        (c) => c['context']['purpose'] = 'Withdraw',
        (c) => c['prompt'] = 'Different auth step',
        (c) => c['fields'][1]['id'] = 'other-password',
        (c) => c['fields'][1]['kind'] = 'text',
        (c) => c['fields'][1]['label'] = 'Different value',
      ]) {
        final changed = application();
        change(changed);
        expect(key(changed), isNot(id));
      }
      expect(key(original, 'different-host-key-or-user'), isNot(id));
      final next = application();
      next['challenge_id'] = 'next-challenge';
      next['recipient']['session_id'] = 'next-session';
      next['recipient']['peer_pid'] = 999;
      expect(key(next), id);
      next['context'] = {'purpose': 'Read history', 'account': 'paper'};
      expect(key(next), id);
      next['recipient'].remove('configuration_revision');
      expect(key(next), isNull);
      expect(CredentialBinding.application(null, 'VM', original), isNull);
      final imprecise = application();
      imprecise['context']['account'] = 18446744073709551615.0;
      expect(
        CredentialBinding.application('verified-host', 'VM', imprecise),
        isNull,
      );
      original['fields'].add({
        'id': 'account-mode',
        'kind': 'choice',
        'choices': ['paper', 'live'],
      });
      final choiceBinding = CredentialBinding.application(
        'verified-host',
        'VM',
        original,
      )!;
      expect(
        choiceBinding.forAnswers({'account-mode': 'paper'}).id,
        isNot(choiceBinding.forAnswers({'account-mode': 'live'}).id),
      );
    },
  );

  test(
    'sudo cache isolates verified host, unix user, runtime, config, caller and exact command',
    () {
      String key(Map<String, dynamic> c) =>
          CredentialBinding.sudo('verified-host', 'VM', c)!.id;
      final id = key(sudo());
      for (final change in <void Function(Map<String, dynamic>)>[
        (c) => c['principal'] = 'another-caller',
        (c) => c['operation'] = 'other-operation',
        (c) => c['command']['program'] = '/usr/bin/other',
        (c) => c['command']['args'] = ['-Syu', 'other-argument'],
        (c) => c['prompt'] = '[sudo] password for bob:',
      ]) {
        final changed = sudo();
        change(changed);
        expect(key(changed), isNot(id));
      }
      final next = sudo();
      next['request_id'] = 'next-job';
      next['challenge_id'] = 'next-challenge';
      expect(key(next), id);
      final profile = Profile(name: 'VM', host: 'localhost', user: 'alice');
      final scope = auditScopeFor(profile, 'fingerprint');
      for (final other in [
        Profile(name: 'VM', host: 'localhost', user: 'bob'),
        Profile(
          name: 'VM',
          host: 'localhost',
          user: 'alice',
          runtime: '/other/runtime',
        ),
        Profile(
          name: 'VM',
          host: 'localhost',
          user: 'alice',
          config: '/other/config',
        ),
      ]) {
        expect(auditScopeFor(other, 'fingerprint'), isNot(scope));
      }
      expect(auditScopeFor(profile, 'new-fingerprint'), isNot(scope));
      expect(
        credentialReceiverScope(scope, 'zondctl'),
        isNot(credentialReceiverScope(scope, '/other/helper')),
      );
    },
  );

  test(
    'OTPs, choices and unknown field kinds never enter saved answers or metadata',
    () {
      final c = application();
      c['fields'].addAll([
        {'id': 'security_code', 'kind': 'secret'},
        {'id': 'input-1', 'label': 'Verification code', 'kind': 'secret'},
        {'id': 'approval', 'kind': 'confirmation'},
        {'id': 'future', 'kind': 'unknown-token'},
      ]);
      final b = CredentialBinding.application('receiver', 'VM', c)!;
      expect(
        b.select({
          'username': 'alice',
          'password': 'secret',
          'otp': '123456',
          'security_code': '456',
          'approval': 'yes',
          'future': 'token',
        }),
        {'username': 'alice', 'password': 'secret'},
      );
      expect(jsonEncode(b.metadata), isNot(contains('secret')));
      c['fields'] = [
        {'id': 'otp', 'kind': 'otp'},
      ];
      expect(CredentialBinding.application('receiver', 'VM', c), isNull);
    },
  );

  testWidgets(
    'sudo offers timed saving by default and explicit biometric reuse',
    (tester) async {
      final c = sudo();
      final b = CredentialBinding.sudo('receiver', 'VM', c)!;
      final vault = MemoryVault();
      await vault.save(b, {
        'password': 'saved-password',
      }, CredentialLifetime.forever);
      await tester.pumpWidget(
        MaterialApp(
          home: SudoPasswordDialog(
            challenge: c,
            isCurrent: () => true,
            binding: b,
            vault: vault,
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(
        tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
        true,
      );
      expect(find.text('1 hour (default)'), findsOneWidget);
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        isEmpty,
      );
      expect(vault.unlocks, 0);
      await tester.tap(find.text('Use saved credentials'));
      await tester.pumpAndSettle();
      expect(vault.unlocks, 1);
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        'saved-password',
      );
      expect(
        tester.widget<TextField>(find.byType(TextField)).obscureText,
        true,
      );
      expect(
        tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
        false,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('withdrawal during biometric unlock discards answers', (
    tester,
  ) async {
    final c = sudo();
    final b = CredentialBinding.sudo('receiver', 'VM', c)!;
    final vault = MemoryVault();
    await vault.save(b, {'password': 'secret'}, CredentialLifetime.hour);
    vault.pendingUnlock = Completer();
    bool current = true;
    await tester.pumpWidget(
      MaterialApp(
        home: SudoPasswordDialog(
          challenge: c,
          isCurrent: () => current,
          binding: b,
          vault: vault,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Use saved credentials'));
    await tester.pump();
    current = false;
    final answers = {'password': 'secret'};
    vault.pendingUnlock!.complete(answers);
    await tester.pumpAndSettle();
    expect(answers, isEmpty);
    expect(
      tester.widget<TextField>(find.byType(TextField)).controller!.text,
      isEmpty,
    );
    expect(
      tester
          .widget<FilledButton>(
            find.widgetWithText(FilledButton, 'Send password'),
          )
          .onPressed,
      isNull,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('cancelled save keeps the form and never reports success', (
    tester,
  ) async {
    final c = sudo();
    final b = CredentialBinding.sudo('receiver', 'VM', c)!;
    final vault = MemoryVault()..cancelSave = true;
    await tester.pumpWidget(
      MaterialApp(
        home: SudoPasswordDialog(
          challenge: c,
          isCurrent: () => true,
          binding: b,
          vault: vault,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'new-secret');
    await tester.pump();
    await tester.tap(find.text('Send password'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Credentials were not saved'), findsOneWidget);
    expect(vault.entries, isEmpty);
    expect(find.byType(SudoPasswordDialog), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'changing a saved username clears its password and OTP remains blank',
    (tester) async {
      final c = application();
      final b = CredentialBinding.application('receiver', 'VM', c)!;
      final vault = MemoryVault();
      await vault.save(b, {
        'username': 'alice',
        'password': 'secret',
      }, CredentialLifetime.hour);
      await tester.pumpWidget(
        MaterialApp(
          home: InteractionDialog(
            challenge: c,
            server: 'VM',
            isCurrent: () => true,
            binding: b,
            vault: vault,
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Use saved credentials'));
      await tester.tap(find.text('Use saved credentials'));
      await tester.pumpAndSettle();
      TextField input(String id) => tester.widget<TextField>(
        find.descendant(
          of: find.byKey(ValueKey('interaction-field-$id')),
          matching: find.byType(TextField),
        ),
      );
      expect(input('password').controller!.text, 'secret');
      expect(input('otp').controller!.text, isEmpty);
      await tester.enterText(
        find.byKey(const ValueKey('interaction-field-username')),
        'bob',
      );
      expect(input('password').controller!.text, isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('saved credentials cannot replace a different entered username', (
    tester,
  ) async {
    final c = application();
    final b = CredentialBinding.application('receiver', 'VM', c)!;
    final vault = MemoryVault();
    await vault.save(b, {
      'username': 'alice',
      'password': 'secret',
    }, CredentialLifetime.hour);
    await tester.pumpWidget(
      MaterialApp(
        home: InteractionDialog(
          challenge: c,
          server: 'VM',
          isCurrent: () => true,
          binding: b,
          vault: vault,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const ValueKey('interaction-field-username')),
      'bob',
    );
    await tester.ensureVisible(find.text('Use saved credentials'));
    await tester.tap(find.text('Use saved credentials'));
    await tester.pumpAndSettle();
    expect(
      find.textContaining('do not match the entered account'),
      findsOneWidget,
    );
    final password = tester.widget<TextField>(
      find.descendant(
        of: find.byKey(const ValueKey('interaction-field-password')),
        matching: find.byType(TextField),
      ),
    );
    expect(password.controller!.text, isEmpty);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'future choice kinds bind selected accounts and clear reused passwords on edits',
    (tester) async {
      final c = application();
      c['fields'].add({
        'id': 'mode',
        'label': 'Account mode',
        'kind': 'future-choice',
        'choices': ['paper', 'live'],
      });
      final b = CredentialBinding.application('receiver', 'VM', c)!;
      final vault = MemoryVault();
      await vault.save(b.forAnswers({'mode': 'paper'}), {
        'username': 'alice',
        'password': 'secret',
      }, CredentialLifetime.hour);
      await tester.pumpWidget(
        MaterialApp(
          home: InteractionDialog(
            challenge: c,
            server: 'VM',
            isCurrent: () => true,
            binding: b,
            vault: vault,
          ),
        ),
      );
      await tester.pumpAndSettle();
      Future<void> choose(String value) async {
        final field = find.byKey(const ValueKey('interaction-field-mode'));
        await tester.ensureVisible(field);
        await tester.tap(field);
        await tester.pumpAndSettle();
        await tester.tap(find.text(value).last);
        await tester.pumpAndSettle();
      }

      await choose('paper');
      await tester.ensureVisible(find.text('Use saved credentials'));
      await tester.tap(find.text('Use saved credentials'));
      await tester.pumpAndSettle();
      final password = tester.widget<TextField>(
        find.descendant(
          of: find.byKey(const ValueKey('interaction-field-password')),
          matching: find.byType(TextField),
        ),
      );
      expect(password.controller!.text, 'secret');
      await choose('live');
      expect(password.controller!.text, isEmpty);
      expect(find.text('Use saved credentials'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'a backgrounded and resumed unlock still discards its late answer',
    (tester) async {
      final c = sudo();
      final b = CredentialBinding.sudo('receiver', 'VM', c)!;
      final vault = MemoryVault();
      await vault.save(b, {'password': 'secret'}, CredentialLifetime.hour);
      vault.pendingUnlock = Completer();
      await tester.pumpWidget(
        MaterialApp(
          home: SudoPasswordDialog(
            challenge: c,
            isCurrent: () => true,
            binding: b,
            vault: vault,
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Use saved credentials'));
      await tester.pump();
      for (final state in [
        AppLifecycleState.inactive,
        AppLifecycleState.hidden,
        AppLifecycleState.paused,
        AppLifecycleState.hidden,
        AppLifecycleState.inactive,
        AppLifecycleState.resumed,
      ]) {
        tester.binding.handleAppLifecycleStateChanged(state);
      }
      final answers = {'password': 'secret'};
      vault.pendingUnlock!.complete(answers);
      await tester.pumpAndSettle();
      expect(answers, isEmpty);
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        isEmpty,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'management lists metadata only and supports individual and all removal',
    (tester) async {
      final vault = MemoryVault();
      final first = CredentialBinding.sudo('receiver', 'VM', sudo())!;
      final second = CredentialBinding.application(
        'receiver',
        'VM',
        application(),
      )!;
      await vault.save(first, {
        'password': 'secret-one',
      }, CredentialLifetime.forever);
      await vault.save(second, {
        'password': 'secret-two',
      }, CredentialLifetime.hour);
      await tester.pumpWidget(
        MaterialApp(home: SavedCredentialsPage(vault: vault)),
      );
      await tester.pumpAndSettle();
      expect(find.textContaining('secret-one'), findsNothing);
      expect(find.textContaining('secret-two'), findsNothing);
      expect(find.textContaining('Forever'), findsOneWidget);
      await tester.tap(find.byTooltip('Remove saved credentials').first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Remove'));
      await tester.pumpAndSettle();
      expect(vault.entries.length, 1);
      await tester.tap(find.byTooltip('Remove all saved credentials'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Remove'));
      await tester.pumpAndSettle();
      expect(vault.entries, isEmpty);
      expect(find.text('No saved credentials'), findsOneWidget);
    },
  );
}
