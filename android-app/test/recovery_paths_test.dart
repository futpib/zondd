import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:zondd_control/connections.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/dashboard.dart';
import 'package:zondd_control/history.dart';
import 'package:zondd_control/keys_page.dart';
import 'package:zondd_control/open_keychain.dart';

class PolicyState {
  String content = '[principals.demo]\ncwd = "/"\n';
  String revision = 'original';
}

class ReviewControl implements ControlApi {
  ReviewControl(this.state);
  final PolicyState state;
  bool lost = false, loseSaveReply = false;
  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    if (lost) throw const ConnectionLost();
    switch (body['method']) {
      case 'pending':
        return {'requests': []};
      case 'reload_config':
        return {'cancelled_approvals': 0};
      case 'request_detail':
        return {
          'request': {
            'request_id': '1',
            'status': 'completed',
            'principal': 'demo',
            'reason': 'allowed',
            'created_unix_ms': 0,
            'updated_unix_ms': 0,
            'input': {
              'command': {'program': 'true', 'args': []},
            },
            'command': {'program': 'true', 'args': []},
          },
          'actions': [],
        };
      case 'read_config':
        return {
          'content': state.content,
          'revision': state.revision,
          'path': 'config.toml',
        };
      case 'status':
        return {'revision': state.revision};
      case 'save_config':
        if (body['revision'] != state.revision) {
          throw StateError('configuration changed; reload before saving');
        }
        state.content = body['content'] as String;
        state.revision = 'saved';
        if (loseSaveReply) {
          lost = true;
          throw const ConnectionLost();
        }
        return {'revision': state.revision};
      default:
        return {};
    }
  }
}

class StalledDetailControl extends ReviewControl {
  StalledDetailControl() : super(PolicyState());
  final pending = Completer<Map<String, dynamic>>();
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) =>
      body['method'] == 'request_detail' ? pending.future : super.request(body);
}

void main() {
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));
  testWidgets(
    'detail screen recovers automatically and respects cancelled authentication',
    (tester) async {
      final old = ReviewControl(PolicyState());
      var reconnects = 0;
      final api = ControlConnection(old, () async {
        reconnects++;
        if (reconnects == 1) throw const AuthenticationCancelled();
        return ReviewControl(PolicyState());
      });
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'Server'),
        ),
      );
      await tester.pumpAndSettle();
      old.lost = true;
      final context = tester.element(find.byType(Dashboard));
      unawaited(
        Navigator.of(context).push(
          MaterialPageRoute<void>(
            builder: (_) => RequestDetailsPage(api: api, requestId: '1'),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(api.disconnected, isTrue);
      expect(
        find.text('Connection lost. Retrying automatically…'),
        findsOneWidget,
      );
      expect(find.byTooltip('Reconnect'), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();
      expect(api.disconnected, isTrue);
      expect(find.textContaining('Authentication cancelled'), findsOneWidget);
      await tester.pump(const Duration(minutes: 1));
      expect(reconnects, 1);
      await tester.tap(find.widgetWithText(TextButton, 'Reconnect'));
      await tester.pumpAndSettle();
      expect(reconnects, 2);
      expect(api.disconnected, isFalse);
      expect(find.text('Run again'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
      await api.close();
      api.dispose();
    },
  );
  testWidgets(
    'lost policy-save reply reconciles revision and preserves newer edits',
    (tester) async {
      final state = PolicyState();
      final old = ReviewControl(state)..loseSaveReply = true;
      final api = ControlConnection(old, () async => ReviewControl(state));
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'Server'),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Policy'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit TOML'));
      await tester.pumpAndSettle();
      const draft = '[principals.demo]\ncwd = "/tmp"\n';
      await tester.enterText(find.byType(TextField), draft);
      await tester.tap(find.text('Save & apply'));
      await tester.pumpAndSettle();
      expect(state.content, draft);
      expect(api.disconnected, isTrue);
      const newerDraft = '$draft# more edits after losing the save reply\n';
      await tester.enterText(find.byType(TextField), newerDraft);
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();
      expect(api.disconnected, isFalse);
      await tester.tap(find.text('Save & apply'));
      await tester.pumpAndSettle();
      expect(state.content, newerDraft);
      expect(find.text('Policy applied.'), findsOneWidget);
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        newerDraft,
      );
      await tester.pumpWidget(const SizedBox.shrink());
      await api.close();
      api.dispose();
    },
  );
  testWidgets(
    'unreadable profiles survive adding a connection alongside recovered profiles',
    (tester) async {
      await tester.binding.setSurfaceSize(const Size(1000, 1400));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final good = Profile(name: 'Keep me', host: 'host', user: 'alice');
      FlutterSecureStorage.setMockInitialValues({
        'profiles': jsonEncode([
          good.toJson(),
          {'name': 'Broken'},
        ]),
      });
      await tester.pumpWidget(const MaterialApp(home: ConnectionsPage()));
      await tester.pumpAndSettle();
      expect(find.text('Keep me'), findsOneWidget);
      await tester.ensureVisible(find.byTooltip('Add connection'));
      await tester.tap(find.byTooltip('Add connection'));
      await tester.pumpAndSettle();
      final replacement = Profile(name: 'New', host: 'new', user: 'alice');
      Navigator.of(tester.element(find.byType(ProfilePage))).pop(replacement);
      await tester.pumpAndSettle();
      final recovered = await const ProfileStore().read();
      expect(recovered.profiles.map((p) => p.name).toList(), [
        'Keep me',
        'New',
      ]);
      expect(recovered.unreadable, [
        {'name': 'Broken'},
      ]);
      await expectLater(const ProfileStore().load(), throwsStateError);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
  testWidgets('late detail fetch cannot overwrite the recovered screen', (
    tester,
  ) async {
    final old = StalledDetailControl();
    final api = ControlConnection(
      old,
      () async => ReviewControl(PolicyState()),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: RequestDetailsPage(api: api, requestId: '1'),
      ),
    );
    await tester.pump();
    await tester.tap(find.byTooltip('Reconnect'));
    await tester.pumpAndSettle();
    expect(find.text('Run again'), findsOneWidget);
    old.pending.completeError(const ConnectionLost());
    await tester.pumpAndSettle();
    expect(find.text('Run again'), findsOneWidget);
    expect(find.text('Connection lost. Retrying automatically…'), findsNothing);
    expect(api.disconnected, isFalse);
    await tester.pumpWidget(const SizedBox.shrink());
    await api.close();
    api.dispose();
  });

  testWidgets('invalid profile JSON blocks writes and can be retried', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(1000, 1400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    FlutterSecureStorage.setMockInitialValues({'profiles': '[broken'});
    await tester.pumpWidget(const MaterialApp(home: ConnectionsPage()));
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<IconButton>(find.widgetWithIcon(IconButton, Icons.add))
          .onPressed,
      isNull,
    );
    await expectLater(const ProfileStore().save([]), throwsFormatException);
    expect(await ProfileStore.storage.read(key: 'profiles'), '[broken');
    await ProfileStore.storage.write(key: 'profiles', value: '[]');
    await tester.tap(find.text('Retry loading connections'));
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<IconButton>(find.widgetWithIcon(IconButton, Icons.add))
          .onPressed,
      isNotNull,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'server policy conflict requires review and keeps draft on cancel',
    (tester) async {
      final state = PolicyState();
      final api = ControlConnection(
        ReviewControl(state),
        () async => ReviewControl(state),
      );
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'Server'),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Policy'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit TOML'));
      await tester.pumpAndSettle();
      const draft = '[principals.mine]';
      await tester.enterText(find.byType(TextField), draft);
      state.content = '[principals.other]';
      state.revision = 'other';
      await tester.tap(find.byTooltip('Reconnect'));
      await tester.pumpAndSettle();
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        draft,
      );
      await tester.tap(find.text('Save & apply'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 350));
      expect(find.text('Replace changed server policy?'), findsOneWidget);
      expect(find.text('[principals.other]'), findsOneWidget);
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(state.content, '[principals.other]');
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        draft,
      );
      await tester.tap(find.text('Save & apply'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 350));
      await tester.tap(find.text('Replace with draft'));
      await tester.pumpAndSettle();
      expect(state.content, draft);
      await tester.pumpWidget(const SizedBox.shrink());
      await api.close();
      api.dispose();
    },
  );

  testWidgets('leaving keys cancels pending import without adding a late key', (
    tester,
  ) async {
    const channel = MethodChannel(openKeychainChannelName);
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    final pending = Completer<Object?>();
    var cancelled = false;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'cancel') {
        cancelled = true;
        return null;
      }
      if (call.method == 'listProviders') {
        return [
          {'packageName': 'provider', 'label': 'Provider'},
        ];
      }
      return pending.future;
    });
    await tester.pumpWidget(const MaterialApp(home: KeysPage()));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Add from OpenKeychain'));
    await tester.pumpAndSettle();
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpAndSettle();
    expect(cancelled, isTrue);
    pending.complete({'keyId': '1', 'description': 'Key'});
    await tester.pumpAndSettle();
    expect(await ProfileStore.storage.read(key: 'identities'), isNull);
    messenger.setMockMethodCallHandler(channel, null);
  });

  for (final phase in ['listProviders', 'selectKey', 'getSshPublicKey']) {
    for (final timeout in [false, true]) {
      testWidgets(
        'provider $phase ${timeout ? 'deadline' : 'cancel'} permits retry and ignores late result',
        (tester) async {
          const channel = MethodChannel(openKeychainChannelName);
          final messenger =
              TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
          final waiting = Completer<Object?>();
          var hang = true, cancellations = 0;
          messenger.setMockMethodCallHandler(channel, (call) async {
            if (call.method == 'cancel') {
              cancellations++;
              return null;
            }
            if (hang && call.method == phase) return waiting.future;
            if (call.method == 'listProviders') {
              return [
                {'packageName': 'provider', 'label': 'Provider'},
              ];
            }
            if (call.method == 'selectKey') {
              return {'keyId': '1', 'description': 'Key'};
            }
            throw PlatformException(code: 'openkeychain_cancelled');
          });
          await tester.pumpWidget(const MaterialApp(home: KeysPage()));
          await tester.pumpAndSettle();
          await tester.tap(find.text('Add from OpenKeychain'));
          await tester.pumpAndSettle();
          if (timeout) {
            await tester.pump(const Duration(minutes: 2));
            await tester.pumpAndSettle();
            expect(find.textContaining('two minutes'), findsOneWidget);
          } else {
            await tester.tap(find.text('Cancel key import'));
            await tester.pumpAndSettle();
          }
          expect(cancellations, 1);
          expect(find.text('Add from OpenKeychain'), findsOneWidget);
          hang = false;
          await tester.tap(find.text('Add from OpenKeychain'));
          await tester.pumpAndSettle();
          expect(find.text('Add from OpenKeychain'), findsOneWidget);
          // A late successful selection must not advance the cancelled import.
          waiting.complete(
            phase == 'listProviders'
                ? [
                    {'packageName': 'provider', 'label': 'Provider'},
                  ]
                : phase == 'selectKey'
                ? {'keyId': '1', 'description': 'Key'}
                : 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5',
          );
          await tester.pumpAndSettle();
          expect(
            find.text('Add this public key to your server’s authorized_keys.'),
            findsNothing,
          );
          expect(await ProfileStore.storage.read(key: 'identities'), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
          messenger.setMockMethodCallHandler(channel, null);
        },
      );
    }
  }
}
