import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/audit.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/history.dart';

class MemoryAuditStorage implements AuditStorage {
  final values = <String, String>{};
  bool fail = false;
  @override
  Future<String?> read(String key) async => values[key];
  @override
  Future<void> write(String key, String value) async {
    if (fail) throw StateError('Storage unavailable');
    values[key] = value;
  }
}

Map<String, dynamic> auditFixture() =>
    jsonDecode(File('../testdata/audit-v1.json').readAsStringSync())
        as Map<String, dynamic>;
Map<String, dynamic> copy(Map<String, dynamic> value) =>
    jsonDecode(jsonEncode(value)) as Map<String, dynamic>;

void appendEvent(
  Map<String, dynamic> bundle, {
  String action = 'daemon_stopped',
  Map<String, dynamic> detail = const {},
}) {
  final checkpoint = bundle['checkpoint'] as Map;
  final row = <String, dynamic>{
    'sequence': (checkpoint['sequence'] as int) + 1,
    'time_unix_ms': 1800000001001,
    'request_id': null,
    'action': action,
    'detail': detail,
    'category': 'management',
  };
  final payload = jsonEncode(row);
  row['previous_hash'] = checkpoint['hash'];
  row['hash_payload'] = payload;
  row['hash'] = auditEventHash(
    checkpoint['log_id'] as String,
    checkpoint['hash'] as String,
    payload,
  );
  (bundle['events'] as List).add(row);
  checkpoint['sequence'] = row['sequence'];
  checkpoint['hash'] = row['hash'];
  bundle['range']['through'] = row['sequence'];
}

void rehash(Map<String, dynamic> bundle) {
  final logId = bundle['checkpoint']['log_id'] as String;
  var previous = auditGenesis(logId);
  for (final row in bundle['events'] as List) {
    final material = {
      for (final field in [
        'sequence',
        'time_unix_ms',
        'request_id',
        'action',
        'detail',
        'category',
      ])
        field: row[field],
    };
    final stored = row['hash_payload'] as String;
    final payload = auditEqual(jsonDecode(stored), material)
        ? stored
        : jsonEncode(material);
    row['previous_hash'] = previous;
    row['hash_payload'] = payload;
    previous = auditEventHash(logId, previous, payload);
    row['hash'] = previous;
  }
  bundle['checkpoint']['hash'] = previous;
}

class AuditControl implements ControlApi, AuditPeer {
  AuditControl(this.bundle, this.storage, this.auditScope) {
    historyVerifier = AuditVerifier(this, auditScope, storage: storage);
  }
  Map<String, dynamic> bundle;
  final MemoryAuditStorage storage;
  @override
  final String auditScope;
  @override
  late final AuditVerifier historyVerifier;
  bool missingPage = false, online = true, legacy = false;
  int pageSize = 2;
  Completer<void>? holdSnapshot;
  final calls = <Map<String, dynamic>>[];
  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    calls.add(body);
    switch (body['method']) {
      case 'audit_snapshot':
        await holdSnapshot?.future;
        if (legacy) throw StateError('invalid control request');
        return {
          'checkpoint': copy(bundle['checkpoint'] as Map<String, dynamic>),
          'legacy_through_sequence': bundle['legacy_through_sequence'],
          'chain_version': 1,
          'daemon_online': online,
        };
      case 'audit_page':
        final rows = (bundle['events'] as List)
            .cast<Map<String, dynamic>>()
            .where(
              (e) =>
                  (e['sequence'] as int) > (body['after'] as int) &&
                  (e['sequence'] as int) <= (body['through'] as int),
            )
            .take(pageSize)
            .map(copy)
            .toList();
        return {
          'actions': missingPage ? [] : rows,
          'through': body['through'],
          'next_after':
              rows.isNotEmpty && rows.last['sequence'] != body['through']
              ? rows.last['sequence']
              : null,
        };
      case 'actions':
        final rows = (bundle['events'] as List)
            .cast<Map<String, dynamic>>()
            .reversed
            .where((e) {
              if (body['include_reads'] == false && e['category'] == 'read') {
                return false;
              }
              if (body['subject_id'] != null &&
                  e['request_id'] != body['subject_id'] &&
                  e['detail']['challenge_id'] != body['subject_id']) {
                return false;
              }
              return body['before'] == null ||
                  (e['sequence'] as int) < (body['before'] as int);
            })
            .take(body['limit'] as int? ?? 30)
            .map(copy)
            .toList();
        return {'actions': rows, 'next_before': null};
      case 'history':
        return {'requests': [], 'next_before': null};
      case 'request_detail':
        final received = bundle['events'][0]['detail'] as Map;
        return {
          'request': {
            'request_id': 'request-1',
            'input': received['input'],
            'principal': received['principal'],
            'retry_of': null,
            'submitted_by': received['actor'],
            'reviewed_by': bundle['events'][4]['detail']['actor'],
            'command': received['input']['command'],
            'status': 'completed',
            'reason': 'Exited with status 0',
            'created_unix_ms': 0,
            'updated_unix_ms': 1,
          },
          'actions': (bundle['events'] as List)
              .cast<Map<String, dynamic>>()
              .where((e) => e['request_id'] == 'request-1')
              .toList()
              .reversed
              .toList(),
          'next_before': null,
        };
      default:
        throw StateError('Unexpected request ${body['method']}');
    }
  }
}

void main() {
  test('strict signature checks reject weak keys, weak R and unreduced S', () {
    final vectors =
        jsonDecode(
              File('../testdata/audit-ed25519-strict.json').readAsStringSync(),
            )
            as Map;
    final message = Uint8List.fromList(
      utf8.encode(vectors['message'] as String),
    );
    final key = auditUnhex(vectors['public_key'] as String, 32);
    for (final point in vectors['weak_points'] as List) {
      expect(
        () => verifyAuditSignature(
          auditUnhex(point as String, 32),
          auditUnhex("01${'00' * 63}", 64),
          message,
        ),
        throwsStateError,
      );
    }
    for (final field in ['weak_r', 'noncanonical_s']) {
      expect(
        () => verifyAuditSignature(
          key,
          auditUnhex(vectors[field] as String, 64),
          message,
        ),
        throwsStateError,
      );
    }
  });

  test('independent signature vector and complete paginated export', () async {
    final storage = MemoryAuditStorage();
    final api = AuditControl(auditFixture(), storage, 'vector');
    await api.historyVerifier.sync();
    expect(api.historyVerifier.events.length, 6);
    expect(api.historyVerifier.firstObservation, true);
    api.historyVerifier.verifyDisplayed(
      api.bundle['events'][2] as Map<String, dynamic>,
    );
    final exported = await api.historyVerifier.export(AuditDevice(storage));
    expect(exported['range'], {'after': 0, 'through': 6});
    expect(exported['events'], api.bundle['events']);
    expect(api.calls.where((c) => c['method'] == 'audit_page').length, 3);
  });

  test(
    'a legacy session discovers an upgrade and cannot bypass a later downgrade',
    () async {
      final storage = MemoryAuditStorage();
      final api = AuditControl(auditFixture(), storage, 'version-changes')
        ..legacy = true;
      final device = AuditDevice(storage);
      final body = {
        'method': 'resolve',
        'approval_id': 'approval-1',
        'approve': true,
      };
      expect(
        await prepareAuditedRequest(api.historyVerifier, device, body),
        body,
      );
      expect(storage.values, isEmpty);
      api.legacy = false;
      final prepared = await prepareAuditedRequest(
        api.historyVerifier,
        device,
        body,
      );
      expect(prepared['actor'], isA<Map>());
      final anchor = storage.values['audit:checkpoint:version-changes'];
      api.legacy = true;
      await expectLater(
        prepareAuditedRequest(api.historyVerifier, device, body),
        throwsStateError,
      );
      expect(storage.values['audit:checkpoint:version-changes'], anchor);
      expect(await device.receipts('version-changes'), hasLength(1));
      api.legacy = false;
      api.bundle['events'][5]['detail']['reason'] = 'changed history';
      rehash(api.bundle);
      await expectLater(
        prepareAuditedRequest(api.historyVerifier, device, body),
        throwsStateError,
      );
      expect(storage.values['audit:checkpoint:version-changes'], anchor);
      expect(await device.receipts('version-changes'), hasLength(1));
    },
  );

  test(
    'rewritten, missing, rolled back and replaced history preserve the phone anchor',
    () async {
      for (final change in [
        'bytes',
        'recomputed',
        'missing',
        'rollback',
        'replacement',
        'migration',
      ]) {
        final storage = MemoryAuditStorage();
        final api = AuditControl(auditFixture(), storage, change);
        await api.historyVerifier.sync();
        final preserved = storage.values['audit:checkpoint:$change'];
        switch (change) {
          case 'bytes':
            api.bundle['events'][5]['detail']['reason'] = 'altered';
          case 'recomputed':
            api.bundle['events'][5]['detail']['reason'] = 'altered';
            rehash(api.bundle);
          case 'missing':
            api.missingPage = true;
          case 'rollback':
            api.bundle['checkpoint']['sequence'] = 5;
          case 'replacement':
            api.bundle['checkpoint']['log_id'] = 'different log';
          case 'migration':
            api.bundle['legacy_through_sequence'] = 1;
        }
        final reopened = AuditVerifier(api, change, storage: storage);
        await expectLater(reopened.sync(), throwsA(anything));
        expect(storage.values['audit:checkpoint:$change'], preserved);
      }
    },
  );

  test(
    'a recomputed forged decision or actor cannot pass a fresh baseline',
    () async {
      for (final change in [
        'signature',
        'weak_key',
        'actor',
        'approval',
        'gap',
      ]) {
        final bundle = auditFixture();
        switch (change) {
          case 'signature':
            bundle['events'][2]['detail']['proof']['signature'] = '00' * 64;
          case 'weak_key':
            final key = "01${'00' * 31}";
            final fingerprint =
                'ed25519:SHA256:${base64Encode(sha256.convert(auditUnhex(key, 32)).bytes).replaceAll('=', '')}';
            bundle['events'][2]['detail']['proof']['public_key'] = key;
            bundle['events'][2]['detail']['proof']['signature'] =
                "01${'00' * 63}";
            bundle['events'][2]['detail']['actor']['device_signing_key'] =
                fingerprint;
            bundle['events'][4]['detail']['actor']['device_signing_key'] =
                fingerprint;
          case 'actor':
            bundle['events'][4]['detail']['actor']['device_signing_key'] =
                'impostor';
          case 'approval':
            bundle['events'][4]['detail']['approval_id'] = 'another approval';
          case 'gap':
            (bundle['events'] as List).removeAt(3);
        }
        rehash(bundle);
        final storage = MemoryAuditStorage();
        final api = AuditControl(bundle, storage, 'forged-$change');
        await expectLater(api.historyVerifier.sync(), throwsA(anything));
        expect(storage.values, isEmpty);
      }
    },
  );

  test(
    'a display rewrite and failed secure write cannot advance the checkpoint',
    () async {
      final storage = MemoryAuditStorage();
      final api = AuditControl(auditFixture(), storage, 'display');
      await api.historyVerifier.sync();
      final before = storage.values['audit:checkpoint:display'];
      final altered = copy(api.bundle['events'][5] as Map<String, dynamic>);
      altered['detail']['reason'] = 'forged display';
      expect(
        () => api.historyVerifier.verifyDisplayed(altered),
        throwsStateError,
      );
      final original = api.bundle['events'][5];
      api.bundle['events'][5] = altered;
      final second = AuditControl(api.bundle, storage, 'display');
      second.historyVerifier.events.addAll(api.historyVerifier.events);
      second.historyVerifier.checkpoint = copy(api.historyVerifier.checkpoint!);
      await expectLater(
        prepareAuditedRequest(second.historyVerifier, AuditDevice(storage), {
          'method': 'resolve',
          'approval_id': 'approval-1',
          'approve': true,
        }),
        throwsStateError,
      );
      expect(storage.values['audit:checkpoint:display'], before);
      expect(await AuditDevice(storage).receipts('display'), isEmpty);
      api.bundle['events'][5] = original;
      appendEvent(api.bundle);
      storage.fail = true;
      await expectLater(api.historyVerifier.sync(), throwsStateError);
      expect(api.historyVerifier.checkpoint!['sequence'], 6);
      expect(api.historyVerifier.events.length, 6);
      expect(storage.values['audit:checkpoint:display'], before);
      storage.fail = false;
      await api.historyVerifier.sync();
      expect(api.historyVerifier.checkpoint!['sequence'], 7);
    },
  );

  test(
    'concurrent connection verifiers cannot roll the phone checkpoint backwards',
    () async {
      final storage = MemoryAuditStorage();
      final first = AuditControl(auditFixture(), storage, 'concurrent');
      final newer = copy(first.bundle);
      appendEvent(newer);
      final second = AuditControl(newer, storage, 'concurrent');
      await Future.wait([
        first.historyVerifier.sync(),
        second.historyVerifier.sync(),
      ]);
      expect(
        jsonDecode(
          storage.values['audit:checkpoint:concurrent']!,
        )['checkpoint']['sequence'],
        7,
      );
      await expectLater(first.historyVerifier.sync(), throwsStateError);
      expect(
        jsonDecode(
          storage.values['audit:checkpoint:concurrent']!,
        )['checkpoint']['sequence'],
        7,
      );
    },
  );

  test(
    'local receipts precede sending, exclude answers and policy values, and expose unknown outcomes',
    () async {
      final storage = MemoryAuditStorage();
      final device = AuditDevice(storage);
      final api = AuditControl(auditFixture(), storage, 'receipts');
      await api.historyVerifier.sync();
      for (final body in [
        {
          'method': 'credential',
          'challenge_id': 'sudo',
          'password': 'private-password',
        },
        {
          'method': 'answer_interaction',
          'challenge_id': 'app',
          'values': {'secret': 'private-answer'},
        },
        {
          'method': 'save_config',
          'revision': 'old',
          'content': 'private-policy-value',
        },
      ]) {
        final proof = await device.sign(
          'receipts',
          api.historyVerifier.checkpoint!,
          body,
        );
        expect((await device.receipts('receipts')).last['proof'], proof);
      }
      final text = jsonEncode(await device.receipts('receipts'));
      for (final secret in [
        'private-password',
        'private-answer',
        'private-policy-value',
      ]) {
        expect(text, isNot(contains(secret)));
      }
      await api.historyVerifier.sync();
      expect(api.historyVerifier.unrecordedReceipts, 3);
      final exported = await api.historyVerifier.export(device);
      expect((exported['device_receipts'] as List).length, 3);
      final freshDevice = AuditDevice(storage);
      final again = await freshDevice.sign(
        'receipts',
        api.historyVerifier.checkpoint!,
        {'method': 'retry', 'request_id': 'old'},
      );
      expect(
        again['public_key'],
        (await device.receipts('receipts')).first['proof']['public_key'],
      );
    },
  );

  test(
    'concurrent verification failures return to each caller error zone',
    () async {
      final api = AuditControl(auditFixture(), MemoryAuditStorage(), 'zones');
      await api.historyVerifier.sync();
      api.bundle['checkpoint']['hash'] = '00' * 32;
      final hold = Completer<void>();
      api.holdSnapshot = hold;
      final failures = <Object>[];
      final completed = <Future<void>>[];
      for (var i = 0; i < 2; i++) {
        final done = Completer<void>();
        completed.add(done.future);
        runZonedGuarded(
          () async {
            try {
              await api.historyVerifier.sync();
              done.completeError(StateError('Altered checkpoint was accepted'));
            } catch (e) {
              done.complete();
            }
          },
          (e, stack) {
            failures.add(e);
            if (!done.isCompleted) done.completeError(e, stack);
          },
        );
      }
      hold.complete();
      await Future.wait(completed).timeout(const Duration(seconds: 2));
      expect(failures, isEmpty);
    },
  );

  test(
    'concurrent device receipts retain one identity and every signed intent',
    () async {
      final storage = MemoryAuditStorage();
      final device = AuditDevice(storage);
      final checkpoint = auditFixture()['checkpoint'] as Map<String, dynamic>;
      final proofs = await Future.wait(
        List.generate(
          20,
          (i) => device.sign('parallel-receipts', checkpoint, {
            'method': 'retry',
            'request_id': 'request-$i',
          }),
        ),
      );
      expect(proofs.map((p) => p['public_key']).toSet().length, 1);
      expect(proofs.map((p) => p['nonce']).toSet().length, 20);
      expect((await device.receipts('parallel-receipts')).length, 20);
      storage.fail = true;
      await expectLater(
        device.sign('parallel-receipts', checkpoint, {
          'method': 'retry',
          'request_id': 'failed',
        }),
        throwsStateError,
      );
      expect((await device.receipts('parallel-receipts')).length, 20);
      storage.fail = false;
      await device.sign('parallel-receipts', checkpoint, {
        'method': 'retry',
        'request_id': 'recovered',
      });
      expect((await device.receipts('parallel-receipts')).length, 21);
    },
  );

  testWidgets(
    'a receiver downgrade preserves an existing anchor and reports unverified legacy receivers',
    (tester) async {
      final storage = MemoryAuditStorage();
      final api = AuditControl(auditFixture(), storage, 'downgrade');
      await api.historyVerifier.sync();
      final anchor = storage.values['audit:checkpoint:downgrade'];
      api.legacy = true;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: HistoryPage(api: api)),
        ),
      );
      await tester.pumpAndSettle();
      expect(
        find.textContaining('Receiver stopped supporting audit verification'),
        findsOneWidget,
      );
      expect(storage.values['audit:checkpoint:downgrade'], anchor);
      await tester.pumpWidget(const SizedBox.shrink());
      final legacy = AuditControl(
        auditFixture(),
        MemoryAuditStorage(),
        'legacy',
      )..legacy = true;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: HistoryPage(api: legacy)),
        ),
      );
      await tester.pumpAndSettle();
      expect(
        find.text('Receiver has no audit verification. History is unverified.'),
        findsOneWidget,
      );
      expect(find.byTooltip('Export audit history'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('grouped request opens an attributed, chronological timeline', (
    tester,
  ) async {
    final api = AuditControl(auditFixture(), MemoryAuditStorage(), 'ui');
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: HistoryPage(api: api)),
      ),
    );
    await tester.pumpAndSettle();
    expect(
      find.textContaining('Activity matches phone checkpoint'),
      findsOneWidget,
    );
    await tester.tap(find.text('Activity'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Command finished'));
    await tester.pumpAndSettle();
    expect(find.text('Activity timeline'), findsOneWidget);
    expect(
      find.textContaining('Activity checked against the phone checkpoint'),
      findsOneWidget,
    );
    await tester.ensureVisible(find.text('Request details'));
    await tester.tap(find.text('Request details'));
    await tester.pumpAndSettle();
    expect(find.text('Recorded reviewer'), findsOneWidget);
    expect(find.textContaining('Device signature checked.'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'verification failure visibly preserves the old checkpoint and disables export',
    (tester) async {
      final storage = MemoryAuditStorage();
      final api = AuditControl(auditFixture(), storage, 'failure-ui');
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: HistoryPage(api: api)),
        ),
      );
      await tester.pumpAndSettle();
      api.bundle['checkpoint']['hash'] = '00' * 32;
      await tester.pump(const Duration(seconds: 2));
      await tester.pumpAndSettle();
      expect(
        find.text('Audit check failed. Previous phone checkpoint preserved.'),
        findsOneWidget,
      );
      final export = tester.widget<IconButton>(
        find.byWidgetPredicate(
          (w) => w is IconButton && w.tooltip == 'Export audit history',
        ),
      );
      expect(export.onPressed, isNull);
      expect(
        jsonDecode(
          storage.values['audit:checkpoint:failure-ui']!,
        )['checkpoint']['hash'],
        auditFixture()['checkpoint']['hash'],
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
