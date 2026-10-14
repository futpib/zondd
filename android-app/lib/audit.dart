import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pinenacl/ed25519.dart' as ed25519;
import 'package:pinenacl/tweetnacl.dart' show TweetNaClExt;
import 'control.dart';
import 'transport.dart';

abstract interface class AuditPeer {
  String? get auditScope;
  AuditVerifier? get historyVerifier;
}

String auditScopeFor(Profile profile, String fingerprint) => sha256
    .convert(
      utf8.encode(
        jsonEncode([
          profile.hostIdentity,
          profile.user,
          fingerprint,
          profile.runtime,
          profile.config,
        ]),
      ),
    )
    .toString();

abstract interface class AuditStorage {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
}

class SecureAuditStorage implements AuditStorage {
  const SecureAuditStorage();
  static const storage = FlutterSecureStorage();
  @override
  Future<String?> read(String key) => storage.read(key: key);
  @override
  Future<void> write(String key, String value) =>
      storage.write(key: key, value: value);
}

String auditHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
Uint8List auditUnhex(String text, int length) {
  if (text.length != length * 2 || !RegExp(r'^[0-9a-f]+$').hasMatch(text)) {
    throw const FormatException('Invalid audit key or signature.');
  }
  return Uint8List.fromList([
    for (var i = 0; i < text.length; i += 2)
      int.parse(text.substring(i, i + 2), radix: 16),
  ]);
}

Map<String, dynamic> auditIntent(Map<String, dynamic> body) {
  final value = {...body}
    ..removeWhere(
      (key, value) =>
          value == null || ['version', 'actor', 'transport'].contains(key),
    );
  switch (value['method']) {
    case 'credential':
      if (!value.containsKey('provided')) {
        value['provided'] = value['password'] != null;
      }
      value.remove('password');
    case 'answer_interaction':
      if (!value.containsKey('provided')) {
        value['provided'] = value['values'] != null;
      }
      value.remove('values');
    case 'save_config':
    case 'validate_config':
      final content = value.remove('content') as String?;
      if (content != null) {
        value['new_revision'] = sha256.convert(utf8.encode(content)).toString();
      }
    case 'reload_config':
      value['method'] = 'reload';
    case 'history':
    case 'actions':
      value.remove('query');
  }
  return value;
}

bool auditableChange(Map<String, dynamic> body) =>
    const {
      'resolve',
      'resolve_rule',
      'revoke_rule',
      'credential',
      'answer_interaction',
      'retry',
      'save_config',
      'reload_config',
    }.contains(body['method']) ||
    (body['method'] == 'service' && body['action'] != 'status');

class AuditPreparationTimeout implements Exception {
  const AuditPreparationTimeout();
  @override
  String toString() =>
      'Preparing your action timed out. It was not sent. Try again.';
}

class AuditHistoryPaused implements Exception {
  const AuditHistoryPaused();
  @override
  String toString() =>
      'History verification paused while preparing a decision. Refresh to continue.';
}

class AuditIntegrityFailure extends StateError {
  AuditIntegrityFailure(super.message);
}

void _checkAuditEvent(String logId, Map<String, dynamic> event) {
  try {
    verifyAuditEvent(logId, event);
  } catch (error) {
    throw AuditIntegrityFailure('$error');
  }
}

Future<Map<String, dynamic>> prepareAuditedRequest(
  AuditVerifier verifier,
  AuditDevice device,
  Map<String, dynamic> body, {
  Duration timeout = const Duration(minutes: 1),
}) async {
  if (!auditableChange(body)) return body;
  var active = true;
  Future<Map<String, dynamic>> prepare() async {
    // Recheck every mutation: a receiver can change versions within one session.
    try {
      await verifier.sync(includeLegacy: false);
    } on StateError catch (e) {
      if (e.message != 'invalid control request') rethrow;
      if (await verifier.hasSavedCheckpoint()) {
        throw StateError(
          'Receiver stopped supporting audit verification. The phone checkpoint is preserved.',
        );
      }
      if (!active) throw const AuditPreparationTimeout();
      return body;
    }
    if (!active) throw const AuditPreparationTimeout();
    final proof = await device.sign(
      verifier.scope,
      Map<String, dynamic>.from(verifier.checkpoint!),
      body,
    );
    if (!active) throw const AuditPreparationTimeout();
    return {...body, 'actor': proof};
  }

  return prepare().timeout(
    timeout,
    onTimeout: () {
      active = false;
      throw const AuditPreparationTimeout();
    },
  );
}

class AuditDevice {
  AuditDevice(this.storage);
  final AuditStorage storage;
  ed25519.SigningKey? _key;
  Future<void> _tail = Future.value();
  Future<T> _serial<T>(Future<T> Function() action) async {
    final previous = _tail;
    final gate = Completer<void>();
    _tail = gate.future;
    await previous;
    try {
      return await action();
    } finally {
      gate.complete();
    }
  }

  Future<ed25519.SigningKey> _loadKey() async {
    final seed = await storage.read('audit:device-seed');
    if (seed != null) return ed25519.SigningKey.fromSeed(auditUnhex(seed, 32));
    final key = ed25519.SigningKey.generate();
    await storage.write('audit:device-seed', auditHex(key.seed.asTypedList));
    return key;
  }

  Future<Map<String, dynamic>> sign(
    String scope,
    Map<String, dynamic> checkpoint,
    Map<String, dynamic> body,
  ) => _serial(() async {
    final key = _key ??= await _loadKey();
    final random = Random.secure();
    final nonce = auditHex(List.generate(32, (_) => random.nextInt(256)));
    final payload = jsonEncode({
      'log_id': checkpoint['log_id'],
      'nonce': nonce,
      'checkpoint': checkpoint,
      'request': auditIntent(body),
    });
    final signature = key
        .sign(
          Uint8List.fromList(utf8.encode('zondd-audit-decision-v1\n$payload')),
        )
        .signature;
    final proof = {
      'public_key': auditHex(key.verifyKey.asTypedList),
      'nonce': nonce,
      'checkpoint': checkpoint,
      'payload': payload,
      'signature': auditHex(signature.asTypedList),
    };
    // Preserve signed intent before sending: a lost reply can hide a mutation.
    // Receipts contain decision metadata, never answers or complete policy files.
    {
      final indexKey = 'audit:receipts:$scope';
      final value = await storage.read(indexKey);
      final receipts = value == null ? <dynamic>[] : jsonDecode(value) as List;
      await storage.write(
        indexKey,
        jsonEncode([
          ...receipts,
          {
            'proof': proof,
            'created_unix_ms': DateTime.now().millisecondsSinceEpoch,
            'evidence': 'device_signed_intent',
          },
        ]),
      );
    }
    return proof;
  });

  Future<List<dynamic>> receipts(String scope) async {
    final value = await storage.read('audit:receipts:$scope');
    return value == null ? [] : jsonDecode(value) as List;
  }
}

bool auditEqual(dynamic a, dynamic b) {
  if (a is Map && b is Map) {
    return a.length == b.length &&
        a.keys.every((k) => b.containsKey(k) && auditEqual(a[k], b[k]));
  }
  if (a is List && b is List) {
    return a.length == b.length &&
        List.generate(a.length, (i) => i).every((i) => auditEqual(a[i], b[i]));
  }
  return a == b;
}

String auditGenesis(String logId) =>
    sha256.convert(utf8.encode('zondd-audit-genesis-v1\n$logId')).toString();
String auditEventHash(String logId, String previous, String payload) => sha256
    .convert(utf8.encode('zondd-audit-event-v1\n$logId\n$previous\n$payload'))
    .toString();

final _verifiedAuditSignatures = <String>{};

void verifyAuditSignature(
  Uint8List publicKey,
  Uint8List signature,
  Uint8List message,
) {
  BigInt littleEndian(List<int> bytes) {
    var value = BigInt.zero;
    for (final byte in bytes.reversed) {
      value = (value << 8) | BigInt.from(byte);
    }
    return value;
  }

  // TweetNaCl permits noncanonical scalars and weak points. Match the receiver's
  // strict Ed25519 checks using the library's point operations.
  final order =
      (BigInt.one << 252) +
      BigInt.parse('27742317777372353535851937790883648493');
  if (publicKey.length != 32 ||
      signature.length != 64 ||
      littleEndian(signature.sublist(32)) >= order) {
    throw StateError('Invalid audit signature scalar.');
  }
  final cacheKey = sha256.convert([
    ...publicKey,
    ...signature,
    ...message,
  ]).toString();
  if (_verifiedAuditSignatures.remove(cacheKey)) {
    _verifiedAuditSignatures.add(cacheKey);
    return;
  }
  if (Platform.isAndroid) {
    verifyNativeAuditSignature(publicKey, signature, message);
    _rememberAuditSignature(cacheKey);
    return;
  }
  final prime = (BigInt.one << 255) - BigInt.from(19);
  for (final point in [publicKey, signature.sublist(0, 32)]) {
    final y = Uint8List.fromList(point)..[31] &= 0x7f;
    if (littleEndian(y) >= prime) {
      throw StateError('Invalid audit signature point.');
    }
    var doubled = Uint8List.fromList(point);
    for (var i = 0; i < 3; i++) {
      final next = Uint8List(32);
      if (TweetNaClExt.crypto_point_add(next, doubled, doubled) != 0) {
        throw StateError('Invalid audit signature point.');
      }
      doubled = next;
    }
    doubled[31] &= 0x7f;
    if (doubled[0] == 1 && doubled.skip(1).every((byte) => byte == 0)) {
      throw StateError('Weak audit signature point.');
    }
  }
  ed25519.VerifyKey(
    publicKey,
  ).verify(signature: ed25519.Signature(signature), message: message);
  _rememberAuditSignature(cacheKey);
}

void _rememberAuditSignature(String cacheKey) {
  _verifiedAuditSignatures.add(cacheKey);
  if (_verifiedAuditSignatures.length > 4096) {
    _verifiedAuditSignatures.remove(_verifiedAuditSignatures.first);
  }
}

void verifyAuditEvent(String logId, Map<String, dynamic> event) {
  final payload = event['hash_payload'] as String;
  final material = {
    for (final key in [
      'sequence',
      'time_unix_ms',
      'request_id',
      'action',
      'detail',
      'category',
    ])
      key: event[key],
  };
  if (!auditEqual(jsonDecode(payload), material) ||
      auditEventHash(logId, event['previous_hash'] as String, payload) !=
          event['hash']) {
    throw StateError('History changed at event ${event['sequence']}.');
  }
  final detail = event['detail'] as Map;
  if (event['action'] == 'signed_decision') {
    final proof = detail['proof'] as Map;
    final intent = jsonDecode(proof['payload'] as String) as Map;
    final observed = proof['checkpoint'] as Map;
    auditUnhex(proof['nonce'] as String, 32);
    if (proof.length != 5 ||
        observed.length != 3 ||
        observed['log_id'] != logId ||
        !auditEqual(intent, {
          'log_id': logId,
          'nonce': proof['nonce'],
          'checkpoint': observed,
          'request': detail['request'],
        }) ||
        !auditEqual(
          detail['request'],
          auditIntent(Map<String, dynamic>.from(detail['request'] as Map)),
        )) {
      throw StateError(
        'Decision receipt does not match event ${event['sequence']}.',
      );
    }
    final key = ed25519.VerifyKey(
      auditUnhex(proof['public_key'] as String, 32),
    );
    verifyAuditSignature(
      key.asTypedList,
      auditUnhex(proof['signature'] as String, 64),
      Uint8List.fromList(
        utf8.encode('zondd-audit-decision-v1\n${proof['payload']}'),
      ),
    );
    final fingerprint =
        'ed25519:SHA256:${base64Encode(sha256.convert(key.asTypedList).bytes).replaceAll('=', '')}';
    if (detail['actor']?['device_signing_key'] != fingerprint ||
        detail['actor']?['device_key_evidence'] != 'signature_verified' ||
        detail['actor']?['receipt_id'] != proof['nonce']) {
      throw StateError('Decision actor does not match its signature.');
    }
  }
}

void verifyAuditBinding(
  Map<String, dynamic> event,
  Map<int, String> hashes,
  Map<String, Map<String, dynamic>> receipts,
) {
  final detail = event['detail'] as Map;
  final actor = detail['actor'] as Map?;
  if (event['action'] == 'signed_decision') {
    final proof = detail['proof'] as Map;
    final observed = proof['checkpoint'] as Map;
    if (hashes[observed['sequence']] != observed['hash']) {
      throw StateError('Signed decision checkpoint changed.');
    }
    final id = '${actor!['device_signing_key']}:${proof['nonce']}';
    if (receipts.containsKey(id)) {
      throw StateError('A decision receipt was reused.');
    }
    receipts[id] = Map<String, dynamic>.from(detail['request'] as Map);
  } else if (actor?['device_key_evidence'] == 'signature_verified') {
    final request =
        receipts['${actor!['device_signing_key']}:${actor['receipt_id']}'];
    if (request == null) {
      throw StateError('Event has no preceding signed decision.');
    }
    final expected = switch (event['action']) {
      'admin_request' => auditIntent(Map<String, dynamic>.from(detail)),
      'approval_granted' || 'approval_denied' => {
        'method': 'resolve',
        'approval_id': detail['approval_id'],
        'approve': event['action'] == 'approval_granted',
      },
      'credential_answered' => {
        'method': 'credential',
        'challenge_id': detail['challenge_id'],
        'provided': detail['provided'],
      },
      'interaction_decision' => {
        'method': 'answer_interaction',
        'challenge_id': detail['challenge_id'],
        'provided': detail['provided'],
      },
      'control.save_config_requested' => {
        'method': 'save_config',
        'revision': detail['revision'],
        'new_revision': detail['new_revision'],
      },
      _ => null,
    };
    if (expected != null && !auditEqual(request, expected)) {
      throw StateError('Event does not match its signed decision.');
    }
  }
}

class AuditVerifier {
  AuditVerifier(
    this.api,
    this.scope, {
    this.storage = const SecureAuditStorage(),
  });
  final ControlApi api;
  final String scope;
  final AuditStorage storage;
  final events = <int, Map<String, dynamic>>{};
  final _receipts = <String, Map<String, dynamic>>{};
  Map<String, dynamic>? checkpoint;
  int legacyThrough = 0;
  int unrecordedReceipts = 0;
  bool online = true, firstObservation = false;
  bool _includesLegacy = false;
  bool _checkingImportedHistory = false;
  static final _scopeTails = <String, Future<void>>{};
  static final _invalidatedScopes = <String>{};
  static final _legacyInvalidatedScopes = <String>{};
  static final _pendingDecisionChecks = <String, int>{};
  Future<bool> hasSavedCheckpoint() async =>
      await storage.read('audit:checkpoint:$scope') != null;
  Future<void> sync({bool includeLegacy = true}) async {
    // Gates only complete successfully. Verification errors belong to each
    // caller, even when UI work and a decision use different Dart error zones.
    final previous = _scopeTails[scope] ?? Future<void>.value();
    final gate = Completer<void>();
    _scopeTails[scope] = gate.future;
    if (!includeLegacy) {
      _pendingDecisionChecks[scope] = (_pendingDecisionChecks[scope] ?? 0) + 1;
    }
    await previous;
    _checkingImportedHistory = false;
    try {
      await _sync(includeLegacy: includeLegacy, allowPause: includeLegacy);
    } on AuditHistoryPaused {
      rethrow;
    } catch (error) {
      _invalidatedScopes.add(scope);
      if (_checkingImportedHistory && error is AuditIntegrityFailure) {
        _legacyInvalidatedScopes.add(scope);
        try {
          await storage.write('audit:legacy-failure:$scope', 'failed');
        } catch (_) {
          // The in-memory block remains when secure storage is unavailable.
        }
      }
      rethrow;
    } finally {
      if (!includeLegacy) {
        final remaining = _pendingDecisionChecks[scope]! - 1;
        if (remaining == 0) {
          _pendingDecisionChecks.remove(scope);
        } else {
          _pendingDecisionChecks[scope] = remaining;
        }
      }
      gate.complete();
      if (identical(_scopeTails[scope], gate.future)) _scopeTails.remove(scope);
    }
  }

  Future<void> _sync({
    required bool includeLegacy,
    bool allowPause = false,
  }) async {
    final snapshot = await api.request({'method': 'audit_snapshot'});
    if (snapshot['chain_version'] != 1) {
      throw AuditIntegrityFailure(
        'This receiver does not support history verification.',
      );
    }
    final target = Map<String, dynamic>.from(snapshot['checkpoint'] as Map);
    final logId = target['log_id'] as String;
    final through = target['sequence'] as int;
    final legacy = snapshot['legacy_through_sequence'] as int;
    if (through < 0 || legacy < 0 || legacy > through) {
      throw AuditIntegrityFailure('Invalid audit snapshot boundary.');
    }
    final stored = await storage.read('audit:checkpoint:$scope');
    final saved = stored == null
        ? null
        : jsonDecode(stored) as Map<String, dynamic>;
    final old = saved?['checkpoint'] as Map?;
    if (old != null &&
        (old['log_id'] != logId ||
            through < (old['sequence'] as int) ||
            saved!['legacy_through_sequence'] != legacy)) {
      throw AuditIntegrityFailure(
        'History was replaced or rolled back. The phone checkpoint is preserved.',
      );
    }
    // Imported events predate integrity tracking. Decisions check the chain
    // from its migration boundary; browsing and exporting still check all rows.
    final legacyFailure =
        await storage.read('audit:legacy-failure:$scope') == 'failed';
    final checkLegacy =
        includeLegacy ||
        legacyFailure ||
        _legacyInvalidatedScopes.contains(scope) ||
        (old != null && old['sequence'] != 0 && old['sequence'] < legacy);
    final full =
        checkpoint == null ||
        _invalidatedScopes.contains(scope) ||
        (checkLegacy && !_includesLegacy);
    _checkingImportedHistory = checkLegacy && legacy > 0;
    var sequence = full
        ? (checkLegacy ? 0 : legacy)
        : checkpoint!['sequence'] as int;
    var previous = full ? auditGenesis(logId) : checkpoint!['hash'] as String;
    if (checkpoint != null &&
        (checkpoint!['log_id'] != logId || through < sequence)) {
      throw AuditIntegrityFailure('History was replaced or rolled back.');
    }
    final additions = <int, Map<String, dynamic>>{};
    final receipts = full
        ? <String, Map<String, dynamic>>{}
        : Map<String, Map<String, dynamic>>.from(_receipts);
    final hashes = <int, String>{
      0: auditGenesis(logId),
      if (!full)
        for (final event in events.values)
          event['sequence'] as int: event['hash'] as String,
    };
    if (full && sequence > 0) {
      final boundary = await api.request({
        'method': 'audit_page',
        'after': legacy - 1,
        'through': legacy,
        'limit': 1,
      });
      final rows = (boundary['actions'] as List).cast<Map<String, dynamic>>();
      if (boundary['through'] != legacy ||
          rows.length != 1 ||
          rows.single['sequence'] != legacy ||
          boundary['next_after'] != null) {
        throw AuditIntegrityFailure(
          'History has a missing migration boundary.',
        );
      }
      final event = rows.single;
      _checkAuditEvent(logId, event);
      previous = event['hash'] as String;
      hashes[legacy] = previous;
      additions[legacy] = Map<String, dynamic>.from(event);
    }
    var foundOld =
        old == null ||
        (old['sequence'] == 0 && old['hash'] == auditGenesis(logId));
    if (old != null && sequence == old['sequence']) {
      if (previous != old['hash']) {
        throw AuditIntegrityFailure('History checkpoint changed.');
      }
      foundOld = true;
    }
    while (sequence < through) {
      if (allowPause &&
          sequence < legacy &&
          (_pendingDecisionChecks[scope] ?? 0) > 0) {
        throw const AuditHistoryPaused();
      }
      final page = await api.request({
        'method': 'audit_page',
        'after': sequence,
        'through': through,
        'limit': 100,
      });
      if (page['through'] != through) {
        throw AuditIntegrityFailure('History snapshot changed.');
      }
      final rows = (page['actions'] as List).cast<Map<String, dynamic>>();
      if (rows.isEmpty) {
        throw AuditIntegrityFailure('History has a missing event.');
      }
      for (final event in rows) {
        final next = event['sequence'] as int;
        if (next <= sequence ||
            next > through ||
            (next > legacy && next != sequence + 1) ||
            event['previous_hash'] != previous) {
          throw AuditIntegrityFailure('History has a gap at event $next.');
        }
        _checkAuditEvent(logId, event);
        if (!checkLegacy && event['action'] == 'signed_decision') {
          final observed = event['detail']['proof']['checkpoint'] as Map;
          if (!hashes.containsKey(observed['sequence']) &&
              (observed['sequence'] as int) < legacy) {
            // An older signed checkpoint needs the imported prefix too.
            await _sync(includeLegacy: true);
            return;
          }
        }
        try {
          verifyAuditBinding(event, hashes, receipts);
        } catch (error) {
          throw AuditIntegrityFailure('$error');
        }
        previous = event['hash'] as String;
        sequence = next;
        additions[next] = Map<String, dynamic>.from(event);
        hashes[next] = previous;
        if (old != null && next == old['sequence']) {
          if (previous != old['hash']) {
            throw AuditIntegrityFailure(
              'History no longer matches the phone checkpoint.',
            );
          }
          foundOld = true;
        }
      }
      if (page['next_after'] != null && page['next_after'] != sequence) {
        throw AuditIntegrityFailure('History pagination skipped an event.');
      }
    }
    if (!foundOld || previous != target['hash'] || sequence != through) {
      throw AuditIntegrityFailure(
        'History no longer matches the phone checkpoint.',
      );
    }
    final local = await storage.read('audit:receipts:$scope');
    var missing = 0;
    for (final receipt in local == null ? [] : jsonDecode(local) as List) {
      final proof = receipt['proof'] as Map;
      final fingerprint =
          'ed25519:SHA256:${base64Encode(sha256.convert(auditUnhex(proof['public_key'] as String, 32)).bytes).replaceAll('=', '')}';
      if (!receipts.containsKey('$fingerprint:${proof['nonce']}')) missing++;
    }
    // A storage failure cannot replace an earlier checkpoint or claim that a
    // fresh observation was preserved independently.
    if (_checkingImportedHistory && legacyFailure) {
      await storage.write('audit:legacy-failure:$scope', '');
    }
    await storage.write(
      'audit:checkpoint:$scope',
      jsonEncode({
        'checkpoint': target,
        'legacy_through_sequence': legacy,
        'observed_unix_ms': DateTime.now().millisecondsSinceEpoch,
      }),
    );
    firstObservation = old == null;
    checkpoint = target;
    legacyThrough = legacy;
    unrecordedReceipts = missing;
    online = snapshot['daemon_online'] != false;
    if (full) {
      events.clear();
      _includesLegacy = checkLegacy || legacy == 0;
      _invalidatedScopes.remove(scope);
      _legacyInvalidatedScopes.remove(scope);
    }
    events.addAll(additions);
    _receipts
      ..clear()
      ..addAll(receipts);
  }

  void verifyDisplayed(Map<String, dynamic> event) {
    final known = events[event['sequence']];
    if (known == null || !auditEqual(known, event)) {
      _invalidatedScopes.add(scope);
      throw StateError('Displayed history differs from the verified snapshot.');
    }
  }

  void verifyRequestAttribution(Map<String, dynamic> record) {
    final related =
        events.values
            .where((e) => e['request_id'] == record['request_id'])
            .toList()
          ..sort(
            (a, b) => (a['sequence'] as int).compareTo(b['sequence'] as int),
          );
    final received = related
        .where((e) => e['action'] == 'request_received')
        .firstOrNull;
    if (received == null) {
      _invalidatedScopes.add(scope);
      throw StateError('Request has no recorded submission.');
    }
    final detail = received['detail'] as Map;
    for (final field in ['input', 'principal', 'retry_of']) {
      if (!auditEqual(record[field], detail[field])) {
        _invalidatedScopes.add(scope);
        throw StateError('Request summary differs from recorded submission.');
      }
    }
    if (!auditEqual(record['submitted_by'], detail['actor'])) {
      _invalidatedScopes.add(scope);
      throw StateError('Request submitter differs from recorded submission.');
    }
    final reviewed = related
        .where(
          (e) => ['approval_granted', 'approval_denied'].contains(e['action']),
        )
        .lastOrNull;
    if (!auditEqual(
      record['reviewed_by'],
      (reviewed?['detail'] as Map?)?['actor'],
    )) {
      _invalidatedScopes.add(scope);
      throw StateError('Request reviewer differs from recorded decision.');
    }
  }

  Future<Map<String, dynamic>> export(AuditDevice device) async {
    await sync();
    final sorted = events.values.toList()
      ..sort((a, b) => (a['sequence'] as int).compareTo(b['sequence'] as int));
    return {
      'format': 'zondd-audit-export',
      'version': 1,
      'receiver_scope': scope,
      'checkpoint': checkpoint,
      'range': {'after': 0, 'through': checkpoint!['sequence']},
      'legacy_through_sequence': legacyThrough,
      'exported_unix_ms': DateTime.now().millisecondsSinceEpoch,
      'evidence': 'receiver_history_checked_against_phone_checkpoint',
      'events': sorted,
      'device_receipts': await device.receipts(scope),
    };
  }
}
