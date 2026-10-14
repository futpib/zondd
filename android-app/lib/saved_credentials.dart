import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';

abstract interface class CredentialPeer {
  String? get credentialScope;
}

String credentialReceiverScope(String verifiedReceiver, String executable) =>
    sha256
        .convert(
          utf8.encode(
            jsonEncode([
              'credential-receiver-v1',
              verifiedReceiver,
              executable,
            ]),
          ),
        )
        .toString();

Object? canonicalCredentialContext(Object? value) {
  if (value is Map) {
    final keys = value.keys.cast<String>().toList()..sort();
    return {
      for (final key in keys) key: canonicalCredentialContext(value[key]),
    };
  }
  if (value is List) return value.map(canonicalCredentialContext).toList();
  return value;
}

bool exactCredentialContext(Object? value) {
  if (value is double && (!value.isFinite || value.abs() > 9007199254740991)) {
    return false;
  }
  if (value is Map) return value.values.every(exactCredentialContext);
  if (value is List) return value.every(exactCredentialContext);
  return true;
}

class CredentialBinding {
  CredentialBinding._(Map<String, dynamic> scope, this.metadata, this.fieldIds)
    : _scope = scope,
      id = sha256
          .convert(utf8.encode(jsonEncode(canonicalCredentialContext(scope))))
          .toString();
  final String id;
  final Map<String, dynamic> _scope;
  final Map<String, dynamic> metadata;
  final Set<String> fieldIds;

  static CredentialBinding? sudo(
    String? receiver,
    String server,
    Map<String, dynamic> challenge,
  ) {
    final command = challenge['command'];
    if (receiver == null ||
        receiver.isEmpty ||
        command is! Map ||
        command['program'] is! String ||
        command['args'] is! List ||
        challenge['principal'] is! String ||
        challenge['operation'] is! String ||
        challenge['prompt'] is! String) {
      return null;
    }
    if (!exactCredentialContext(challenge)) return null;
    return CredentialBinding._(
      {
        'version': 1,
        'kind': 'sudo',
        'receiver': receiver,
        'principal': challenge['principal'],
        'operation': challenge['operation'],
        'command': command,
        'prompt': challenge['prompt'],
      },
      {
        'server': server,
        'recipient': 'Sudo · ${challenge['principal']}',
        'purpose': challenge['operation'],
        'fields': ['password'],
      },
      {'password'},
    );
  }

  static CredentialBinding? application(
    String? receiver,
    String server,
    Map<String, dynamic> challenge,
  ) {
    final recipient = challenge['recipient'];
    final fields = challenge['fields'];
    if (!exactCredentialContext(challenge)) return null;
    if (receiver == null ||
        receiver.isEmpty ||
        recipient is! Map ||
        fields is! List ||
        recipient['name'] is! String ||
        recipient['configuration_revision'] is! String ||
        recipient['peer_uid'] is! int ||
        recipient['identity'] is! String ||
        challenge['provider_origin'] is! String ||
        challenge['prompt'] is! String) {
      return null;
    }
    final ids = <String>{};
    for (final field in fields) {
      if (field is! Map || field['id'] is! String) return null;
      final id = field['id'] as String;
      if (const ['text', 'password', 'secret'].contains(field['kind']) &&
          (field['choices'] as List? ?? []).isEmpty &&
          !RegExp(
            r'otp|totp|one.?time|2fa|mfa|code|verification|captcha|nonce',
            caseSensitive: false,
          ).hasMatch('$id ${field['label'] ?? ''}')) {
        ids.add(id);
      }
    }
    if (ids.isEmpty) return null;
    return CredentialBinding._(
      {
        'version': 1,
        'kind': 'application',
        'receiver': receiver,
        'recipient': {
          for (final key in recipient.keys.cast<String>())
            if (!['session_id', 'peer_pid'].contains(key)) key: recipient[key],
        },
        'provider_origin': challenge['provider_origin'],
        'prompt': challenge['prompt'],
        'fields': fields,
        'context': challenge['context'],
      },
      {
        'server': server,
        'recipient': recipient['label'] ?? recipient['name'],
        'purpose': challenge['provider_origin'],
        'fields': ids.toList()..sort(),
      },
      ids,
    );
  }

  Map<String, String> select(Map<String, String> values) => {
    for (final id in fieldIds)
      if (values[id]?.isNotEmpty == true) id: values[id]!,
  };

  CredentialBinding forAnswers(Map<String, String> values) {
    if (_scope['kind'] != 'application') return this;
    final selections = <String, String>{};
    for (final field in _scope['fields'] as List) {
      if (field['kind'] == 'choice' ||
          field['kind'] == 'confirmation' ||
          (field['choices'] as List? ?? []).isNotEmpty) {
        final id = field['id'] as String;
        selections[id] = values[id] ?? '';
      }
    }
    if (selections.isEmpty) return this;
    return CredentialBinding._(
      {..._scope, 'selections': selections},
      metadata,
      fieldIds,
    );
  }
}

enum CredentialLifetime {
  minutes15('15 minutes', 900),
  hour('1 hour (default)', 3600),
  hours8('8 hours', 28800),
  forever('Forever', 0);

  const CredentialLifetime(this.label, this.seconds);
  final String label;
  final int seconds;
}

class SavedCredential {
  const SavedCredential(this.id, this.created, this.expires, this.metadata);
  final String id;
  final int created, expires;
  final Map<String, dynamic> metadata;
  factory SavedCredential.fromJson(Map<String, dynamic> json) =>
      SavedCredential(
        json['id'] as String,
        json['created'] as int,
        json['expires'] as int,
        jsonDecode(json['metadata'] as String) as Map<String, dynamic>,
      );
}

abstract interface class CredentialVault {
  Future<bool> available();
  Future<List<SavedCredential>> list();
  Future<Map<String, String>> unlock(CredentialBinding binding);
  Future<void> save(
    CredentialBinding binding,
    Map<String, String> values,
    CredentialLifetime lifetime,
  );
  Future<void> remove(String id);
  Future<void> removeAll();
}

class AndroidCredentialVault implements CredentialVault {
  const AndroidCredentialVault();
  static const channel = MethodChannel(
    'io.github.futpib.zond/credential_vault',
  );
  @override
  Future<bool> available() async =>
      await channel.invokeMethod<bool>('available') ?? false;
  @override
  Future<List<SavedCredential>> list() async =>
      (await channel.invokeListMethod<dynamic>('list') ?? [])
          .map(
            (entry) => SavedCredential.fromJson(
              Map<String, dynamic>.from(entry as Map),
            ),
          )
          .toList();
  @override
  Future<Map<String, String>> unlock(CredentialBinding binding) async {
    final encoded = await channel.invokeMethod<String>('unlock', {
      'id': binding.id,
    });
    final values = Map<String, String>.from(jsonDecode(encoded!) as Map);
    if (values.keys.any((id) => !binding.fieldIds.contains(id))) {
      values.clear();
      throw const FormatException('Saved credentials do not match this form.');
    }
    return values;
  }

  @override
  Future<void> save(
    CredentialBinding binding,
    Map<String, String> values,
    CredentialLifetime lifetime,
  ) async {
    final selected = binding.select(values);
    if (selected.isEmpty) return;
    try {
      await channel.invokeMethod<void>('save', {
        'id': binding.id,
        'values': jsonEncode(selected),
        'metadata': jsonEncode(binding.metadata),
        'seconds': lifetime.seconds,
      });
    } finally {
      selected.clear();
    }
  }

  @override
  Future<void> remove(String id) =>
      channel.invokeMethod<void>('delete', {'id': id});
  @override
  Future<void> removeAll() => channel.invokeMethod<void>('deleteAll');
}
