import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'transport.dart';
import 'identities.dart';

class Profile {
  Profile({
    required this.name,
    required this.host,
    required this.user,
    this.port = 22,
    this.iroh = false,
    this.privateKey = '',
    this.password = '',
    this.passphrase = '',
    this.keyId = '',
    this.relays = const [],
    this.executable = 'zondctl',
    this.runtime = '',
    this.config = '',
  });
  final String name,
      host,
      user,
      privateKey,
      password,
      passphrase,
      keyId,
      executable,
      runtime,
      config;
  final int port;
  final bool iroh;
  final List<String> relays;
  String get hostIdentity =>
      '${iroh ? 'iroh' : 'ssh'}:$host:${iroh ? 22 : port}';
  Map<String, dynamic> toJson() => {
    'name': name,
    'host': host,
    'user': user,
    'port': port,
    'iroh': iroh,
    'privateKey': privateKey,
    'password': password,
    'passphrase': passphrase,
    'keyId': keyId,
    'relays': relays,
    'executable': executable,
    'runtime': runtime,
    'config': config,
  };
  factory Profile.fromJson(Map<String, dynamic> value) => Profile(
    name: value['name'] as String,
    host: value['host'] as String,
    user: value['user'] as String,
    port: value['port'] as int,
    iroh: value['iroh'] as bool,
    privateKey: value['privateKey'] as String,
    password: value['password'] as String,
    passphrase: value['passphrase'] as String,
    keyId: value['keyId'] as String? ?? '',
    executable: value['executable'] as String,
    runtime: value['runtime'] as String,
    config: value['config'] as String,
    relays: (value['relays'] as List).cast<String>(),
  );
}

class ProfileStore {
  const ProfileStore();
  static const storage = FlutterSecureStorage();
  Future<List<Profile>> load() async {
    final value = await storage.read(key: 'profiles');
    final profiles = value == null
        ? <Profile>[]
        : (jsonDecode(value) as List)
              .map((v) => Profile.fromJson(v as Map<String, dynamic>))
              .toList();
    var migrated = false;
    for (var i = 0; i < profiles.length; i++) {
      final profile = profiles[i];
      if (profile.privateKey.isEmpty) continue;
      Identity identity;
      try {
        identity = await IdentityStore().import(
          '${profile.name} key',
          profile.privateKey,
          profile.passphrase,
        );
      } catch (_) {
        // Preserve legacy credentials if they cannot be migrated; the connection remains editable.
        continue;
      }
      profiles[i] = Profile.fromJson({
        ...profile.toJson(),
        'keyId': identity.id,
        'privateKey': '',
        'passphrase': '',
      });
      migrated = true;
    }
    if (migrated) await save(profiles);
    return profiles;
  }

  Future<void> save(List<Profile> profiles) => storage.write(
    key: 'profiles',
    value: jsonEncode(profiles.map((p) => p.toJson()).toList()),
  );
  Future<String?> hostKey(String identity) =>
      storage.read(key: 'host:$identity');
  Future<void> trust(String identity, String fingerprint) =>
      storage.write(key: 'host:$identity', value: fingerprint);
  Future<void> forget(String identity) => storage.delete(key: 'host:$identity');
}

String shellQuote(String value) => "'${value.replaceAll("'", "'\"'\"'")}'";

abstract class ControlApi {
  Future<Map<String, dynamic>> request(Map<String, dynamic> body);
  Future<void> close();
}

class ConnectionLost implements Exception {
  const ConnectionLost();
  @override
  String toString() => 'Connection lost. Reconnect to continue.';
}

/// Keeps the dashboard and its drafts alive while replacing the transport.
/// Requests are never retried: a lost response may hide a completed mutation.
class ControlConnection extends ChangeNotifier implements ControlApi {
  ControlConnection(this._api, this._connect);
  ControlApi? _api;
  final Future<ControlApi> Function() _connect;
  Future<void>? _reconnection;
  bool disconnected = false, _closed = false;
  bool get reconnecting => _reconnection != null;

  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    final api = _api;
    if (_closed || disconnected || reconnecting || api == null) {
      throw const ConnectionLost();
    }
    try {
      final result = await api.request(body);
      if (_closed || api != _api) throw const ConnectionLost();
      return result;
    } on ConnectionLost {
      if (!_closed && api == _api && !disconnected) {
        disconnected = true;
        notifyListeners();
      }
      rethrow;
    }
  }

  Future<void> reconnect() {
    if (_closed) return Future.error(const ConnectionLost());
    if (_reconnection != null) return _reconnection!;
    final done = Completer<void>();
    _reconnection = done.future;
    disconnected = true;
    notifyListeners();
    () async {
      try {
        final old = _api;
        _api = null;
        await old?.close();
        if (_closed) throw const ConnectionLost();
        final next = await _connect();
        if (_closed) {
          await next.close();
          throw const ConnectionLost();
        }
        _api = next;
        disconnected = false;
        done.complete();
      } catch (error, stack) {
        done.completeError(error, stack);
      } finally {
        _reconnection = null;
        if (!_closed) notifyListeners();
      }
    }();
    return done.future;
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final api = _api;
    _api = null;
    await api?.close();
  }
}

typedef AuthenticationRequest =
    Future<List<String>?> Function(SSHUserInfoRequest request, bool retry);

class AuthenticationCancelled implements Exception {
  const AuthenticationCancelled();
  @override
  String toString() => 'Authentication cancelled';
}

class SshControl implements ControlApi {
  SshControl._(this._ssh, this.profile, this._tunnel);
  final SSHClient _ssh;
  final Profile profile;
  final int? _tunnel;
  bool _closed = false;

  static Future<SshControl> connect(
    Profile profile,
    Future<bool> Function(String type, String fingerprint) verify, {
    AuthenticationRequest? onAuthenticationRequest,
  }) async {
    for (var attempt = 0; ; attempt++) {
      var submitted = false;
      try {
        return await _connect(
          profile,
          verify,
          onAuthenticationRequest: onAuthenticationRequest,
          retry: attempt > 0,
          onSubmitted: () => submitted = true,
        );
      } on SSHAuthFailError {
        // dartssh2 tries each authentication method once per connection.
        if (onAuthenticationRequest == null || !submitted || attempt >= 2) {
          rethrow;
        }
      }
    }
  }

  static Future<SshControl> _connect(
    Profile profile,
    Future<bool> Function(String type, String fingerprint) verify, {
    required AuthenticationRequest? onAuthenticationRequest,
    required bool retry,
    required void Function() onSubmitted,
  }) async {
    int? tunnel;
    SSHClient? client;
    SSHSocket? socket;
    (Object, StackTrace)? verificationFailure;
    var cancelled = false, active = true, savedPasswordUsed = retry;
    Future<List<String>?> ask(SSHUserInfoRequest request) async {
      if (!active) return null;
      if (request.prompts.isEmpty) return <String>[];
      final responses = await onAuthenticationRequest!(request, retry);
      if (!active) return null;
      if (responses == null) {
        cancelled = true;
        client?.close();
        return null;
      }
      onSubmitted();
      return responses;
    }

    try {
      final identity = profile.keyId.isEmpty
          ? null
          : await IdentityStore().get(profile.keyId);
      final pem = identity?.pem ?? profile.privateKey;
      final passphrase = identity?.passphrase ?? profile.passphrase;
      final identities = identity != null
          ? identity.createIdentities()
          : pem.trim().isEmpty
          ? null
          : SSHKeyPair.fromPem(pem, passphrase.isEmpty ? null : passphrase);
      if (profile.iroh) {
        tunnel = await IrohTransport.connect(profile.host, profile.relays);
      }
      socket = await SSHSocket.connect(
        tunnel == null ? profile.host : '127.0.0.1',
        tunnel ?? profile.port,
        timeout: const Duration(seconds: 30),
      );
      client = SSHClient(
        socket,
        username: profile.user,
        identities: identities,
        onPasswordRequest: () async {
          if (!active) return null;
          if (!savedPasswordUsed && profile.password.isNotEmpty) {
            savedPasswordUsed = true;
            onSubmitted();
            return profile.password;
          }
          if (onAuthenticationRequest == null) return null;
          final responses = await ask(
            SSHUserInfoRequest('SSH password', '', [
              SSHUserInfoPrompt('Password', false),
            ]),
          );
          return responses?.single;
        },
        onUserInfoRequest: onAuthenticationRequest == null ? null : ask,
        onVerifyHostKey: (type, fingerprint) async {
          try {
            return await verify(type, utf8.decode(fingerprint));
          } catch (error, stack) {
            verificationFailure = (error, stack);
            return false;
          }
        },
        keepAliveInterval: const Duration(seconds: 15),
      );
      await client.authenticated.timeout(const Duration(minutes: 2));
      return SshControl._(client, profile, tunnel);
    } catch (_) {
      client?.close();
      if (client == null) socket?.close();
      if (tunnel != null) await IrohTransport.disconnect(tunnel);
      if (cancelled) throw const AuthenticationCancelled();
      final failure = verificationFailure;
      if (failure != null) Error.throwWithStackTrace(failure.$1, failure.$2);
      rethrow;
    } finally {
      active = false;
    }
  }

  String get command => [
    shellQuote(profile.executable),
    if (profile.runtime.isNotEmpty) ...[
      '--runtime-dir',
      shellQuote(profile.runtime),
    ],
    'control',
    if (profile.config.isNotEmpty) ...['--config', shellQuote(profile.config)],
  ].join(' ');

  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    try {
      return await _request(body);
    } on TimeoutException {
      _ssh.close();
      throw const ConnectionLost();
    } catch (_) {
      if (_ssh.isClosed) throw const ConnectionLost();
      rethrow;
    }
  }

  Future<Map<String, dynamic>> _request(Map<String, dynamic> body) async {
    final session = await _ssh
        .execute(command)
        .timeout(const Duration(seconds: 15));
    Future<List<int>> bounded(Stream<Uint8List> stream) async {
      final builder = BytesBuilder(copy: false);
      await for (final bytes in stream) {
        builder.add(bytes);
        if (builder.length > 4 * 1024 * 1024) {
          session.close();
          throw StateError('Control response exceeded 4 MiB');
        }
      }
      return builder.takeBytes();
    }

    try {
      final output = Future.wait([
        bounded(session.stdout),
        bounded(session.stderr),
      ]);
      session.stdin.add(
        Uint8List.fromList(
          utf8.encode('${jsonEncode({'version': 1, ...body})}\n'),
        ),
      );
      // A complete request is sufficient; keeping stdin open also works with SSH proxies.
      final streams = await output.timeout(const Duration(seconds: 40));
      await session.done.timeout(const Duration(seconds: 5));
      final stdout = utf8.decode(streams[0]);
      if (stdout.trim().isEmpty) {
        throw StateError(
          'SSH command failed (${session.exitCode}): ${utf8.decode(streams[1], allowMalformed: true)}',
        );
      }
      final response = jsonDecode(stdout) as Map<String, dynamic>;
      if (response['version'] != 1) {
        throw StateError('Unsupported control protocol');
      }
      if (response['ok'] != true) throw StateError(response['error'] as String);
      if (session.exitCode != 0) {
        throw StateError('Control helper exited ${session.exitCode}');
      }
      return response['result'] as Map<String, dynamic>;
    } finally {
      session.close();
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _ssh.close();
    if (_tunnel != null) await IrohTransport.disconnect(_tunnel);
  }
}
