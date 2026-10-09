import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'transport.dart';

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
    this.relays = const [],
    this.executable = '.cargo/bin/zondctl',
    this.runtime = '',
    this.config = '',
  });
  final String name,
      host,
      user,
      privateKey,
      password,
      passphrase,
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
    return value == null
        ? []
        : (jsonDecode(value) as List)
              .map((v) => Profile.fromJson(v as Map<String, dynamic>))
              .toList();
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

class SshControl implements ControlApi {
  SshControl._(this._ssh, this.profile, this._tunnel);
  final SSHClient _ssh;
  final Profile profile;
  final int? _tunnel;

  static Future<SshControl> connect(
    Profile profile,
    Future<bool> Function(String type, String fingerprint) verify,
  ) async {
    int? tunnel;
    SSHClient? client;
    SSHSocket? socket;
    try {
      final identities = profile.privateKey.trim().isEmpty
          ? null
          : SSHKeyPair.fromPem(
              profile.privateKey,
              profile.passphrase.isEmpty ? null : profile.passphrase,
            );
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
        onPasswordRequest: () =>
            profile.password.isEmpty ? null : profile.password,
        onVerifyHostKey: (type, fingerprint) =>
            verify(type, utf8.decode(fingerprint)),
        keepAliveInterval: const Duration(seconds: 15),
      );
      await client.authenticated.timeout(const Duration(minutes: 2));
      return SshControl._(client, profile, tunnel);
    } catch (_) {
      client?.close();
      if (client == null) socket?.close();
      if (tunnel != null) await IrohTransport.disconnect(tunnel);
      rethrow;
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
    _ssh.close();
    if (_tunnel != null) await IrohTransport.disconnect(_tunnel);
  }
}
