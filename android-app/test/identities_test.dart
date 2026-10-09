import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/identities.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  test('an invalid legacy key does not hide the connection list', () async {
    const store = ProfileStore();
    await store.save([
      Profile(
        name: 'Needs repair',
        host: 'host',
        user: 'alice',
        privateKey: 'invalid',
      ),
    ]);
    final profiles = await store.load();
    expect(profiles.single.name, 'Needs repair');
    expect(profiles.single.privateKey, 'invalid');
  });

  test(
    'generated Ed25519 identities round-trip and duplicate imports reuse them',
    () async {
      final store = IdentityStore();
      final key = await store.generate('Phone');
      final pair = SSHKeyPair.fromPem(key.pem).single;
      expect(pair.type, 'ssh-ed25519');
      expect(key.publicKey, startsWith('ssh-ed25519 '));
      expect(key.fingerprint, startsWith('SHA256:'));
      final duplicate = await store.import('Other name', key.pem);
      expect(duplicate.id, key.id);
      expect((await store.load()).length, 1);
      expect((await store.get(key.id)).pem, key.pem);
      await expectLater(
        store.import('Bad key', 'not a private key'),
        throwsA(anything),
      );
      expect((await store.load()).length, 1);
    },
  );

  test(
    'legacy profile migration deduplicates identities and preserves host trust',
    () async {
      final keys = IdentityStore();
      final key = await keys.generate('Existing');
      await keys.save([]);
      const profiles = ProfileStore();
      final first = Profile(
        name: 'One',
        host: 'one',
        user: 'alice',
        privateKey: key.pem,
      );
      final second = Profile(
        name: 'Two',
        host: 'two',
        user: 'bob',
        privateKey: key.pem,
      );
      await profiles.save([first, second]);
      await profiles.trust(first.hostIdentity, 'pinned');
      final migrated = await profiles.load();
      expect(migrated.map((p) => p.keyId).toSet(), {key.id});
      expect(
        migrated.every((p) => p.privateKey.isEmpty && p.passphrase.isEmpty),
        isTrue,
      );
      expect((await keys.load()).length, 1);
      expect(await profiles.hostKey(first.hostIdentity), 'pinned');
      expect((await profiles.load()).first.keyId, key.id);
      expect((await keys.load()).length, 1);
    },
  );
}
