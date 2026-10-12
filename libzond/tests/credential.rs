use libzond::config::Config;

#[test]
fn registrations_require_distinct_private_identities_and_canonical_origins() {
    let registration = format!(
        "[credential_recipients.example]\nlabel = 'Example'\nkey_sha256 = '{}'\nfield_ids = ['password']\norigins = ['https://example.test']\n",
        "a".repeat(64)
    );
    Config::parse(&registration).unwrap();
    for origin in [
        "https://example.test/",
        "https://example.test/path",
        "https://example.test:443",
        "https://user@example.test",
        "https://example.test?secret",
        "file:///example",
        "null",
    ] {
        assert!(
            Config::parse(&registration.replace("https://example.test", origin)).is_err(),
            "{origin}"
        );
    }
    assert!(
        Config::parse(&(registration.clone() + &registration.replace("example]", "other]")))
            .is_err()
    );
    assert!(Config::parse(&registration.replace("['password']", "[]")).is_err());
    assert!(Config::parse(&registration.replace(&"a".repeat(64), "weak")).is_err());
    // Daemon-owned credential processes require migration, never silent startup.
    assert!(
        Config::parse("[credential_adapters.old]\nlabel='Old'\nprogram='/bin/true'\ncwd='/'")
            .is_err()
    );
    for name in ["admin", "askpass", "credential"] {
        assert!(Config::parse(&format!("[principals.{name}]\ncwd='/'")).is_err());
    }
}
