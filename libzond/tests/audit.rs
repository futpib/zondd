use ed25519_dalek::{Signer, SigningKey};
use libzond::{
    RequestRecord,
    audit::{self, ActorProof, Checkpoint, TransportActor},
    history::History,
};
use rusqlite::Connection;
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../testdata/audit-v1.json")).unwrap()
}

fn proof(checkpoint: Checkpoint, request: &Value, nonce: u8) -> ActorProof {
    let key = SigningKey::from_bytes(&[7; 32]);
    let nonce = audit::hex(&[nonce; 32]);
    let payload = json!({"log_id":checkpoint.log_id,"checkpoint":checkpoint,"nonce":nonce,"request":audit::intent(request.clone())}).to_string();
    ActorProof {
        public_key: audit::hex(key.verifying_key().as_bytes()),
        nonce,
        checkpoint,
        signature: audit::hex(
            &key.sign(format!("{}{payload}", audit::DECISION_DOMAIN).as_bytes())
                .to_bytes(),
        ),
        payload,
    }
}

fn rehash(bundle: &mut Value) {
    let log_id = bundle["checkpoint"]["log_id"].as_str().unwrap().to_owned();
    let mut previous = audit::genesis(&log_id);
    for row in bundle["events"].as_array_mut().unwrap() {
        let material = json!({"sequence":row["sequence"],"time_unix_ms":row["time_unix_ms"],"request_id":row["request_id"],"action":row["action"],"detail":row["detail"],"category":row["category"]});
        let payload = material.to_string();
        row["previous_hash"] = json!(previous);
        previous = audit::event_hash(&log_id, &previous, &payload);
        row["hash"] = json!(previous);
        row["hash_payload"] = json!(payload);
    }
    let last = bundle["events"].as_array().unwrap().last().unwrap();
    bundle["checkpoint"]["sequence"] = last["sequence"].clone();
    bundle["range"]["through"] = bundle["checkpoint"]["sequence"].clone();
    bundle["checkpoint"]["hash"] = json!(previous);
}

#[test]
fn independently_generated_export_checks_signatures_and_actor_binding() {
    let bundle = fixture();
    let anchor = serde_json::from_value(bundle["checkpoint"].clone()).unwrap();
    let verified = audit::verify_export(&bundle, Some(&anchor)).unwrap();
    assert_eq!(verified.signed_decisions, 1);
    assert_eq!(verified.device_receipts_not_recorded, 0);
    assert!(verified.external_checkpoint_matched);
    for (index, field, value) in [
        (0, "principal", json!("someone else")),
        (4, "approval_id", json!("another approval")),
    ] {
        let mut changed = bundle.clone();
        changed["events"][index]["detail"][field] = value;
        assert!(audit::verify_export(&changed, None).is_err());
        rehash(&mut changed);
        assert!(audit::verify_export(&changed, None).is_err());
    }
    let mut changed = bundle.clone();
    changed["events"][2]["detail"]["proof"]["signature"] = json!("00".repeat(64));
    rehash(&mut changed);
    assert!(audit::verify_export(&changed, None).is_err());
    let mut changed = bundle.clone();
    changed["events"][4]["detail"]["actor"]["device_signing_key"] = json!("impostor");
    rehash(&mut changed);
    assert!(audit::verify_export(&changed, None).is_err());
    let mut changed = bundle;
    changed["events"].as_array_mut().unwrap().remove(3);
    rehash(&mut changed);
    assert!(audit::verify_export(&changed, None).is_err());
}

#[test]
fn strict_signature_vectors_reject_weak_keys_weak_r_and_unreduced_s() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../testdata/audit-ed25519-strict.json")).unwrap();
    let bundle = fixture();
    let mut proof: ActorProof =
        serde_json::from_value(bundle["events"][2]["detail"]["proof"].clone()).unwrap();
    for point in vectors["weak_points"].as_array().unwrap() {
        proof.public_key = point.as_str().unwrap().into();
        proof.signature = format!("01{}", "00".repeat(63));
        assert!(
            proof
                .verify(
                    &proof.checkpoint.log_id,
                    &bundle["events"][2]["detail"]["request"]
                )
                .is_err()
        );
    }
    proof.public_key = vectors["public_key"].as_str().unwrap().into();
    for field in ["weak_r", "noncanonical_s"] {
        proof.signature = vectors[field].as_str().unwrap().into();
        assert!(
            proof
                .verify(
                    &proof.checkpoint.log_id,
                    &bundle["events"][2]["detail"]["request"]
                )
                .is_err()
        );
    }
}

#[test]
fn independent_checkpoint_detects_recomputed_tail_and_rollback() {
    let bundle = fixture();
    let anchor = serde_json::from_value(bundle["checkpoint"].clone()).unwrap();
    let mut changed = bundle.clone();
    changed["events"][5]["detail"]["reason"] = json!("rewritten result");
    rehash(&mut changed);
    assert!(audit::verify_export(&changed, None).is_ok());
    assert!(audit::verify_export(&changed, Some(&anchor)).is_err());
    let mut truncated = bundle;
    truncated["events"].as_array_mut().unwrap().pop();
    // Keep the original bytes of the retained prefix.
    let last = truncated["events"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    truncated["checkpoint"]["sequence"] = last["sequence"].clone();
    truncated["checkpoint"]["hash"] = last["hash"].clone();
    truncated["range"]["through"] = last["sequence"].clone();
    assert!(audit::verify_export(&truncated, None).is_ok());
    assert!(audit::verify_export(&truncated, Some(&anchor)).is_err());
}

#[test]
fn signed_intent_binds_receiver_decision_checkpoint_and_rejects_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let history = History::open(&path).unwrap();
    let request = json!({"method":"answer_interaction","challenge_id":"challenge","values":{"password":"answer-must-stay-private"}});
    let signed = proof(history.checkpoint().unwrap(), &request, 1);
    assert!(!signed.payload.contains("answer-must-stay-private"));
    assert!(signed.verify("other-log", &request).is_err());
    let other = json!({"method":"answer_interaction","challenge_id":"other","values":{"password":"answer-must-stay-private"}});
    assert!(signed.verify(&signed.checkpoint.log_id, &other).is_err());
    history
        .actor(
            Some(&signed),
            &TransportActor::default(),
            &request,
            None,
            None,
        )
        .unwrap();
    assert!(
        history
            .actor(
                Some(&signed),
                &TransportActor::default(),
                &request,
                None,
                None
            )
            .is_err()
    );
    assert_eq!(history.checkpoint().unwrap().sequence, 1);
    let mut stale = proof(history.checkpoint().unwrap(), &request, 2);
    stale.checkpoint.hash = "00".repeat(32);
    stale = proof(stale.checkpoint, &request, 2);
    assert!(
        history
            .actor(
                Some(&stale),
                &TransportActor::default(),
                &request,
                None,
                None
            )
            .is_err()
    );
    assert_eq!(history.checkpoint().unwrap().sequence, 1);
    history.verify_chain().unwrap();
    let rows = serde_json::to_string(&history.audit_page(0, 1, 10).unwrap()).unwrap();
    assert!(!rows.contains("answer-must-stay-private"));
}

#[test]
fn old_history_has_an_explicit_migration_boundary_and_offline_open_does_not_recover_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let db = Connection::open(config.with_extension("history.sqlite3")).unwrap();
    db.execute_batch("CREATE TABLE actions(sequence INTEGER PRIMARY KEY AUTOINCREMENT,time INTEGER NOT NULL,request_id TEXT,action TEXT NOT NULL,detail TEXT NOT NULL); INSERT INTO actions(time,action,detail) VALUES (1,'old_event','{}');").unwrap();
    drop(db);
    let mut history = History::open(&config).unwrap();
    assert_eq!(history.legacy_through_sequence().unwrap(), 1);
    let mut record: RequestRecord = serde_json::from_value(json!({"sequence":0,"request_id":"running-job","principal":"exec","input":{"method":"run","command":{"program":"/usr/bin/true","args":[]}},"status":"running","reason":"active","created_unix_ms":1,"updated_unix_ms":1})).unwrap();
    history
        .record(&mut record, "execution_started", json!({}))
        .unwrap();
    drop(history);
    let mut history = History::open(&config).unwrap();
    assert_eq!(history.get("running-job").unwrap().status, "running");
    history.daemon_started(&config).unwrap();
    assert_eq!(history.get("running-job").unwrap().status, "interrupted");
    assert_eq!(history.legacy_through_sequence().unwrap(), 1);
    history.verify_chain().unwrap();
}

#[test]
fn concurrent_writers_preserve_chain_and_snapshot_pages() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    History::open(&config).unwrap();
    let handles: Vec<_> = (0..4)
        .map(|writer| {
            let path = config.clone();
            std::thread::spawn(move || {
                let history = History::open(&path).unwrap();
                for index in 0..25 {
                    history
                        .audit(
                            None,
                            "offline_change",
                            json!({"writer":writer,"index":index}),
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let history = History::open(&config).unwrap();
    history.verify_chain().unwrap();
    let snapshot = history.checkpoint().unwrap();
    assert_eq!(snapshot.sequence, 100);
    history.audit(None, "later", json!({})).unwrap();
    let rows = history.audit_page(0, snapshot.sequence, 1000).unwrap();
    assert_eq!(rows.len(), 100);
    assert_eq!(rows.last().unwrap().hash, snapshot.hash);
    history
        .audit(None, "admin_request", json!({"method":"request_detail"}))
        .unwrap();
    assert!(
        history
            .filtered_actions(None, None, 1000, None, None, false)
            .unwrap()
            .iter()
            .all(|r| r.category != "read")
    );
}

#[test]
fn disk_tampering_and_deleted_events_fail_without_resetting_the_chain() {
    for sql in [
        "UPDATE actions SET detail='{}' WHERE sequence=1",
        "DELETE FROM actions WHERE sequence=1",
        "DELETE FROM actions WHERE sequence=2",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let history = History::open(&path).unwrap();
        history
            .audit(None, "one", json!({"original":true}))
            .unwrap();
        history.audit(None, "two", json!({})).unwrap();
        let head = history.checkpoint().unwrap();
        drop(history);
        let db = Connection::open(path.with_extension("history.sqlite3")).unwrap();
        db.execute_batch(sql).unwrap();
        assert!(History::open(&path).is_err(), "{sql}");
        assert_eq!(
            db.query_row(
                "SELECT value FROM audit_meta WHERE key='head_hash'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            head.hash
        );
    }
}
