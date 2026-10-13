use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Read, os::unix::fs::MetadataExt, path::Path};

pub const VERSION: u32 = 1;
pub const DECISION_DOMAIN: &str = "zondd-audit-decision-v1\n";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub log_id: String,
    pub sequence: u64,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProof {
    pub public_key: String,
    pub nonce: String,
    pub checkpoint: Checkpoint,
    pub payload: String,
    pub signature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportActor {
    pub ssh_key_fingerprint: Option<String>,
    pub evidence: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == N * 2,
        "invalid audit key or signature length"
    );
    let mut bytes = [0; N];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        ensure!(
            pair.iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "invalid audit hex"
        );
        bytes[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}

pub fn genesis(log_id: &str) -> String {
    hex(&Sha256::digest(format!("zondd-audit-genesis-v1\n{log_id}")))
}

pub fn event_hash(log_id: &str, previous: &str, payload: &str) -> String {
    hex(&Sha256::digest(format!(
        "zondd-audit-event-v1\n{log_id}\n{previous}\n{payload}"
    )))
}

// Intent contains decision metadata, never human answers or complete policy files.
pub fn intent(mut value: Value) -> Value {
    let Some(object) = value.as_object_mut() else {
        return json!({"method":"invalid"});
    };
    object.remove("version");
    object.remove("actor");
    object.remove("transport");
    match object.get("method").and_then(Value::as_str).unwrap_or("") {
        "credential" => {
            if !object.contains_key("provided") {
                let provided = object.remove("password").is_some_and(|v| !v.is_null());
                object.insert("provided".into(), json!(provided));
            } else {
                object.remove("password");
            }
        }
        "answer_interaction" => {
            if !object.contains_key("provided") {
                let provided = object.remove("values").is_some_and(|v| !v.is_null());
                object.insert("provided".into(), json!(provided));
            } else {
                object.remove("values");
            }
        }
        "save_config" | "validate_config" => {
            if let Some(content) = object
                .remove("content")
                .and_then(|v| v.as_str().map(str::to_owned))
            {
                object.insert(
                    "new_revision".into(),
                    json!(crate::config::revision(&content)),
                );
            }
        }
        "reload_config" => {
            object.insert("method".into(), json!("reload"));
        }
        "actions" | "history" => {
            object.remove("query");
        }
        _ => {}
    }
    // Absent optional arguments and explicit null are equivalent on the wire.
    object.retain(|_, v| !v.is_null());
    value
}

impl ActorProof {
    pub fn verify(&self, log_id: &str, request: &Value) -> Result<String> {
        unhex::<32>(&self.nonce)?;
        ensure!(
            self.checkpoint.log_id == log_id,
            "audit receipt is for another receiver log"
        );
        unhex::<32>(&self.checkpoint.hash)?;
        let expected = json!({"log_id":log_id,"nonce":self.nonce,"checkpoint":self.checkpoint,"request":intent(request.clone())});
        let supplied: Value =
            serde_json::from_str(&self.payload).context("invalid signed audit intent")?;
        ensure!(
            supplied == expected,
            "audit signature does not match this receiver and decision"
        );
        let key = VerifyingKey::from_bytes(&unhex::<32>(&self.public_key)?)?;
        let signature = Signature::from_bytes(&unhex::<64>(&self.signature)?);
        let message = format!("{DECISION_DOMAIN}{}", self.payload);
        key.verify_strict(message.as_bytes(), &signature)
            .context("invalid audit signature")?;
        Ok(format!(
            "ed25519:SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(key.as_bytes()))
        ))
    }
}

// SSH metadata is supplied by a trusted account-side helper. It is distinct from
// the independently verifiable device signature and does not isolate same-UID code.
pub fn ssh_actor(forced_key: Option<&str>) -> TransportActor {
    if let Some(fingerprint) = forced_key.filter(|v| {
        v.strip_prefix("SHA256:").is_some_and(|hash| {
            STANDARD_NO_PAD
                .decode(hash)
                .is_ok_and(|bytes| bytes.len() == 32)
        })
    }) {
        return TransportActor {
            ssh_key_fingerprint: Some(fingerprint.into()),
            evidence: "forced_command_key_binding".into(),
        };
    }
    let fingerprint = std::env::var_os("SSH_USER_AUTH").and_then(|path| {
        let path = Path::new(&path);
        crate::paths::trusted_path(path).ok()?;
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.is_file() || (meta.uid() != 0 && meta.uid() != crate::paths::current_uid()) {
            return None;
        }
        let mut text = String::new();
        std::fs::File::open(path)
            .ok()?
            .take(64 * 1024)
            .read_to_string(&mut text)
            .ok()?;
        text.lines().find_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.first() != Some(&"publickey") {
                return None;
            }
            let blob = base64::engine::general_purpose::STANDARD
                .decode(parts.get(2)?)
                .ok()?;
            Some(format!(
                "SHA256:{}",
                STANDARD_NO_PAD.encode(Sha256::digest(blob))
            ))
        })
    });
    TransportActor {
        evidence: if fingerprint.is_some() {
            "openssh_auth_info"
        } else {
            "unix_account_only"
        }
        .into(),
        ssh_key_fingerprint: fingerprint,
    }
}

pub fn category(action: &str, detail: &Value) -> &'static str {
    if action == "admin_request" || action == "caller_request" {
        let method = detail
            .get("method")
            .or_else(|| detail.get("request").and_then(|v| v.get("method")))
            .and_then(Value::as_str)
            .unwrap_or("");
        if matches!(
            method,
            "status"
                | "pending"
                | "rules"
                | "permissions"
                | "list_operations"
                | "history"
                | "actions"
                | "request_detail"
                | "job"
                | "check"
                | "audit_snapshot"
                | "audit_page"
        ) {
            return "read";
        }
    }
    if matches!(
        action,
        "control.read_config" | "control.validate_config" | "control.service_status"
    ) {
        return "read";
    }
    if action.contains("interaction") || action.starts_with("credential_") {
        return "credential";
    }
    if action.contains("rule") || action.starts_with("approval_") || action == "signed_decision" {
        return "decision";
    }
    if action.starts_with("control.")
        || action.starts_with("daemon_")
        || action.starts_with("reload_")
        || action == "policy_reloaded"
    {
        return "management";
    }
    "request"
}

pub fn routine_read(request: &crate::Request) -> bool {
    matches!(
        request,
        crate::Request::Status
            | crate::Request::Pending
            | crate::Request::History { .. }
            | crate::Request::Actions { .. }
            | crate::Request::AuditSnapshot
            | crate::Request::AuditPage { .. }
    )
}

#[derive(Debug, Serialize)]
pub struct Verification {
    pub checkpoint: Checkpoint,
    pub legacy_through_sequence: u64,
    pub signed_decisions: usize,
    pub device_receipts_not_recorded: usize,
    pub external_checkpoint_matched: bool,
}

pub fn verify_event(log_id: &str, row: &crate::ActionRecord) -> Result<()> {
    let material = json!({"sequence":row.sequence,"time_unix_ms":row.time_unix_ms,"request_id":row.request_id,"action":row.action,"detail":row.detail,"category":row.category});
    ensure!(
        serde_json::from_str::<Value>(&row.hash_payload)? == material
            && row.hash == event_hash(log_id, &row.previous_hash, &row.hash_payload),
        "audit event {} has changed",
        row.sequence
    );
    Ok(())
}

// The checkpoint must come from an independent source to detect a fully
// rewritten export. A bundle's own checkpoint only proves internal consistency.
pub fn verify_export(bundle: &Value, anchor: Option<&Checkpoint>) -> Result<Verification> {
    use std::collections::BTreeMap;
    ensure!(
        bundle["format"] == "zondd-audit-export" && bundle["version"] == VERSION,
        "unsupported audit export"
    );
    let checkpoint: Checkpoint = serde_json::from_value(bundle["checkpoint"].clone())?;
    let legacy = bundle["legacy_through_sequence"]
        .as_u64()
        .context("missing migration boundary")?;
    ensure!(legacy <= checkpoint.sequence, "invalid migration boundary");
    ensure!(
        bundle["range"]["after"] == 0 && bundle["range"]["through"] == checkpoint.sequence,
        "export is not a complete range"
    );
    let rows: Vec<crate::ActionRecord> = serde_json::from_value(bundle["events"].clone())?;
    let mut hashes = BTreeMap::from([(0, genesis(&checkpoint.log_id))]);
    let mut receipts: BTreeMap<(String, String), Value> = BTreeMap::new();
    let mut previous = genesis(&checkpoint.log_id);
    let mut sequence = 0;
    for row in rows {
        ensure!(
            row.sequence > sequence
                && row.previous_hash == previous
                && (row.sequence <= legacy || row.sequence == sequence + 1),
            "audit history gap at event {}",
            row.sequence
        );
        verify_event(&checkpoint.log_id, &row)?;
        if row.action == "signed_decision" {
            let proof: ActorProof = serde_json::from_value(row.detail["proof"].clone())?;
            let fingerprint = proof.verify(&checkpoint.log_id, &row.detail["request"])?;
            ensure!(
                hashes.get(&proof.checkpoint.sequence) == Some(&proof.checkpoint.hash),
                "signed decision checkpoint changed at event {}",
                row.sequence
            );
            ensure!(
                row.detail["actor"]["device_signing_key"] == fingerprint
                    && row.detail["actor"]["receipt_id"] == proof.nonce
                    && row.detail["actor"]["device_key_evidence"] == "signature_verified",
                "decision actor does not match its signature"
            );
            ensure!(
                receipts
                    .insert((fingerprint, proof.nonce), row.detail["request"].clone())
                    .is_none(),
                "reused decision receipt"
            );
        } else if let Some(actor) = row.detail.get("actor")
            && actor["device_key_evidence"] == "signature_verified"
        {
            let key = (
                actor["device_signing_key"]
                    .as_str()
                    .context("missing device key")?
                    .to_owned(),
                actor["receipt_id"]
                    .as_str()
                    .context("missing receipt")?
                    .to_owned(),
            );
            let request = receipts
                .get(&key)
                .context("event has no preceding signed decision")?;
            let expected = match row.action.as_str() {
                "admin_request" => Some(intent(row.detail.clone())),
                "approval_granted" | "approval_denied" => Some(
                    json!({"method":"resolve","approval_id":row.detail["approval_id"],"approve":row.action == "approval_granted"}),
                ),
                "credential_answered" => Some(
                    json!({"method":"credential","challenge_id":row.detail["challenge_id"],"provided":row.detail["provided"]}),
                ),
                "interaction_decision" => Some(
                    json!({"method":"answer_interaction","challenge_id":row.detail["challenge_id"],"provided":row.detail["provided"]}),
                ),
                "control.save_config_requested" => Some(
                    json!({"method":"save_config","revision":row.detail["revision"],"new_revision":row.detail["new_revision"]}),
                ),
                _ => None,
            };
            if let Some(expected) = expected {
                ensure!(
                    request == &expected,
                    "event {} does not match signed decision",
                    row.sequence
                );
            }
        }
        sequence = row.sequence;
        previous = row.hash;
        hashes.insert(sequence, previous.clone());
    }
    ensure!(
        sequence == checkpoint.sequence && previous == checkpoint.hash,
        "audit export is truncated or checkpoint changed"
    );
    if let Some(anchor) = anchor {
        ensure!(
            anchor.log_id == checkpoint.log_id
                && hashes.get(&anchor.sequence) == Some(&anchor.hash),
            "export no longer matches independent checkpoint"
        );
    }
    let mut missing = 0;
    for local in bundle["device_receipts"]
        .as_array()
        .context("missing device receipts")?
    {
        let proof: ActorProof = serde_json::from_value(local["proof"].clone())?;
        let payload: Value = serde_json::from_str(&proof.payload)?;
        let fingerprint = proof.verify(&checkpoint.log_id, &payload["request"])?;
        ensure!(
            hashes.get(&proof.checkpoint.sequence) == Some(&proof.checkpoint.hash),
            "local decision checkpoint changed"
        );
        if !receipts.contains_key(&(fingerprint, proof.nonce)) {
            missing += 1;
        }
    }
    Ok(Verification {
        checkpoint,
        legacy_through_sequence: legacy,
        signed_decisions: receipts.len(),
        device_receipts_not_recorded: missing,
        external_checkpoint_matched: anchor.is_some(),
    })
}
