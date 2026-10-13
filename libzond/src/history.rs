use crate::{ActionRecord, RequestRecord, audit};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub struct OutputChunk {
    pub sequence: u64,
    pub stderr: bool,
    pub data: Vec<u8>,
}

pub struct History(Connection);
impl History {
    fn action_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ActionRecord> {
        let detail: String = r.get(4)?;
        Ok(ActionRecord {
            sequence: r.get::<_, i64>(0)? as u64,
            time_unix_ms: r.get::<_, i64>(1)? as u64,
            request_id: r.get(2)?,
            action: r.get(3)?,
            detail: serde_json::from_str(&detail).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
            category: r.get(5)?,
            previous_hash: r.get(6)?,
            hash: r.get(7)?,
            hash_payload: r.get(8)?,
        })
    }

    fn payload(row: &ActionRecord) -> Value {
        json!({"sequence":row.sequence,"time_unix_ms":row.time_unix_ms,"request_id":row.request_id,"action":row.action,"detail":row.detail,"category":row.category})
    }

    fn initialize_chain(&mut self) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS audit_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit_receipts(public_key TEXT NOT NULL,nonce TEXT NOT NULL,PRIMARY KEY(public_key,nonce));")?;
        let columns: Vec<String> = {
            let mut statement = tx.prepare("PRAGMA table_info(actions)")?;
            statement
                .query_map([], |r| r.get(1))?
                .collect::<rusqlite::Result<_>>()?
        };
        for column in ["category", "previous_hash", "hash", "hash_payload"] {
            if !columns.iter().any(|v| v == column) {
                tx.execute_batch(&format!(
                    "ALTER TABLE actions ADD COLUMN {column} TEXT NOT NULL DEFAULT '';"
                ))?;
            }
        }
        let log_id: Option<String> = tx
            .query_row("SELECT value FROM audit_meta WHERE key='log_id'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if log_id.is_none() {
            let log_id = uuid::Uuid::new_v4().to_string();
            let rows: Vec<ActionRecord> = {
                let mut statement = tx.prepare("SELECT sequence,time,request_id,action,detail,category,previous_hash,hash,hash_payload FROM actions ORDER BY sequence")?;
                statement
                    .query_map([], Self::action_row)?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut previous = audit::genesis(&log_id);
            let mut last = 0;
            for mut row in rows {
                // A migration binds existing bytes, without claiming they were
                // protected before integrity tracking began.
                row.category = audit::category(&row.action, &row.detail).into();
                row.previous_hash = previous.clone();
                row.hash_payload = Self::payload(&row).to_string();
                row.hash = audit::event_hash(&log_id, &previous, &row.hash_payload);
                tx.execute("UPDATE actions SET category=?2,previous_hash=?3,hash=?4,hash_payload=?5 WHERE sequence=?1", params![row.sequence as i64,row.category,row.previous_hash,row.hash,row.hash_payload])?;
                previous = row.hash;
                last = row.sequence;
            }
            for (key, value) in [
                ("log_id", log_id),
                ("head_sequence", last.to_string()),
                ("head_hash", previous),
                ("legacy_through_sequence", last.to_string()),
            ] {
                tx.execute(
                    "INSERT INTO audit_meta(key,value) VALUES (?1,?2)",
                    params![key, value],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn checkpoint_from(db: &Connection) -> Result<audit::Checkpoint> {
        let value = |key: &str| -> Result<String> {
            Ok(
                db.query_row("SELECT value FROM audit_meta WHERE key=?1", [key], |r| {
                    r.get(0)
                })?,
            )
        };
        Ok(audit::Checkpoint {
            log_id: value("log_id")?,
            sequence: value("head_sequence")?.parse()?,
            hash: value("head_hash")?,
        })
    }

    fn insert_action(db: &Connection, id: Option<&str>, action: &str, detail: Value) -> Result<()> {
        let checkpoint = Self::checkpoint_from(db)?;
        let time = now();
        let category = audit::category(action, &detail);
        db.execute(
            "INSERT INTO actions(time,request_id,action,detail,category) VALUES (?1,?2,?3,?4,?5)",
            params![time as i64, id, action, detail.to_string(), category],
        )?;
        let sequence = db.last_insert_rowid() as u64;
        ensure!(
            sequence == checkpoint.sequence + 1,
            "audit sequence has a gap or rolled back"
        );
        let mut row = ActionRecord {
            sequence,
            time_unix_ms: time,
            request_id: id.map(str::to_owned),
            action: action.into(),
            detail,
            category: category.into(),
            previous_hash: checkpoint.hash,
            hash: String::new(),
            hash_payload: String::new(),
        };
        row.hash_payload = Self::payload(&row).to_string();
        row.hash = audit::event_hash(&checkpoint.log_id, &row.previous_hash, &row.hash_payload);
        db.execute(
            "UPDATE actions SET previous_hash=?2,hash=?3,hash_payload=?4 WHERE sequence=?1",
            params![
                sequence as i64,
                row.previous_hash,
                row.hash,
                row.hash_payload
            ],
        )?;
        db.execute(
            "UPDATE audit_meta SET value=?1 WHERE key='head_sequence'",
            [sequence.to_string()],
        )?;
        db.execute(
            "UPDATE audit_meta SET value=?1 WHERE key='head_hash'",
            [row.hash],
        )?;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<audit::Checkpoint> {
        let tx = self.0.unchecked_transaction()?;
        Self::checkpoint_from(&tx)
    }

    pub fn legacy_through_sequence(&self) -> Result<u64> {
        let value: String = self.0.query_row(
            "SELECT value FROM audit_meta WHERE key='legacy_through_sequence'",
            [],
            |r| r.get(0),
        )?;
        Ok(value.parse()?)
    }

    pub fn verify_chain(&self) -> Result<()> {
        let tx = self.0.unchecked_transaction()?;
        let checkpoint = Self::checkpoint_from(&tx)?;
        let legacy = self.legacy_through_sequence()?;
        let mut previous = audit::genesis(&checkpoint.log_id);
        let mut sequence = 0;
        let mut statement = tx.prepare("SELECT sequence,time,request_id,action,detail,category,previous_hash,hash,hash_payload FROM actions ORDER BY sequence")?;
        for row in statement.query_map([], Self::action_row)? {
            let row = row?;
            ensure!(
                row.sequence > sequence
                    && row.previous_hash == previous
                    && (row.sequence <= legacy || row.sequence == sequence + 1),
                "audit history gap at sequence {}",
                row.sequence
            );
            let payload: Value = serde_json::from_str(&row.hash_payload)?;
            ensure!(
                payload == Self::payload(&row)
                    && row.hash
                        == audit::event_hash(&checkpoint.log_id, &previous, &row.hash_payload),
                "audit history changed at sequence {}",
                row.sequence
            );
            previous = row.hash;
            sequence = row.sequence;
        }
        ensure!(
            sequence == checkpoint.sequence && previous == checkpoint.hash,
            "audit history truncated or checkpoint changed"
        );
        Ok(())
    }

    pub fn audit_page(&self, after: u64, through: u64, limit: usize) -> Result<Vec<ActionRecord>> {
        ensure!(
            after <= through && through <= self.checkpoint()?.sequence,
            "invalid audit snapshot range"
        );
        let mut statement = self.0.prepare("SELECT sequence,time,request_id,action,detail,category,previous_hash,hash,hash_payload FROM actions WHERE sequence>?1 AND sequence<=?2 ORDER BY sequence LIMIT ?3")?;
        let rows = statement.query_map(
            params![after as i64, through as i64, limit as i64],
            Self::action_row,
        )?;
        rows.map(|r| Ok(r?)).collect()
    }

    pub fn actor(
        &self,
        proof: Option<&audit::ActorProof>,
        transport: &audit::TransportActor,
        request: &Value,
        id: Option<&str>,
        peer_pid: Option<u32>,
    ) -> Result<Value> {
        let mut actor = json!({"unix_uid":crate::paths::current_uid(),"peer_pid":peer_pid,"transport":transport,"identity_scope":"receiver Unix account","operation_id":uuid::Uuid::new_v4().to_string()});
        if let Some(proof) = proof {
            let checkpoint = self.checkpoint()?;
            let fingerprint = proof.verify(&checkpoint.log_id, request)?;
            let tx = rusqlite::Transaction::new_unchecked(
                &self.0,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let observed_hash = if proof.checkpoint.sequence == 0 {
                audit::genesis(&checkpoint.log_id)
            } else {
                tx.query_row(
                    "SELECT hash FROM actions WHERE sequence=?1",
                    [i64::try_from(proof.checkpoint.sequence)?],
                    |r| r.get::<_, String>(0),
                )?
            };
            ensure!(
                proof.checkpoint.sequence <= checkpoint.sequence
                    && proof.checkpoint.hash == observed_hash,
                "signed audit checkpoint no longer matches receiver history"
            );
            tx.execute(
                "INSERT INTO audit_receipts(public_key,nonce) VALUES (?1,?2)",
                params![proof.public_key, proof.nonce],
            )
            .context("audit decision receipt was already used")?;
            actor["device_signing_key"] = json!(fingerprint);
            actor["device_key_evidence"] = json!("signature_verified");
            actor["receipt_id"] = json!(proof.nonce);
            let mut detail =
                json!({"actor":actor,"proof":proof,"request":audit::intent(request.clone())});
            if let Some(subject) = request.get("challenge_id").and_then(Value::as_str) {
                detail["challenge_id"] = json!(subject);
            }
            if let Some(subject) = request.get("proposal_id").and_then(Value::as_str) {
                detail["proposal_id"] = json!(subject);
            }
            if let Some(subject) = request.get("grant_id").and_then(Value::as_str) {
                detail["grant_id"] = json!(subject);
            }
            Self::insert_action(&tx, id, "signed_decision", detail)?;
            tx.commit()?;
        } else {
            actor["device_key_evidence"] = json!("not_provided");
        }
        Ok(actor)
    }

    pub fn open(config: &Path) -> Result<Self> {
        let path = config.with_extension("history.sqlite3");
        crate::paths::create_private_dir_all(path.parent().context("history path has no parent")?)?;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        crate::paths::trusted_path(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS rule_states(id TEXT PRIMARY KEY, principal TEXT NOT NULL, status TEXT NOT NULL, updated INTEGER NOT NULL, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS requests(sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, record TEXT NOT NULL, result TEXT);
            CREATE TABLE IF NOT EXISTS actions(sequence INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, request_id TEXT, action TEXT NOT NULL, detail TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS actions_request ON actions(request_id, sequence);
            CREATE TABLE IF NOT EXISTS job_output_state(request_id TEXT PRIMARY KEY, next_sequence INTEGER NOT NULL, retained_bytes INTEGER NOT NULL, truncated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS job_output(request_id TEXT NOT NULL, sequence INTEGER NOT NULL, stderr INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(request_id, sequence));")?;
        let mut history = Self(db);
        history.initialize_chain()?;
        history.verify_chain()?;
        Ok(history)
    }

    pub fn daemon_started(&mut self, config: &Path) -> Result<()> {
        let history = self;
        let unfinished: Vec<String> = {
            let mut q = history.0.prepare("SELECT record FROM requests WHERE json_extract(record, '$.status') IN ('received','pending','approved','allowed','running')")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        for text in unfinished {
            let mut record: RequestRecord = serde_json::from_str(&text)?;
            record.status = "interrupted".into();
            record.reason = "daemon stopped before the request finished".into();
            let reason = record.reason.clone();
            history.record(&mut record, "interrupted", json!({"reason":reason}))?;
        }
        // Human input is transient; a restart must leave a terminal audit trail.
        for (start, finish, detail) in [
            ("interaction_requested", "interaction_ended", "status"),
            ("interaction_ended", "interaction_result", "outcome"),
        ] {
            let interrupted: Vec<String> = {
                let mut q = history.0.prepare("SELECT json_extract(a.detail, '$.challenge_id') FROM actions a WHERE a.action=?1 AND (?1!='interaction_ended' OR json_extract(a.detail, '$.status')='answered') AND NOT EXISTS (SELECT 1 FROM actions b WHERE b.action=?2 AND json_extract(b.detail, '$.challenge_id')=json_extract(a.detail, '$.challenge_id'))")?;
                q.query_map(params![start, finish], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for id in interrupted {
                history.audit(
                    None,
                    finish,
                    json!({"challenge_id":id, detail:"interrupted", "evidence":"broker_observation"}),
                )?;
            }
        }
        history.audit(None, "daemon_started", json!({"config":config,"process_id":std::process::id(),"instance_id":uuid::Uuid::new_v4().to_string(),"chain_version":audit::VERSION}))?;
        Ok(())
    }

    pub fn rule_states(
        &self,
        principal: Option<&str>,
        live_only: bool,
    ) -> Result<Vec<crate::rules::RuleState>> {
        let mut q = self.0.prepare("SELECT record FROM rule_states WHERE (?1 IS NULL OR principal=?1) AND (?2=0 OR status IN ('pending','active')) ORDER BY (status IN ('pending','active')) DESC, updated DESC LIMIT 256")?;
        let rows = q.query_map(params![principal, live_only], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }

    pub fn save_rule_states(
        &mut self,
        rules: &[crate::rules::RuleState],
        action: &str,
    ) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for rule in rules {
            tx.execute("INSERT INTO rule_states(id,principal,status,updated,record) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET status=excluded.status,updated=excluded.updated,record=excluded.record", params![rule.proposal.id, rule.proposal.principal, rule.status, now() as i64, serde_json::to_string(rule)?])?;
            Self::insert_action(&tx, None, action, serde_json::to_value(rule)?)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn record(
        &mut self,
        record: &mut RequestRecord,
        action: &str,
        detail: Value,
    ) -> Result<()> {
        record.updated_unix_ms = now();
        let mut summary = record.clone();
        summary.result = None;
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO requests(id,record,result) VALUES (?1,?2,?3) ON CONFLICT(id) DO UPDATE SET record=excluded.record,result=excluded.result", params![record.request_id, serde_json::to_string(&summary)?, record.result.as_ref().map(serde_json::to_string).transpose()?])?;
        record.sequence = tx.query_row(
            "SELECT sequence FROM requests WHERE id=?1",
            [&record.request_id],
            |r| r.get::<_, i64>(0),
        )? as u64;
        Self::insert_action(&tx, Some(&record.request_id), action, detail.clone())?;
        tx.commit()?;
        tracing::info!(request_id=%record.request_id, principal=%record.principal, %action, %detail, "request action");
        Ok(())
    }

    pub fn reevaluated(
        &mut self,
        records: &[RequestRecord],
        revision: &str,
        rules: &[crate::rules::RuleState],
    ) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for rule in rules {
            tx.execute(
                "UPDATE rule_states SET status=?2,updated=?3,record=?4 WHERE id=?1",
                params![
                    rule.proposal.id,
                    rule.status,
                    now() as i64,
                    serde_json::to_string(rule)?
                ],
            )?;
            Self::insert_action(&tx, None, "rule_invalidated", serde_json::to_value(rule)?)?;
        }
        for record in records {
            tx.execute(
                "UPDATE requests SET record=?2 WHERE id=?1",
                params![record.request_id, serde_json::to_string(record)?],
            )?;
            Self::insert_action(
                &tx,
                Some(&record.request_id),
                "policy_re_evaluated",
                json!({"status":record.status,"reason":record.reason,"command":record.command,"cwd":record.cwd,"approval_id":record.approval_id,"revision":revision}),
            )?;
        }
        Self::insert_action(&tx, None, "policy_reloaded", json!({"revision":revision}))?;
        tx.commit()?;
        for record in records {
            tracing::info!(request_id=%record.request_id, status=%record.status, reason=%record.reason, %revision, "policy re-evaluated");
        }
        Ok(())
    }

    pub fn audit(&self, id: Option<&str>, action: &str, detail: Value) -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.0,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        Self::insert_action(&tx, id, action, detail.clone())?;
        tx.commit()?;
        tracing::info!(request_id=?id, %action, %detail, "daemon action");
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<RequestRecord> {
        let (sequence, text, result): (i64, String, Option<String>) = self
            .0
            .query_row(
                "SELECT sequence,record,result FROM requests WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .context("unknown request")?;
        let mut record: RequestRecord = serde_json::from_str(&text)?;
        record.sequence = sequence as u64;
        record.result = result.map(|text| serde_json::from_str(&text)).transpose()?;
        Ok(record)
    }

    pub fn list(
        &self,
        before: Option<u64>,
        limit: usize,
        query: Option<&str>,
    ) -> Result<Vec<RequestRecord>> {
        let mut q = self.0.prepare("SELECT sequence,record FROM requests WHERE sequence < ?1
            AND (?3 = '' OR EXISTS (SELECT 1 FROM json_tree(record) WHERE atom IS NOT NULL AND instr(lower(CAST(atom AS TEXT)), lower(?3)) > 0)
                OR instr(CASE json_extract(record, '$.status') WHEN 'completed' THEN 'finished' WHEN 'pending' THEN 'needs approval' ELSE '' END, lower(?3)) > 0)
            ORDER BY sequence DESC LIMIT ?2")?;
        let rows = q.query_map(
            params![
                before.unwrap_or(i64::MAX as u64).min(i64::MAX as u64) as i64,
                limit as i64,
                query.unwrap_or("").trim(),
            ],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )?;
        rows.map(|row| {
            let (sequence, text) = row?;
            let mut record: RequestRecord = serde_json::from_str(&text)?;
            record.sequence = sequence as u64;
            Ok(record)
        })
        .collect()
    }

    pub fn actions(
        &self,
        id: Option<&str>,
        before: Option<u64>,
        limit: usize,
        query: Option<&str>,
    ) -> Result<Vec<ActionRecord>> {
        self.filtered_actions(id, before, limit, query, None, true)
    }

    pub fn filtered_actions(
        &self,
        id: Option<&str>,
        before: Option<u64>,
        limit: usize,
        query: Option<&str>,
        subject_id: Option<&str>,
        include_reads: bool,
    ) -> Result<Vec<ActionRecord>> {
        let mut q = self.0.prepare("SELECT sequence,time,request_id,action,detail,category,previous_hash,hash,hash_payload FROM actions WHERE (?1 IS NULL OR request_id=?1) AND sequence < ?2
            AND (?4 = '' OR instr(lower(action || ' ' || replace(action, '_', ' ') || ' ' || coalesce(request_id, '')), lower(?4)) > 0
                OR EXISTS (SELECT 1 FROM json_tree(detail) WHERE atom IS NOT NULL AND instr(lower(CAST(atom AS TEXT)), lower(?4)) > 0))
            AND (?5 IS NULL OR request_id=?5 OR json_extract(detail,'$.challenge_id')=?5 OR json_extract(detail,'$.session_id')=?5 OR json_extract(detail,'$.recipient.session_id')=?5 OR json_extract(detail,'$.proposal.id')=?5 OR json_extract(detail,'$.grant_id')=?5 OR json_extract(detail,'$.proposal_id')=?5 OR json_extract(detail,'$.actor.receipt_id')=?5 OR json_extract(detail,'$.actor.operation_id')=?5)
            AND (?6 OR category!='read')
            ORDER BY sequence DESC LIMIT ?3")?;
        let rows = q.query_map(
            params![
                id,
                before.unwrap_or(i64::MAX as u64).min(i64::MAX as u64) as i64,
                limit as i64,
                query.unwrap_or("").trim(),
                subject_id,
                include_reads,
            ],
            Self::action_row,
        )?;
        rows.map(|row| Ok(row?)).collect()
    }

    pub fn append_output(
        &mut self,
        id: &str,
        stderr: bool,
        data: &[u8],
        max_bytes: usize,
    ) -> Result<bool> {
        let partial = data.len() > max_bytes;
        let data = &data[data.len().saturating_sub(max_bytes)..];
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (sequence, mut retained, mut truncated): (i64, i64, bool) = tx
            .query_row(
                "SELECT next_sequence, retained_bytes, truncated FROM job_output_state WHERE request_id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
            )
            .optional()?
            .unwrap_or((1, 0, false));
        truncated |= partial;
        tx.execute(
            "INSERT INTO job_output(request_id,sequence,stderr,data) VALUES (?1,?2,?3,?4)",
            params![id, sequence, stderr, data],
        )?;
        retained += data.len() as i64;
        while retained > max_bytes as i64 {
            let (old_sequence, size): (i64, i64) = tx.query_row(
                "SELECT sequence,length(data) FROM job_output WHERE request_id=?1 ORDER BY sequence LIMIT 1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            tx.execute(
                "DELETE FROM job_output WHERE request_id=?1 AND sequence=?2",
                params![id, old_sequence],
            )?;
            retained -= size;
            truncated = true;
        }
        tx.execute(
            "INSERT INTO job_output_state(request_id,next_sequence,retained_bytes,truncated) VALUES (?1,?2,?3,?4) ON CONFLICT(request_id) DO UPDATE SET next_sequence=excluded.next_sequence,retained_bytes=excluded.retained_bytes,truncated=excluded.truncated",
            params![id, sequence + 1, retained, truncated],
        )?;
        tx.commit()?;
        Ok(truncated)
    }

    pub fn output(
        &self,
        id: &str,
        after: u64,
        limit: usize,
    ) -> Result<(u64, bool, Vec<OutputChunk>)> {
        let (next, truncated): (i64, bool) = self
            .0
            .query_row(
                "SELECT next_sequence, truncated FROM job_output_state WHERE request_id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?
            .unwrap_or((1, false));
        let first: i64 = self
            .0
            .query_row(
                "SELECT MIN(sequence) FROM job_output WHERE request_id=?1",
                [id],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(next);
        let mut q = self.0.prepare(
            "SELECT sequence,stderr,data FROM job_output WHERE request_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3",
        )?;
        let rows = q.query_map(
            params![id, after.min(i64::MAX as u64) as i64, limit as i64],
            |row| {
                Ok(OutputChunk {
                    sequence: row.get::<_, i64>(0)? as u64,
                    stderr: row.get::<_, i64>(1)? != 0,
                    data: row.get(2)?,
                })
            },
        )?;
        Ok((
            first as u64,
            truncated,
            rows.collect::<rusqlite::Result<Vec<_>>>()?,
        ))
    }

    pub fn retained_output(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>, bool)> {
        let truncated: bool = self
            .0
            .query_row(
                "SELECT truncated FROM job_output_state WHERE request_id=?1",
                [id],
                |row| Ok(row.get::<_, i64>(0)? != 0),
            )
            .optional()?
            .unwrap_or(false);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut q = self
            .0
            .prepare("SELECT stderr,data FROM job_output WHERE request_id=?1 ORDER BY sequence")?;
        let rows = q.query_map([id], |row| {
            Ok((row.get::<_, i64>(0)? != 0, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (is_stderr, data) = row?;
            if is_stderr {
                stderr.extend(data);
            } else {
                stdout.extend(data);
            }
        }
        Ok((stdout, stderr, truncated))
    }
}
