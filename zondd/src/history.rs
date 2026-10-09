use crate::security;
use anyhow::{Context, Result};
use libzond::{ActionRecord, RequestRecord};
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

pub struct History(Connection);
impl History {
    pub fn open(config: &Path) -> Result<Self> {
        let path = config.with_extension("history.sqlite3");
        libzond::paths::create_private_dir_all(
            path.parent().context("history path has no parent")?,
        )?;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        security::trusted_path(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS requests(sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, record TEXT NOT NULL, result TEXT);
            CREATE TABLE IF NOT EXISTS actions(sequence INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, request_id TEXT, action TEXT NOT NULL, detail TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS actions_request ON actions(request_id, sequence);")?;
        let mut history = Self(db);
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
        history.audit(None, "daemon_started", json!({"config":config}))?;
        Ok(history)
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
        let tx = self.0.transaction()?;
        tx.execute("INSERT INTO requests(id,record,result) VALUES (?1,?2,?3) ON CONFLICT(id) DO UPDATE SET record=excluded.record,result=excluded.result", params![record.request_id, serde_json::to_string(&summary)?, record.result.as_ref().map(serde_json::to_string).transpose()?])?;
        record.sequence = tx.query_row(
            "SELECT sequence FROM requests WHERE id=?1",
            [&record.request_id],
            |r| r.get::<_, i64>(0),
        )? as u64;
        tx.execute(
            "INSERT INTO actions(time,request_id,action,detail) VALUES (?1,?2,?3,?4)",
            params![
                record.updated_unix_ms as i64,
                record.request_id,
                action,
                detail.to_string()
            ],
        )?;
        tx.commit()?;
        tracing::info!(request_id=%record.request_id, principal=%record.principal, %action, %detail, "request action");
        Ok(())
    }

    pub fn reevaluated(&mut self, records: &[RequestRecord], revision: &str) -> Result<()> {
        let tx = self.0.transaction()?;
        for record in records {
            tx.execute(
                "UPDATE requests SET record=?2 WHERE id=?1",
                params![record.request_id, serde_json::to_string(record)?],
            )?;
            tx.execute("INSERT INTO actions(time,request_id,action,detail) VALUES (?1,?2,'policy_re_evaluated',?3)", params![now() as i64, record.request_id, json!({"status":record.status,"reason":record.reason,"command":record.command,"cwd":record.cwd,"approval_id":record.approval_id,"revision":revision}).to_string()])?;
        }
        tx.execute(
            "INSERT INTO actions(time,action,detail) VALUES (?1,'policy_reloaded',?2)",
            params![now() as i64, json!({"revision":revision}).to_string()],
        )?;
        tx.commit()?;
        for record in records {
            tracing::info!(request_id=%record.request_id, status=%record.status, reason=%record.reason, %revision, "policy re-evaluated");
        }
        Ok(())
    }

    pub fn audit(&self, id: Option<&str>, action: &str, detail: Value) -> Result<()> {
        self.0.execute(
            "INSERT INTO actions(time,request_id,action,detail) VALUES (?1,?2,?3,?4)",
            params![now() as i64, id, action, detail.to_string()],
        )?;
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

    pub fn list(&self, before: Option<u64>, limit: usize) -> Result<Vec<RequestRecord>> {
        let mut q = self.0.prepare("SELECT sequence,record FROM requests WHERE sequence < ?1 ORDER BY sequence DESC LIMIT ?2")?;
        let rows = q.query_map(
            params![
                before.unwrap_or(i64::MAX as u64).min(i64::MAX as u64) as i64,
                limit as i64
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
    ) -> Result<Vec<ActionRecord>> {
        let mut q = self.0.prepare("SELECT sequence,time,request_id,action,detail FROM actions WHERE (?1 IS NULL OR request_id=?1) AND sequence < ?2 ORDER BY sequence DESC LIMIT ?3")?;
        let rows = q.query_map(
            params![
                id,
                before.unwrap_or(i64::MAX as u64).min(i64::MAX as u64) as i64,
                limit as i64
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (sequence, time_unix_ms, request_id, action, text) = row?;
            Ok(ActionRecord {
                sequence: sequence as u64,
                time_unix_ms: time_unix_ms as u64,
                request_id,
                action,
                detail: serde_json::from_str(&text)?,
            })
        })
        .collect()
    }
}
