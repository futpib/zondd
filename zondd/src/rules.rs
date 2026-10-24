use crate::history::{History, now};
use anyhow::{Context, Result, ensure};
use libzond::{
    config::{Config, revision},
    rules::{BoundRule, Invocation, Proposal, RuleState},
};
use std::{collections::BTreeMap, path::PathBuf};

mod migration;
mod review;

#[derive(Clone)]
pub struct Rules(pub BTreeMap<String, RuleState>);

fn principal_revision(config: &Config, principal: &str) -> Result<String> {
    Ok(revision(&serde_json::to_string(
        config
            .principals
            .get(principal)
            .context("principal is no longer configured")?,
    )?))
}

fn compile(source: &str) -> Result<libzond::rules::Rule> {
    resolve_program(libzond::rules::parse(source)?)
}

fn resolve_program(mut rule: libzond::rules::Rule) -> Result<libzond::rules::Rule> {
    if rule.program == "~" || rule.program.starts_with("~/") {
        rule.program = libzond::paths::home_dir()
            .join(rule.program.strip_prefix("~/").unwrap_or(""))
            .to_str()
            .context("non-UTF8 home executable")?
            .into();
    }
    let program = if rule.program.contains('/') {
        let path = PathBuf::from(&rule.program);
        ensure!(path.is_absolute(), "executable paths must be absolute");
        path
    } else {
        ["/usr/bin", "/bin"]
            .iter()
            .map(|dir| PathBuf::from(dir).join(&rule.program))
            .find(|p| p.is_file())
            .context("executable not found in /usr/bin:/bin")?
    };
    let program = std::fs::canonicalize(program).context("resolve executable")?;
    libzond::paths::trusted_path(&program)?;
    ensure!(program.is_file(), "executable must be a file");
    rule.program = program.to_str().context("non-UTF8 executable")?.into();
    Ok(rule)
}

fn check_stored(proposal: &Proposal) -> Result<()> {
    ensure!(
        compile(&proposal.source)? == proposal.bound.rule,
        "rule source and compiled definition disagree"
    );
    ensure!(
        std::path::Path::new(&proposal.bound.home) == libzond::paths::home_dir(),
        "rule HOME binding changed"
    );
    let mut unsigned = proposal.clone();
    unsigned.digest.clear();
    ensure!(
        revision(&serde_json::to_string(&unsigned)?) == proposal.digest,
        "rule proposal digest does not match its contents"
    );
    Ok(())
}

impl Rules {
    pub fn revision(&self, principal: Option<&str>) -> Result<String> {
        let states: Vec<_> = self
            .0
            .values()
            .filter(|s| principal.is_none_or(|p| s.proposal.principal == p))
            .collect();
        Ok(revision(&serde_json::to_string(&states)?))
    }

    pub fn load(history: &mut History) -> Result<Self> {
        history.migrate_rule_states(migration::migrate)?;
        let mut live = BTreeMap::new();
        let mut invalid = Vec::new();
        for mut state in history.rule_states(None, true)? {
            // Review changes have their own invalidation reason during refresh.
            if review::is_current(&state.proposal.bound, state.proposal.review.as_ref())
                && let Err(error) = check_stored(&state.proposal)
            {
                state.status = "invalidated".into();
                state.reason = format!(
                    "stored proposal failed consistency checks: {error:#}; submit a new proposal"
                );
                invalid.push(state);
            } else {
                live.insert(state.proposal.id.clone(), state);
            }
        }
        history.save_rule_states(&invalid, "rule_invalidated")?;
        Ok(Self(live))
    }

    pub fn invalidated(&self, config: &Config, current_revision: &str) -> Vec<RuleState> {
        let mut changed = Vec::new();
        for state in self.0.values() {
            let proposal = &state.proposal;
            let expiry = if state.status == "pending" {
                Some(proposal.expires_unix_ms)
            } else {
                state.grant_expires_unix_ms
            };
            let reason = if expiry.is_some_and(|e| e <= now()) {
                Some(("expired", "rule or proposal expired"))
            } else if !review::is_current(&proposal.bound, proposal.review.as_ref()) {
                Some((
                    "invalidated",
                    "rule review changed or is missing; submit a new proposal",
                ))
            } else if principal_revision(config, &proposal.principal)
                .ok()
                .as_ref()
                != Some(&proposal.principal_revision)
                || config.operations.contains_key(&proposal.bound.rule.name)
                || config
                    .principals
                    .get(&proposal.principal)
                    .is_some_and(|p| p.cwd != proposal.bound.cwd)
            {
                Some((
                    "invalidated",
                    "principal policy changed or operation name was claimed by configuration",
                ))
            } else if state.status == "pending"
                && (proposal.revision != current_revision || !config.approvals.enabled)
            {
                Some((
                    "invalidated",
                    "policy changed before rule approval; submit a new proposal",
                ))
            } else {
                None
            };
            if let Some((status, reason)) = reason {
                let mut state = state.clone();
                state.status = status.into();
                state.reason = reason.into();
                changed.push(state);
            }
        }
        changed
    }

    pub fn refresh(
        &mut self,
        config: &Config,
        current_revision: &str,
        history: &mut History,
    ) -> Result<()> {
        let changed = self.invalidated(config, current_revision);
        if !changed.is_empty() {
            history.save_rule_states(&changed, "rules_invalidated")?;
            for state in changed {
                self.0.remove(&state.proposal.id);
            }
        }
        Ok(())
    }

    pub fn proposals(&self) -> Vec<Proposal> {
        self.0
            .values()
            .filter(|s| s.status == "pending")
            .map(|s| s.proposal.clone())
            .collect()
    }

    pub fn invoke(&self, principal: &str, name: &str, args: &[String]) -> Result<Invocation> {
        let state = self
            .0
            .values()
            .find(|s| {
                s.status == "active"
                    && s.proposal.principal == principal
                    && s.proposal.bound.rule.name == name
            })
            .context("operation or rule is not authorized")?;
        ensure!(
            state.grant_expires_unix_ms.is_none_or(|e| e > now()),
            "rule expired"
        );
        state
            .proposal
            .bound
            .instantiate(&state.proposal.id, args, None)
    }

    pub fn propose(
        &mut self,
        config: &Config,
        current_revision: &str,
        principal: &str,
        source: String,
        history: &mut History,
        pending_commands: usize,
    ) -> Result<Proposal> {
        ensure!(
            config.approvals.enabled,
            "rule proposals require enabled approvals"
        );
        ensure!(
            self.proposals().len() + pending_commands < config.approvals.max_pending.min(64),
            "approval queue full"
        );
        ensure!(self.0.len() < 192, "rule capacity exhausted");
        let rule = compile(&source)?;
        ensure!(
            !config.operations.contains_key(&rule.name),
            "rule name conflicts with configured operation"
        );
        ensure!(
            !self
                .0
                .values()
                .any(|s| s.proposal.principal == principal
                    && s.proposal.bound.rule.name == rule.name),
            "rule already active or pending; withdraw it before proposing a replacement"
        );
        let bound = BoundRule {
            rule,
            home: libzond::paths::home_dir()
                .to_str()
                .context("non-UTF8 home")?
                .into(),
            cwd: config
                .principals
                .get(principal)
                .context("unknown principal")?
                .cwd
                .clone(),
        };
        bound.validate_template()?;
        let mut proposal = Proposal {
            id: uuid::Uuid::new_v4().to_string(),
            principal: principal.into(),
            source,
            review: Some(review::describe(&bound)?),
            bound,
            digest: String::new(),
            revision: current_revision.into(),
            principal_revision: principal_revision(config, principal)?,
            created_unix_ms: now(),
            expires_unix_ms: now() + config.approvals.timeout_secs * 1000,
        };
        proposal.digest = revision(&serde_json::to_string(&proposal)?);
        ensure!(
            serde_json::to_vec(&proposal)?.len() <= 12 * 1024,
            "compiled rule exceeds 12 KiB; simplify the proposal"
        );
        let state = RuleState {
            proposal: proposal.clone(),
            status: "pending".into(),
            reason: "awaiting approval of reusable rule".into(),
            grant_expires_unix_ms: None,
        };
        history.save_rule_states(std::slice::from_ref(&state), "rule_proposed")?;
        self.0.insert(proposal.id.clone(), state);
        Ok(proposal)
    }

    pub fn resolve(
        &mut self,
        id: &str,
        digest: &str,
        approve: bool,
        expires_in_secs: Option<u64>,
        history: &mut History,
    ) -> Result<RuleState> {
        let mut state = self
            .0
            .get(id)
            .filter(|s| s.status == "pending")
            .context("rule proposal is no longer pending")?
            .clone();
        ensure!(
            state.proposal.digest == digest,
            "rule digest changed; review the exact proposal"
        );
        ensure!(
            state.proposal.expires_unix_ms > now(),
            "rule proposal expired"
        );
        if approve {
            ensure!(
                self.0.values().filter(|s| s.status == "active").count() < 128,
                "active rule limit reached"
            );
        }
        state.grant_expires_unix_ms = if approve {
            expires_in_secs
                .map(|seconds| {
                    ensure!(
                        (1..=31_536_000).contains(&seconds),
                        "grant lifetime must be 1 second to 365 days"
                    );
                    Ok(now() + seconds * 1000)
                })
                .transpose()?
        } else {
            None
        };
        state.status = if approve { "active" } else { "denied" }.into();
        state.reason = if approve {
            "reusable rule approved"
        } else {
            "rule proposal denied"
        }
        .into();
        history.save_rule_states(
            std::slice::from_ref(&state),
            if approve {
                "rule_approved"
            } else {
                "rule_denied"
            },
        )?;
        if approve {
            self.0.insert(id.into(), state.clone());
        } else {
            self.0.remove(id);
        }
        Ok(state)
    }

    pub fn withdraw(
        &mut self,
        principal: &str,
        id: &str,
        history: &mut History,
    ) -> Result<RuleState> {
        let mut state = self
            .0
            .get(id)
            .filter(|s| s.proposal.principal == principal)
            .context("unknown submission")?
            .clone();
        state.status = "withdrawn".into();
        state.reason = "rule withdrawn by caller".into();
        history.save_rule_states(std::slice::from_ref(&state), "rule_withdrawn")?;
        self.0.remove(id);
        Ok(state)
    }

    pub fn revoke(&mut self, id: &str, history: &mut History) -> Result<()> {
        let mut state = self
            .0
            .get(id)
            .filter(|s| s.status == "active")
            .context("unknown active rule")?
            .clone();
        state.status = "revoked".into();
        state.reason = "rule revoked by administrator".into();
        history.save_rule_states(&[state], "rule_revoked")?;
        self.0.remove(id);
        Ok(())
    }
}
