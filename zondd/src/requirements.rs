use crate::{create_new, execution};
use anyhow::{Context, Result, ensure};
use libzond::{Command, Event, rules::ResolvedRequirement};
use std::{collections::BTreeMap, path::Path, time::Duration};

pub async fn check(requirements: &[ResolvedRequirement], cwd: &Path) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for requirement in requirements {
            if requirement.kind == "user-service-active-or-enabled" {
                let unit = requirement.path.to_str().context("non-UTF8 service name")?;
                user_service(unit, cwd)
                    .await
                    .with_context(|| format!("require user-service-active-or-enabled {unit}"))?;
            } else {
                create_new::check(std::slice::from_ref(requirement))?;
            }
        }
        Ok(())
    })
    .await
    .context("rule checks timed out after 5 seconds")?
}

async fn user_service(unit: &str, cwd: &Path) -> Result<()> {
    ensure!(
        libzond::rules::valid_service_unit(unit),
        "invalid service name"
    );
    let command = Command {
        program: "/usr/bin/systemctl".into(),
        args: [
            "--user",
            "--no-pager",
            "--no-ask-password",
            "show",
            "--property=LoadState,ActiveState,UnitFileState",
            "--",
            unit,
        ]
        .map(str::to_owned)
        .into(),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    // Use the same session bus and restricted environment as the reviewed command.
    // Dropping this future on timeout or cancellation kills and reaps the query process.
    let result = execution::execute(&command, cwd, None, |is_err, bytes| {
        ensure!(
            stdout.len() + stderr.len() + bytes.len() <= 16 * 1024,
            "service query output exceeded limit"
        );
        if is_err { &mut stderr } else { &mut stdout }.extend_from_slice(bytes);
        Ok(())
    })
    .await?;
    ensure!(
        matches!(
            result,
            Event::Completed {
                code: Some(0),
                signal: None,
                ..
            }
        ),
        "cannot query systemd user manager: {}",
        String::from_utf8_lossy(&stderr).trim()
    );
    check_service_state(std::str::from_utf8(&stdout).context("invalid service query output")?)
}

fn check_service_state(output: &str) -> Result<()> {
    let mut properties = BTreeMap::new();
    for line in output.lines() {
        let (key, value) = line.split_once('=').context("malformed service state")?;
        ensure!(
            matches!(key, "LoadState" | "ActiveState" | "UnitFileState")
                && properties.insert(key, value).is_none(),
            "unexpected or duplicate service state property"
        );
    }
    let load = properties.get("LoadState").context("missing LoadState")?;
    let active = properties
        .get("ActiveState")
        .context("missing ActiveState")?;
    let enabled = properties
        .get("UnitFileState")
        .context("missing UnitFileState")?;
    ensure!(
        *load == "loaded",
        "service is not loaded (LoadState={load})"
    );
    ensure!(
        *active == "active" || matches!(*enabled, "enabled" | "enabled-runtime"),
        "service is neither active nor enabled (ActiveState={active}, UnitFileState={enabled})"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_active_or_explicitly_enabled_loaded_services_pass() {
        for (load, active, enabled, allowed) in [
            ("loaded", "active", "disabled", true),
            ("loaded", "active", "static", true),
            ("loaded", "active", "", true),
            ("loaded", "inactive", "enabled", true),
            ("loaded", "failed", "enabled", true),
            ("loaded", "inactive", "enabled-runtime", true),
            ("loaded", "failed", "enabled-runtime", true),
            ("loaded", "inactive", "disabled", false),
            ("loaded", "failed", "disabled", false),
            ("loaded", "activating", "disabled", false),
            ("loaded", "deactivating", "disabled", false),
            ("loaded", "inactive", "static", false),
            ("loaded", "inactive", "indirect", false),
            ("loaded", "inactive", "alias", false),
            ("loaded", "inactive", "generated", false),
            ("loaded", "inactive", "transient", false),
            ("loaded", "inactive", "linked", false),
            ("loaded", "inactive", "", false),
            ("not-found", "inactive", "enabled", false),
            ("masked", "active", "enabled", false),
            ("error", "active", "enabled", false),
            ("bad-setting", "active", "enabled", false),
        ] {
            let state =
                format!("LoadState={load}\nActiveState={active}\nUnitFileState={enabled}\n");
            assert_eq!(check_service_state(&state).is_ok(), allowed, "{state}");
        }
    }

    #[test]
    fn missing_or_ambiguous_properties_fail_closed() {
        for output in [
            "",
            "active\nenabled\n",
            "LoadState=loaded\nActiveState=active\n",
            "LoadState=loaded\nUnitFileState=enabled\n",
            "ActiveState=active\nUnitFileState=enabled\n",
            "LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled\nActiveState=active\n",
            "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nUnknown=true\n",
        ] {
            assert!(check_service_state(output).is_err(), "{output}");
        }
    }
}
