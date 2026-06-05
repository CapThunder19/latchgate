//! `latchgate audit` — query the audit trail.

use serde_json::json;

use latchgate_config::Config;

use crate::client::{AuditParams, GateClient};
use crate::cmd::text::truncate;
use crate::output::{print_json, Printer};

/// Run the `audit` command. Returns exit code.
pub async fn run(
    config: &Config,
    auth: &crate::OperatorAuth,
    params: AuditParams,
    pr: &Printer,
) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };
    let limit = params.limit.unwrap_or(20);

    let events = match client.audit_events(auth, &params).await {
        Ok(e) => e,
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Cannot reach gate: {e}"));
                pr.blank();
            }
            return 1;
        }
    };

    if pr.json {
        print_json(&json!({ "events": events }));
        return 0;
    }

    pr.blank();

    if events.is_empty() {
        pr.info("No audit events match the filter.");
        pr.blank();
        return 0;
    }

    // Header
    let act_w = events
        .iter()
        .filter_map(|e| e["action_id"].as_str())
        .map(|s| s.len())
        .max()
        .unwrap_or(9)
        .max(9);

    println!(
        "  {ts:<19}  {dec:<7}  {act:<act_w$}  {principal}",
        ts = pr.dim("timestamp"),
        dec = pr.dim("decision"),
        act = pr.dim("action"),
        principal = pr.dim("principal"),
    );
    println!(
        "  {}  {}  {}  {}",
        pr.dim(&"─".repeat(19)),
        pr.dim(&"─".repeat(7)),
        pr.dim(&"─".repeat(act_w)),
        pr.dim(&"─".repeat(20)),
    );

    for ev in &events {
        let ts = ev["timestamp"].as_str().unwrap_or("?");
        let ts_short = &ts[..ts.len().min(19)]; // "2025-01-01T12:00:00"
        let dec = ev["decision"].as_str().unwrap_or("?");
        let action_id = ev["action_id"].as_str().unwrap_or("-");
        let principal = ev["principal"].as_str().unwrap_or("-");

        let dec_col = match dec {
            "allow" => pr.green(dec),
            "allow_unverified" => pr.yellow("allow⚠"),
            "deny" => pr.red(dec),
            "pending_approval" => pr.yellow("pending"),
            "error" => pr.yellow(dec),
            other => pr.dim(other),
        };

        println!(
            "  {ts:<19}  {dec:<7}  {act:<act_w$}  {principal}",
            ts = pr.dim(ts_short),
            dec = dec_col,
            act = action_id,
            principal = pr.dim(&truncate(principal, 32)),
        );

        // Surface the deny/error reason inline if present
        if dec != "allow" {
            if let Some(reason) = ev["reason"].as_str().filter(|s| !s.is_empty()) {
                println!("  {}", pr.dim(&format!("  └─ {reason}")),);
            }
        }
    }

    println!(
        "\n  {} event(s){}",
        events.len(),
        if events.len() == limit {
            format!(
                "  ·  {}",
                pr.dim(&format!("showing latest {limit}; use --limit to see more"))
            )
        } else {
            String::new()
        },
    );
    pr.blank();
    0
}
