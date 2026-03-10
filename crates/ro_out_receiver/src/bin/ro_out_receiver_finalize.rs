use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use ro_out_receiver::build_bundle;

const PASS_LINE: &str = "PASS: evidence_bundle";
const FAIL_IO: &str = "FAIL: FINALIZE_IO";
const FAIL_BUILD: &str = "FAIL: FINALIZE_BUILD";
const FAIL_CHECK: &str = "FAIL: FINALIZE_CHECK";

fn main() {
    match run_finalize() {
        Ok(true) => println!("{PASS_LINE}"),
        Ok(false) => {
            println!("{FAIL_CHECK}");
            std::process::exit(1);
        }
        Err(code) => {
            println!("{code}");
            std::process::exit(1);
        }
    }
}

fn run_finalize() -> Result<bool, &'static str> {
    let args: Vec<String> = env::args().collect();
    let runs_dir = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/enterprise"));
    let audit_key_path = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("secrets/audit_key.bin"));

    let audit_key = fs::read(&audit_key_path).map_err(|_| FAIL_IO)?;
    let bundle = build_bundle(&runs_dir, &audit_key).map_err(|_| FAIL_BUILD)?;

    let bundle_dir = runs_dir.join("evidence_bundle");
    fs::create_dir_all(&bundle_dir).map_err(|_| FAIL_IO)?;

    write_json(&bundle_dir.join("manifest.json"), &bundle.manifest)?;
    write_json(&bundle_dir.join("comparisons.json"), &bundle.comparisons)?;
    write_json(
        &bundle_dir.join("bucket_policy.json"),
        &bundle.bucket_policy,
    )?;
    write_json(
        &bundle_dir.join("chain_verification.json"),
        &bundle.chain_verification,
    )?;
    write_json(&bundle_dir.join("approvals.json"), &bundle.approvals)?;
    write_json(&bundle_dir.join("replay.json"), &bundle.replay)?;

    let comparisons_pass = bundle.comparisons.iter().all(|c| c.pass);
    let bucket_policy_pass = bundle.bucket_policy.values().all(|p| p.pass);
    let chain_pass = bundle.chain_verification.values().all(|c| c.pass);
    let approvals_pass = bundle.approvals.values().all(|a| a.pass);
    let replay_pass = bundle.replay.values().all(|r| r.within_run_pass);

    let mut checks = BTreeMap::new();
    checks.insert("comparisons", comparisons_pass);
    checks.insert("bucket_policy", bucket_policy_pass);
    checks.insert("chain_verification", chain_pass);
    checks.insert("approvals", approvals_pass);
    checks.insert("replay", replay_pass);

    let summary = serde_json::json!({
        "pass": bundle.pass,
        "checks": checks,
    });
    let proof_report_dir = runs_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| runs_dir.clone());
    let proof_report = proof_report_dir.join("proof_report_enterprise.json");
    write_json(&proof_report, &summary)?;

    Ok(bundle.pass)
}

fn write_json(path: &PathBuf, value: &impl serde::Serialize) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| FAIL_IO)?;
    fs::write(path, bytes).map_err(|_| FAIL_IO)?;
    Ok(())
}
