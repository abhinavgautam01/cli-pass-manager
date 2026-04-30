use std::{
    io::Write,
    process::{Command, Stdio},
};

use serde_json::Value;
use tempfile::tempdir;

use freaky_vault::vault::{Vault, VaultData};

const MASTER: &str = "correct horse 42";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_freaky-vault")
}

fn prepared_vault() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json.enc");
    let vault = Vault::new(path.clone());
    vault.init(MASTER, false).unwrap();
    let mut data = VaultData::default();
    data.set("github-personal".to_string(), "token\nvalue".to_string());
    data.set("linear".to_string(), "lin_secret".to_string());
    vault.write(&data, MASTER).unwrap();
    (dir, path)
}

fn run_with_stdin(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn api_get_returns_strict_json_success() {
    let (_dir, path) = prepared_vault();
    let output = run_with_stdin(
        &[
            "--vault",
            path.to_str().unwrap(),
            "api",
            "get",
            "--key",
            "github-personal",
        ],
        &format!("{MASTER}\n"),
    );

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["command"], "api get");
    assert_eq!(response["data"]["key"], "github-personal");
    assert_eq!(response["data"]["value"], "token\nvalue");
}

#[test]
fn api_list_returns_keys_only() {
    let (_dir, path) = prepared_vault();
    let output = run_with_stdin(
        &["--vault", path.to_str().unwrap(), "api", "list"],
        &format!("{MASTER}\n"),
    );

    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"]["keys"].as_array().unwrap().len(), 2);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("lin_secret"));
}

#[test]
fn api_get_missing_vault_returns_json_error_without_json_flag() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("missing.enc");
    let output = run_with_stdin(
        &[
            "--vault",
            path.to_str().unwrap(),
            "api",
            "get",
            "--key",
            "github-personal",
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["command"], "api get");
    assert_eq!(response["error"]["code"], "vault_missing");
}

#[test]
fn human_get_requires_interactive_master_key_prompt() {
    let (_dir, path) = prepared_vault();
    let output = Command::new(binary())
        .args(["--vault", path.to_str().unwrap(), "get", "github-personal"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Use --master-key-stdin for non-interactive use")
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("token"));
}

#[test]
fn non_interactive_get_works_with_master_key_stdin() {
    let (_dir, path) = prepared_vault();
    let output = run_with_stdin(
        &[
            "--master-key-stdin",
            "--vault",
            path.to_str().unwrap(),
            "get",
            "github-personal",
        ],
        &format!("{MASTER}\n"),
    );

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "token\nvalue\n");
}

#[test]
fn set_stdin_rejects_master_key_stdin_combo() {
    let (_dir, path) = prepared_vault();
    let output = run_with_stdin(
        &[
            "--master-key-stdin",
            "--vault",
            path.to_str().unwrap(),
            "set",
            "new-key",
            "--stdin",
        ],
        &format!("{MASTER}\nsecret\n"),
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("cannot be combined with `--master-key-stdin`")
    );
}

#[test]
fn valut_alias_is_supported() {
    let (_dir, path) = prepared_vault();
    let output = run_with_stdin(
        &["--valut", path.to_str().unwrap(), "api", "list"],
        &format!("{MASTER}\n"),
    );

    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], true);
}
