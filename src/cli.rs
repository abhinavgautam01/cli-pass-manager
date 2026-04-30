use std::io::Write;

use clap::{Parser, Subcommand};
use colored::Colorize;
use is_terminal::IsTerminal;
use serde::Serialize;
use serde_json::json;
use zeroize::Zeroize;

use crate::{
    error::{AppError, AppResult},
    output::JsonResponse,
    vault::{self, Vault, validate_key, validate_value},
};

#[derive(Debug, Parser)]
#[command(name = "freaky-vault")]
#[command(about = "A local-first encrypted password vault")]
#[command(version)]
pub struct Cli {
    #[arg(long, visible_alias = "valut", global = true)]
    pub vault: Option<std::path::PathBuf>,

    #[arg(long, global = true)]
    pub json: bool,

    #[arg(long, global = true)]
    pub no_color: bool,

    #[arg(long, global = true, value_parser = ["auto", "always", "never"])]
    pub color: Option<String>,

    #[arg(long, global = true)]
    pub quiet: bool,

    #[arg(long, global = true)]
    pub verbose: bool,

    #[arg(
        long,
        global = true,
        help = "Read master key from stdin for non-interactive use"
    )]
    pub master_key_stdin: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init {
        #[arg(long)]
        force: bool,
    },
    Set {
        key: Option<String>,
        value: Option<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        allow_empty: bool,
    },
    Get {
        key: String,
    },
    List,
    Delete {
        key: String,
        #[arg(long)]
        yes: bool,
    },
    Rename {
        old: String,
        new: String,
        #[arg(long)]
        overwrite: bool,
    },
    Doctor,
    ChangeMasterKey,
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Init { .. } => "init",
            Command::Set { .. } => "set",
            Command::Get { .. } => "get",
            Command::List => "list",
            Command::Delete { .. } => "delete",
            Command::Rename { .. } => "rename",
            Command::Doctor => "doctor",
            Command::ChangeMasterKey => "change-master-key",
            Command::Api { command } => command.name(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ApiCommand {
    Get {
        #[arg(long)]
        key: String,
    },
    List,
    Doctor,
}

impl ApiCommand {
    pub fn name(&self) -> &'static str {
        match self {
            ApiCommand::Get { .. } => "api get",
            ApiCommand::List => "api list",
            ApiCommand::Doctor => "api doctor",
        }
    }
}

#[derive(Debug, Serialize)]
struct MessageData {
    message: String,
}

#[derive(Debug, Serialize)]
struct GetData {
    key: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ListData {
    keys: Vec<String>,
}

pub fn cmd_init(cli: &Cli, force: bool) -> AppResult<String> {
    let vault = vault_from_cli(cli)?;
    let _lock = vault.lock()?;
    let mut master_key = prompt_new_master_key()?;
    let init_result = vault.init(&master_key, force);
    master_key.zeroize();
    init_result?;
    success(cli, "init", "Vault initialized.")
}

pub fn cmd_set(
    cli: &Cli,
    key: Option<String>,
    value: Option<String>,
    read_stdin: bool,
    yes: bool,
    allow_empty: bool,
) -> AppResult<String> {
    if read_stdin && cli.master_key_stdin {
        return Err(AppError::Usage(
            "`set --stdin` cannot be combined with `--master-key-stdin` because stdin can carry only one input stream."
                .to_string(),
        ));
    }

    let key = get_or_prompt(key, "Key")?;
    let key = validate_key(&key)?;
    let value = if read_stdin {
        vault::read_stdin_to_string()?
    } else {
        get_or_prompt(value, "Value")?
    };
    validate_value(&value, allow_empty)?;

    let vault = vault_from_cli(cli)?;
    let _lock = vault.lock()?;
    let key_for_message = key.clone();
    with_master_key(cli, "Master key", |master_key| {
        let mut data = vault.read(master_key)?;
        if data.entries.contains_key(&key) && !yes && !confirm("Key exists. Overwrite?")? {
            return Err(AppError::Usage("Cancelled.".to_string()));
        }
        data.set(key.clone(), value.clone());
        vault.write(&data, master_key)
    })?;
    success(
        cli,
        "set",
        &format!("Stored secret for key '{key_for_message}'."),
    )
}

pub fn cmd_get(cli: &Cli, key: &str) -> AppResult<String> {
    let key = validate_key(key)?;
    let vault = vault_from_cli(cli)?;
    let _lock = vault.lock()?;
    with_master_key(cli, "Master key", |master_key| {
        let data = vault.read(master_key)?;
        let entry = data.get(&key)?;
        if cli.json {
            to_json(&JsonResponse::success(
                "get",
                GetData {
                    key: key.clone(),
                    value: entry.value.clone(),
                },
            ))
        } else {
            Ok(entry.value.clone())
        }
    })
}

pub fn cmd_list(cli: &Cli) -> AppResult<String> {
    let vault = vault_from_cli(cli)?;
    let _lock = vault.lock()?;
    with_master_key(cli, "Master key", |master_key| {
        let data = vault.read(master_key)?;
        let keys = data.entries.keys().cloned().collect::<Vec<_>>();
        if cli.json {
            to_json(&JsonResponse::success("list", ListData { keys }))
        } else if keys.is_empty() {
            Ok("No keys found.".to_string())
        } else {
            Ok(keys.join("\n"))
        }
    })
}

pub fn cmd_delete(cli: &Cli, key: &str, yes: bool) -> AppResult<String> {
    let key = validate_key(key)?;
    let vault = vault_from_cli(cli)?;
    let _lock = vault.lock()?;
    with_master_key(cli, "Master key", |master_key| {
        let mut data = vault.read(master_key)?;
        if !yes && !confirm(&format!("Delete secret '{key}'?"))? {
            return Err(AppError::Usage("Cancelled.".to_string()));
        }
        data.delete(&key)?;
        vault.write(&data, master_key)
    })?;
    success(cli, "delete", &format!("Deleted secret '{key}'."))
}

pub fn cmd_rename(cli: &Cli, old: &str, new: &str, overwrite: bool) -> AppResult<String> {
    let old = validate_key(old)?;
    let new = validate_key(new)?;
    let vault = vault_from_cli(cli)?;
    let _lock = vault.lock()?;
    with_master_key(cli, "Master key", |master_key| {
        let mut data = vault.read(master_key)?;
        data.rename(&old, new.clone(), overwrite)?;
        vault.write(&data, master_key)
    })?;
    success(cli, "rename", &format!("Renamed '{old}' to '{new}'."))
}

pub fn cmd_doctor(cli: &Cli) -> AppResult<String> {
    let vault = vault_from_cli(cli)?;
    let report = if vault.exists() {
        with_master_key(cli, "Master key", |master_key| {
            vault.doctor(Some(master_key))
        })?
    } else {
        vault.doctor(None)?
    };
    if cli.json {
        to_json(&JsonResponse::success("doctor", report))
    } else {
        let mut lines = vec![format!("Vault: {}", report.path)];
        lines.push(format!("Exists: {}", report.exists));
        if let Some(version) = report.version {
            lines.push(format!("Version: {version}"));
        }
        if let Some(entries) = report.entries {
            lines.push(format!("Entries: {entries}"));
        }
        if report.warnings.is_empty() {
            lines.push("Status: ok".green().to_string());
        } else {
            lines.push("Warnings:".yellow().to_string());
            lines.extend(
                report
                    .warnings
                    .into_iter()
                    .map(|warning| format!("- {warning}")),
            );
        }
        Ok(lines.join("\n"))
    }
}

pub fn cmd_change_master_key(cli: &Cli) -> AppResult<String> {
    let vault = vault_from_cli(cli)?;
    let _lock = vault.lock()?;
    let mut current = master_key_from_cli(cli, "Current master key")?;
    let mut new_key = prompt_new_master_key()?;
    let update_result = (|| {
        let data = vault.read(&current)?;
        vault.write(&data, &new_key)
    })();
    current.zeroize();
    new_key.zeroize();
    update_result?;
    success(cli, "change-master-key", "Master key changed.")
}

pub fn cmd_api(cli: &Cli, command: &ApiCommand) -> AppResult<String> {
    let vault = vault_from_cli(cli)?;
    match command {
        ApiCommand::Get { key } => {
            let key = validate_key(key)?;
            let mut master_key = read_master_key_from_stdin()?;
            let result = (|| {
                let _lock = vault.lock()?;
                let data = vault.read(&master_key)?;
                let entry = data.get(&key)?;
                to_json(&JsonResponse::success(
                    "api get",
                    GetData {
                        key,
                        value: entry.value.clone(),
                    },
                ))
            })();
            master_key.zeroize();
            result
        }
        ApiCommand::List => {
            let mut master_key = read_master_key_from_stdin()?;
            let result = (|| {
                let _lock = vault.lock()?;
                let data = vault.read(&master_key)?;
                let keys = data.entries.keys().cloned().collect::<Vec<_>>();
                to_json(&JsonResponse::success("api list", ListData { keys }))
            })();
            master_key.zeroize();
            result
        }
        ApiCommand::Doctor => {
            let mut master_key = read_optional_master_key_from_stdin();
            let result = vault.doctor(master_key.as_deref());
            if let Some(master_key) = master_key.as_mut() {
                master_key.zeroize();
            }
            let report = result?;
            to_json(&JsonResponse::success("api doctor", report))
        }
    }
}

fn vault_from_cli(cli: &Cli) -> AppResult<Vault> {
    Ok(Vault::new(match &cli.vault {
        Some(path) => path.clone(),
        None => Vault::default_path()?,
    }))
}

fn success(cli: &Cli, command: &str, message: &str) -> AppResult<String> {
    if cli.json {
        to_json(&JsonResponse::success(
            command,
            MessageData {
                message: message.to_string(),
            },
        ))
    } else if cli.quiet {
        Ok(String::new())
    } else {
        Ok(format!("{} {message}", "ok:".green().bold()))
    }
}

fn to_json<T: Serialize>(value: &T) -> AppResult<String> {
    serde_json::to_string(value).map_err(AppError::from)
}

fn get_or_prompt(value: Option<String>, label: &str) -> AppResult<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(AppError::Usage(format!("{label} is required.")));
    }
    print!("{label}: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt_master_key_with_label(label: &str) -> AppResult<String> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(AppError::Usage(
            "Master key prompt requires an interactive terminal. Use --master-key-stdin for non-interactive use."
                .to_string(),
        ));
    }
    rpassword::prompt_password(format!("{label}: ")).map_err(|_| {
        AppError::Usage(
            "Master key prompt requires an interactive terminal. Use --master-key-stdin for non-interactive use."
                .to_string(),
        )
    })
}

fn prompt_new_master_key() -> AppResult<String> {
    let first = prompt_master_key_with_label("New master key")?;
    vault::validate_master_key(&first)?;
    let second = prompt_master_key_with_label("Confirm master key")?;
    if first != second {
        return Err(AppError::Usage("Master keys do not match.".to_string()));
    }
    Ok(first)
}

fn confirm(prompt: &str) -> AppResult<bool> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(AppError::Usage(
            "Confirmation required. Re-run with --yes for non-interactive use.".to_string(),
        ));
    }
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim(), "y" | "Y" | "yes" | "YES"))
}

fn read_master_key_from_stdin() -> AppResult<String> {
    let value = vault::read_stdin_to_string()?;
    let trimmed = value.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(AppError::Usage(
            "Master key must be supplied on stdin for API commands.".to_string(),
        ));
    }
    Ok(trimmed)
}

fn master_key_from_cli(cli: &Cli, label: &str) -> AppResult<String> {
    if cli.master_key_stdin {
        read_master_key_from_stdin()
    } else {
        prompt_master_key_with_label(label)
    }
}

fn with_master_key<T, F>(cli: &Cli, label: &str, operation: F) -> AppResult<T>
where
    F: FnOnce(&str) -> AppResult<T>,
{
    let mut master_key = master_key_from_cli(cli, label)?;
    let result = operation(&master_key);
    master_key.zeroize();
    result
}

fn read_optional_master_key_from_stdin() -> Option<String> {
    if std::io::stdin().is_terminal() {
        return None;
    }
    let value = vault::read_stdin_to_string().ok()?;
    let trimmed = value.trim_end_matches(['\r', '\n']).to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

#[allow(dead_code)]
fn _json_value_ok() -> serde_json::Value {
    json!({})
}
