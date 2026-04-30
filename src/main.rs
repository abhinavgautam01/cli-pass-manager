use std::process::ExitCode;

use clap::Parser;
use colored::Colorize;

use freaky_vault::cli::{self, Cli, Command};
use freaky_vault::error::{AppError, AppResult};
use freaky_vault::output::{self, JsonError, JsonResponse};

fn main() -> ExitCode {
    let cli = Cli::parse();
    output::configure_color(&cli);

    let command = cli.command.name().to_string();
    match run(cli) {
        Ok(response) => {
            if response.json {
                println!("{}", response.body);
            } else if !response.body.is_empty() {
                println!("{}", response.body);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            if err.json {
                let response = JsonResponse::<serde_json::Value>::failure(
                    &command,
                    JsonError::from_error(&err.error),
                );
                println!(
                    "{}",
                    serde_json::to_string(&response).unwrap_or_else(|_| {
                        r#"{"ok":false,"command":"unknown","error":{"code":"internal_error","message":"Internal error."}}"#.to_string()
                    })
                );
            } else {
                eprintln!("{} {}", "error:".red().bold(), err.error);
            }
            ExitCode::from(err.error.exit_code())
        }
    }
}

struct RunResponse {
    json: bool,
    body: String,
}

struct RunError {
    json: bool,
    error: AppError,
}

impl From<(bool, AppError)> for RunError {
    fn from((json, error): (bool, AppError)) -> Self {
        Self { json, error }
    }
}

fn run(cli: Cli) -> Result<RunResponse, RunError> {
    let json = cli.json || matches!(cli.command, Command::Api { .. });
    let result = run_inner(&cli);
    match result {
        Ok(body) => Ok(RunResponse { json, body }),
        Err(error) => Err((json, error).into()),
    }
}

fn run_inner(cli: &Cli) -> AppResult<String> {
    match &cli.command {
        Command::Init { force } => cli::cmd_init(cli, *force),
        Command::Set {
            key,
            value,
            stdin,
            yes,
            allow_empty,
        } => cli::cmd_set(cli, key.clone(), value.clone(), *stdin, *yes, *allow_empty),
        Command::Get { key } => cli::cmd_get(cli, key),
        Command::List => cli::cmd_list(cli),
        Command::Delete { key, yes } => cli::cmd_delete(cli, key, *yes),
        Command::Rename {
            old,
            new,
            overwrite,
        } => cli::cmd_rename(cli, old, new, *overwrite),
        Command::Doctor => cli::cmd_doctor(cli),
        Command::ChangeMasterKey => cli::cmd_change_master_key(cli),
        Command::Api { command } => cli::cmd_api(cli, command),
    }
}
