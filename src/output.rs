use colored::control;
use is_terminal::IsTerminal;
use serde::Serialize;

use crate::{cli::Cli, error::AppError};

pub fn configure_color(cli: &Cli) {
    let enabled = if cli.no_color {
        false
    } else {
        match cli.color.as_deref() {
            Some("always") => true,
            Some("never") => false,
            _ => std::io::stdout().is_terminal(),
        }
    };
    control::set_override(enabled);
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum JsonResponse<T: Serialize> {
    Success {
        ok: bool,
        command: String,
        data: T,
    },
    Failure {
        ok: bool,
        command: String,
        error: JsonError,
    },
}

impl<T: Serialize> JsonResponse<T> {
    pub fn success(command: &str, data: T) -> Self {
        Self::Success {
            ok: true,
            command: command.to_string(),
            data,
        }
    }
}

impl JsonResponse<serde_json::Value> {
    pub fn failure(command: &str, error: JsonError) -> Self {
        Self::Failure {
            ok: false,
            command: command.to_string(),
            error,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct JsonError {
    pub code: &'static str,
    pub message: String,
}

impl JsonError {
    pub fn from_error(error: &AppError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}
