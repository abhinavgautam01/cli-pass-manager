use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Usage(String),
    #[error("Vault is not initialized. Run `freaky-vault init` first.")]
    VaultMissing,
    #[error("Authentication failed.")]
    AuthFailed,
    #[error("Vault data is corrupt or has been tampered with.")]
    Integrity,
    #[error("Unsupported vault version {0}. Migration is required.")]
    UnsupportedVersion(u32),
    #[error("No secret exists for key '{0}'.")]
    KeyNotFound(String),
    #[error("A secret already exists for key '{0}'.")]
    KeyExists(String),
    #[error("File lock failed or timed out.")]
    Lock,
    #[error("Unsafe file permissions for {path}: expected {expected}.")]
    UnsafePermissions { path: String, expected: String },
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Json(String),
}

impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Usage(_) => "usage_error",
            AppError::VaultMissing => "vault_missing",
            AppError::AuthFailed => "auth_failed",
            AppError::Integrity => "integrity_failed",
            AppError::UnsupportedVersion(_) => "unsupported_version",
            AppError::KeyNotFound(_) => "not_found",
            AppError::KeyExists(_) => "already_exists",
            AppError::Lock => "lock_failed",
            AppError::UnsafePermissions { .. } => "unsafe_permissions",
            AppError::Io(_) => "io_error",
            AppError::Crypto(_) => "crypto_error",
            AppError::Json(_) => "json_error",
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            AppError::Usage(_) => 2,
            AppError::AuthFailed => 3,
            AppError::VaultMissing => 4,
            AppError::Integrity => 5,
            AppError::Lock => 6,
            AppError::UnsupportedVersion(_) => 7,
            AppError::KeyNotFound(_)
            | AppError::KeyExists(_)
            | AppError::UnsafePermissions { .. }
            | AppError::Io(_)
            | AppError::Crypto(_)
            | AppError::Json(_) => 1,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Json(err.to_string())
    }
}
