use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{AppError, AppResult};

const VERSION: u32 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const DEFAULT_MEMORY_KIB: u32 = 65_536;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;
const MAX_KEY_LEN: usize = 256;
const MAX_VALUE_LEN: usize = 1024 * 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfMetadata {
    pub name: String,
    pub params: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u32,
    pub kdf: KdfMetadata,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub value: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug)]
pub struct Vault {
    pub path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub path: String,
    pub exists: bool,
    pub version: Option<u32>,
    pub entries: Option<usize>,
    pub warnings: Vec<String>,
}

pub struct VaultLock {
    _file: File,
}

impl Vault {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn default_path() -> AppResult<PathBuf> {
        #[cfg(unix)]
        {
            return Ok(PathBuf::from("/tmp/freaky-test/vault.json.enc"));
        }
        #[cfg(not(unix))]
        {
            let home = dirs::home_dir()
                .ok_or_else(|| AppError::Io("Unable to determine home directory.".to_string()))?;
            Ok(home.join(".freaky-vault").join("vault.json.enc"))
        }
    }

    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    pub fn ensure_parent_dir(&self) -> AppResult<()> {
        let Some(parent) = self.path.parent() else {
            return Err(AppError::Usage(
                "Vault path must include a parent directory.".to_string(),
            ));
        };
        fs::create_dir_all(parent)?;
        set_dir_permissions(parent)?;
        Ok(())
    }

    pub fn lock(&self) -> AppResult<VaultLock> {
        let lock_path = self.lock_path();
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
            set_dir_permissions(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)?;
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(AppError::Lock);
                    }
                    thread::sleep(LOCK_RETRY_DELAY);
                }
                Err(_) => return Err(AppError::Lock),
            }
        }
        Ok(VaultLock { _file: file })
    }

    fn lock_path(&self) -> PathBuf {
        let mut lock = self.path.clone();
        let file_name = self
            .path
            .file_name()
            .map(|name| format!("{}.lock", name.to_string_lossy()))
            .unwrap_or_else(|| "vault.lock".to_string());
        lock.set_file_name(file_name);
        lock
    }

    pub fn init(&self, master_key: &str, force: bool) -> AppResult<()> {
        validate_master_key(master_key)?;
        self.ensure_parent_dir()?;
        reject_symlink(&self.path)?;
        if self.exists() && !force {
            return Err(AppError::Usage(
                "Vault already exists. Use --force to overwrite.".to_string(),
            ));
        }
        let data = VaultData::default();
        self.write(&data, master_key)
    }

    pub fn read(&self, master_key: &str) -> AppResult<VaultData> {
        if !self.exists() {
            return Err(AppError::VaultMissing);
        }
        reject_symlink(&self.path)?;
        check_file_permissions(&self.path)?;
        let bytes = fs::read(&self.path)?;
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| AppError::Integrity)?;
        decrypt_envelope(&envelope, master_key)
    }

    pub fn write(&self, data: &VaultData, master_key: &str) -> AppResult<()> {
        self.ensure_parent_dir()?;
        reject_symlink(&self.path)?;
        let envelope = encrypt_data(data, master_key)?;
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        atomic_write(&self.path, &bytes)
    }

    pub fn doctor(&self, master_key: Option<&str>) -> AppResult<DoctorReport> {
        let path = self.path.display().to_string();
        if !self.path.exists() {
            return Ok(DoctorReport {
                path,
                exists: false,
                version: None,
                entries: None,
                warnings: vec!["vault file is missing".to_string()],
            });
        }

        reject_symlink(&self.path)?;
        let mut warnings = Vec::new();
        if let Err(error) = check_file_permissions(&self.path) {
            warnings.push(error.to_string());
        }

        let bytes = fs::read(&self.path)?;
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| AppError::Integrity)?;
        if envelope.version != VERSION {
            return Err(AppError::UnsupportedVersion(envelope.version));
        }
        validate_envelope_shape(&envelope)?;

        let entries = if let Some(master_key) = master_key {
            Some(decrypt_envelope(&envelope, master_key)?.entries.len())
        } else {
            None
        };

        Ok(DoctorReport {
            path,
            exists: true,
            version: Some(envelope.version),
            entries,
            warnings,
        })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

pub fn validate_key(key: &str) -> AppResult<String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err(AppError::Usage("Key must not be empty.".to_string()));
    }
    if trimmed.len() > MAX_KEY_LEN {
        return Err(AppError::Usage(format!(
            "Key is too long. Maximum length is {MAX_KEY_LEN} bytes."
        )));
    }
    Ok(trimmed.to_string())
}

pub fn validate_value(value: &str, allow_empty: bool) -> AppResult<()> {
    if value.is_empty() && !allow_empty {
        return Err(AppError::Usage(
            "Value is empty. Use --allow-empty to store an empty secret.".to_string(),
        ));
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(AppError::Usage(format!(
            "Value is too large. Maximum length is {MAX_VALUE_LEN} bytes."
        )));
    }
    Ok(())
}

pub fn validate_master_key(master_key: &str) -> AppResult<()> {
    if master_key.len() < 12 {
        return Err(AppError::Usage(
            "Master key is too weak. Use at least 12 characters.".to_string(),
        ));
    }
    let has_letter = master_key.chars().any(char::is_alphabetic);
    let has_other = master_key.chars().any(|c| !c.is_alphabetic());
    if !has_letter || !has_other {
        return Err(AppError::Usage(
            "Master key is too weak. Mix letters with numbers or symbols.".to_string(),
        ));
    }
    Ok(())
}

impl VaultData {
    pub fn set(&mut self, key: String, value: String) {
        let now = timestamp();
        let created_at = self
            .entries
            .get(&key)
            .map(|entry| entry.created_at.clone())
            .unwrap_or_else(|| now.clone());
        self.entries.insert(
            key,
            Entry {
                value,
                created_at,
                updated_at: now,
            },
        );
    }

    pub fn get(&self, key: &str) -> AppResult<&Entry> {
        self.entries
            .get(key)
            .ok_or_else(|| AppError::KeyNotFound(key.to_string()))
    }

    pub fn delete(&mut self, key: &str) -> AppResult<()> {
        self.entries
            .remove(key)
            .map(|_| ())
            .ok_or_else(|| AppError::KeyNotFound(key.to_string()))
    }

    pub fn rename(&mut self, old: &str, new: String, overwrite: bool) -> AppResult<()> {
        if !self.entries.contains_key(old) {
            return Err(AppError::KeyNotFound(old.to_string()));
        }
        if self.entries.contains_key(&new) && !overwrite {
            return Err(AppError::KeyExists(new));
        }
        let mut entry = self.entries.remove(old).expect("checked above");
        entry.updated_at = timestamp();
        self.entries.insert(new, entry);
        Ok(())
    }
}

fn encrypt_data(data: &VaultData, master_key: &str) -> AppResult<Envelope> {
    validate_master_key(master_key)?;
    let params = KdfParams::default();
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(master_key, &salt, &params)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Crypto("Unable to initialize cipher.".to_string()))?;
    let plaintext = serde_json::to_vec(data)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| AppError::Crypto("Encryption failed.".to_string()))?;
    key.zeroize();

    Ok(Envelope {
        version: VERSION,
        kdf: KdfMetadata {
            name: "argon2id".to_string(),
            params,
        },
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt_envelope(envelope: &Envelope, master_key: &str) -> AppResult<VaultData> {
    if envelope.version != VERSION {
        return Err(AppError::UnsupportedVersion(envelope.version));
    }
    validate_envelope_shape(envelope)?;
    let salt = BASE64
        .decode(&envelope.salt)
        .map_err(|_| AppError::Integrity)?;
    let nonce = BASE64
        .decode(&envelope.nonce)
        .map_err(|_| AppError::Integrity)?;
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| AppError::Integrity)?;

    let mut key = derive_key(master_key, &salt, &envelope.kdf.params)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Crypto("Unable to initialize cipher.".to_string()))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| AppError::AuthFailed)?;
    key.zeroize();

    serde_json::from_slice(&plaintext).map_err(|_| AppError::Integrity)
}

fn validate_envelope_shape(envelope: &Envelope) -> AppResult<()> {
    if envelope.kdf.name != "argon2id" {
        return Err(AppError::Integrity);
    }
    if BASE64
        .decode(&envelope.salt)
        .map_err(|_| AppError::Integrity)?
        .len()
        != SALT_LEN
    {
        return Err(AppError::Integrity);
    }
    if BASE64
        .decode(&envelope.nonce)
        .map_err(|_| AppError::Integrity)?
        .len()
        != NONCE_LEN
    {
        return Err(AppError::Integrity);
    }
    BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| AppError::Integrity)?;
    Ok(())
}

fn derive_key(master_key: &str, salt: &[u8], params: &KdfParams) -> AppResult<[u8; KEY_LEN]> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| AppError::Crypto(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_key.as_bytes(), salt, &mut key)
        .map_err(|error| AppError::Crypto(error.to_string()))?;
    Ok(key)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let Some(parent) = path.parent() else {
        return Err(AppError::Usage(
            "Vault path must include a parent directory.".to_string(),
        ));
    };
    if path.exists() && path.is_dir() {
        return Err(AppError::Usage(
            "Vault path points to a directory.".to_string(),
        ));
    }
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_else(|| "vault".into()),
        std::process::id()
    ));

    {
        let mut file = open_private_file(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    set_file_permissions(path)?;
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn open_private_file(path: &Path) -> AppResult<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn reject_symlink(path: &Path) -> AppResult<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(AppError::Usage(
                "Symlinked vault files are rejected by default.".to_string(),
            ));
        }
    }
    Ok(())
}

fn set_dir_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_file_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn check_file_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(AppError::UnsafePermissions {
                path: path.display().to_string(),
                expected: "0600".to_string(),
            });
        }
    }
    Ok(())
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn read_stdin_to_string() -> AppResult<String> {
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs2::FileExt;

    const MASTER: &str = "correct horse 42";

    #[test]
    fn round_trips_secret() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(dir.path().join("vault.json.enc"));
        vault.init(MASTER, false).unwrap();
        let mut data = vault.read(MASTER).unwrap();
        data.set("github".to_string(), "token\nvalue".to_string());
        vault.write(&data, MASTER).unwrap();

        let loaded = vault.read(MASTER).unwrap();
        assert_eq!(loaded.get("github").unwrap().value, "token\nvalue");
        let on_disk = fs::read_to_string(vault.path).unwrap();
        assert!(!on_disk.contains("token"));
    }

    #[test]
    fn wrong_master_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(dir.path().join("vault.json.enc"));
        vault.init(MASTER, false).unwrap();
        let error = vault.read("wrong password 42").unwrap_err();
        assert!(matches!(error, AppError::AuthFailed));
    }

    #[test]
    fn validates_key_and_value() {
        assert!(validate_key("   ").is_err());
        assert_eq!(validate_key("  github  ").unwrap(), "github");
        assert!(validate_value("", false).is_err());
        assert!(validate_value("", true).is_ok());
    }

    #[test]
    fn tampered_vault_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(dir.path().join("vault.json.enc"));
        vault.init(MASTER, false).unwrap();

        let mut envelope: Envelope =
            serde_json::from_slice(&fs::read(&vault.path).unwrap()).unwrap();
        envelope.ciphertext.push('A');
        fs::write(&vault.path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let error = vault.read(MASTER).unwrap_err();
        assert!(matches!(error, AppError::AuthFailed | AppError::Integrity));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(dir.path().join("vault.json.enc"));
        vault.init(MASTER, false).unwrap();

        let mut envelope: Envelope =
            serde_json::from_slice(&fs::read(&vault.path).unwrap()).unwrap();
        envelope.version = 999;
        fs::write(&vault.path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let error = vault.read(MASTER).unwrap_err();
        assert!(matches!(error, AppError::UnsupportedVersion(999)));
    }

    #[test]
    fn lock_times_out_when_already_locked() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(dir.path().join("vault.json.enc"));
        vault.ensure_parent_dir().unwrap();

        let lock_path = vault.lock_path();
        let held_lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        held_lock.lock_exclusive().unwrap();

        let start = Instant::now();
        let error = vault
            .lock()
            .err()
            .expect("expected lock acquisition to time out");
        assert!(matches!(error, AppError::Lock));
        assert!(start.elapsed() >= LOCK_TIMEOUT);
    }

    #[cfg(unix)]
    #[test]
    fn default_path_uses_tmp_freaky_test() {
        assert_eq!(
            Vault::default_path().unwrap(),
            PathBuf::from("/tmp/freaky-test/vault.json.enc")
        );
    }
}
