# SPEC: Freaky Vault CLI

## 1. Product Summary

Freaky Vault is a local-first Rust CLI password manager for storing secrets as key-value pairs:
- `key`: what the secret is for (example: `github-personal`)
- `value`: secret/password text

This project scope is CLI-only.

## 2. Goals

1. Provide secure local encrypted storage.
2. Support both interactive and script-friendly command usage.
3. Keep UX clean and fast for daily terminal workflows.

## 3. Non-Goals

1. Desktop/mobile GUI app
2. Cloud sync and team sharing
3. Browser extension

## 4. CLI Surfaces

1. `freaky-vault`: scriptable command/API binary
2. `freaky`: interactive terminal workspace
3. One-time setup script: `./scripts/setup.sh` for global install

## 5. Functional Requirements

### 5.1 `freaky-vault` Commands

1. `init [--force]` - initialize encrypted vault and set master key
2. `set <key> [value] [--stdin] [--yes] [--allow-empty]` - add/update secret
3. `get <key>` - retrieve secret value
4. `list` - list stored keys only
5. `delete <key> [--yes]` - delete secret
6. `rename <old> <new> [--overwrite]` - rename key
7. `doctor` - integrity and safety diagnostics
8. `change-master-key` - rotate master key
9. `api get --key <key>`, `api list`, `api doctor` - structured JSON API mode

### 5.2 Global Flags

1. `--vault <path>` (alias `--valut`) - custom vault path
2. `--json` - JSON output for non-API commands
3. `--no-color` and `--color auto|always|never`
4. `--master-key-stdin` - use stdin for master key in non-interactive runs
5. `--quiet`, `--verbose`

### 5.3 Interactive CLI (`freaky`)

Required commands:
1. `init`, `unlock`, `lock`
2. `set`, `get`, `list`, `delete`, `rename`
3. `status`, `doctor`, `path`, `clear`, `help`, `quit`

Behavior:
1. Session can cache master key while unlocked.
2. `lock` and `quit` must clear in-memory session key.
3. Secrets are only revealed on explicit confirmation.
4. Command history must support arrow-key recall (up/down).

## 6. Security Requirements

1. Encrypt vault data at rest using AES-256-GCM.
2. Derive encryption key from master key using Argon2id + random per-vault salt.
3. Use random nonce per encryption operation.
4. Store only encrypted envelope metadata and ciphertext on disk.
5. Fail closed on tamper/corruption/authentication failures.
6. Enforce safe file/dir permissions (`0600` file, `0700` dir on Unix).
7. Reject symlinked vault files by default.
8. Zeroize derived keys and master-key strings after sensitive operations.

## 7. Data Format

Default vault path:
- `/tmp/freaky-test/vault.json.enc` (Unix default)

Envelope fields:
1. `version`
2. `kdf` (`name`, params)
3. `salt` (base64)
4. `nonce` (base64)
5. `ciphertext` (base64)

Decrypted payload:
- map/object of `key -> { value, created_at, updated_at }`

## 8. Error and Exit-Code Contract

1. Stable error codes/messages for scripting.
2. Non-interactive prompt attempts must fail fast with usage error.
3. JSON mode must return valid JSON error payloads.
4. Authentication, integrity, and missing-vault failures must be distinct.

## 9. Edge Cases and Required Handling

1. Vault already exists on `init` -> require `--force` or explicit confirmation in interactive CLI.
2. Missing vault on read operations -> actionable `init`-first error.
3. Corrupted/tampered envelope -> no partial decrypt, return integrity/auth failure.
4. Unsupported vault version -> explicit migration-required error.
5. Empty/whitespace key -> reject.
6. Oversized key/value -> reject with clear max-limit message.
7. Key not found on `get/delete/rename` -> not-found error.
8. Rename target exists without overwrite -> conflict error.
9. File lock already held -> bounded wait, then timeout error (no indefinite block).
10. Non-interactive command without master key -> fail fast and suggest `--master-key-stdin`.
11. `set --stdin` + `--master-key-stdin` -> reject due stdin stream ambiguity.

## 10. Testing Requirements

1. Unit tests for crypto round-trip and validation rules.
2. Tests for wrong master key, tampered data, and unsupported version.
3. Contract tests for API JSON success/failure responses.
4. Non-interactive CLI tests for master key behavior and error handling.
5. Lock timeout test for contention handling.

## 11. Acceptance Criteria

1. Secrets can be added, read, renamed, listed, and deleted through CLI.
2. Vault file never stores plaintext secrets.
3. Script usage works via JSON and stdin-based master key flow.
4. Interactive CLI is visually clean and usable for daily operations.
5. Error paths are deterministic and automation-friendly.
