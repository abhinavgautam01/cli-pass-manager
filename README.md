# Freaky Vault

Freaky Vault is a local-first Rust password manager with:

- `freaky` -> interactive terminal workspace
- `freaky-vault` -> scriptable CLI/API binary

Default vault path (Unix):

```text
/tmp/freaky-test/vault.json.enc
```

---

## Local setup

### 1. Prerequisites

```bash
rustc --version
cargo --version
```

Install Rust if needed: https://rustup.rs

### 2. Clone and install globally

```bash
git clone <YOUR_REPO_URL>
cd <YOUR_REPO_DIR>
./scripts/setup.sh
```

After setup, you can run `freaky` from **any** directory.

If `freaky` is not found, add Cargo bin path and restart shell:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 3. Optional: install directly from GitHub (after publish)

```bash
cargo install --git https://github.com/<your-user>/<your-repo> --bins --locked --force
```

---

## Quick start

Run interactive mode:

```bash
freaky
```

First launch creates the default vault if missing. Every launch rotates to a different ASCII startup banner.

Current first startup banner (`FREAKY VAULT`):

```text
       .--------.
      / .------. \
     / /        \ \
     | |        | |
    _| |________| |_
  .' |_|        |_| '.
  '._____ ____ _____.'
  |     .'____'.     |
  '.__.'.'    '.'.__.'
  '.__  | FREAK|  __.'
  |   '.'.____.'.'   |
  '.____'.____.'____.'
  '.________________.'
```

Use a custom vault:

```bash
freaky --vault /path/to/vault.json.enc
```

Alias supported:

```bash
freaky --valut /path/to/vault.json.enc
```

Interactive prompt supports command history with arrow keys (`up/down`).

---

## Core interactive commands

```text
help
init
unlock
set github
get github
list
status
doctor
lock
quit
```

`lock` and `quit` clear the in-memory session key.

---

## Scriptable CLI usage

Initialize and store/read secret:

```bash
freaky-vault init
printf 'secret\n' | freaky-vault set github --stdin
freaky-vault get github
```

Non-interactive master key flow:

```bash
printf 'master-key\n' | freaky-vault --master-key-stdin get github
```

JSON API mode:

```bash
printf 'master-key\n' | freaky-vault api get --key github
printf 'master-key\n' | freaky-vault api list
```

---

## Development checks

```bash
cargo fmt
cargo test
```
