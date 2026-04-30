#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Installing freaky and freaky-vault..."
cargo install --path . --bins --force --locked

DEFAULT_VAULT="/tmp/freaky-test/vault.json.enc"
mkdir -p "$(dirname "$DEFAULT_VAULT")"

echo
echo "Setup complete."
echo "Default vault path: $DEFAULT_VAULT"

if command -v freaky >/dev/null 2>&1; then
  echo "Run from anywhere: freaky"
else
  echo "Binary not found on PATH yet."
  echo "Add \$HOME/.cargo/bin to PATH, then run: freaky"
fi
