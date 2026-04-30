use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use colored::{Colorize, control};
use is_terminal::IsTerminal;
use rustyline::{DefaultEditor, error::ReadlineError};
use zeroize::Zeroize;

use freaky_vault::error::{AppError, AppResult};
use freaky_vault::vault::{Vault, validate_key, validate_master_key, validate_value};

#[derive(Debug, Parser)]
#[command(name = "freaky")]
#[command(about = "Open the Freaky Vault interactive CLI")]
struct Args {
    #[arg(long, visible_alias = "valut")]
    vault: Option<PathBuf>,

    #[arg(long)]
    no_color: bool,
}

#[derive(Clone, Copy)]
struct Banner {
    title: &'static str,
    art: &'static str,
    subtitle: &'static str,
}

const BANNERS: [Banner; 5] = [
    Banner {
        title: "FREAKY VAULT",
        art: r#"
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
"#,
        subtitle: "stealth mode: armed",
    },
    Banner {
        title: "FREAKY CORE",
        art: r#"
       .-----------------.
      /                   \
     |   .-------------.   |
     |  /               \  |
     | |                 | |
     | |    [ FREAK ]    | |
     | |                 | |
     | |                 | |
      \ \               / /
       \ '._         _.' /
        '._ ''-----'' _.'
           '---------'
"#,
        subtitle: "keys in. noise out.",
    },
    Banner {
        title: "VAULT TERMINAL",
        art: r#"
         _......_
       .'        '.
      /   .----.   \
     |   |      |   |
      \   '----'   /
       '.________.'.-.
         ||     |  |
         ||     |__|
         ||      .-.
         ||_____|  |
         ||_____|__|
         ||
"#,
        subtitle: "encrypted by default",
    },
    Banner {
        title: "FREAKY OPS",
        art: r#"
        ___..--"""--..___
     .-'                 '-.
    /    ___.........___    \
   /   .'               '.   \
  |  .'                   '.  |
  | /                       \ |
  | |       ( FREAK )       | |
  | \                       / |
  |  '.                   .'  |
   \   '.___         ___.'   /
    \       '.......'       /
     '-.___           ___.-'
           """-----"""
"#,
        subtitle: "small cli, big lock",
    },
    Banner {
        title: "SECRET ENGINE",
        art: r#"
        .----------------.
       /                  \
      /      _      _      \
     /      (_)    (_)      \
    |                        |
    |       [ FREAKY ]       |
    |           ||           |
    |      _    ||    _      |
     \    (_)        (_)    /
      \                    /
       \                  /
        '----------------'
"#,
        subtitle: "argon2id + aes-256-gcm",
    },
];

struct Shell {
    vault: Vault,
    master_key: Option<String>,
    banner: Banner,
}

fn main() -> ExitCode {
    let args = Args::parse();
    control::set_override(!args.no_color && io::stdout().is_terminal());

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "{} {}",
            "error:".red().bold(),
            "`freaky` requires an interactive terminal. Use `freaky-vault` for scripts."
        );
        return ExitCode::from(2);
    }

    let vault_path = match args.vault {
        Some(path) => path,
        None => match Vault::default_path() {
            Ok(path) => path,
            Err(error) => {
                print_error(&error);
                return ExitCode::from(error.exit_code());
            }
        },
    };

    let banner = pick_startup_banner(&vault_path);
    let mut shell = Shell {
        vault: Vault::new(vault_path),
        master_key: None,
        banner,
    };

    if let Err(error) = shell.run() {
        print_error(&error);
        return ExitCode::from(error.exit_code());
    }

    ExitCode::SUCCESS
}

impl Shell {
    fn run(&mut self) -> AppResult<()> {
        self.redraw();
        self.setup_if_needed()?;

        let mut editor = DefaultEditor::new()
            .map_err(|error| AppError::Io(format!("Unable to start line editor: {error}")))?;
        let history_path = self.history_path();
        let _ = editor.load_history(&history_path);

        loop {
            let line = match editor.readline(&format!("{} › ", self.prompt_label())) {
                Ok(line) => line,
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
                Err(error) => {
                    return Err(AppError::Io(format!("Line editor failure: {error}")));
                }
            };
            let input = line.trim();
            if input.is_empty() {
                continue;
            }
            let _ = editor.add_history_entry(input);

            let mut parts = input.split_whitespace();
            let command = parts.next().unwrap_or_default();
            let args = parts.collect::<Vec<_>>();

            let result = match command {
                "help" | "?" => {
                    self.print_help();
                    Ok(())
                }
                "init" => self.init_wizard(false),
                "unlock" => self.unlock(),
                "lock" => {
                    self.clear_master_key();
                    println!("{}", "Locked session key.".dimmed());
                    Ok(())
                }
                "set" | "add" => self.set(args.first().copied()),
                "get" | "show" => self.get(args.first().copied()),
                "list" | "ls" => self.list(),
                "delete" | "del" | "rm" => self.delete(args.first().copied()),
                "rename" | "mv" => self.rename(args.first().copied(), args.get(1).copied()),
                "doctor" => self.doctor(),
                "status" => self.status(),
                "path" => {
                    println!("{}", self.vault.path.display().to_string().cyan());
                    Ok(())
                }
                "clear" => {
                    self.redraw();
                    Ok(())
                }
                "quit" | "exit" => break,
                _ => Err(AppError::Usage(format!(
                    "Unknown command '{command}'. Type `help`."
                ))),
            };

            if let Err(error) = result {
                print_error(&error);
            }
        }

        if let Some(parent) = history_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = editor.save_history(&history_path);
        self.clear_master_key();
        println!("{}", "Session closed.".dimmed());
        Ok(())
    }

    fn setup_if_needed(&mut self) -> AppResult<()> {
        if self.vault.exists() {
            println!(
                "{} {}",
                "vault".bright_black(),
                self.vault.path.display().to_string().dimmed()
            );
            println!(
                "{}",
                "Type `unlock` to start. Try `help`, `status`, or `list`.".dimmed()
            );
            return Ok(());
        }

        println!("{}", "No vault found.".yellow().bold());
        println!(
            "{}",
            "Freaky will now create the default encrypted vault.".dimmed()
        );
        self.init_wizard(false)?;
        Ok(())
    }

    fn init_wizard(&mut self, force: bool) -> AppResult<()> {
        if self.vault.exists() && !force {
            println!("{}", "Vault already exists.".yellow());
            if !confirm_default_no("Overwrite it?")? {
                return Ok(());
            }
        }

        println!("{}", "Create master key".bold());
        println!(
            "{}",
            "Use at least 12 characters with letters plus numbers or symbols.".dimmed()
        );
        let master_key = prompt_new_master_key()?;
        let _lock = self.vault.lock()?;
        self.vault.init(&master_key, true)?;
        self.master_key = Some(master_key);
        println!(
            "{}",
            "Vault initialized and unlocked for this session."
                .green()
                .bold()
        );
        Ok(())
    }

    fn unlock(&mut self) -> AppResult<()> {
        if !self.vault.exists() {
            return Err(AppError::VaultMissing);
        }

        let master_key = prompt_password("Master key")?;
        let _lock = self.vault.lock()?;
        let data = self.vault.read(&master_key)?;
        let count = data.entries.len();
        self.clear_master_key();
        self.master_key = Some(master_key);
        println!(
            "{} {}",
            "Unlocked.".green().bold(),
            format!("{count} entr{}", if count == 1 { "y" } else { "ies" }).dimmed()
        );
        Ok(())
    }

    fn set(&mut self, key_arg: Option<&str>) -> AppResult<()> {
        let key = match key_arg {
            Some(key) => validate_key(key)?,
            None => validate_key(&prompt_plain("Key")?)?,
        };
        let value = prompt_password("Secret value")?;
        validate_value(&value, false)?;

        let mut master_key = self.require_master_key()?;
        let result = (|| {
            let _lock = self.vault.lock()?;
            let mut data = self.vault.read(&master_key)?;
            if data.entries.contains_key(&key) && !confirm_default_no("Key exists. Overwrite?")? {
                return Ok(());
            }
            data.set(key.clone(), value);
            self.vault.write(&data, &master_key)
        })();
        master_key.zeroize();
        result?;
        println!("{} {}", "stored".green().bold(), key.cyan());
        Ok(())
    }

    fn get(&mut self, key_arg: Option<&str>) -> AppResult<()> {
        let key = match key_arg {
            Some(key) => validate_key(key)?,
            None => validate_key(&prompt_plain("Key")?)?,
        };
        let mut master_key = self.require_master_key()?;
        let entry = (|| {
            let _lock = self.vault.lock()?;
            let data = self.vault.read(&master_key)?;
            data.get(&key).cloned()
        })();
        master_key.zeroize();
        let entry = entry?;

        println!("{}", "Secret found.".green().bold());
        println!(
            "{} {}",
            "masked".bright_black(),
            mask_secret(&entry.value).bright_black()
        );

        if confirm_default_no("Reveal in terminal?")? {
            print_secret_box(&key, &entry.value);
            let _ = prompt_line("press enter to clear");
            self.redraw();
        }
        Ok(())
    }

    fn list(&mut self) -> AppResult<()> {
        let mut master_key = self.require_master_key()?;
        let data = (|| {
            let _lock = self.vault.lock()?;
            self.vault.read(&master_key)
        })();
        master_key.zeroize();
        let data = data?;

        if data.entries.is_empty() {
            println!("{}", "No keys stored yet.".dimmed());
            return Ok(());
        }

        println!("{}", "Stored keys".bold());
        println!(
            "{}",
            format!("{:<4} {:<34} {}", "#", "key", "updated (UTC)").dimmed()
        );
        for (index, (key, entry)) in data.entries.iter().enumerate() {
            println!(
                "{:<4} {:<34} {}",
                index + 1,
                truncate_cell(key, 34).cyan(),
                entry.updated_at.dimmed()
            );
        }
        Ok(())
    }

    fn delete(&mut self, key_arg: Option<&str>) -> AppResult<()> {
        let key = match key_arg {
            Some(key) => validate_key(key)?,
            None => validate_key(&prompt_plain("Key")?)?,
        };
        if !confirm_default_no(&format!("Delete '{key}'?"))? {
            return Ok(());
        }

        let mut master_key = self.require_master_key()?;
        let result = (|| {
            let _lock = self.vault.lock()?;
            let mut data = self.vault.read(&master_key)?;
            data.delete(&key)?;
            self.vault.write(&data, &master_key)
        })();
        master_key.zeroize();
        result?;
        println!("{} {}", "deleted".green().bold(), key.cyan());
        Ok(())
    }

    fn rename(&mut self, old_arg: Option<&str>, new_arg: Option<&str>) -> AppResult<()> {
        let old = match old_arg {
            Some(key) => validate_key(key)?,
            None => validate_key(&prompt_plain("Old key")?)?,
        };
        let new = match new_arg {
            Some(key) => validate_key(key)?,
            None => validate_key(&prompt_plain("New key")?)?,
        };

        let mut master_key = self.require_master_key()?;
        let result = (|| {
            let _lock = self.vault.lock()?;
            let mut data = self.vault.read(&master_key)?;
            data.rename(&old, new.clone(), false)?;
            self.vault.write(&data, &master_key)
        })();
        master_key.zeroize();
        result?;
        println!(
            "{} {} -> {}",
            "renamed".green().bold(),
            old.cyan(),
            new.cyan()
        );
        Ok(())
    }

    fn doctor(&mut self) -> AppResult<()> {
        let mut master_key = self.master_key.clone();
        let report = self.vault.doctor(master_key.as_deref())?;
        if let Some(master_key) = master_key.as_mut() {
            master_key.zeroize();
        }
        println!("{}", "Vault doctor".bold());
        println!("  path     {}", report.path.cyan());
        println!("  exists   {}", bool_label(report.exists));
        if let Some(version) = report.version {
            println!("  version  {}", version.to_string().cyan());
        }
        if let Some(entries) = report.entries {
            println!("  entries  {}", entries.to_string().cyan());
        } else if report.exists {
            println!("  entries  {}", "unlock to inspect".dimmed());
        }
        if report.warnings.is_empty() {
            println!("  status   {}", "ok".green().bold());
        } else {
            println!("  status   {}", "warnings".yellow().bold());
            for warning in report.warnings {
                println!("    - {warning}");
            }
        }
        Ok(())
    }

    fn status(&mut self) -> AppResult<()> {
        let lock_label = if self.master_key.is_some() {
            "unlocked".green().bold()
        } else {
            "locked".yellow().bold()
        };
        println!("{}", "Session status".bold());
        println!("  state    {}", lock_label);
        println!(
            "  vault    {}",
            self.vault.path.display().to_string().cyan()
        );

        if self.master_key.is_some() {
            let mut master_key = self.require_master_key()?;
            let entry_count = (|| {
                let _lock = self.vault.lock()?;
                let data = self.vault.read(&master_key)?;
                Ok::<usize, AppError>(data.entries.len())
            })();
            master_key.zeroize();
            let entry_count = entry_count?;
            println!("  entries  {}", entry_count.to_string().cyan());
        } else {
            println!("  entries  {}", "unlock to inspect".dimmed());
        }
        Ok(())
    }

    fn require_master_key(&mut self) -> AppResult<String> {
        if let Some(master_key) = &self.master_key {
            return Ok(master_key.clone());
        }
        self.unlock()?;
        self.master_key
            .clone()
            .ok_or_else(|| AppError::Usage("Session is locked.".to_string()))
    }

    fn redraw(&mut self) {
        print!("\x1b[2J\x1b[H");
        let _ = io::stdout().flush();
        self.print_banner();
    }

    fn print_banner(&self) {
        let status = if self.master_key.is_some() {
            "unlocked".green().bold()
        } else {
            "locked".yellow().bold()
        };
        println!(
            "{}",
            "================================================".bright_black()
        );
        println!("{}", self.banner.title.bright_magenta().bold());
        println!("{}", self.banner.art.bright_cyan());
        println!("tag   : {}", self.banner.subtitle.bright_black());
        println!(
            "{}",
            "------------------------------------------------".bright_black()
        );
        println!(
            "state : {}   mode: {}",
            status,
            if self.master_key.is_some() {
                "hot".green().bold()
            } else {
                "cold".yellow().bold()
            }
        );
        println!("vault : {}", self.vault.path.display().to_string().dimmed());
        println!(
            "tips  : {} {} {}",
            "`help`".cyan(),
            "`status`".cyan(),
            "`doctor`".cyan()
        );
        println!(
            "{}",
            "================================================".bright_black()
        );
        println!();
    }

    fn print_help(&self) {
        println!("{}", "Core commands".bold());
        println!("  {:<22} create or reset the vault", "init".cyan());
        println!("  {:<22} unlock vault for this session", "unlock".cyan());
        println!("  {:<22} clear cached session key", "lock".cyan());
        println!("  {:<22} add or update a secret", "set [key]".cyan());
        println!(
            "  {:<22} reveal a secret with confirmation",
            "get [key]".cyan()
        );
        println!("  {:<22} list keys with timestamps", "list".cyan());
        println!("  {:<22} delete a secret", "delete [key]".cyan());
        println!("  {:<22} rename a key", "rename <old> <new>".cyan());
        println!();
        println!("{}", "Diagnostics".bold());
        println!("  {:<22} show lock state and vault info", "status".cyan());
        println!("  {:<22} validate vault health", "doctor".cyan());
        println!("  {:<22} show active vault path", "path".cyan());
        println!("  {:<22} redraw the screen", "clear".cyan());
        println!();
        println!("{}", "Exit".bold());
        println!("  {:<22} leave Freaky", "quit".cyan());
    }

    fn prompt_label(&self) -> String {
        if self.master_key.is_some() {
            "freaky:unlocked".to_string()
        } else {
            "freaky:locked".to_string()
        }
    }

    fn history_path(&self) -> PathBuf {
        state_path_for(&self.vault.path, ".freaky_history")
    }

    fn clear_master_key(&mut self) {
        if let Some(master_key) = self.master_key.as_mut() {
            master_key.zeroize();
        }
        self.master_key = None;
    }
}

fn prompt_new_master_key() -> AppResult<String> {
    let first = prompt_password("New master key")?;
    validate_master_key(&first)?;
    let second = prompt_password("Confirm master key")?;
    if first != second {
        return Err(AppError::Usage("Master keys do not match.".to_string()));
    }
    Ok(first)
}

fn pick_startup_banner(vault_path: &Path) -> Banner {
    let path = state_path_for(vault_path, ".freaky_banner_index");
    let previous = fs::read_to_string(&path)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok());
    let next = previous.map(|idx| (idx + 1) % BANNERS.len()).unwrap_or(0);

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, next.to_string());
    BANNERS[next]
}

fn state_path_for(vault_path: &Path, file_name: &str) -> PathBuf {
    let parent = vault_path.parent().unwrap_or_else(|| Path::new("/tmp"));
    parent.join(file_name)
}

fn prompt_password(label: &str) -> AppResult<String> {
    rpassword::prompt_password(format!("{label}: "))
        .map_err(|_| AppError::Usage("Password prompt requires a terminal.".to_string()))
}

fn prompt_plain(label: &str) -> AppResult<String> {
    print!("{}: ", label.cyan());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt_line(label: &str) -> AppResult<String> {
    print!("{} ", format!("{label} ›").bright_magenta().bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}

fn confirm_default_no(prompt: &str) -> AppResult<bool> {
    print!("{} [y/N]: ", prompt.cyan());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim(), "y" | "Y" | "yes" | "YES"))
}

fn print_secret_box(key: &str, secret: &str) {
    println!(
        "{}",
        "╭─ secret ─────────────────────────────────────╮".bright_black()
    );
    println!("  key    {}", key.cyan());
    println!("  value  {}", secret);
    println!(
        "{}",
        "╰──────────────────────────────────────────────╯".bright_black()
    );
}

fn mask_secret(secret: &str) -> String {
    let count = secret.chars().count().clamp(8, 32);
    "•".repeat(count)
}

fn truncate_cell(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out = value
        .chars()
        .take(width.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn bool_label(value: bool) -> String {
    if value {
        "yes".green().bold().to_string()
    } else {
        "no".yellow().bold().to_string()
    }
}

fn print_error(error: &AppError) {
    eprintln!("{} {}", "error:".red().bold(), error);
}
