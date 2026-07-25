use clap::{Parser, Subcommand};
use nono_cedar_pdp::{cedar, config::Config};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "nono-cedar-pdp",
    version,
    about = "Cedar PDP for nono approvals"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load and strict-validate the configured policy directory, then exit.
    Validate {
        #[arg(long, default_value = "./nono-cedar-pdp.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Validate { config } => match run_validate(&config) {
            Ok(count) => {
                println!("OK: {count} policies loaded and validated");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("FAIL: {message}");
                ExitCode::FAILURE
            }
        },
    }
}

fn run_validate(config_path: &std::path::Path) -> Result<usize, String> {
    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let loaded =
        cedar::engine::load_dir(&config.policy_dir, &schema, 1).map_err(|e| e.to_string())?;
    Ok(loaded.set.num_of_policies())
}
