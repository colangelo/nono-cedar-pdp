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
    /// Evaluate a saved webhook payload against the configured policies.
    Check {
        #[arg(long, default_value = "./nono-cedar-pdp.toml")]
        config: PathBuf,
        /// Path to a JSON file containing a nono webhook envelope.
        fixture: PathBuf,
    },
    /// Run the PDP daemon.
    Serve {
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
        Command::Check { config, fixture } => match run_check(&config, &fixture) {
            Ok(decision) => {
                println!(
                    "{}: {} ({} µs)",
                    if decision.allow { "ALLOW" } else { "DENY" },
                    decision.reason,
                    decision.eval_us
                );
                if decision.allow {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(message) => {
                eprintln!("FAIL: {message}");
                ExitCode::FAILURE
            }
        },
        Command::Serve { config } => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match runtime.block_on(run_serve(&config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(message) => {
                    eprintln!("FAIL: {message}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn run_validate(config_path: &std::path::Path) -> Result<usize, String> {
    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let loaded =
        cedar::engine::load_dir(&config.policy_dir, &schema, 1).map_err(|e| e.to_string())?;
    Ok(loaded.set.num_of_policies())
}

async fn run_serve(config_path: &std::path::Path) -> Result<(), String> {
    use nono_cedar_pdp::{audit::AuditLog, server};
    use std::sync::Arc;

    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    // Before anything is loaded, opened or bound: who can write the policies
    // decides every approval this daemon will ever make. An `Err` here is a
    // refusal to serve; the warnings are advisory and deliberately loud. Both
    // checks are narrower than they look — see `isolation`'s module docs and
    // README "Keep the policy directory out of the sandbox".
    let cwd = match std::env::current_dir() {
        Ok(cwd) => Some(cwd),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "no readable working directory; cannot tell whether the policy \
                 directory sits in one an agent may write"
            );
            None
        }
    };
    let warnings =
        nono_cedar_pdp::isolation::check(&config.policy_dir, &config.audit_log, cwd.as_deref())
            .map_err(|e| e.to_string())?;
    for warning in &warnings {
        tracing::warn!("{warning}");
    }

    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let engine = Arc::new(
        cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone())
            .map_err(|e| e.to_string())?,
    );
    // Bound to `_watcher`, not `_`: dropping it here would silently stop the
    // watch and every later policy edit would be ignored until a restart.
    let _watcher = nono_cedar_pdp::watcher::spawn(Arc::clone(&engine))
        .map_err(|e| format!("starting policy watcher: {e}"))?;
    let audit = Arc::new(
        AuditLog::open(&config.audit_log)
            .map_err(|e| format!("opening audit log {}: {e}", config.audit_log.display()))?,
    );
    let bind = config.bind;
    let state = server::AppState {
        engine,
        config: Arc::new(config),
        audit,
    };
    server::serve(state, bind)
        .await
        .map_err(|e| format!("serving on {bind}: {e}"))
}

fn run_check(
    config_path: &std::path::Path,
    fixture: &std::path::Path,
) -> Result<nono_cedar_pdp::decision::Decision, String> {
    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let engine = cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone())
        .map_err(|e| e.to_string())?;
    let body = std::fs::read(fixture).map_err(|e| e.to_string())?;
    let query =
        nono_cedar_pdp::adapter::nono_webhook::parse(&body, &config).map_err(|e| e.to_string())?;
    let decision = engine.evaluate(&query);
    match nono_cedar_pdp::audit::AuditLog::open(&config.audit_log) {
        Ok(log) => log.record(&query, &decision),
        Err(e) => eprintln!(
            "warning: audit log {} unavailable: {e}",
            config.audit_log.display()
        ),
    }
    Ok(decision)
}
