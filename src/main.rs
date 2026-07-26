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
        /// Also append this evaluation to the configured audit log.
        ///
        /// Off by default: a `check` run is a what-if, not a decision the daemon made
        /// for nono, and its record would be byte-identical to a real one — so an
        /// investigator could not tell a genuine allow from someone's local experiment.
        #[arg(long)]
        audit: bool,
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
        Command::Check {
            config,
            fixture,
            audit,
        } => match run_check(&config, &fixture, audit) {
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

    let mut config = Config::load(config_path).map_err(|e| e.to_string())?;
    // Resolve the configured state paths ONCE, before the checks (D7): the
    // chain the isolation checks walk and the chain the loader, the watcher and
    // the audit log use must be the same object, or a symlink on the configured
    // path could be repointed after startup to a tree the checks never saw.
    // `policy_dir` must exist to serve, so failing to resolve it is a refusal;
    // the audit log may not exist yet, so its *existing prefix* is what
    // resolves. Everything below holds only the resolved paths — a post-startup
    // repoint of the configured path changes nothing the daemon will ever read.
    // (The named residual — a pre-startup repoint at a stale tree this same
    // user owns — is in `isolation`'s module docs.)
    config.policy_dir = std::fs::canonicalize(&config.policy_dir).map_err(|e| {
        format!(
            "resolving policy_dir {}: {e} — refusing to serve without knowing which \
             directory the policies would come from",
            config.policy_dir.display()
        )
    })?;
    config.audit_log = nono_cedar_pdp::isolation::resolve_existing_prefix(&config.audit_log);
    // The TLS pair rides the same rule (D7). Both must exist to serve, so plain
    // `canonicalize` like `policy_dir` rather than the audit log's
    // existing-prefix form — and resolving here, before the key check below,
    // is what makes the chain that check walks the chain the listener reads. A
    // symlinked `key` resolved twice would be two different objects, and the
    // gap between them is where a repoint lands.
    if let Some(tls) = config.tls.as_mut() {
        for (what, path) in [("cert", &mut tls.cert), ("key", &mut tls.key)] {
            *path = std::fs::canonicalize(&path).map_err(|e| {
                format!(
                    "resolving tls {what} {}: {e} — [tls] is configured, and a transport \
                     that cannot be established is a refusal to serve, never a silent \
                     fallback to plaintext",
                    path.display()
                )
            })?;
        }
    }
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
    // And the private key, on the same terms and in the same place: read access
    // to it is the ability to *be* this daemon, since nono verifies the
    // certificate and has no other way to tell who answered (T4). Narrower than
    // it looks — other local users only; see `isolation`'s module docs for why
    // the sandboxed agent is bounded by its profile's read grants instead.
    if let Some(tls) = &config.tls {
        nono_cedar_pdp::isolation::refuse_a_readable_private_key(&tls.key)
            .map_err(|e| e.to_string())?;
        // TRANSITIONAL, and deleted by the change that adds the axum-server arm
        // (T3): the https listener does not exist yet, so falling through from
        // here would start the *plaintext* one behind a configuration that says
        // the transport is authenticated — precisely the silent downgrade T2
        // forbids, and the worst of the available behaviours. A refusal is the
        // fail-closed answer until the listener lands.
        return Err(format!(
            "[tls] names {} but the https listener is not implemented yet — refusing to \
             serve, because serving plaintext behind a configuration that asks for TLS \
             would leave the operator believing the transport is authenticated when it \
             is not",
            tls.cert.display()
        ));
    }

    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let engine = Arc::new(
        cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone())
            .map_err(|e| e.to_string())?,
    );
    let audit = Arc::new(
        AuditLog::open(&config.audit_log)
            .map_err(|e| format!("opening audit log {}: {e}", config.audit_log.display()))?,
    );
    // `at_risk` is decided here because this is the only place that has the
    // advisory warnings — `isolation::check` returns them and nothing deeper down
    // sees them.
    let last_reload = Arc::new(arc_swap::ArcSwapOption::empty());
    let provenance = nono_cedar_pdp::watcher::Provenance {
        audit: Arc::clone(&audit),
        at_risk: !warnings.is_empty(),
        last_reload: Arc::clone(&last_reload),
    };
    // The bootstrap load already happened above; record it now that there is
    // somewhere durable to record it. The checks still gate everything — a load
    // that fails at bootstrap exits with its error and writes nothing, because
    // creating an audit log as a side effect of refusing to serve would be worse
    // than the silence.
    provenance.record_bootstrap(&engine.snapshot());
    // Bound to `_watcher`, not `_`: dropping it here would silently stop the
    // watch and every later policy edit would be ignored until a restart.
    let _watcher = nono_cedar_pdp::watcher::spawn(Arc::clone(&engine), provenance)
        .map_err(|e| format!("starting policy watcher: {e}"))?;
    let bind = config.bind;
    let state = server::AppState {
        engine,
        config: Arc::new(config),
        audit,
        last_reload,
    };
    server::serve(state, bind)
        .await
        .map_err(|e| format!("serving on {bind}: {e}"))
}

fn run_check(
    config_path: &std::path::Path,
    fixture: &std::path::Path,
    audit: bool,
) -> Result<nono_cedar_pdp::decision::Decision, String> {
    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let engine = cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone())
        .map_err(|e| e.to_string())?;
    let body = std::fs::read(fixture).map_err(|e| e.to_string())?;
    let query =
        nono_cedar_pdp::adapter::nono_webhook::parse(&body, &config).map_err(|e| e.to_string())?;
    let decision = engine.evaluate(&query);
    if audit {
        match nono_cedar_pdp::audit::AuditLog::open(&config.audit_log) {
            // No HTTP request behind a `check`, so there is no observed
            // `User-Agent` to record: the line carries an explicit null.
            Ok(log) => log.record(&query, &decision, None),
            Err(e) => eprintln!(
                "warning: audit log {} unavailable: {e}",
                config.audit_log.display()
            ),
        }
    }
    Ok(decision)
}
