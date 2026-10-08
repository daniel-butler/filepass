//! The `filepass` binary: `serve` (load config, start the server, shut
//! down gracefully) and `token` (mint a new agent credential).

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use filepass::app;
use filepass::auth::{generate_token, hash_token};
use filepass::clock::SystemClock;
use filepass::config::{Config, LogFormat};
use filepass::obs::Obs;
use filepass::sweeper::Sweeper;

#[derive(Parser)]
#[command(
    name = "filepass",
    version,
    about = "A small file-drop server for agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the server, loading its configuration from `--config`.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generates a new agent token and its SHA-256, per the spec's
    /// Authentication section. The operator puts the hash in the config and
    /// gives the token to the agent.
    Token,
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Token => {
            run_token();
            ExitCode::SUCCESS
        }
        Command::Serve { config } => run_serve(config).await,
    }
}

fn run_token() {
    let token = generate_token();
    let token_sha256 = hex::encode(hash_token(&token));
    println!("token: {token}");
    println!("token_sha256: {token_sha256}");
}

/// Loads `config_path`, starts the server, and runs it until shutdown.
/// Exits 2 on a bad config, 1 on any other startup failure.
async fn run_serve(config_path: PathBuf) -> ExitCode {
    let cfg = match Config::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    init_tracing(cfg.log_format);

    let listen = cfg.listen;
    let (state, report) = match app::build_state(cfg, Arc::new(SystemClock), Obs::new()) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    for warning in &report.warnings {
        tracing::warn!("{warning}");
    }

    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("binding {listen}: {e}");
            return ExitCode::from(1);
        }
    };

    Sweeper::new(state.clone()).spawn();
    let addr = listener.local_addr().unwrap_or(listen);
    tracing::info!("listening on {addr}");

    match app::serve(listener, state, shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

/// Installs the global `tracing` subscriber: text or JSON per
/// `log_format`, with an `EnvFilter` that defaults to `info` but honours
/// `RUST_LOG` when set.
fn init_tracing(log_format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match log_format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        LogFormat::Text => {
            // No colour codes unless stdout is a terminal: under systemd it
            // is journald, which would store the escapes verbatim.
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(std::io::stdout().is_terminal())
                .init();
        }
    }
}

/// Resolves once SIGTERM or Ctrl-C arrives, per the spec's Shutdown
/// section.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
