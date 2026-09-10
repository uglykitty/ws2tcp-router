use std::{
    env,
    fs::{self, OpenOptions},
    path::Path,
};

use anyhow::{Context, Result};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::args::Args;

pub fn init_logging(args: &Args) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = match &args.log_level {
        Some(log_level) => EnvFilter::try_new(log_level)
            .with_context(|| format!("invalid --log-level filter {log_level:?}"))?,
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| "ws2tcp_router=info".into()),
    };

    let running_under_systemd = env::var_os("JOURNAL_STREAM").is_some();

    if let Some(path) = &args.log_file {
        let (file_writer, guard) = open_log_writer(path)?;

        if running_under_systemd {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(file_writer)
                        .with_ansi(false)
                        .without_time(),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(file_writer)
                        .with_ansi(false),
                )
                .init();
        }

        Ok(Some(guard))
    } else {
        if running_under_systemd {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .without_time(),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .init();
        }

        Ok(None)
    }
}

fn open_log_writer(
    path: &Path,
) -> Result<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
)> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory {}", parent.display()))?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log file {}", path.display()))?;

    Ok(tracing_appender::non_blocking(file))
}
