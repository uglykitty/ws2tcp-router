use std::{
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

    if let Some(path) = &args.log_file {
        let (file_writer, guard) = open_log_writer(path)?;
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(file_writer)
            .with_ansi(false);

        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .init();

        Ok(Some(guard))
    } else {
        let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .init();

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
