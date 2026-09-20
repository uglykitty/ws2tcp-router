use std::{
    env, fmt,
    fs::{self, OpenOptions},
    path::Path,
};

use anyhow::{Context, Result};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{
    EnvFilter,
    fmt::{
        FmtContext, FormatEvent, FormatFields,
        format::Writer,
        time::{FormatTime, SystemTime},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

use crate::args::Args;

pub fn init_logging(args: &Args) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = match &args.log_level {
        Some(log_level) => EnvFilter::try_new(log_level)
            .with_context(|| format!("invalid --log-level filter {log_level:?}"))?,
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| "ws2tcp_router=info".into()),
    };

    // journald adds its own timestamps.
    let format = ShortTarget {
        with_time: env::var_os("JOURNAL_STREAM").is_none(),
    };

    if let Some(path) = &args.log_file {
        let (file_writer, guard) = open_log_writer(path)?;

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(format)
                    .with_writer(file_writer)
                    .with_ansi(false),
            )
            .init();

        Ok(Some(guard))
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(format)
                    .with_writer(std::io::stderr),
            )
            .init();

        Ok(None)
    }
}

/// The default `fmt` output, except that the crate prefix is dropped from the target
/// (`proxy` instead of `ws2tcp_router::proxy`).
struct ShortTarget {
    with_time: bool,
}

impl<S, N> FormatEvent<S, N> for ShortTarget
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();
        let ansi = writer.has_ansi_escapes();

        if self.with_time {
            SystemTime.format_time(&mut writer)?;
            writer.write_char(' ')?;
        }

        let level = meta.level();
        let color = match *level {
            Level::ERROR => "\x1b[31m",
            Level::WARN => "\x1b[33m",
            Level::INFO => "\x1b[32m",
            Level::DEBUG => "\x1b[34m",
            Level::TRACE => "\x1b[35m",
        };
        let (on, off) = paint(ansi, color);
        write!(writer, "{on}{level:>5}{off} ")?;

        let target = meta.target();
        let target = target.strip_prefix(CRATE_PREFIX).unwrap_or(target);
        let (on, off) = paint(ansi, "\x1b[2m");
        write!(writer, "{on}{target}:{off} ")?;

        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

const CRATE_PREFIX: &str = concat!(env!("CARGO_CRATE_NAME"), "::");

fn paint(ansi: bool, code: &'static str) -> (&'static str, &'static str) {
    if ansi { (code, "\x1b[0m") } else { ("", "") }
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
