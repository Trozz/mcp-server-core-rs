//! Logs, metrics and traces.
//!
//! [`init`] installs a `tracing` subscriber writing JSON (or pretty) logs to stdout, a Prometheus
//! exporter when `METRICS_ADDR` is set (feature `prometheus`) and an OTLP trace exporter when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set (feature `otel`).
//!
//! Secrets and personal content stay out of logs by default. Services should log content (message
//! bodies, search terms) only when [`content_logging_enabled`] says the operator asked for it with
//! `DEBUG_UNSAFE_LOG_CONTENT`.

#[cfg(feature = "otel")]
use opentelemetry::trace::TracerProvider as _;
#[cfg(feature = "otel")]
use opentelemetry_sdk::Resource;
#[cfg(feature = "otel")]
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// `LOG_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// One JSON object per line, for log collectors.
    Json,
    /// Multi-line, coloured output for people.
    Pretty,
}

impl FromStr for LogFormat {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(LogFormat::Json),
            "pretty" => Ok(LogFormat::Pretty),
            _ => Err(()),
        }
    }
}

/// What [`init`] sets up.
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// The OpenTelemetry service name.
    pub service_name: String,
    /// The tracing target prefix of your crates, raised to debug by `debug`.
    pub crate_target: String,
    /// A `tracing` filter, `LOG_LEVEL`.
    pub log_level: String,
    /// `LOG_FORMAT`.
    pub log_format: LogFormat,
    /// `DEBUG`.
    pub debug: bool,
    /// `DEBUG_UNSAFE_LOG_CONTENT`.
    pub unsafe_content: bool,
    /// Whether `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
    pub otlp_enabled: bool,
    /// `METRICS_ADDR`.
    pub metrics_addr: Option<SocketAddr>,
}

static DEBUG: AtomicBool = AtomicBool::new(false);
static CONTENT: AtomicBool = AtomicBool::new(false);

/// Whether `DEBUG` (or `DEBUG_UNSAFE_LOG_CONTENT`) is on.
pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

/// Whether the operator allowed content in logs with `DEBUG_UNSAFE_LOG_CONTENT`. Check it before
/// logging anything a person wrote or read.
pub fn content_logging_enabled() -> bool {
    CONTENT.load(Ordering::Relaxed)
}

/// The filter directives for `level`, with `crate_target` and this crate at debug when `debug`.
pub fn build_filter(level: &str, debug: bool, crate_target: &str) -> String {
    if !debug {
        return level.to_string();
    }
    format!("{level},{crate_target}=debug,mcp_server_core=debug")
}

/// Rewrites a `LOG_LEVEL` filter so it cannot reveal secrets: every target in `caps` (and its
/// children) is set to info whatever the filter says, and the rmcp targets in
/// [`QUIET_LOG_TARGETS`](crate::service::QUIET_LOG_TARGETS), which log MCP session ids, to warn.
/// Span-scoped directives (containing `[`) are dropped, as they could re-enable a capped target.
///
/// Setting a target to info also keeps it on when the filter is quieter, which is how the audit
/// target stays enabled at any level.
///
/// ```
/// use mcp_server_core::observability::log_filter;
///
/// let filter = log_filter("trace,noisy_dep=trace", &["noisy_dep"]);
/// assert!(filter.starts_with("trace,noisy_dep=info,"));
/// ```
pub fn log_filter(level: &str, caps: &[&str]) -> String {
    use crate::service::QUIET_LOG_TARGETS;
    let mut parts: Vec<String> = level
        .split(',')
        .map(str::trim)
        .filter(|d| {
            !d.is_empty()
                && !d.contains('[')
                && !caps
                    .iter()
                    .chain(QUIET_LOG_TARGETS)
                    .any(|c| d.starts_with(c))
        })
        .map(String::from)
        .collect();
    parts.extend(caps.iter().map(|c| format!("{c}=info")));
    parts.extend(QUIET_LOG_TARGETS.iter().map(|t| format!("{t}=warn")));
    parts.join(",")
}

/// Keeps exporters running; flushes traces when dropped. Hold it for the life of the process.
pub struct ObservabilityGuard {
    #[cfg(feature = "otel")]
    provider: Option<SdkTracerProvider>,
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(p) = self.provider.take() {
            let _ = p.shutdown();
        }
    }
}

#[cfg(feature = "prometheus")]
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Installs the global subscriber and exporters. Call once, early in `main`.
pub fn init(cfg: &ObservabilityConfig) -> anyhow::Result<ObservabilityGuard> {
    let debug = cfg.debug || cfg.unsafe_content;
    DEBUG.store(debug, Ordering::Relaxed);
    CONTENT.store(cfg.unsafe_content, Ordering::Relaxed);

    let filter = EnvFilter::try_new(build_filter(&cfg.log_level, debug, &cfg.crate_target))?;
    let fmt_layer = match cfg.log_format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(true)
            .flatten_event(true)
            .boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer().pretty().boxed(),
    };

    #[cfg(feature = "otel")]
    let provider = if cfg.otlp_enabled {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()?;
        Some(
            SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    Resource::builder()
                        .with_service_name(cfg.service_name.clone())
                        .build(),
                )
                .build(),
        )
    } else {
        None
    };
    #[cfg(feature = "otel")]
    let otel_layer = provider
        .as_ref()
        .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer(cfg.service_name.clone())));
    #[cfg(not(feature = "otel"))]
    let otel_layer: Option<tracing_subscriber::layer::Identity> = None;

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()?;

    #[cfg(feature = "otel")]
    if let Some(p) = &provider {
        opentelemetry::global::set_tracer_provider(p.clone());
    }
    #[cfg(not(feature = "otel"))]
    if cfg.otlp_enabled {
        tracing::warn!(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but this build has no OpenTelemetry support (feature `otel`): traces are not exported"
        );
    }

    if let Some(addr) = cfg.metrics_addr {
        #[cfg(feature = "prometheus")]
        {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .with_http_listener(addr)
                .set_buckets(DURATION_BUCKETS)?
                .install()?;
            tracing::info!(%addr, "prometheus metrics listener started");
        }
        #[cfg(not(feature = "prometheus"))]
        tracing::warn!(
            %addr,
            "METRICS_ADDR is set but this build has no Prometheus support (feature `prometheus`): metrics are not served"
        );
    }
    if cfg.unsafe_content {
        tracing::warn!(
            "DEBUG_UNSAFE_LOG_CONTENT is enabled: message content WILL be written to logs"
        );
    }
    Ok(ObservabilityGuard {
        #[cfg(feature = "otel")]
        provider,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_format_parses() {
        assert!(matches!("json".parse::<LogFormat>(), Ok(LogFormat::Json)));
        assert!(matches!(
            "Pretty".parse::<LogFormat>(),
            Ok(LogFormat::Pretty)
        ));
        assert!("xml".parse::<LogFormat>().is_err());
    }

    #[test]
    fn filter_without_debug_is_level_as_given() {
        assert_eq!(build_filter("info", false, "mcp_example"), "info");
        assert_eq!(
            build_filter("warn,mcp_example::api=trace", false, "mcp_example"),
            "warn,mcp_example::api=trace"
        );
    }

    #[test]
    fn debug_raises_own_crates() {
        assert_eq!(
            build_filter("info", true, "mcp_example"),
            "info,mcp_example=debug,mcp_server_core=debug"
        );
    }

    const Q: &str = "rmcp::transport::streamable_http_server=warn,rmcp::transport::worker=warn";

    #[test]
    fn log_filter_caps_every_listed_target() {
        assert_eq!(
            log_filter("trace,a=trace,b::x=debug", &["a", "b"]),
            format!("trace,a=info,b=info,{Q}")
        );
        assert_eq!(log_filter("warn", &[]), format!("warn,{Q}"));
        assert_eq!(log_filter("", &["a"]), format!("a=info,{Q}"));
        assert_eq!(
            log_filter("info,[{x}]=trace,[x]=trace,debug", &["a"]),
            format!("info,debug,a=info,{Q}")
        );
        assert_eq!(
            log_filter("debug,a=trace,a::client=trace", &["a"]),
            format!("debug,a=info,{Q}")
        );
    }

    #[test]
    fn session_ids_stay_out_of_logs_whatever_the_level() {
        use tracing::Level;
        let filter = log_filter(
            "trace,rmcp=trace,rmcp::transport::streamable_http_server::session::local=trace",
            &[],
        );
        let subscriber = tracing_subscriber::registry().with(EnvFilter::new(filter));
        tracing::subscriber::with_default(subscriber, || {
            assert!(!tracing::enabled!(
                target: "rmcp::transport::streamable_http_server::session::local",
                Level::INFO
            ));
            assert!(tracing::enabled!(
                target: "rmcp::transport::streamable_http_server::session::local",
                Level::WARN
            ));
            assert!(!tracing::enabled!(
                target: "rmcp::transport::streamable_http_server::tower",
                Level::INFO
            ));
            // The transport worker's trace span carries the session id in its name.
            assert!(!tracing::span_enabled!(
                target: "rmcp::transport::worker",
                Level::TRACE
            ));
            assert!(tracing::enabled!(target: "rmcp::handler", Level::TRACE));
        });
    }

    #[test]
    fn a_capped_target_stays_on_at_info_at_any_level() {
        use tracing::Level;
        for level in [
            "warn",
            "error",
            "off",
            "info,audit=off",
            "trace,audit=error",
        ] {
            let directives = build_filter(&log_filter(level, &["audit"]), false, "mcp_example");
            let subscriber = tracing_subscriber::registry().with(EnvFilter::new(directives));
            tracing::subscriber::with_default(subscriber, || {
                assert!(tracing::enabled!(target: "audit", Level::INFO), "{level}");
            });
        }
    }

    #[test]
    fn debug_covers_own_crates_but_not_capped_ones() {
        use tracing::Level;
        let level = log_filter("trace", &["noisy_dep"]);
        let directives = build_filter(&level, true, "mcp_example");
        let subscriber = tracing_subscriber::registry().with(EnvFilter::new(directives));
        tracing::subscriber::with_default(subscriber, || {
            assert!(tracing::enabled!(target: "mcp_example_tools::api", Level::DEBUG));
            assert!(tracing::enabled!(target: "mcp_example", Level::DEBUG));
            assert!(!tracing::enabled!(target: "noisy_dep::client", Level::DEBUG));
            assert!(tracing::enabled!(target: "noisy_dep::client", Level::INFO));
        });
        let directives = build_filter("info", true, "mcp_example");
        let subscriber = tracing_subscriber::registry().with(EnvFilter::new(directives));
        tracing::subscriber::with_default(subscriber, || {
            assert!(tracing::enabled!(target: "mcp_example_tools", Level::DEBUG));
            assert!(!tracing::enabled!(target: "hyper", Level::DEBUG));
        });
    }
}
