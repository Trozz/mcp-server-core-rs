# Observability

This page covers the server's logs (format, filters, targets, caps and what is kept out of them), its Prometheus metrics and its OpenTelemetry traces, and the feature flags behind the last two.

All three are configured with environment variables; the [configuration reference](configuration.md#logs-metrics-and-traces) lists them with their defaults.

## Logs

The server writes logs to standard output. `LOG_FORMAT=json`, the default, writes one JSON object per line for a log collector:

```json
{"timestamp":"2026-10-18T13:55:55.909869Z","level":"INFO","message":"service enabled","service":"notes","url":"https://mcp.example.com/notes","read_only":false,"tools":"[\"add_note\", \"list_notes\"]","target":"mcp_server_core::app"}
```

| Field | Meaning |
|---|---|
| `timestamp` | When, in UTC, RFC 3339 with microseconds. |
| `level` | `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE`. |
| `message` | What happened. |
| `target` | Where it came from, usually a Rust module path such as `mcp_server_core::app`. Filters select by target. |
| `span`, `spans` | The span the event happened in, and every enclosing span, with their fields. An event during an HTTP request is in the `request` span, with `method` and `path`. |
| anything else | The event's own fields, such as `url` and `read_only` above. |

`LOG_FORMAT=pretty` writes multi-line, coloured output with the source location of each event, for reading in a terminal. It writes colour codes even when its output is not a terminal, unless the `NO_COLOR` environment variable is set and not empty, so use `json` for files and collectors.

### LOG_LEVEL

`LOG_LEVEL` is a [`tracing` filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html): comma-separated directives, each either a level for everything or `target=level` for one target and everything under it. Levels, from quietest: `off`, `error`, `warn`, `info`, `debug`, `trace`. The default is `info`.

| `LOG_LEVEL` | Effect |
|---|---|
| `info` | Everything at `info` and above. |
| `warn` | Warnings and errors only, plus audit lines, which stay on. |
| `info,mcp_weather=debug` | Everything at `info`, and your crate `mcp_weather` at `debug`. |
| `info,tower_http=debug` | Everything at `info`, and each HTTP request's start and finish, with its status and latency. |
| `debug,rmcp=info` | `debug` for everything except rmcp, which stays at `info`. |

A target matches by prefix: `mcp_weather` also covers `mcp_weather::client` and a crate named `mcp_weather_api`.

- **Always include a level for everything.** `LOG_LEVEL=mcp_weather=debug` on its own logs `mcp_weather` and audit lines and nothing else: not the startup lines, not warnings. A word that is not a level, such as `verbose`, is read as a target name, with the same result.
- **A filter that does not parse stops the server** right after the configuration loads, before logging starts, with an `error:` line: `error: error parsing level filter: expected one of "off", "error", "warn", "info", "debug", "trace", or a number 0-5: ...` for a bad level such as `mcp_weather=verbose`, or `error: invalid filter directive` for a directive such as `=debug`.
- **Some directives are replaced.** Directives for the audit target, for [capped targets](#log-caps) and for [rmcp's session targets](#rmcp-session-targets) are dropped and set by the server instead. Span-scoped directives, such as `[request]=debug`, are dropped too, because they could re-enable a capped target.

### DEBUG

`DEBUG=true` adds two directives after `LOG_LEVEL`: your crates at `debug`, and `mcp_server_core` at `debug`. Your crates are the server's crate target, which is the server's name with `-` replaced by `_` (`mcp-weather` gives `mcp_weather`), or what you set with [`Server::crate_target`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.crate_target). By prefix, it covers crates such as `mcp_weather_api` too.

`DEBUG` is the safe way to get more detail:

- It leaves dependencies at `LOG_LEVEL`, so rmcp does not start logging requests and responses (see [Content in logs](#content-in-logs)).
- Capped targets stay capped, even under your crate target.
- Your services can ask whether it is on with [`observability::debug_enabled`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/fn.debug_enabled.html), for example before doing work only a debug line needs.

This crate's own messages are at `info`, `warn` and `error`, so for it `DEBUG` mostly matters to the services you write.

### Targets

| Target | What it logs |
|---|---|
| `mcp_server_core::app` | Startup: `starting`, warnings about weak settings, `service enabled`, `combined endpoint enabled`, `listening`. A fatal error while serving. |
| `mcp_server_core::tls` | How the server listens; certificate reloads. |
| `mcp_server_core::observability` | The metrics listener; features missing from the build; the content-logging warning. |
| `mcp_server_core::oauth::register` | Client registrations. |
| `mcp_server_core::oauth::authorize` | Sign-ins granted, rejected or not checkable. |
| `mcp_server_core::oauth::middleware` | Rejected static tokens and bearer credentials. |
| `mcp_server_core::oauth::token` | Authorization codes used twice. |
| `mcp_server_core::policy` | Audit file write failures. |
| `mcp_server_core` | The shutdown signal. |
| `audit` | One line per write tool call. Always on at `info`, whatever `LOG_LEVEL` says. See [The audit log](read-only-and-audit.md#the-audit-log). |
| `rmcp::…` | rmcp's own logs: MCP sessions starting and ending, and refused `Host` and `Origin` headers. |
| `tower_http::trace::…` | Each request's start and finish at `debug`, and `response failed` at `error` for every 5xx response. |
| your crate target | Your services. |

### What the server logs

At startup, in this order:

| Level | Message | Fields |
|---|---|---|
| `WARN` | ``OTEL_EXPORTER_OTLP_ENDPOINT is set but this build has no OpenTelemetry support (feature `otel`): traces are not exported`` | Only in a build without `otel`. |
| `INFO` | `prometheus metrics listener started` | `addr`. Only with `METRICS_ADDR`. |
| `WARN` | ``METRICS_ADDR is set but this build has no Prometheus support (feature `prometheus`): metrics are not served`` | `addr`. Only in a build without `prometheus`, instead of the line above. |
| `WARN` | `DEBUG_UNSAFE_LOG_CONTENT is enabled: message content WILL be written to logs` | Only with `DEBUG_UNSAFE_LOG_CONTENT`. |
| `INFO` | `starting <name>` | `version` |
| `WARN` | weak settings, such as `OAUTH_ADMIN_PASSWORD is shorter than 15 characters: a longer passphrase is much harder to guess` | |
| `INFO` | `service enabled`, once per service | `service`, `url`, `read_only`, `tools` |
| `INFO` | `combined endpoint enabled` | `url`, `tools` (how many) |
| `WARN` | ``allowed origin without a port matches any port; a future release will match only the scheme default port. Use `:*` or an explicit port instead``, from rmcp, once per path for each such `ALLOWED_ORIGINS` entry | `allowed_origin` |
| `INFO` | `listening` | `addr` |
| `INFO` or `WARN` | `serving HTTPS with certificate from files`, or the self-signed or plain HTTP warning | `addr`; `fingerprint_sha256` and `sans` for a self-signed certificate |

While running:

| Level | Message | Fields |
|---|---|---|
| `INFO` | `oauth client registered` | `client_name`, as the client reported it |
| `INFO` | `oauth authorization granted` | `subject` |
| `WARN` | `oauth login failed: credential rejected` | `ip` |
| `WARN` | `oauth login: credential could not be checked` | `ip`, `reason` |
| `WARN` | `wrong static token rejected` | `ip` |
| `WARN` | `bearer credential rejected` | `ip` |
| `WARN` | `bearer credential could not be checked` | `reason` |
| `WARN` | `authorization code replay rejected` | |
| `INFO` | `tool write`, on the `audit` target | `service`, `endpoint`, `tool`, `outcome`, `error_kind`, `caller`, `subject`, `elapsed_ms` |
| `WARN` | `could not write the audit log`, at most once a minute | `path`, `error` |
| `INFO` | `tls certificate reloaded` | |
| `WARN` | `tls certificate reload failed, keeping previous certificate` | `error` |
| `WARN` | `rejected request with disallowed Host header (possible DNS rebinding attempt)`, from rmcp | `host` |
| `WARN` | `rejected request with malformed Host header`, from rmcp | `host` |
| `WARN` | `rejected request with disallowed Origin header (possible cross-origin attack)`, from rmcp | `origin` |
| `WARN` | `rejected request with malformed Origin header`, from rmcp | `origin` |
| `ERROR` | `response failed`, from tower_http, for every 5xx response | `classification`, `latency` |
| `INFO` | `shutdown signal received` | |
| `ERROR` | `fatal` | `error` |

rmcp also logs at `info` when an MCP session starts (`Service initialized as server`, with the client's `initialize` parameters: its name, version and capabilities), when the client finishes initialising (`client initialized`, unless the handler overrides `on_initialized`) and when a session ends (`serve finished`).

Every HTTP request to `/healthz`, the OAuth routes and the MCP endpoints runs in a `request` span with its `method` and `path`. `/favicon.ico` and routes added with `Server::wrap_router` sit outside it. The path never includes the query string, so the parameters of a sign-in request are not logged.

### Log caps

Some dependencies can reveal secrets at `debug` or `trace`, typically an HTTP client that logs request headers. A service names those targets in [`Service::log_caps`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/trait.Service.html#method.log_caps), and the server caps each of them, and everything under it, at `info`. A cap is never above the level `LOG_LEVEL` sets for everything: with `LOG_LEVEL=error` a capped target logs errors only.

The server builds the final filter with [`observability::log_filter`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/fn.log_filter.html). With `reqwest` capped:

```rust
use mcp_server_core::observability::log_filter;

assert_eq!(
    log_filter("trace,reqwest=trace", &["reqwest"], &["audit"]),
    "trace,reqwest=info,audit=info,\
     rmcp::transport::streamable_http_server=warn,rmcp::transport::worker=warn"
);
assert_eq!(
    log_filter("error", &["reqwest"], &["audit"]),
    "error,reqwest=error,audit=info,\
     rmcp::transport::streamable_http_server=error,rmcp::transport::worker=error"
);
```

The `reqwest=trace` that `LOG_LEVEL` asked for is dropped, `reqwest` is capped, the audit target is switched on at `info` and rmcp's session targets are capped at `warn`. `DEBUG` then appends its two directives.

### rmcp session targets

rmcp's Streamable HTTP server logs MCP session ids at `info` and in error messages, and its transport workers carry them in the `name` field of a `trace` span. Session ids should stay out of logs and traces, so two targets, [`service::QUIET_LOG_TARGETS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/constant.QUIET_LOG_TARGETS.html), are kept at `warn` whatever `LOG_LEVEL` says (lower if `LOG_LEVEL` is quieter):

- `rmcp::transport::streamable_http_server`
- `rmcp::transport::worker`

Their warnings, such as refused `Host` headers, still appear.

### Content in logs

This crate never logs content: not tool arguments or results, not prompts, not anything a person sent or read. The audit log records which tool was called and how it ended, never its arguments, ids or results.

`DEBUG_UNSAFE_LOG_CONTENT=true` lets your services log content, for a short investigation on a server you control. It turns on `DEBUG` too, and logs a warning at startup. Services decide with [`observability::content_logging_enabled`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/fn.content_logging_enabled.html), which they should check before logging anything a person wrote or read:

```rust
use mcp_server_core::observability::content_logging_enabled;

fn log_search(query: &str, hits: usize) {
    if content_logging_enabled() {
        tracing::debug!(query, hits, "search");
    } else {
        tracing::debug!(query_len = query.len(), hits, "search");
    }
}
# log_search("tide times", 3);
```

**rmcp logs content at `debug`.** At `debug` its `rmcp::service` target logs every request and response in full (`received request`, `response message`), tool arguments and results included, whatever `DEBUG_UNSAFE_LOG_CONTENT` says. So:

- do not set `LOG_LEVEL` to `debug` or `trace` for everything on a server people use;
- use `DEBUG=true`, or raise only the targets you need, such as `info,mcp_weather=debug`;
- if you need `debug` for everything, keep rmcp at `info`: `LOG_LEVEL=debug,rmcp=info`.

At `trace`, other dependencies log protocol detail too. Keep it brief, on a server only you use.

## Metrics

With `METRICS_ADDR` set, such as `METRICS_ADDR=0.0.0.0:9090`, the server serves Prometheus metrics on a separate listener at that address:

- It is plain HTTP without authentication. Keep it on a network only your monitoring can reach, and never publish its port.
- Any path answers with the metrics in the Prometheus text format, so scrape `/metrics`. `/health` answers `OK`.
- It starts before the main listener and logs `prometheus metrics listener started`. If it cannot bind, the server stops with `error: failed to create HTTP listener: <reason>`.
- A metric appears once something has recorded it, so a fresh server shows few.

It needs the `prometheus` feature, on by default. In a build without it, `METRICS_ADDR` is still checked as an address, and the server logs ``METRICS_ADDR is set but this build has no Prometheus support (feature `prometheus`): metrics are not served`` instead of serving.

### Metric names

| Metric | Labels | What it counts |
|---|---|---|
| `http_requests_total` | `route`, `status` | HTTP requests to `/healthz`, the OAuth routes and the MCP endpoints. `route` is the matched route pattern, such as `/healthz`, `/token`, `/weather`, `/mcp` or `/.well-known/oauth-protected-resource/{service}`, or `unmatched` for a path no route matches; `status` is the status code, such as `200` or `401`. |
| `oauth_requests_total` | `endpoint`, `outcome` | Requests to the OAuth endpoints, by result. `endpoint="register"`: `ok`, `invalid`. `endpoint="authorize"`: `ok`, `rate_limited`, `unavailable`. `endpoint="token"`: `ok`, or the OAuth error code, such as `invalid_grant`, `invalid_request`, `invalid_client`, `invalid_target` or `unsupported_grant_type`. |
| `oauth_login_failures_total` | none | Sign-ins on the sign-in page whose credential was checked and rejected. Input that cannot be a credential, refusals by the limits and checks that could not run are not counted. |
| `bearer_credential_checks_total` | `outcome` | Requests whose bearer token is a person's own credential, decided by a check rather than the cache: `valid`, `invalid` or `unavailable`. `rate_limited` counts requests refused by the sign-in limits before a check, including requests with the static token. |

`http_requests_total` covers `/healthz`, the OAuth routes and the MCP endpoints; `/favicon.ico` and routes you add with `Server::wrap_router` are not counted. Nor is a request refused with 413 because its declared `Content-Length` is over the body limit: it is refused before it reaches the counter.

### Your own metrics

With `METRICS_ADDR` set, the server installs a global recorder for the [`metrics`](https://docs.rs/metrics) crate, so metrics your services record with it are served on the same listener. Add `metrics = "0.24"` to your crate:

```rust
fn record_upstream_call(status: u16, seconds: f64) {
    metrics::counter!("weather_api_requests_total", "status" => status.to_string()).increment(1);
    metrics::histogram!("weather_api_request_duration_seconds").record(seconds);
}
# record_upstream_call(200, 0.12);
```

Histograms are exported with these buckets, in seconds: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 and 30.

### Scraping

```yaml
scrape_configs:
  - job_name: mcp-weather
    static_configs:
      - targets: ["mcp-weather:9090"]
```

Some queries worth watching:

| Query | Shows |
|---|---|
| `sum(rate(oauth_login_failures_total[5m]))` | Failed sign-ins: someone guessing, or a person with a wrong password or key. |
| `sum by (outcome) (rate(bearer_credential_checks_total[5m]))` | Credentials sent as bearer tokens; a rise in `unavailable` means the upstream service is down or slow. |
| `sum(rate(http_requests_total{status="429"}[5m]))` | Requests refused by the sign-in limits. |
| `sum(rate(http_requests_total{status="503"}[5m]))` | Checks that could not run, the server refusing new addresses, or full session tables. |
| `sum by (route) (rate(http_requests_total{status="401"}[5m]))` | Requests without a usable token, by path. |

[Refusals: 429 and 503](limits.md#refusals-429-and-503) explains when the server answers each.

## Traces

With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the server exports traces over OTLP/HTTP (protobuf) to a collector, batched in the background:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
```

- Spans go to `<endpoint>/v1/traces`. The server's name, the first argument of `Server::new`, is the `service.name` resource attribute.
- The exporter reads the standard OpenTelemetry variables itself, such as `OTEL_EXPORTER_OTLP_HEADERS` for a collector that needs an API key, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` for a full URL used as given, and `OTEL_EXPORTER_OTLP_TIMEOUT` (10 seconds by default). These have no `_FILE` variants, and neither does the endpoint itself: set it directly.
- Export is on only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` on its own does not turn it on.
- An endpoint the exporter cannot parse stops the server at startup, before logging starts, with an `error:` line such as `error: invalid exporter configuration: OTEL_EXPORTER_OTLP_ENDPOINT: invalid endpoint 'http://bad host': invalid uri character`.
- Spans not yet sent are flushed when the server shuts down.

One filter, `LOG_LEVEL` with its caps, decides both what is logged and what is traced. So the exported spans are:

- `request`, for every HTTP request to `/healthz`, the OAuth routes and the MCP endpoints, with `method` and `path`;
- rmcp's spans for MCP sessions, apart from the session targets kept at `warn`;
- the spans of your own code, such as functions marked `#[tracing::instrument]`, at the levels `LOG_LEVEL` allows.

Log events inside a span are attached to it as span events.

It needs the `otel` feature, on by default. In a build without it the server logs ``OTEL_EXPORTER_OTLP_ENDPOINT is set but this build has no OpenTelemetry support (feature `otel`): traces are not exported``.

## Feature flags

| Feature | Default | What it adds |
|---|---|---|
| `otel` | on | Trace export over OTLP/HTTP, with the OpenTelemetry crates and an HTTP client. |
| `prometheus` | on | The Prometheus metrics listener. |

Without them the crate pulls in fewer dependencies. Metrics are still recorded through the `metrics` crate but go nowhere, and setting `METRICS_ADDR` or `OTEL_EXPORTER_OTLP_ENDPOINT` only logs a warning. To keep metrics and leave out traces:

```toml
[dependencies]
mcp-server-core = { version = "0.2", default-features = false, features = ["prometheus"] }
```

## What is never logged

| Never logged | How |
|---|---|
| `OAUTH_SIGNING_KEY`, the owner's password, `MCP_AUTH_TOKEN` | Configuration errors about them name the variable and the rule, never the value. The settings' `Debug` output hides them. |
| People's upstream credentials | They are held as secrets whose `Debug` output is `Credential(..)`. Logs, audit lines and tokens name the person by a subject: unless the verifier names them itself, `key:` and 16 hex digits of a hash keyed by `OAUTH_SIGNING_KEY`, which cannot be used to guess the credential. |
| Bearer tokens, authorization codes and refresh tokens | Never logged, at any level, `trace` included. |
| The sign-in page's parameters | The `request` span records the path, not the query string, and form bodies are never logged. |
| MCP session ids | rmcp's session targets are kept at `warn`. |
| Tool arguments and results, prompts, anything a person sent or read | Never logged by this crate, nor by rmcp below `debug`. Your services log them only when `content_logging_enabled()` is true. |

What is logged, and may count as personal data where you are: client IP addresses on failed sign-ins and rejected tokens (`ip`), the names clients give themselves when they register, OAuth client ids in audit lines (`caller`), and subjects (`owner`, `static`, `key:…` or a custom verifier's names).

Next: [Troubleshooting](troubleshooting.md).
