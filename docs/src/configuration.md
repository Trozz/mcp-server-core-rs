# Configuration reference

A server built with `app::Server` is configured entirely with environment variables. This page lists every variable the server itself reads, how values are read, and how they are checked. Your services read their own variables in the same way.

The server checks its configuration at startup and, if anything is wrong, prints every problem it found and exits without starting, so a typo never leaves it half configured. A few checks wait until others pass; see [Validation](#validation).

## How values are read

- **An empty value counts as unset.** `MCP_AUTH_TOKEN=` is the same as not setting it.
- **Any variable can be read from a file** by appending `_FILE` to its name, such as `OAUTH_SIGNING_KEY_FILE=/run/secrets/oauth_signing_key`. Use it for secrets with Docker or Kubernetes secrets. A value set directly wins over the file. Trailing newlines (`\n` and `\r`) are removed from the file's contents, and an empty file counts as unset. A file that cannot be read is a configuration error: `OAUTH_SIGNING_KEY_FILE: cannot read /run/secrets/oauth_signing_key: No such file or directory (os error 2)`.
- **Booleans** accept `true`, `false`, `1`, `0`, `yes`, `no`, `on` and `off`, in any case. Anything else is an error, such as `INSECURE_HTTP must be true or false, got "maybe"`.
- **Lists** are comma separated. Spaces around entries are ignored, and so are empty entries: `" a, b ,,c "` is `a`, `b` and `c`.
- **Addresses** (`BIND_ADDR`, `METRICS_ADDR`) are an IP address and a port, such as `0.0.0.0:8443` or `[::]:8443`. Host names are not accepted.
- **Error messages never contain secret values.** A rejected `OAUTH_SIGNING_KEY` is reported by name and rule, never by its value.

## The prefix

Three variables belong to one server and carry its prefix: `<PREFIX>_SERVICES`, `<PREFIX>_COMBINED` and `<PREFIX>_READ_ONLY`. The prefix is `MCP` unless the server sets another with [`Server::env_prefix`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.env_prefix), which removes trailing underscores and converts it to upper case:

```rust
use mcp_server_core::app::Server;

let server = Server::new("mcp-weather", "1.0.0").env_prefix("weather_");
assert_eq!(server.var("SERVICES"), "WEATHER_SERVICES");

let default = Server::new("mcp-weather", "1.0.0");
assert_eq!(default.var("READ_ONLY"), "MCP_READ_ONLY");
```

Every other variable on this page has a fixed name, whatever the prefix. `MCP_AUTH_TOKEN` is always `MCP_AUTH_TOKEN`. A server's own documentation should give its prefix; mcp-icloud uses `ICLOUD`, for example `ICLOUD_SERVICES`.

## Public address and listening

| Variable | Default | Example | Meaning |
|---|---|---|---|
| `PUBLIC_URL` | required | `https://mcp.example.com` | The external URL clients use, without a path. It must be `https://`; `http://` is accepted only when the host is `localhost`, `127.0.0.1` or `[::1]`. A port is allowed, a trailing `/` is removed, and a path, query or fragment is an error. It is the OAuth issuer, the prefix of every service's URL and the host the MCP endpoints accept; see [TLS and deployment](deployment.md#public_url). |
| `BIND_ADDR` | `0.0.0.0:8443` | `127.0.0.1:8443` | The address and port to listen on. `--healthcheck` connects to `127.0.0.1` on this port, so the address must accept loopback connections; `0.0.0.0` does. |
| `TLS_CERT_PATH` | none | `/certs/fullchain.pem` | A PEM certificate chain, leaf first. Set it together with `TLS_KEY_PATH`; setting only one is an error. The server checks both files every 30 seconds and reloads them when either changes. Without either, the server generates a self-signed certificate. See [TLS and deployment](deployment.md#choosing-how-the-server-listens). |
| `TLS_KEY_PATH` | none | `/certs/privkey.pem` | The PEM private key for `TLS_CERT_PATH`. |
| `INSECURE_HTTP` | `false` | `true` | Serve plain HTTP, for a reverse proxy or tunnel that terminates TLS in front of the server. It wins over `TLS_CERT_PATH` and `TLS_KEY_PATH`, which are then ignored. `--healthcheck` reads it too. |
| `TRUSTED_PROXIES` | none | `10.0.0.2,10.0.0.3` | Comma-separated IP addresses of reverse proxies you run. A request from one of them is limited by the client address in its `X-Forwarded-For` header instead of the proxy's. Single addresses only, not ranges; an invalid entry is an error. See [Reverse proxies](deployment.md#reverse-proxies-and-trusted_proxies). |
| `ALLOWED_ORIGINS` | none | `http://localhost:6274` | Comma-separated browser origins, besides `PUBLIC_URL`'s own, allowed to call the MCP endpoints. Each is `scheme://host` with an optional `:port`, or `:*` for any port. Entries are passed to rmcp as written and not checked at startup: one that does not parse matches nothing. See [Host and Origin checks](deployment.md#host-and-origin-checks). |

## Sign-in and tokens

| Variable | Default | Example | Meaning |
|---|---|---|---|
| `OAUTH_SIGNING_KEY` | required | output of `openssl rand -hex 32` | Signs every token the server issues and derives the key that seals people's credentials into their tokens. At least 32 bytes; the value is used as text, so 64 hex characters are 64 bytes. Changing it signs everyone out and every client must register again. Keep it secret: whoever has it can mint tokens and open sealed credentials. |
| `OAUTH_ADMIN_PASSWORD` | required with `SignIn::OwnerPassword` | a passphrase | The owner's password for the sign-in page. At least 12 characters and not only spaces; shorter than 15 gets a warning at startup. It is compared exactly as typed, spaces included, and the sign-in page accepts at most 1024 bytes. Changing it ends every grant. Not read with the other sign-in modes. See [Sign-in modes](sign-in.md#the-owners-password). |
| `MCP_AUTH_TOKEN` | none | output of `openssl rand -hex 32` | A fixed bearer token accepted on every path, for clients that cannot sign in with OAuth. It must not have the shape of a JWT (three dot-separated parts), and cannot be used when people sign in with their own credential, or when the verifier accepts credentials as bearer tokens. Shorter than 32 characters gets a warning. Wrong tokens count towards the sign-in limits. See [The static token](sign-in.md#the-static-token). |

## Services

| Variable | Default | Example | Meaning |
|---|---|---|---|
| `<PREFIX>_SERVICES` | every registered service | `weather,tides` | The services to run, comma separated. An unknown name, or a list with no names, is an error. A service that is not selected is not mounted and never reads its own variables, so they need not be set. Selected services are built, mounted and listed on `/mcp` in the order this variable names them. |
| `<PREFIX>_COMBINED` | `true` | `false` | Serve every selected service's tools and prompts together at `/mcp`, as `<service>_<name>`. With `false`, `/mcp` answers 404. See [Several services and /mcp](combined.md). |
| `<PREFIX>_READ_ONLY` | none | `tides` or `all` | Services whose write tools are hidden and refused, on their own path and under `/mcp`. Comma separated, or `all` for every registered service. An unknown name is an error; a registered service that is not selected is accepted and has no effect. See [Read-only mode and the audit log](read-only-and-audit.md). |
| `AUDIT_LOG_PATH` | none | `/audit/audit.jsonl` | A file to append one JSON line to for every write tool call, made or refused. It is opened on the first write. On Unix it is created with mode 0600, and an existing file is narrowed to 0600. Audit lines are logged on the `audit` target whether or not this is set. See [The audit file](read-only-and-audit.md#the-audit-file). |

## Logs, metrics and traces

| Variable | Default | Example | Meaning |
|---|---|---|---|
| `LOG_LEVEL` | `info` | `info,mcp_weather=debug` | A `tracing` filter: a level for everything, then `target=level` directives. It is not checked with the other variables: an invalid filter stops the server right after them, with an `error:` line. See [Logs](observability.md#log_level). |
| `LOG_FORMAT` | `json` | `pretty` | `json` for one JSON object per line, or `pretty` for multi-line, coloured output (without colour when the `NO_COLOR` environment variable is set and not empty). Any case. |
| `DEBUG` | `false` | `true` | Debug logs for your own crates and this one, without content. See [DEBUG](observability.md#debug). |
| `DEBUG_UNSAFE_LOG_CONTENT` | `false` | `true` | Lets services log content, such as the text people send and read, and turns on `DEBUG` too. A warning is logged at startup. Never in production. See [Content in logs](observability.md#content-in-logs). |
| `METRICS_ADDR` | none | `0.0.0.0:9090` | Serve Prometheus metrics on a separate plain HTTP listener at this address. Keep it on an internal network. Needs the `prometheus` feature (on by default); without it the server logs a warning. See [Metrics](observability.md#metrics). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none | `http://otel-collector:4318` | Export traces over OTLP/HTTP to this collector. Only this variable turns export on: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` on its own does not. The standard `OTEL_*` variables apply. Needs the `otel` feature (on by default); without it the server logs a warning. See [Traces](observability.md#traces). |

Those are all the variables the server reads while loading its configuration. Two other readers exist:

- The OpenTelemetry exporter reads the standard OpenTelemetry variables itself when traces are on, such as `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and `OTEL_EXPORTER_OTLP_TIMEOUT`. It reads them directly from the environment, so they have no `_FILE` variants. That includes `OTEL_EXPORTER_OTLP_ENDPOINT`: set it directly, because the `_FILE` form turns export on but the exporter itself does not see the address.
- `--healthcheck` reads `BIND_ADDR` and `INSECURE_HTTP` (or their `_FILE` variants), and nothing else. Run it with the server's environment.

## Services' own variables

Each service reads its own variables in its factory, through the [`ServiceEnv`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/type.ServiceEnv.html) it is given. They follow the same rules as the server's: empty means unset, `_FILE` variants, the same booleans and lists, and problems recorded rather than returned one at a time. A server's documentation lists them; [Reading configuration with ServiceEnv](writing-a-service.md#reading-configuration-with-serviceenv) shows how to write a factory.

Name a service's variables after the service, such as `WEATHER_API_URL`, unless two services share one on purpose. A problem with a shared variable is reported once.

## Validation

`Server::load` reads the core variables, then the sign-in settings, then `<PREFIX>_SERVICES`, `<PREFIX>_READ_ONLY`, `AUDIT_LOG_PATH` and `<PREFIX>_COMBINED`, then each selected service's variables, all into one list of problems. Each message appears once, even when two services report the same one. When the list is not empty the binary prints each problem on its own line and exits with status 1:

```text
configuration error: PUBLIC_URL must be an https URL (http is only allowed for localhost)
configuration error: OAUTH_SIGNING_KEY must be at least 32 bytes
configuration error: TLS_CERT_PATH and TLS_KEY_PATH must be set together
configuration error: OAUTH_ADMIN_PASSWORD is required
configuration error: WEATHER_API_KEY is required
```

What is checked:

| Variable | Rule |
|---|---|
| `PUBLIC_URL` | Set; a URL with a host; `https`, or `http` for a loopback host; no path, query or fragment. |
| `OAUTH_SIGNING_KEY` | Set; at least 32 bytes. |
| `OAUTH_ADMIN_PASSWORD` | With `SignIn::OwnerPassword`: set; at least 12 characters; not only spaces. |
| `MCP_AUTH_TOKEN` | Not shaped like a JWT; not next to a verifier that carries credentials or accepts them as bearer tokens. |
| `TRUSTED_PROXIES` | Every entry an IP address. |
| `BIND_ADDR` | An IP address and port. |
| `METRICS_ADDR` | An IP address and port. |
| `INSECURE_HTTP` | A boolean. |
| `DEBUG` | A boolean. |
| `DEBUG_UNSAFE_LOG_CONTENT` | A boolean. |
| `LOG_FORMAT` | `json` or `pretty`. |
| `TLS_CERT_PATH` | Set together with `TLS_KEY_PATH`, unless `INSECURE_HTTP` is on. The files themselves are read when the server starts serving. |
| `<PREFIX>_SERVICES` | Only registered names, at least one. |
| `<PREFIX>_READ_ONLY` | Only registered names, or `all`. |
| `<PREFIX>_COMBINED` | A boolean. |

The sign-in mode adds rules of its own. With `SignIn::ServiceCredential`, exactly one enabled service must define how people sign in; see [Only one service may define sign-in](sign-in.md#only-one-service-may-define-sign-in).

A few checks can only run once others pass, so fixing one round of errors can reveal another:

- The checks on `MCP_AUTH_TOKEN` run once `PUBLIC_URL`, `OAUTH_SIGNING_KEY` and the other server variables are valid.
- Services read their variables only once `<PREFIX>_SERVICES` is valid, since until then the server does not know which services to build.
- `LOG_LEVEL`, the OpenTelemetry endpoint's address, the TLS files and the listening addresses are used when the server starts serving, after the configuration has loaded. A problem with them ends the server with an `error:` line instead of `configuration error:`.

[Troubleshooting](troubleshooting.md) quotes every message with its fix.

### Warnings

Some settings work but are weak. The server starts and logs a warning for each, straight after its `starting` line:

| Setting | Warning |
|---|---|
| `OAUTH_ADMIN_PASSWORD` of 12 to 14 characters | `OAUTH_ADMIN_PASSWORD is shorter than 15 characters: a longer passphrase is much harder to guess` |
| `MCP_AUTH_TOKEN` shorter than 32 characters | `MCP_AUTH_TOKEN is shorter than 32 characters: use a long random value` |

Other warnings at startup describe how the server runs rather than a weak value: plain HTTP, a self-signed certificate, `DEBUG_UNSAFE_LOG_CONTENT`, an `ALLOWED_ORIGINS` entry without a port, and `METRICS_ADDR` or `OTEL_EXPORTER_OTLP_ENDPOINT` set in a build without the feature. [Troubleshooting](troubleshooting.md#warnings-at-startup) lists them.

## A complete example

A server with the prefix `SEA`, two services, its secrets in files and a TLS-terminating proxy in front:

```sh
PUBLIC_URL=https://sea.example.com
BIND_ADDR=0.0.0.0:8443
INSECURE_HTTP=true
TRUSTED_PROXIES=10.0.0.2
OAUTH_SIGNING_KEY_FILE=/run/secrets/oauth_signing_key
OAUTH_ADMIN_PASSWORD_FILE=/run/secrets/oauth_admin_password
MCP_AUTH_TOKEN_FILE=/run/secrets/mcp_auth_token
SEA_SERVICES=weather,tides
SEA_READ_ONLY=tides
SEA_COMBINED=true
AUDIT_LOG_PATH=/audit/audit.jsonl
LOG_LEVEL=info
LOG_FORMAT=json
METRICS_ADDR=0.0.0.0:9090
```

To create the secrets:

```sh
mkdir -p secrets
openssl rand -hex 32 > secrets/oauth_signing_key
openssl rand -hex 32 > secrets/mcp_auth_token
printf '%s' 'a long passphrase you will remember' > secrets/oauth_admin_password
chmod 600 secrets/*
```

[TLS and deployment](deployment.md#containers) shows settings like these in a container, with the secrets mounted as files.
