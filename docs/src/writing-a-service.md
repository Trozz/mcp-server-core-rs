# Writing a service

This page covers everything you write yourself: the `Service` trait, the factory that reads a service's configuration, tools written with rmcp, how a tool finds out who is calling, and the `Server` builder that turns services into a binary.

The examples build one service, `tasks`, a small task list that talks to an imaginary upstream API.

## The parts

| You write | It is | The server does with it |
|---|---|---|
| An rmcp handler | A type implementing rmcp's `ServerHandler`, usually with `#[tool_router]` | Serves it over Streamable HTTP, one instance per MCP session |
| A [`Service`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/trait.Service.html) | A name and a way to make a handler | Mounts it at `/<name>`, makes it an OAuth protected resource, adds its tools to `/mcp` |
| A [`ServiceFactory`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/type.ServiceFactory.html) | `fn(&mut ServiceEnv) -> Option<Arc<dyn Service>>` | Calls it at startup when the service is selected, so the service reads its own variables |
| `main` | A [`Server`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html) with your services | Reads the configuration, signs people in, serves |

## The Service trait

`Service` is `Send + Sync + 'static`. Only `name` and `handler` are required:

| Method | Default | Purpose |
|---|---|---|
| `fn name(&self) -> &'static str` | required | The path segment, OAuth resource suffix and scope, and the prefix on `/mcp`. See [Names](#names). |
| `fn handler(&self) -> DynHandler` | required | A new MCP handler. Called once per MCP session, on `/<name>` and on `/mcp`. |
| `fn router(self: Arc<Self>, ctx: &ServiceContext) -> axum::Router` | serves `handler()` with [`mcp_service`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/fn.mcp_service.html) | The Streamable HTTP service mounted at `/<name>`. Override it to serve resources or to do work when the service is mounted. |
| `fn tool_names(&self) -> Vec<String>` | none | Tool names for the startup log. They change nothing that is served. |
| `fn log_caps(&self) -> &'static [&'static str]` | none | Tracing targets, usually dependencies, kept at `info` or below whatever `LOG_LEVEL` says, because their debug output could leak secrets. |
| `fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>>` | `None` | How people sign in with their own credential for this service's upstream, with [`SignIn::ServiceCredential`](sign-in.md). |

A service with every method written out:

```rust
use mcp_server_core::axum::Router;
use mcp_server_core::combined::DynHandler;
use mcp_server_core::credential::CredentialVerifier;
use mcp_server_core::service::{Service, ServiceContext, mcp_service};
use std::sync::Arc;
# use mcp_server_core::rmcp::ServerHandler;
# #[derive(Clone)]
# struct TasksTools;
# impl TasksTools { fn new(_: Arc<String>) -> Self { TasksTools } }
# impl ServerHandler for TasksTools {}

struct TasksService {
    /// Shared by every session: clone it into each handler.
    api_url: Arc<String>,
}

impl Service for TasksService {
    fn name(&self) -> &'static str {
        "tasks"
    }

    fn handler(&self) -> DynHandler {
        DynHandler::new(TasksTools::new(self.api_url.clone()))
    }

    // The default, written out.
    fn router(self: Arc<Self>, ctx: &ServiceContext) -> Router {
        mcp_service(ctx, move || Ok(self.handler()))
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["add_task".into(), "list_tasks".into()]
    }

    fn log_caps(&self) -> &'static [&'static str] {
        &["hyper", "reqwest"]
    }

    fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
        None
    }
}
```

### Names

A service name is used as the path (`/tasks`), the OAuth resource (`PUBLIC_URL/tasks`) and its scope, the tool prefix on `/mcp` (`tasks_add_task`) and the `service` field of the audit log. So it must be:

- lowercase ASCII letters, digits and `-`, and not empty. `_` is not allowed because `/mcp` splits a prefixed name at its first `_`;
- not `mcp`, which is the combined endpoint;
- unique within the server.

[`Server::service`](#the-server-builder) checks these when you register the service and panics, so a bad name fails the first time you run the binary:

| Name | Panic message |
|---|---|
| `my_service` | `service name "my_service" must be lowercase letters, digits and '-'` |
| `mcp` | `service name "mcp" is reserved for the combined endpoint` |
| registered twice | `service "tasks" is registered twice` |

The service the factory returns must report the name it was registered under. Otherwise startup stops with `the service registered as tasks is named todo`.

### The handler

`handler` runs once for every MCP session, on the service's own path and again on `/mcp`, so keep it cheap: clone `Arc`s into a new handler and do the real work in tools. State shared by every session, such as an HTTP client, a cache or a connection pool, lives in the `Service` and is cloned into each handler.

[`DynHandler`](https://docs.rs/mcp-server-core/latest/mcp_server_core/combined/struct.DynHandler.html) boxes any rmcp `ServerHandler`, so services with different handler types fit in one server. It forwards the server information (`initialize`), tools and prompts: `get_info`, `get_tool`, `list_tools`, `call_tool`, `list_prompts` and `get_prompt`. Tools and prompts are listed in one page. Everything else, such as resources and completions, is not forwarded.

### Overriding the router

The default `router` serves `handler()`, which carries tools and prompts. Override it when you need more:

- **Resources.** Serve your concrete handler type with `mcp_service`, so rmcp sees all of its methods. Resources are served on the service's own path only, never on `/mcp`.
- **Work at mount time**, such as logging the service's settings or warming a cache. `router` runs once, when the server mounts the service.

```rust
use mcp_server_core::axum::Router;
use mcp_server_core::combined::DynHandler;
use mcp_server_core::service::{Service, ServiceContext, mcp_service};
use std::sync::Arc;
# use mcp_server_core::rmcp::ServerHandler;
# #[derive(Clone)]
# struct TasksTools;
# impl TasksTools { fn new(_: Arc<String>) -> Self { TasksTools } }
# impl ServerHandler for TasksTools {}

struct TasksService {
    api_url: Arc<String>,
}

impl Service for TasksService {
    fn name(&self) -> &'static str {
        "tasks"
    }

    fn handler(&self) -> DynHandler {
        DynHandler::new(TasksTools::new(self.api_url.clone()))
    }

    fn router(self: Arc<Self>, ctx: &ServiceContext) -> Router {
        // Runs once, when the service is mounted: warm caches or log settings here.
        let api_url = self.api_url.clone();
        // The concrete type, not DynHandler, so resources are served too.
        mcp_service(ctx, move || Ok(TasksTools::new(api_url.clone())))
    }
}
```

The read-only rule and the audit log still apply to an overridden router: the server attaches the service's policy to the router it returns, and `mcp_service` wraps every handler it makes. `mcp_service` also adds the Host and Origin checks, the request body limit and session binding; see [Lower-level API](lower-level-api.md) for using it on its own.

### Log caps

`log_caps` names tracing targets whose debug or trace output could reveal secrets, typically an HTTP client that logs request headers. Each target and its children are capped at `info`, and never raised above what `LOG_LEVEL` sets for everything. With `reqwest` capped as above, `LOG_LEVEL=trace` still cannot make it log at trace. See [Observability](observability.md).

### Sign-in

With [`SignIn::ServiceCredential`](sign-in.md#each-persons-own-credential), people sign in with their own credential for the upstream service, and the server asks the enabled service that returns a verifier from `credential_verifier`. Exactly one enabled service may return one:

- none, with at least one service enabled, stops startup with `no enabled service defines how people sign in`;
- two or more stop it with `more than one enabled service defines how people sign in (<names>): enable one of them`, because each service's tools would receive a credential meant for another upstream.

With the other sign-in modes `credential_verifier` is not asked. See [Only one service may define sign-in](sign-in.md#only-one-service-may-define-sign-in).

## Service factories

A [`ServiceFactory`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/type.ServiceFactory.html) is a plain function:

```rust
# use mcp_server_core::service::{Service, ServiceEnv};
# use std::sync::Arc;
type ServiceFactory = fn(&mut ServiceEnv) -> Option<Arc<dyn Service>>;
```

The server calls the factory of each selected service once at startup: in registration order, or, when `<PREFIX>_SERVICES` is set, in the order that variable names them. A service that is not selected (see `<PREFIX>_SERVICES` in the [configuration reference](configuration.md)) never has its factory called, so its variables are not read and a missing one does not stop the server. The factory records every problem in `env.errors` and returns `None` when the service cannot start.

## Reading configuration with ServiceEnv

[`ServiceEnv`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/type.ServiceEnv.html) is an [`EnvReader`](https://docs.rs/mcp-server-core/latest/mcp_server_core/config/struct.EnvReader.html) over the process environment. It reads every variable the same way as the server's own:

- An empty value counts as unset.
- Any variable can come from a file instead: `TASKS_API_KEY_FILE=/run/secrets/tasks` reads `TASKS_API_KEY` from that file, without its trailing newline (`\n` or `\r\n`). A value set directly wins over the file.
- Problems are pushed to `env.errors` instead of returned, so one start reports all of them.

| Method | Returns | Behaviour and error message |
|---|---|---|
| `optional(name)` | `Option<String>` | The value, or the contents of the file named by `<name>_FILE`. An unreadable file records `<name>_FILE: cannot read <path>: <reason>`. |
| `required(name)` | `Option<String>` | Like `optional`; when neither is set it records `<name> is required`. |
| `secret_optional(name)` | `Option<SecretString>` | `optional` as a [`secrecy::SecretString`](https://docs.rs/secrecy/0.10/secrecy/type.SecretString.html), which never prints its value. |
| `secret_required(name)` | `Option<SecretString>` | `required` as a `SecretString`. |
| `bool(name, default)` | `bool` | `1`, `true`, `yes`, `on` or `0`, `false`, `no`, `off`, in any case. Anything else records `<name> must be true or false, got "<value>"` and returns `default`. |
| `parse(name, default)` | `T: FromStr` | `default` when unset. A value that does not parse records `<name> has an invalid value` and returns `default`. |
| `parse_optional(name)` | `Option<T>` | Like `parse`, without a default. |
| `list(name)` | `Vec<String>` | A comma-separated list, each entry trimmed, empty entries dropped. Unset is an empty list. |
| `ServiceEnv::new(get)` | `ServiceEnv` | A reader over your own lookup function, for tests. |
| `errors` | `Vec<String>` | Every problem so far, as messages for the operator. Only `bool` quotes the value it could not read, and the `_FILE` error names the file's path; the other messages name only the variable, so secrets stay out of them. |

To read a `SecretString` you need the `secrecy` crate (`cargo add secrecy`) for its `ExposeSecret` trait.

A configuration reader for the `tasks` service, and a test of it:

```rust
use mcp_server_core::service::ServiceEnv;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::time::Duration;

struct TasksConfig {
    api_url: String,
    api_key: SecretString,
    timeout: Duration,
    projects: Vec<String>,
    archive_done: bool,
}

/// Reads every variable first, so every problem is recorded, then gives up if there were any.
fn tasks_config(env: &mut ServiceEnv) -> Option<TasksConfig> {
    let before = env.errors.len();
    let api_url = env
        .optional("TASKS_API_URL")
        .unwrap_or_else(|| "https://api.example.com".into());
    if !api_url.starts_with("https://") {
        env.errors.push("TASKS_API_URL must be an https URL".into());
    }
    let api_key = env.secret_required("TASKS_API_KEY");
    let timeout = Duration::from_secs(env.parse("TASKS_TIMEOUT_SECS", 10));
    let projects = env.list("TASKS_PROJECTS");
    let archive_done = env.bool("TASKS_ARCHIVE_DONE", false);
    if env.errors.len() > before {
        return None;
    }
    Some(TasksConfig { api_url, api_key: api_key?, timeout, projects, archive_done })
}

// Three mistakes, all reported by one start.
let vars: HashMap<String, String> = [
    ("TASKS_API_URL", "http://api.example.com"),
    ("TASKS_TIMEOUT_SECS", "soon"),
]
.into_iter()
.map(|(k, v)| (k.to_string(), v.to_string()))
.collect();
let mut env = ServiceEnv::new(Box::new(move |k: &str| vars.get(k).cloned()));
assert!(tasks_config(&mut env).is_none());
assert_eq!(
    env.errors,
    [
        "TASKS_API_URL must be an https URL",
        "TASKS_API_KEY is required",
        "TASKS_TIMEOUT_SECS has an invalid value",
    ]
);

// A good configuration, with the key from the environment.
let vars: HashMap<String, String> = [
    ("TASKS_API_KEY", "tk_live_0123"),
    ("TASKS_PROJECTS", "home, work,,"),
]
.into_iter()
.map(|(k, v)| (k.to_string(), v.to_string()))
.collect();
let mut env = ServiceEnv::new(Box::new(move |k: &str| vars.get(k).cloned()));
let config = tasks_config(&mut env).expect("valid");
assert_eq!(config.api_url, "https://api.example.com");
assert_eq!(config.api_key.expose_secret(), "tk_live_0123");
assert_eq!(config.timeout, Duration::from_secs(10));
assert_eq!(config.projects, ["home", "work"]);
assert!(!config.archive_done);
```

The factory then builds the service from it:

```rust
# use mcp_server_core::combined::DynHandler;
# use mcp_server_core::rmcp::ServerHandler;
# use mcp_server_core::service::{Service, ServiceEnv};
# use std::sync::Arc;
# #[derive(Clone)] struct Tools;
# impl ServerHandler for Tools {}
# struct TasksConfig;
# fn tasks_config(_: &mut ServiceEnv) -> Option<TasksConfig> { Some(TasksConfig) }
# struct TasksService { config: Arc<TasksConfig> }
# impl Service for TasksService {
#     fn name(&self) -> &'static str { "tasks" }
#     fn handler(&self) -> DynHandler { DynHandler::new(Tools) }
# }
fn tasks(env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    let config = tasks_config(env)?;
    Some(Arc::new(TasksService { config: Arc::new(config) }))
}
```

### Every error at once

`Server::load` reads the core variables, the sign-in settings, the server's own `<PREFIX>_` variables and `AUDIT_LOG_PATH`, and then each selected service's, all into the same `ServiceEnv`. When anything was recorded, the binary prints each problem on its own line and exits with status 1 without starting:

```text
configuration error: OAUTH_SIGNING_KEY must be at least 32 bytes
configuration error: TASKS_API_URL must be an https URL
configuration error: TASKS_API_KEY is required
```

Each message is printed once, so two services reading the same variable do not report it twice. Name your variables after the service (`TASKS_…`) unless two services share them on purpose. The [configuration reference](configuration.md) lists the server's own variables.

## Writing tools with rmcp

Tools are ordinary [rmcp](https://docs.rs/rmcp) tools. Use rmcp through the re-export, `mcp_server_core::rmcp`, so the versions match.

```rust
use mcp_server_core::rmcp;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::handler::server::wrapper::Parameters;
use mcp_server_core::rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use mcp_server_core::rmcp::schemars::{self, JsonSchema};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

/// One instance per MCP session; the task list is shared.
#[derive(Clone)]
struct TasksTools {
    tasks: Arc<Mutex<Vec<String>>>,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, JsonSchema)]
struct AddTask {
    /// What needs doing.
    title: String,
    /// When it is due, as YYYY-MM-DD.
    due: Option<String>,
}

#[tool_router]
impl TasksTools {
    fn new(tasks: Arc<Mutex<Vec<String>>>) -> Self {
        Self { tasks, tool_router: Self::tool_router() }
    }

    #[tool(description = "List the open tasks.", annotations(read_only_hint = true))]
    async fn list_tasks(&self) -> Result<CallToolResult, McpError> {
        let text = self.tasks.lock().unwrap().join("\n");
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(
        description = "Add a task.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = false)
    )]
    async fn add_task(
        &self,
        Parameters(AddTask { title, due }): Parameters<AddTask>,
    ) -> Result<CallToolResult, McpError> {
        if title.trim().is_empty() {
            // `kind: message`: the audit log records the kind.
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "invalid_argument: title is empty",
            )]));
        }
        let entry = match due {
            Some(due) => format!("{title} (due {due})"),
            None => title,
        };
        self.tasks.lock().unwrap().push(entry);
        Ok(CallToolResult::success(vec![ContentBlock::text("added")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for TasksTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Keeps a task list. Dates are YYYY-MM-DD.")
    }
}
```

- `use mcp_server_core::rmcp;` is needed in every file that uses rmcp's macros: they generate code that names the crate `rmcp`, which otherwise only resolves when rmcp is in your own `Cargo.toml`.
- `#[tool_router]` collects the `#[tool]` methods of the `impl` block into a `ToolRouter`, and `#[tool_handler]` answers `tools/list` and `tools/call` from it.
- Arguments are one `Parameters<T>` whose `T` derives `Deserialize` and `JsonSchema`. Doc comments on its fields become the descriptions in the tool's input schema. Import `schemars` from `mcp_server_core::rmcp` as above so the derive finds it.
- `get_info` declares the capabilities and the instructions clients show the model. On `/mcp` each service's instructions appear under its name; see [Several services and /mcp](combined.md).

### Annotations

rmcp's `annotations(...)` sets the MCP tool annotations clients see:

| Annotation | Used by this crate | Meaning to clients |
|---|---|---|
| `read_only_hint` | yes | The tool does not change anything |
| `destructive_hint` | no | A write may delete or overwrite, not only add |
| `idempotent_hint` | no | Repeating a call with the same arguments changes nothing more |
| `open_world_hint` | no | The tool reaches beyond a closed set of data, such as the web |
| `title` | no | A display name |

The server reads only `read_only_hint`. A tool marked `read_only_hint = true` is a read. Every other tool, including one with no annotations at all, is a write: it is hidden and refused on a read-only service, and every call to it, made or refused, is written to the audit log. Mark every tool explicitly. See [Read-only mode and the audit log](read-only-and-audit.md).

### Results and errors

| You return | Client sees | Audit `outcome`, `error_kind` (writes only) |
|---|---|---|
| `Ok(CallToolResult::success(..))` | A result | `ok`, none |
| `Ok(CallToolResult::error(..))` whose first text starts `kind: ` | A tool error the model can read and act on | `error`, the kind |
| `Ok(CallToolResult::error(..))` without that prefix | A tool error | `error`, none |
| `Err(McpError)` | A JSON-RPC error | `error`, `protocol` |

A kind is lowercase ASCII letters and `_`, followed by `: `, such as `not_found: no task with that id` or `conflict: the task changed since you read it`. Prefer tool errors over `Err` for anything the model could fix, such as a bad argument: a tool error reaches the model as the call's result, while a JSON-RPC error may not.

## Who is calling

The bearer guard in front of each service puts what it knows about the caller in the HTTP request's extensions, and rmcp passes the request's `Parts` to tools that ask for them with an `Extension<Parts>` argument. This works the same on the service's own path and on `/mcp`.

| Extension | Type | Present when |
|---|---|---|
| The caller | [`caller::Caller`](https://docs.rs/mcp-server-core/latest/mcp_server_core/caller/struct.Caller.html) | Every request that reached the service |
| The person's credential | [`credential::Credential`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/struct.Credential.html) | The verifier carries credentials, as with `SignIn::ServiceCredential`: from a sealed OAuth token or a credential sent directly as the bearer token |
| The token's claims | [`jwt::Claims`](https://docs.rs/mcp-server-core/latest/mcp_server_core/jwt/struct.Claims.html) | The request used one of this server's OAuth access tokens |

`Caller` has two fields:

- `subject`: who signed in. `owner` for the owner's password, `key:` and 16 hex digits for a person's own credential (a keyed hash, never the credential), `static` for the static token, or what a custom verifier names. The audit log records it.
- `via`: how the request was authenticated, a [`Via`](https://docs.rs/mcp-server-core/latest/mcp_server_core/caller/enum.Via.html): `OAuth { client_id }`, `Credential` (sent directly as the bearer token) or `StaticToken`.

`Credential::expose` gives the secret to send upstream; its `Debug` output never shows it. Never log it.

```rust
use mcp_server_core::rmcp;
use mcp_server_core::axum::http::request::Parts;
use mcp_server_core::caller::{Caller, Via};
use mcp_server_core::credential::Credential;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::handler::server::tool::Extension;
use mcp_server_core::rmcp::model::{CallToolResult, ContentBlock};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};

#[derive(Clone)]
struct AccountTools {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl AccountTools {
    #[tool(description = "Say who is calling.", annotations(read_only_hint = true))]
    async fn whoami(&self, Extension(parts): Extension<Parts>) -> Result<CallToolResult, McpError> {
        let caller = parts.extensions.get::<Caller>();
        let subject = caller.map_or("unknown", |c| c.subject.as_str());
        // `Via` is #[non_exhaustive]: keep a catch-all arm.
        let how = match caller.map(|c| &c.via) {
            Some(Via::OAuth { client_id: Some(id) }) => format!("OAuth client {id}"),
            Some(Via::OAuth { client_id: None }) => "OAuth".to_string(),
            Some(Via::Credential) => "a credential sent as the bearer token".to_string(),
            Some(Via::StaticToken) => "the static token".to_string(),
            _ => "an unknown way".to_string(),
        };
        let key = match parts.extensions.get::<Credential>() {
            // Send `c.expose()` upstream; never log it.
            Some(c) => format!("a key of {} characters", c.expose().len()),
            None => "no key of their own".to_string(),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{subject}, through {how}, with {key}."
        ))]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AccountTools {}
```

On an owner's-password server there is no `Credential`: tools use the server's own upstream configuration, read by the factory. [Who made a request](sign-in.md#who-made-a-request) and [Subjects](sign-in.md#subjects) explain callers and subjects in full, and [Sealed credentials](sign-in.md#sealed-credentials) how the credential travels.

## ServiceContext and HttpSettings

`router` receives a [`ServiceContext`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/struct.ServiceContext.html):

| Field | Type | Holds |
|---|---|---|
| `http` | [`HttpSettings`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/struct.HttpSettings.html) | What `mcp_service` needs for its Host and Origin checks |
| `shutdown` | `tokio_util::sync::CancellationToken` | Cancelled on Ctrl-C or `SIGTERM`. Watch it to stop a background task you started in `router`. |

`HttpSettings` has three fields, built from the core configuration with `HttpSettings::from_core(&core)`:

| Field | Holds |
|---|---|
| `public_url` | `PUBLIC_URL` without a trailing slash, such as `https://mcp.example.com` |
| `public_host` | Its host, such as `mcp.example.com` (IPv6 without brackets) |
| `allowed_origins` | `ALLOWED_ORIGINS` |

## The Server builder

[`app::Server`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html) turns services into a binary. A complete `main`:

```rust,no_run
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::axum::{Router, routing::get};
use mcp_server_core::service::{Service, ServiceEnv};
use std::sync::Arc;
# fn tasks(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { None }
# fn calendar(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { None }
# const ICON_PNG: &[u8] = b"";
# const ICON_SVG: &str = "<svg/>";

/// Extra routes, outside every service.
fn extras(app: Router) -> Router {
    app.route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    Server::new("mcp-planner", env!("CARGO_PKG_VERSION"))
        .env_prefix("PLANNER")
        .crate_target("mcp_planner")
        .services(&[("tasks", tasks), ("calendar", calendar)])
        .sign_in(SignIn::OwnerPassword)
        .icon(ICON_PNG, ICON_SVG)
        .docs_url("https://example.com/mcp-planner")
        .wrap_router(extras)
        .main()
        .await
}
```

Every public method:

| Method | Default | What it does |
|---|---|---|
| `Server::new(name, version)` | | A server called `name`, used in logs, as the OpenTelemetry service name, in `--version` and `--help`, and as the `/mcp` endpoint's `serverInfo`. |
| `.env_prefix(prefix)` | `MCP` | The prefix of `<PREFIX>_SERVICES`, `<PREFIX>_COMBINED` and `<PREFIX>_READ_ONLY`. Upper-cased, with trailing `_` removed: `"my_app_"` gives `MY_APP_SERVICES`. |
| `.crate_target(target)` | `name` with `-` replaced by `_` | The tracing target prefix of your crates, raised to debug by `DEBUG=true` (or `DEBUG_UNSAFE_LOG_CONTENT=true`). With `mcp_planner`, `mcp_planner_api::client` is covered too. |
| `.service(name, factory)` | | Registers a service at `/<name>`. Services are mounted, and their tools listed on `/mcp`, in registration order, or in the order `<PREFIX>_SERVICES` names them when it is set. Panics on a bad or repeated [name](#names). |
| `.services(&[(name, factory), ..])` | | Registers several, as `service` does. |
| `.sign_in(sign_in)` | `SignIn::OwnerPassword` | How people sign in. See [Sign-in modes](sign-in.md). |
| `.icon(png, svg)` | none | A 128x128 PNG, served at `/favicon.ico`, and an SVG; both appear as icons in the `/mcp` endpoint's `serverInfo`. |
| `.wrap_router(f)` | none | `f: fn(axum::Router) -> axum::Router` wraps the whole application: extra routes, or your own layers such as a request rate limiter, outside every built-in layer except the one that adds the security headers, so responses from your routes get them too. |
| `.docs_url(url)` | none | Named by `--help`. |
| `.name()`, `.version()` | | What `new` was given. |
| `.registered()` | | The registered service names, in order. |
| `.var(suffix)` | | `<PREFIX>_<suffix>`: `.var("SERVICES")` is `PLANNER_SERVICES`. |
| `.load(&mut env)` | | Reads and checks the whole configuration and builds the selected services, returning an [`app::Loaded`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Loaded.html), or `None` with every problem in `env.errors`. |
| `.router(&loaded, &ctx)` | | The whole HTTP application as an `axum::Router`, without serving it. |
| `.run(loaded)` | | Starts logging, logs the services and serves until Ctrl-C or `SIGTERM`. |
| `.main()` | | Everything a binary's `main` does: the flags below, `load` from the process environment, then `run`. Returns the exit code. |
| `Server::log_caps(&services)` | | Every service's `log_caps`, together. |
| `Server::combined_tool_names(&services)` | | The tool names `/mcp` offers, from each service's `tool_names`. |

`Loaded` holds the core settings (`core`), the built `services`, the read-only services and the audit log (`safety`), whether `/mcp` is served (`combined`), the sign-in verifier (`verifier`) and the `warnings` logged at startup. It is `#[non_exhaustive]`.

### Testing a whole server

`load` and `router` build exactly what `main` serves, from a map instead of the process environment, so a test can send requests to it without a network. This test uses the `tower` crate (`cargo add --dev tower --features util`):

```rust
use mcp_server_core::app::Server;
use mcp_server_core::axum::body::Body;
use mcp_server_core::axum::http::{Request, StatusCode};
use mcp_server_core::service::{HttpSettings, Service, ServiceContext, ServiceEnv};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;
# use mcp_server_core::combined::DynHandler;
# use mcp_server_core::rmcp::ServerHandler;
# #[derive(Clone)] struct Tools;
# impl ServerHandler for Tools {}
# struct Tasks;
# impl Service for Tasks {
#     fn name(&self) -> &'static str { "tasks" }
#     fn handler(&self) -> DynHandler { DynHandler::new(Tools) }
# }
# fn tasks(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { Some(Arc::new(Tasks)) }

# #[tokio::main(flavor = "current_thread")]
# async fn main() {
let server = Server::new("mcp-planner", "1.0.0").service("tasks", tasks);
let vars: HashMap<String, String> = [
    ("PUBLIC_URL", "https://mcp.example.com"),
    ("OAUTH_SIGNING_KEY", "0123456789abcdef0123456789abcdef"),
    ("OAUTH_ADMIN_PASSWORD", "a long password"),
]
.into_iter()
.map(|(k, v)| (k.to_string(), v.to_string()))
.collect();
let mut env = ServiceEnv::new(Box::new(move |k: &str| vars.get(k).cloned()));
let loaded = server.load(&mut env).unwrap_or_else(|| panic!("{:?}", env.errors));
let ctx = ServiceContext {
    http: HttpSettings::from_core(&loaded.core),
    shutdown: Default::default(),
};
let app = server.router(&loaded, &ctx);

let res = app.clone().oneshot(Request::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
assert_eq!(res.status(), StatusCode::OK);
// Without a token, the service asks the client to sign in.
let res = app.oneshot(Request::post("/tasks").body(Body::empty()).unwrap()).await.unwrap();
assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
# }
```

The repository's [`tests/app_e2e.rs`](https://github.com/Trozz/mcp-server-core-rs/blob/main/tests/app_e2e.rs) goes further: it opens MCP sessions with a static token and calls tools on each path.

### The binary's flags

`main` reads only its first argument:

| Argument | Prints | Exit status |
|---|---|---|
| `--version` or `-V` | `<name> <version>`, such as `mcp-planner 1.4.0` | 0 |
| `--help` or `-h` | `usage: <name> [--version \| --healthcheck]`, then `All configuration is read from environment variables.`, or `…environment variables; see <docs_url>` when `docs_url` is set | 0 |
| `--healthcheck` | Nothing when healthy, `healthcheck failed` on stderr otherwise | 0 when `GET /healthz` on `127.0.0.1` at the `BIND_ADDR` port answers 200 within 5 seconds, 1 otherwise |
| anything else | `unknown argument: <arg>` and the usage, on stderr | 2 |
| none | Runs the server. Configuration errors are printed as `configuration error: <message>`, one per line | 1 on configuration errors or a fatal error while serving (`error: <message>`), 0 after a graceful shutdown |

`--healthcheck` reads `BIND_ADDR` and `INSECURE_HTTP` from the environment, so run it with the server's environment. It speaks TLS unless `INSECURE_HTTP` is set and accepts any certificate, since it only talks to itself. The same check is public as `app::healthcheck()`, for a `main` of your own. In a container image:

```dockerfile
HEALTHCHECK CMD ["/usr/local/bin/mcp-planner", "--healthcheck"]
```

[TLS and deployment](deployment.md) covers containers, shutdown and replicas.

Next: [Several services and /mcp](combined.md), or [Sign-in modes](sign-in.md) to let people sign in with their own credentials.
