# Read-only mode and the audit log

Every service gets two safety features from the same source, each tool's `read_only_hint` annotation: a read-only mode you switch on per service, and an audit log of every call to a tool that can change something. This page covers how tools are classified, what clients see on a read-only service, every field of the audit log and the `policy` module behind both.

## Reads and writes

The server classifies each tool by its `read_only_hint` annotation alone:

| The tool declares | The server treats it as |
|---|---|
| `annotations(read_only_hint = true)` | A read |
| `annotations(read_only_hint = false)` | A write |
| Annotations without `read_only_hint` | A write |
| No annotations at all | A write |
| A name the service does not have | A write |

Reads are never refused and never audited. Writes are hidden and refused on a read-only service, and every call to one is audited, made or refused. Treating anything unmarked as a write means a forgotten annotation fails safe: the tool disappears on a read-only service instead of slipping through.

Mark every tool explicitly:

```rust
use mcp_server_core::rmcp;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::model::{CallToolResult, ContentBlock};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};

#[derive(Clone)]
struct NotesTools {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl NotesTools {
    fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }

    // A read: listed and callable on a read-only service, never audited.
    #[tool(description = "List every note.", annotations(read_only_hint = true))]
    async fn list_notes(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("")]))
    }

    // A write: hidden and refused on a read-only service, audited on every call.
    #[tool(
        description = "Delete every note.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn clear_notes(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("cleared")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for NotesTools {}
# let _ = NotesTools::new();
```

The server looks the tool up with the handler's `get_tool`, which `#[tool_handler]` generates. A `ServerHandler` written by hand without `get_tool` has no tool the server can find, so every call to it counts as a write. The other annotations, such as `destructive_hint`, are for clients; the server ignores them. [Annotations](writing-a-service.md#annotations) lists them.

## Making a service read-only

Set `<PREFIX>_READ_ONLY` to the services whose write tools should be hidden and refused, with `<PREFIX>` from [`Server::env_prefix`](writing-a-service.md#the-server-builder). The `notes` example uses the prefix `NOTES`:

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
NOTES_READ_ONLY=notes cargo run --example notes
```

| Value | Effect |
|---|---|
| unset or empty | No service is read-only. |
| `notes` | `notes` is read-only. |
| `notes, tasks` | Both are. Names are comma separated; spaces around them, empty entries and repeated names are ignored. |
| `all` | Every registered service is read-only. Names before `all` must still be known; names after it are not checked. |
| a registered service that is not selected | Accepted, and has no effect while the service is not running. |
| any other name | The server refuses to start. |

An unknown name stops startup with an error that lists the names it accepts, for example:

```text
configuration error: NOTES_READ_ONLY contains an unknown service: note (known: all, notes)
```

`mcp` is not a service, so it is never accepted; making each service read-only also covers it on `/mcp`. At startup the server logs a `service enabled` line for each service with a `read_only` field, which shows the rule in force. The [Configuration reference](configuration.md) lists the variable with the others.

## What clients see on a read-only service

| Request | On a read-only service |
|---|---|
| `tools/list` | Only the tools marked `read_only_hint = true`. |
| `tools/call` of a read | Runs as usual, and is not audited. |
| `tools/call` of a write, or of a name the service does not have | Refused before the tool runs, even with invalid arguments, and audited with outcome `refused`. |
| `prompts/list`, `prompts/get` | Unchanged: prompts stay listed. See [Prompts on read-only services](prompts.md#prompts-on-read-only-services). |
| Resources | Unchanged. |

A refused call is a tool error, not a JSON-RPC error, so the model reads why and can tell the person. On the notes example with `NOTES_READ_ONLY=notes`, calling `add_note` returns:

```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"read_only: the notes service is read-only on this server"}],"isError":true}}
```

The text is always `read_only: the <service> service is read-only on this server`. Its `read_only: ` prefix is the error kind the audit log records.

The rule follows the service everywhere it is served. On `/mcp` each service keeps its own rule, so a read-only service's write tools are missing from `/mcp` as well, while the other services' tools work as usual; see [Read-only services and the audit log](combined.md#read-only-services-and-the-audit-log) on the combined endpoint page. A name on `/mcp` that does not start with a known `<service>_` prefix belongs to no service: it gets the JSON-RPC error `tool not found` and is not audited.

Read-only mode is enforced by [`service::mcp_service`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/fn.mcp_service.html), which the default `Service::router` uses. If you override `router`, build it with `mcp_service` as [Overriding the router](writing-a-service.md#overriding-the-router) shows; a router built without it gets neither read-only mode nor the audit log on the service's own path.

## The audit log

Every call to a write tool produces one audit record, whether it succeeds, fails or is refused. Calls to reads produce none. A request that never reaches the tools, such as one refused with 401 by the bearer check, is not a tool call and is not recorded.

A call to `add_note` on the notes example, made with `MCP_AUTH_TOKEN`, is recorded as this JSON line:

```json
{"ts":"2026-10-18T13:59:42.304Z","service":"notes","endpoint":"/notes","tool":"add_note","outcome":"ok","error_kind":null,"caller":"static","subject":"static","elapsed_ms":0}
```

A failed call to the same tool through `/mcp`, on a server where people send their own key as the bearer token, would look like this:

```json
{"ts":"2026-10-18T14:02:10.877Z","service":"notes","endpoint":"/mcp","tool":"add_note","outcome":"error","error_kind":"invalid_argument","caller":"credential","subject":"key:3f9a1c0e5b7d2468","elapsed_ms":3}
```

### Fields

Every line has every field, in this order:

| Field | Meaning |
|---|---|
| `ts` | When the call finished: RFC 3339 in UTC with milliseconds, such as `2026-10-18T13:59:42.304Z`. |
| `service` | The service the tool belongs to. |
| `endpoint` | The path the call arrived on: `/<service>` or `/mcp`. |
| `tool` | The tool's own name, without the `<service>_` prefix `/mcp` adds, so the same tool has the same name on both paths. A call to a name the service does not have records that name. |
| `outcome` | `ok`, `error` or `refused`. |
| `error_kind` | `null` for `ok`. For `error`: the kind at the start of the tool error's first text block (`invalid_argument` for `invalid_argument: text is empty`), `protocol` when the call failed with a JSON-RPC error, or `null` when the tool error has no kind. For `refused`: `read_only`. |
| `caller` | How the request was authenticated: `oauth:<client_id>` for an OAuth access token, `oauth` for one without a client id, `credential` for a person's credential sent as the bearer token, `static` for `MCP_AUTH_TOKEN`. |
| `subject` | Who signed in: `owner`, `key:` and 16 hex digits for a person's own credential, `static`, or what a custom verifier names. See [Subjects](sign-in.md#subjects). |
| `elapsed_ms` | How long the call took, in whole milliseconds, rounded down. A refusal never runs the tool, so it records `0` in practice. |

A kind is one or more lowercase ASCII letters or `_` at the start of the first content block, which must be text, followed by `: `. Anything else, such as `Something: else`, gives no kind. [Results and errors](writing-a-service.md#results-and-errors) shows how to write tool errors with kinds. Calling a name the service does not have on a writable service gives `error` with `protocol`, because the tool router answers with a JSON-RPC error.

The OAuth client id is the client's registration, a signed token, so an `oauth:` caller can run to several hundred characters. Every token issued to one connector carries the same client id, so it still identifies the connector.

Behind `app::Server`, `caller` and `subject` are always set. A handler served without the bearer guard in front, as with `mcp_service` mounted on its own, has no caller to record: `subject` is `null` and `caller` reads `static`.

### What is never recorded

Tool arguments, ids, results and error details beyond the kind are never written, and neither are credentials, access or refresh tokens, or session ids. The only token-like value is the OAuth client id in `caller`, which is a public client registration, not a secret. The audit log shows that `subject` called `add_note` at a given time with a given outcome, never what the note said. If you need the content of changes, record it in your service, and only where its sensitivity allows.

### Where the lines go

Each record goes to two places:

1. **The `audit` log target**, always. The server keeps this target at `info` whatever `LOG_LEVEL` says, even `LOG_LEVEL=off`, so the audit trail cannot be switched off by accident. The event's message is `tool write`, and its fields are those of the line except `ts`, since the log has its own timestamp. A field that would be `null`, such as `error_kind` on a success, is left out. With `LOG_FORMAT=json` and the default `LOG_LEVEL=info` (with `LOG_LEVEL=off` the `span` and `spans` fields are absent):

   ```json
   {"timestamp":"2026-10-18T13:59:42.304855Z","level":"INFO","message":"tool write","service":"notes","endpoint":"/notes","tool":"add_note","outcome":"ok","caller":"static","subject":"static","elapsed_ms":0,"target":"audit","span":{"name":"serve_inner"},"spans":[{"name":"serve_inner"}]}
   ```

   To collect only audit events from the process output, filter on `"target":"audit"`. [Observability](observability.md) describes the logs in full.

2. **The file named by `AUDIT_LOG_PATH`**, when it is set: one JSON object per line, as shown above.

### The audit file

```sh
AUDIT_LOG_PATH=/var/lib/notes/audit.jsonl
```

- The file is opened on the first write, not at startup, and appended to. The server never truncates or rotates it.
- On Unix it is created with mode `0600`, and an existing file is narrowed to `0600` when it is opened, so only the server's user can read it.
- The directory must exist; the server creates the file, not its directory. In a container, mount a volume for the directory so the file outlives the container, for example `./audit:/audit` with `AUDIT_LOG_PATH=/audit/audit.jsonl`.
- The server keeps the file open between writes. To rotate it, use a method that keeps the same file, such as logrotate's `copytruncate`; a file renamed away keeps receiving lines until the server reopens it, which happens only after a failed write or a restart.
- Lines are written one at a time under a lock, so concurrent calls never interleave.
- Give each replica a file of its own and collect them, or rely on the `audit` log target, which reaches your log collector from every replica.

### When the file cannot be written

A failed write never fails the tool call: by then the tool has run, and an error would tell the model that a change failed when it was made. Instead:

- the line still goes to the `audit` log target;
- the server logs a warning, `could not write the audit log`, with the path and the error, at most once a minute however many writes fail;
- the next write opens the file afresh, so the file recovers on its own once, say, the missing directory exists or the disk has space again.

Lines that failed to reach the file are not written to it later. Watch for the warning, or treat the log target as the copy of record.

## The policy module

[`mcp_server_core::policy`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/index.html) implements both features. `app::Server` wires it up for you; use it directly when you build the application yourself.

| Item | What it is |
|---|---|
| [`ToolPolicy`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/struct.ToolPolicy.html) | What applies to one service's tools on one path: `service`, `endpoint`, `read_only` and the `audit` log, all public fields. |
| [`AuditLog`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/struct.AuditLog.html) | `AuditLog::new(path)` with the `AUDIT_LOG_PATH` file or `None`; `record(&line)` writes a line to the log target and the file. Share one in an `Arc`. |
| [`AuditLine`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/struct.AuditLine.html) | One record, with the fields above as public fields. Serialises to the file's JSON. |
| [`Guarded`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/struct.Guarded.html) | An rmcp `ServerHandler` that wraps another and applies a policy to `tools/list` and `tools/call`, forwarding everything else unchanged. `Guarded::new(handler)` reads the policy from each request; `Guarded::with_policy(handler, policy)` uses the one given. Without a policy it changes nothing. |
| [`is_read_only`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/fn.is_read_only.html) | `is_read_only(tool: Option<&Tool>) -> bool`: `true` only for a tool with `read_only_hint = true`. |
| [`visible_tools`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/fn.visible_tools.html) | `visible_tools(tools, read_only)`: all of `tools`, or only the reads when `read_only`. |
| [`AUDIT_TARGET`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/constant.AUDIT_TARGET.html) | `"audit"`, the log target. |
| [`app::Safety`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Safety.html) | The read-only services and the audit log of a loaded server, the `safety` field of `app::Loaded`: public fields `read_only` (`Vec<&'static str>`) and `audit` (`Arc<AuditLog>`), with `is_read_only(service)` and `policy(service)`, the `ToolPolicy` for `/<service>`. |

How `app::Server` uses them:

- It builds one `AuditLog` from `AUDIT_LOG_PATH`, shared by every service.
- Each service's router gets its `ToolPolicy` (endpoint `/<service>`) as an `axum::Extension`. `mcp_service` wraps every handler it serves in `Guarded::new`, which finds the policy in the HTTP request parts that rmcp passes to each request.
- For `/mcp`, each service's handler is wrapped in `Guarded::with_policy` with that service's rule and endpoint `/mcp`, before the handlers are combined. The combined endpoint strips the `<service>_` prefix before the call reaches the service, which is why `tool` is the tool's own name.
- When it starts logging, it adds `audit=info` to the log filter with [`observability::log_filter`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/fn.log_filter.html). If you install logging yourself, pass `&[AUDIT_TARGET]` as its `always_on` argument to keep the audit target on.

Attaching a policy to a service you mount yourself, for example with [`server::build_app`](https://docs.rs/mcp-server-core/latest/mcp_server_core/server/fn.build_app.html):

```rust,no_run
# use mcp_server_core::rmcp::ServerHandler;
# #[derive(Clone)]
# struct NotesTools;
# impl NotesTools { fn new() -> Self { NotesTools } }
# impl ServerHandler for NotesTools {}
use mcp_server_core::axum::Extension;
use mcp_server_core::policy::{AuditLog, ToolPolicy};
use mcp_server_core::service::{HttpSettings, ServiceContext, mcp_service};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let ctx = ServiceContext {
        http: HttpSettings {
            public_url: "https://mcp.example.com".into(),
            public_host: "mcp.example.com".into(),
            allowed_origins: Vec::new(),
        },
        shutdown: mcp_server_core::shutdown_signal(),
    };
    let audit = Arc::new(AuditLog::new(Some("/var/lib/notes/audit.jsonl".into())));
    let policy = ToolPolicy {
        service: "notes".into(),
        endpoint: "/notes".into(),
        read_only: true,
        audit,
    };
    // mcp_service wraps the handler in Guarded::new, which reads this extension.
    let notes = mcp_service(&ctx, || Ok(NotesTools::new())).layer(Extension(policy));
    // Mount `notes` at /notes behind the bearer guard; see the lower-level API page.
#   let _ = notes;
}
```

[Lower-level API](lower-level-api.md) shows the rest of a server built this way.

An `AuditLog` of your own writes the same format, for example to audit a change your service makes outside a tool call, such as a scheduled job:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let dir = tempfile::tempdir()?;
# let path = dir.path().join("audit.jsonl");
use mcp_server_core::policy::{AuditLine, AuditLog};

let audit = AuditLog::new(Some(path.clone()));
audit.record(&AuditLine {
    ts: "2026-10-18T10:00:00.000Z".into(),
    service: "notes".into(),
    endpoint: "/notes".into(),
    tool: "nightly_cleanup".into(),
    outcome: "ok",
    error_kind: None,
    caller: None,
    subject: Some("owner".into()),
    elapsed_ms: 12,
});

let written = std::fs::read_to_string(&path)?;
assert_eq!(
    written,
    "{\"ts\":\"2026-10-18T10:00:00.000Z\",\"service\":\"notes\",\"endpoint\":\"/notes\",\
     \"tool\":\"nightly_cleanup\",\"outcome\":\"ok\",\"error_kind\":null,\"caller\":null,\
     \"subject\":\"owner\",\"elapsed_ms\":12}\n"
);
# Ok(())
# }
```

`record` also logs the line on the `audit` target. The server's own `AuditLog` is not handed to services, so give yours a file of its own: two logs appending to one file each keep their own lock, and their lines could interleave.

Next: [Observability](observability.md).
