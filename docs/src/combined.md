# Several services and /mcp

One server can run several services. This page explains how they are mounted, how the combined `/mcp` endpoint offers all of their tools in one connector, and how each path stays its own OAuth resource.

## One server, several services

Register each service with the `Server` builder:

```rust,no_run
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::service::{Service, ServiceEnv};
use std::sync::Arc;
# fn tasks(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { None }
# fn calendar(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { None }

#[tokio::main]
async fn main() -> std::process::ExitCode {
    Server::new("mcp-planner", env!("CARGO_PKG_VERSION"))
        .env_prefix("PLANNER")
        .service("tasks", tasks)
        .service("calendar", calendar)
        .sign_in(SignIn::OwnerPassword)
        .main()
        .await
}
```

With `PUBLIC_URL=https://mcp.example.com`, the server answers on:

| Path | Serves |
|---|---|
| `/tasks` | The `tasks` service: its tools, prompts and, if its router serves them, resources |
| `/calendar` | The `calendar` service |
| `/mcp` | Every enabled service's tools and prompts, each name prefixed with its service |

`PLANNER_SERVICES=tasks` runs only some of the registered services; an unselected service is not mounted, is not on `/mcp` and reads none of its configuration. Services are mounted, and listed on `/mcp`, in registration order, or in the order `PLANNER_SERVICES` names them when it is set. See the [configuration reference](configuration.md) for `<PREFIX>_SERVICES`.

## The combined endpoint

`/mcp` is one MCP server built from every enabled service's handler. A client connected to it sees every service at once, with one sign-in.

### Tool names

Each tool is offered as `<service>_<tool>`: the `tasks` service's `add_task` is `tasks_add_task` on `/mcp`, and `calendar`'s `list_events` is `calendar_list_events`. A tool's description, input schema and annotations are unchanged.

A call is routed by its prefix. Service names never contain `_`, so the first `_` ends the prefix; the call reaches that service's handler under the tool's own name, `add_task`. Tool names themselves may contain `_`. A name with no enabled service as its prefix is answered with a JSON-RPC `invalid_params` error, `tool not found`.

### What `initialize` returns

| Field | Value on `/mcp` |
|---|---|
| `serverInfo` | The server's name and version from `Server::new`, and its icons from `Server::icon` |
| `capabilities` | Tools always; prompts when any enabled service declares them; never resources |
| `instructions` | A short guide to the prefixes, then each service's own instructions under its name |

The instructions start with a fixed paragraph naming the prefixes, and add each service's instructions, trimmed, after a line with its name. Services without instructions, or with blank ones, are left out:

```rust
use mcp_server_core::combined::{Combined, DynHandler};
use mcp_server_core::rmcp::ServerHandler;
use mcp_server_core::rmcp::model::{Implementation, ServerCapabilities, ServerConfig};

#[derive(Clone)]
struct Tools(&'static str);

impl ServerHandler for Tools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(self.0)
    }
}

let combined = Combined::new(
    Implementation::new("mcp-planner", "1.0.0"),
    vec![
        ("tasks", DynHandler::new(Tools("Keeps a task list. Dates are YYYY-MM-DD.\n"))),
        ("calendar", DynHandler::new(Tools("Times are in UTC."))),
    ],
);
assert_eq!(
    combined.get_info().instructions.unwrap(),
    "This server combines several services. Each tool and prompt name starts with its \
     service: tasks_, calendar_. The notes below, tool descriptions and error messages \
     name tools without that prefix.\n\
     \n\
     tasks:\n\
     Keeps a task list. Dates are YYYY-MM-DD.\n\
     \n\
     calendar:\n\
     Times are in UTC."
);
```

Write your service's instructions and tool descriptions for its own path, naming tools without a prefix; the first paragraph tells the model how to read them on `/mcp`.

### Prompts and resources

Prompts are offered as `<service>_<prompt>`, and tool names in a prompt's text are prefixed for you. [Prompts](prompts.md) has the details.

Resources are served on each service's own path only. `/mcp` forwards tools and prompts, nothing else.

### Read-only services and the audit log

Each service keeps its own read-only rule on `/mcp`. With `PLANNER_READ_ONLY=calendar`:

- `/mcp` lists every `tasks_` tool, but only the `calendar_` tools marked `read_only_hint = true`;
- calling a hidden `calendar_` write tool returns the tool error `read_only: the calendar service is read-only on this server`;
- `tasks_` write tools work as on `/tasks`.

Every write tool call on `/mcp` is audited as on the service's own path, with `endpoint` set to `/mcp`, `service` to the service and `tool` to its own name without the prefix, such as `add_task`. See [Read-only mode and the audit log](read-only-and-audit.md).

### Who is calling

A call forwarded from `/mcp` keeps its request context, so a tool reads the [`Caller`](writing-a-service.md#who-is-calling) and the person's `Credential` from the request extensions exactly as on its own path.

## Turning /mcp off

`/mcp` is served whenever at least one service is enabled, even a single one. Set `<PREFIX>_COMBINED=false` (`PLANNER_COMBINED=false` here) to turn it off; it accepts `true`, `false`, `1`, `0`, `yes`, `no`, `on` and `off` in any case, and anything else stops startup with `PLANNER_COMBINED must be true or false, got "<value>"`. Then `/mcp` and its metadata document answer 404, and `mcp` is no longer listed in the authorization server's `scopes_supported`.

Keep it on when people want one connector for everything. Turn it off when every client should be given one service at a time: a token for `/tasks` never works on `/calendar`, while a token for `/mcp` reaches every service.

## Service names

Because the name is the path, the OAuth resource and the prefix on `/mcp`, a service name must be lowercase ASCII letters, digits and `-`, never `mcp`, and unique. `_` is excluded so a prefixed name can always be split, and `mcp` is the combined endpoint itself. `Server::service` panics on a name that breaks these rules; see [Names](writing-a-service.md#names) for the messages.

## Each path is its own OAuth resource

Every path, `/mcp` included, is a separate OAuth 2.1 protected resource:

| | For `/tasks` | For `/mcp` |
|---|---|---|
| Resource | `https://mcp.example.com/tasks` | `https://mcp.example.com/mcp` |
| Metadata document | `/.well-known/oauth-protected-resource/tasks` | `/.well-known/oauth-protected-resource/mcp` |
| `scopes_supported` in it | `["tasks"]` | `["mcp"]` |
| Sign-in page says | "the **tasks** service on this server" | "**every service** on this server, through `/mcp`" |

- A request without a token gets `401` with a `WWW-Authenticate` header naming that path's metadata document, so a client signs in for the path it was given.
- An access token is bound to the resource it was issued for (RFC 8707). A token for `/mcp` is refused on `/tasks` and the other way round, with `401` and `error="invalid_token"`. A refresh keeps the resource; asking for another one fails with `invalid_target`.
- One sign-in page, and one password or credential, covers every path.
- A client that sends no `resource` parameter when it signs in gets the only service when there is exactly one; `/mcp` is never chosen for it. With several services such a request fails with `invalid_target`: `resource is required: name the URL of the service, or of /mcp for every service`.
- The static token (`MCP_AUTH_TOKEN`) and a person's credential sent directly as the bearer token are not bound to a path: they work on every path.
- MCP sessions belong to the path that opened them, and each path keeps its own session table and caps; see [Limits and abuse protection](limits.md).

[Resource indicators and audiences](oauth.md#resource-indicators-and-audiences) and [Choosing the resource](oauth.md#choosing-the-resource) explain the tokens in full, and [Which URL to use](connecting-clients.md#which-url-to-use) which URL to give each client.

Next: [Prompts](prompts.md).
