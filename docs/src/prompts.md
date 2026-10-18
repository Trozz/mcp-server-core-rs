# Prompts

MCP prompts are ready-made instructions a client offers the person, such as "plan my week", which tell the model which tools to call and how. This page covers writing prompts for a service, the helpers in the [`prompt`](https://docs.rs/mcp-server-core/latest/mcp_server_core/prompt/index.html) module, and how prompts behave on `/mcp` and on read-only services.

## The problem prompts have

A prompt that names tools must name them as the client sees them. On a service's own path the `tasks` service's tool is `list_tasks`; on the combined `/mcp` endpoint it is `tasks_list_tasks`. A prompt that says "call `list_tasks`" would send the model looking for a tool that `/mcp` does not have.

The crate solves this twice over:

1. [`tool_prefix`](#the-prompt-module) tells a prompt the prefix of the endpoint it is served from, so it can name tools exactly.
2. `/mcp` prefixes the service's tool names that are still bare in a prompt's text, so a prompt written for the service's own path works on `/mcp` unchanged.

## Writing prompts

A service offers prompts by declaring the prompts capability in `get_info` and answering `prompts/list` and `prompts/get`. Keep the prompts in a module of plain functions, as [mcp-icloud](https://github.com/Trozz/mcp-icloud) does: they are then easy to test without a server.

```rust
use mcp_server_core::prompt::{UNAVAILABLE, argument, not_found, number_argument, user_prompt};
use mcp_server_core::rmcp::ErrorData as McpError;
use mcp_server_core::rmcp::model::{GetPromptResult, JsonObject, Prompt, PromptArgument};
use serde_json::json;

const PLAN_WEEK: &str = "plan_week";
const PLAN_WEEK_DESCRIPTION: &str = "Plan the coming days from the open tasks.";

/// Every prompt of the tasks service.
pub fn list() -> Vec<Prompt> {
    vec![
        Prompt::new(
            PLAN_WEEK,
            Some(PLAN_WEEK_DESCRIPTION),
            Some(vec![
                PromptArgument::new("days")
                    .with_description("How many days to plan, 1 to 14. Default 7.")
                    .with_required(false),
                PromptArgument::new("project")
                    .with_description("Only this project. Default: every project.")
                    .with_required(false),
            ]),
        )
        .with_title("Plan the week"),
    ]
}

/// Renders prompt `name`, naming tools as `<p><tool>`.
pub fn get(name: &str, arguments: Option<&JsonObject>, p: &str) -> Result<GetPromptResult, McpError> {
    match name {
        PLAN_WEEK => {
            let days = number_argument(arguments, "days", 7, 1..=14)?;
            let scope = match argument(arguments, "project")? {
                Some(project) => format!("in the {project} project"),
                None => "in every project".to_string(),
            };
            let text = format!(
                "Plan my next {days} days.\n\n\
                 1. Call `{p}list_tasks` and keep the open tasks {scope}.\n\
                 2. Spread them over the days, the ones due soonest first.\n\
                 3. Offer to add any task I mention with `{p}add_task`, only after I confirm.\n\n\
                 {UNAVAILABLE}"
            );
            Ok(user_prompt(PLAN_WEEK_DESCRIPTION, text))
        }
        _ => Err(not_found(name)),
    }
}

// On /tasks the prefix is empty; on /mcp it is "tasks_".
let args = json!({"days": " 3 ", "project": "home"}).as_object().cloned();
let own = get(PLAN_WEEK, args.as_ref(), "").unwrap();
assert!(own.messages[0].content.as_text().unwrap().text.contains("Call `list_tasks`"));
let combined = get(PLAN_WEEK, args.as_ref(), "tasks_").unwrap();
let text = &combined.messages[0].content.as_text().unwrap().text;
assert!(text.starts_with("Plan my next 3 days."));
assert!(text.contains("Call `tasks_list_tasks` and keep the open tasks in the home project."));

// Arguments are checked, and unknown prompts get the message rmcp's prompt router uses.
let bad = json!({"days": "30"}).as_object().cloned();
assert_eq!(get(PLAN_WEEK, bad.as_ref(), "").unwrap_err().message, "days must be a whole number from 1 to 14");
assert_eq!(get("nope", None, "").unwrap_err().message, "prompt 'nope' not found");
```

The handler declares the capability and hands the requests to that module, passing the prefix for the current request:

```rust
use mcp_server_core::rmcp;
use mcp_server_core::prompt::tool_prefix;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::model::{
    CallToolResult, ContentBlock, GetPromptRequestParams, GetPromptResponse, ListPromptsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use mcp_server_core::rmcp::service::{RequestContext, RoleServer};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
# mod prompts {
#     use mcp_server_core::rmcp::ErrorData as McpError;
#     use mcp_server_core::rmcp::model::{GetPromptResult, JsonObject, Prompt};
#     pub fn list() -> Vec<Prompt> { Vec::new() }
#     pub fn get(name: &str, _: Option<&JsonObject>, _: &str) -> Result<GetPromptResult, McpError> {
#         Err(mcp_server_core::prompt::not_found(name))
#     }
# }

#[derive(Clone)]
struct TasksTools {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl TasksTools {
    #[tool(description = "List the open tasks.", annotations(read_only_hint = true))]
    async fn list_tasks(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("Buy milk")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for TasksTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().enable_prompts().build())
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult::with_all_items(prompts::list()))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        let prefix = tool_prefix(&context);
        prompts::get(&request.name, request.arguments.as_ref(), prefix).map(Into::into)
    }
}
```

### With rmcp's prompt macros

rmcp's `#[prompt_router]`, `#[prompt]` and `#[prompt_handler]` work too. Like the tool macros, they need `use mcp_server_core::rmcp;` in the file (see [Writing tools with rmcp](writing-a-service.md#writing-tools-with-rmcp)). A `#[prompt]` method can take the `RequestContext<RoleServer>` as an argument to read the prefix:

```rust
use mcp_server_core::rmcp;
use mcp_server_core::prompt::{UNAVAILABLE, tool_prefix, user_prompt};
use mcp_server_core::rmcp::handler::server::router::prompt::PromptRouter;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::model::{
    CallToolResult, ContentBlock, GetPromptResult, ServerCapabilities, ServerConfig,
};
use mcp_server_core::rmcp::service::{RequestContext, RoleServer};
use mcp_server_core::rmcp::{
    ErrorData as McpError, ServerHandler, prompt, prompt_handler, prompt_router, tool,
    tool_handler, tool_router,
};

#[derive(Clone)]
struct TasksTools {
    tool_router: ToolRouter<Self>,
    prompt_router: PromptRouter<Self>,
}

impl TasksTools {
    fn new() -> Self {
        Self { tool_router: Self::tool_router(), prompt_router: Self::prompt_router() }
    }
}

#[tool_router]
impl TasksTools {
    #[tool(description = "List the open tasks.", annotations(read_only_hint = true))]
    async fn list_tasks(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("Buy milk")]))
    }
}

#[prompt_router]
impl TasksTools {
    #[prompt(name = "review", description = "Review the open tasks.")]
    async fn review(&self, context: RequestContext<RoleServer>) -> GetPromptResult {
        let p = tool_prefix(&context);
        user_prompt(
            "Review the open tasks.",
            format!("Call `{p}list_tasks` and point out anything overdue. {UNAVAILABLE}"),
        )
    }
}

#[tool_handler(router = self.tool_router)]
#[prompt_handler(router = self.prompt_router)]
impl ServerHandler for TasksTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().enable_prompts().build())
    }
}
# let _ = TasksTools::new();
```

## The prompt module

Everything in [`mcp_server_core::prompt`](https://docs.rs/mcp-server-core/latest/mcp_server_core/prompt/index.html):

| Item | What it does |
|---|---|
| `tool_prefix(&context) -> &str` | The tool-name prefix of the endpoint this request came to: `""` on the service's own path, `"<service>_"` on `/mcp`. |
| `ToolPrefix(pub String)` | The request extension `/mcp` sets on a `prompts/get` it forwards, which `tool_prefix` reads. Insert it yourself only in tests or in a combined handler of your own. |
| `UNAVAILABLE` | A sentence for the end of any prompt that names tools, telling the model what to do when one is missing. |
| `user_prompt(description, text) -> GetPromptResult` | A rendered prompt: one user message holding `text`, with `description`. |
| `argument(arguments, name) -> Result<Option<String>, McpError>` | A string argument, trimmed. Missing, `null`, empty or blank is `None`, so the default applies. Any other non-string value is an `invalid_params` error: `<name> must be a string`. |
| `number_argument(arguments, name, default, range) -> Result<u32, McpError>` | A whole number within `range` (a `RangeInclusive<u32>`), given as a string, `default` when missing, `null` or blank. A non-string value is the `invalid_params` error `<name> must be a string`; text that is not a whole number in range is `<name> must be a whole number from <start> to <end>`. |
| `not_found(name) -> McpError` | The error for a prompt the service does not have, `invalid_params` with `prompt '<name>' not found` and no `data`. rmcp's own prompt router uses the same message, and adds the names of the available prompts as `data`. |

`UNAVAILABLE` reads, in full:

```text
If a tool named here is not available on this server (for example because the service is read-only or the tool is turned off), say so and stop that step.
```

MCP sends prompt arguments as strings, which is why `number_argument` parses text: `" 3 "` is 3.

## Prompts on /mcp

On the combined endpoint:

- **Names.** Each prompt is listed as `<service>_<prompt>`: `plan_week` is `tasks_plan_week`. Its title, description and arguments are unchanged.
- **Capability.** `/mcp` declares the prompts capability when any enabled service declares it.
- **Routing.** `prompts/get` for `tasks_plan_week` reaches the `tasks` service as `plan_week`, with `ToolPrefix("tasks_")` set, so `tool_prefix` returns `"tasks_"`.
- **Unknown prompts.** When the service answers with exactly `not_found` for its own name, `/mcp` rewords it with the name the client sent: `prompt 'tasks_nope' not found`. A name without an enabled service's prefix gets the same error. Other errors pass through unchanged, and that includes the error of rmcp's `#[prompt_handler]`: its `data` makes it differ from `not_found`, so on `/mcp` it names the prompt without the prefix, `prompt 'nope' not found`.

### Tool names are prefixed for you

After the service renders a prompt, `/mcp` rewrites the text of each message: every whole identifier that is one of the service's tool names gets the service's prefix. An identifier is a run of ASCII letters, digits and `_`, so only exact names change:

| In the prompt's text | On `/mcp` |
|---|---|
| `` Call `list_tasks` `` | `` Call `tasks_list_tasks` `` |
| `list_tasks_due` (a longer identifier) | unchanged |
| `my_list_tasks` | unchanged |
| `tasks_list_tasks` (already prefixed, for example by `tool_prefix`) | unchanged |

So a prompt that names its tools bare works on both paths, and one that uses `tool_prefix` is not prefixed twice. Some limits of the rewriting:

- Any whole word equal to a tool name is prefixed wherever it appears, prose included. A tool called `search` would turn "search the tasks" into "tasks_search the tasks". Give tools names that are not ordinary words, such as `search_tasks`.
- Only the service's own tool names are prefixed. A prompt that mentions another service's tools must name them itself.
- The names are those the service lists to this client. On a read-only service that is its read-only tools only, so a bare name of a hidden write tool stays bare. The tool is not available on `/mcp` either way.
- Only the text content of a completed prompt is rewritten. Images, embedded resources, other content and the prompt's description pass through unchanged.

## Prompts on read-only services

[Read-only mode](read-only-and-audit.md) hides and refuses write tools, but never prompts: a read-only service lists and renders its prompts as usual, on its own path and on `/mcp`. A prompt step that needs a write tool then cannot be done. End every prompt that names tools with `UNAVAILABLE`, so the model says so and stops that step instead of guessing at another tool.

Next: [Examples](examples.md).
