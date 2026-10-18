//! Read-only services and the write audit log, applied once around every service's MCP handler.
//!
//! Tools are classified by their `read_only_hint` annotation: a tool marked
//! `read_only_hint = true` reads; every other tool, including one without annotations, writes.
//! On a read-only service write tools are hidden from `tools/list` and refused if called anyway.
//! Every write tool call, made or refused, is recorded in the audit log: the service, tool,
//! outcome, error kind and caller, never arguments, ids or results.
//!
//! [`Guarded`] wraps one service's handler. Its policy is either given when it is built
//! ([`Guarded::with_policy`], for handlers composed outside a service's own route) or read per
//! request ([`Guarded::new`]): [`Server`](crate::app::Server) attaches a [`ToolPolicy`] to each
//! service's router as a request extension and [`crate::service::mcp_service`] wraps every
//! handler, reading the policy from the HTTP request parts that rmcp puts into each request
//! context. Without a policy the wrapper changes nothing.
//!
//! Tool errors are classified by a `kind: ` prefix on their first text block, such as
//! `not_found: no event with that id`, which the audit log records as `error_kind`.

// The wrapper forwards every handler method, including the legacy (SEP-2577 deprecated) ones.
#![expect(deprecated)]

use crate::caller::Caller;
use crate::credential::Credential;
use crate::jwt::Claims;
use axum::http::request::Parts;
use chrono::{SecondsFormat, Utc};
use rmcp::model::*;
use rmcp::service::{
    MaybeSendFuture, NotificationContext, RequestContext, RoleServer, SubscriptionContext,
};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde::Serialize;
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Tracing target of audit events; the binary keeps it enabled at info whatever `LOG_LEVEL` says.
pub const AUDIT_TARGET: &str = "audit";
const WARN_EVERY: Duration = Duration::from_secs(60);

/// What the server enforces and records for one service's tools on one endpoint.
#[derive(Clone)]
pub struct ToolPolicy {
    /// The service the tools belong to.
    pub service: String,
    /// The path the calls arrive on, such as `/weather` or `/mcp`.
    pub endpoint: String,
    /// Hide and refuse write tools.
    pub read_only: bool,
    /// Where write tool calls are recorded.
    pub audit: Arc<AuditLog>,
}

/// One audit record: never arguments, ids or results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditLine {
    /// When the call finished, RFC 3339 in UTC with milliseconds.
    pub ts: String,
    /// The service the tool belongs to.
    pub service: String,
    /// The path the call arrived on.
    pub endpoint: String,
    /// The tool's own name, without a combined-endpoint prefix.
    pub tool: String,
    /// `ok`, `error` or `refused`.
    pub outcome: &'static str,
    /// For an error, its kind: the tool error's `kind: ` prefix, `protocol`, or `read_only`.
    pub error_kind: Option<String>,
    /// `oauth:<client_id>`, `oauth` (a token without a client id), `credential` (a credential
    /// sent as the bearer token) or `static` (the static token).
    pub caller: Option<String>,
    /// Who signed in ([`Caller::subject`]): `owner`, `key:<16 hex digits>`, `static` or a custom
    /// verifier's subject. Never a credential.
    pub subject: Option<String>,
    /// How long the call took.
    pub elapsed_ms: u64,
}

/// Emits audit lines on the `audit` target and, when configured, appends them to a JSON lines file.
pub struct AuditLog {
    file: Option<Mutex<AuditFile>>,
}

struct AuditFile {
    path: PathBuf,
    file: Option<File>,
    last_warn: Option<Instant>,
}

impl AuditLog {
    /// `path`: the `AUDIT_LOG_PATH` file, opened on the first write. On Unix it is created with
    /// mode 0600 and an existing file is narrowed to 0600.
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            file: path.map(|path| {
                Mutex::new(AuditFile {
                    path,
                    file: None,
                    last_warn: None,
                })
            }),
        }
    }

    /// Emits `line` on the [`AUDIT_TARGET`] tracing target and appends it to the file, if any. A
    /// failed write logs a warning at most once a minute and never fails the tool call.
    pub fn record(&self, line: &AuditLine) {
        tracing::info!(
            target: AUDIT_TARGET,
            service = %line.service,
            endpoint = %line.endpoint,
            tool = %line.tool,
            outcome = line.outcome,
            error_kind = line.error_kind.as_deref(),
            caller = line.caller.as_deref(),
            subject = line.subject.as_deref(),
            elapsed_ms = line.elapsed_ms,
            "tool write"
        );
        if let Some(file) = &self.file {
            file.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .append(line);
        }
    }
}

impl AuditFile {
    /// A failed write logs a warning at most once a minute and never fails the tool call.
    fn append(&mut self, line: &AuditLine) {
        let mut text = serde_json::to_string(line).expect("audit lines serialize");
        text.push('\n');
        let written = self.open().and_then(|f| f.write_all(text.as_bytes()));
        let Err(e) = written else {
            return;
        };
        self.file = None;
        let now = Instant::now();
        if self
            .last_warn
            .is_some_and(|t| now.duration_since(t) < WARN_EVERY)
        {
            return;
        }
        self.last_warn = Some(now);
        tracing::warn!(path = %self.path.display(), error = %e, "could not write the audit log");
    }

    fn open(&mut self) -> std::io::Result<&mut File> {
        if self.file.is_none() {
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options.open(&self.path)?;
            #[cfg(unix)]
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            self.file = Some(file);
        }
        Ok(self.file.as_mut().expect("opened above"))
    }
}

fn parts(ctx: &RequestContext<RoleServer>) -> Option<&Parts> {
    ctx.extensions.get::<Parts>()
}

fn request_policy(ctx: &RequestContext<RoleServer>) -> Option<ToolPolicy> {
    parts(ctx)?.extensions.get::<ToolPolicy>().cloned()
}

/// The bearer guard stores OAuth claims for an OAuth token and the credential for a credential
/// sent directly; the static token leaves neither.
fn caller(ctx: &RequestContext<RoleServer>) -> Option<String> {
    let parts = parts(ctx)?;
    if let Some(c) = parts.extensions.get::<Caller>() {
        return Some(c.audit_label());
    }
    Some(match parts.extensions.get::<Claims>() {
        Some(claims) => match &claims.payload.client_id {
            Some(id) => format!("oauth:{id}"),
            None => "oauth".into(),
        },
        None if parts.extensions.get::<Credential>().is_some() => "credential".into(),
        None => "static".into(),
    })
}

/// Whether a tool declares `read_only_hint = true`; an unknown tool or one without annotations is
/// treated as a write.
pub fn is_read_only(tool: Option<&Tool>) -> bool {
    tool.and_then(|t| t.annotations.as_ref())
        .and_then(|a| a.read_only_hint)
        == Some(true)
}

/// The kind of a tool error result (`conflict` for `conflict: ...`).
fn error_kind(result: &CallToolResult) -> Option<String> {
    let text = result.content.first()?.as_text()?.text.as_str();
    let (kind, _) = text.split_once(": ")?;
    let valid = !kind.is_empty() && kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    valid.then(|| kind.to_string())
}

fn outcome(response: &Result<CallToolResponse, McpError>) -> (&'static str, Option<String>) {
    match response {
        Ok(CallToolResponse::Complete(r)) if r.is_error == Some(true) => ("error", error_kind(r)),
        Ok(_) => ("ok", None),
        Err(_) => ("error", Some("protocol".into())),
    }
}

/// The tools a client may see: all of them, or only the read-only ones on a read-only service.
pub fn visible_tools(mut tools: Vec<Tool>, read_only: bool) -> Vec<Tool> {
    if read_only {
        tools.retain(|t| is_read_only(Some(t)));
    }
    tools
}

/// A service handler with the read-only rule and the audit log applied.
pub struct Guarded<S> {
    inner: S,
    policy: Option<ToolPolicy>,
}

impl<S> Guarded<S> {
    /// Reads the policy from each request's extensions (set on the service's router).
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            policy: None,
        }
    }

    /// Uses `policy` for every request.
    pub fn with_policy(inner: S, policy: ToolPolicy) -> Self {
        Self {
            inner,
            policy: Some(policy),
        }
    }

    fn policy(&self, ctx: &RequestContext<RoleServer>) -> Option<ToolPolicy> {
        self.policy.clone().or_else(|| request_policy(ctx))
    }
}

impl<S: ServerHandler> ServerHandler for Guarded<S> {
    fn ping(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.ping(context)
    }

    fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.initialize(request, context)
    }

    fn negotiate_initialize(
        &self,
        request: &InitializeRequestParams,
    ) -> Result<InitializeResult, McpError> {
        self.inner.negotiate_initialize(request)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }

    fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.discover(context)
    }

    fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CompleteResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.complete(request, context)
    }

    fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.set_level(request, context)
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResponse, McpError>> + MaybeSendFuture + '_ {
        self.inner.get_prompt(request, context)
    }

    fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.list_prompts(request, context)
    }

    fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.list_resources(request, context)
    }

    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, McpError>> + MaybeSendFuture + '_
    {
        self.inner.list_resource_templates(request, context)
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, McpError>> + MaybeSendFuture + '_ {
        self.inner.read_resource(request, context)
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.inner.accepted_subscription_filter(requested)
    }

    fn listen(
        &self,
        context: SubscriptionContext,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.listen(context)
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.subscribe(request, context)
    }

    fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.unsubscribe(request, context)
    }

    /// Read-only tools pass through. Other tools are refused on a read-only service and are
    /// audited either way.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(policy) = self.policy(&context) else {
            return self.inner.call_tool(request, context).await;
        };
        if is_read_only(self.inner.get_tool(&request.name).as_ref()) {
            return self.inner.call_tool(request, context).await;
        }
        let tool = request.name.to_string();
        let caller = caller(&context);
        let subject = parts(&context)
            .and_then(|p| p.extensions.get::<Caller>())
            .map(|c| c.subject.clone());
        let started = Instant::now();
        let (outcome, error_kind, response) = if policy.read_only {
            let text = format!(
                "read_only: the {} service is read-only on this server",
                policy.service
            );
            let refused = CallToolResult::error(vec![ContentBlock::text(text)]);
            ("refused", Some("read_only".to_string()), Ok(refused.into()))
        } else {
            let response = self.inner.call_tool(request, context).await;
            let (outcome, kind) = outcome(&response);
            (outcome, kind, response)
        };
        policy.audit.record(&AuditLine {
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            service: policy.service.clone(),
            endpoint: policy.endpoint.clone(),
            tool,
            outcome,
            error_kind,
            caller,
            subject,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
        response
    }

    /// A read-only service lists only the tools annotated `read_only_hint = true`.
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let read_only = self.policy(&context).is_some_and(|p| p.read_only);
        let mut result = self.inner.list_tools(request, context).await?;
        result.tools = visible_tools(result.tools, read_only);
        Ok(result)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CustomResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.on_custom_request(request, context)
    }

    fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_cancelled(notification, context)
    }

    fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_progress(notification, context)
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_initialized(context)
    }

    fn on_roots_list_changed(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_roots_list_changed(context)
    }

    fn on_custom_notification(
        &self,
        notification: CustomNotification,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_custom_notification(notification, context)
    }

    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetTaskResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.get_task(request, context)
    }

    fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.update_task(request, context)
    }

    fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.cancel_task(request, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line() -> AuditLine {
        AuditLine {
            ts: "2026-10-18T10:00:00.000Z".into(),
            service: "svc".into(),
            endpoint: "/svc".into(),
            tool: "change".into(),
            outcome: "ok",
            error_kind: None,
            caller: Some("static".into()),
            subject: Some("static".into()),
            elapsed_ms: 1,
        }
    }

    #[test]
    fn write_failures_warn_at_most_once_a_minute() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = AuditFile {
            path: dir.path().join("missing").join("audit.jsonl"),
            file: None,
            last_warn: None,
        };
        file.append(&line());
        let first = file.last_warn.expect("the first failure warns");
        file.append(&line());
        assert_eq!(
            file.last_warn,
            Some(first),
            "a second failure within a minute is quiet"
        );
        file.last_warn = Some(first - WARN_EVERY);
        file.append(&line());
        assert!(
            file.last_warn.unwrap() > first,
            "warns again after a minute"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_audit_file_is_narrowed_to_0600() {
        use std::fs::Permissions;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let mut file = AuditFile {
            path: path.clone(),
            file: None,
            last_warn: None,
        };
        file.append(&line());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_failed_write_reopens_the_file_next_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("later").join("audit.jsonl");
        let mut file = AuditFile {
            path: path.clone(),
            file: None,
            last_warn: None,
        };
        file.append(&line());
        assert!(file.file.is_none());
        std::fs::create_dir(dir.path().join("later")).unwrap();
        file.append(&line());
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    }

    #[test]
    fn error_kinds_are_read_from_the_tool_error_text() {
        let r = |t: &str| CallToolResult::error(vec![ContentBlock::text(t)]);
        assert_eq!(
            error_kind(&r("not_found: no such id")).as_deref(),
            Some("not_found")
        );
        assert_eq!(error_kind(&r("Something: else")), None);
        assert_eq!(error_kind(&r("no colon")), None);
    }

    #[test]
    fn visible_tools_keeps_only_read_only_tools_when_read_only() {
        let tool = |name: &'static str, ro: Option<bool>| {
            let mut t = Tool::new(name, "d", Arc::new(serde_json::Map::new()));
            t.annotations = ro.map(|r| ToolAnnotations::new().read_only(r));
            t
        };
        let tools = vec![
            tool("look", Some(true)),
            tool("change", Some(false)),
            tool("plain", None),
        ];
        let names = |v: Vec<Tool>| {
            v.into_iter()
                .map(|t| t.name.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(visible_tools(tools.clone(), false)),
            ["look", "change", "plain"]
        );
        assert_eq!(names(visible_tools(tools, true)), ["look"]);
    }
}
