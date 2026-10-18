//! Helpers for services' MCP prompts: the tool-name prefix a prompt's text should use, argument
//! parsing and the shape of a rendered prompt.
//!
//! A prompt that tells the model which tools to call must name them as the client sees them:
//! `search` on the service's own endpoint, `<service>_search` on the combined `/mcp` endpoint.
//! [`tool_prefix`] gives the prefix for the current request:
//!
//! ```
//! use mcp_server_core::prompt::{UNAVAILABLE, tool_prefix, user_prompt};
//! use mcp_server_core::rmcp::model::GetPromptResult;
//! use mcp_server_core::rmcp::service::{RequestContext, RoleServer};
//!
//! fn summarise(context: &RequestContext<RoleServer>) -> GetPromptResult {
//!     let p = tool_prefix(context);
//!     user_prompt(
//!         "Summarise today's notes.",
//!         format!("Call {p}list_notes and summarise them. {UNAVAILABLE}"),
//!     )
//! }
//! ```

use rmcp::ErrorData as McpError;
use rmcp::model::{GetPromptResult, JsonObject, PromptMessage, Role};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::Value;
use std::ops::RangeInclusive;

/// A sentence for the end of a prompt that names tools: what to do when one is missing, say on a
/// read-only service.
pub const UNAVAILABLE: &str = "If a tool named here is not available on this server (for example because the service is read-only or the tool is turned off), say so and stop that step.";

/// The prefix of the tool names on the endpoint a prompt is served from. The combined endpoint
/// sets `"<service>_"` on the request it forwards; a service's own endpoint sets nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPrefix(pub String);

/// The tool-name prefix for this request: `""` on a service's own endpoint.
pub fn tool_prefix(context: &RequestContext<RoleServer>) -> &str {
    context
        .extensions
        .get::<ToolPrefix>()
        .map_or("", |p| p.0.as_str())
}

/// A string argument, trimmed. Missing, null, empty or blank is `None` (the default applies);
/// any other non-string value is `invalid_params`.
pub fn argument(arguments: Option<&JsonObject>, name: &str) -> Result<Option<String>, McpError> {
    match arguments.and_then(|a| a.get(name)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(_) => Err(McpError::invalid_params(
            format!("{name} must be a string"),
            None,
        )),
    }
}

/// A whole-number argument in `range`, `default` when absent or blank.
pub fn number_argument(
    arguments: Option<&JsonObject>,
    name: &str,
    default: u32,
    range: RangeInclusive<u32>,
) -> Result<u32, McpError> {
    let Some(text) = argument(arguments, name)? else {
        return Ok(default);
    };
    text.parse::<u32>()
        .ok()
        .filter(|n| range.contains(n))
        .ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "{name} must be a whole number from {} to {}",
                    range.start(),
                    range.end()
                ),
                None,
            )
        })
}

/// A rendered prompt: one user message holding `text`.
pub fn user_prompt(description: &str, text: String) -> GetPromptResult {
    GetPromptResult::new(vec![PromptMessage::new_text(Role::User, text)])
        .with_description(description)
}

/// The error for a prompt name the service does not have, worded as rmcp's prompt router does.
pub fn not_found(name: &str) -> McpError {
    McpError::invalid_params(format!("prompt '{name}' not found"), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ErrorCode;
    use serde_json::json;

    fn args(v: serde_json::Value) -> JsonObject {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn string_arguments_are_trimmed() {
        let a = args(json!({"mailbox": "  Work "}));
        assert_eq!(
            argument(Some(&a), "mailbox").unwrap().as_deref(),
            Some("Work")
        );
    }

    #[test]
    fn blank_arguments_take_their_defaults() {
        let a = args(json!({"a": "", "b": "   ", "c": null}));
        for name in ["a", "b", "c", "missing"] {
            assert_eq!(argument(Some(&a), name).unwrap(), None, "{name}");
        }
        assert_eq!(argument(None, "a").unwrap(), None);
        assert_eq!(number_argument(Some(&a), "a", 25, 1..=100).unwrap(), 25);
        assert_eq!(number_argument(None, "limit", 25, 1..=100).unwrap(), 25);
    }

    #[test]
    fn arguments_must_be_strings() {
        let a = args(json!({"limit": 25, "flag": true, "list": ["x"]}));
        for name in ["limit", "flag", "list"] {
            let e = argument(Some(&a), name).unwrap_err();
            assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
            assert_eq!(e.message, format!("{name} must be a string"));
        }
    }

    #[test]
    fn numbers_must_be_whole_and_in_range() {
        let ok = args(json!({"n": "1", "m": " 100 "}));
        assert_eq!(number_argument(Some(&ok), "n", 25, 1..=100).unwrap(), 1);
        assert_eq!(number_argument(Some(&ok), "m", 25, 1..=100).unwrap(), 100);
        for bad in ["0", "101", "-1", "2.5", "ten", "99999999999"] {
            let a = args(json!({"limit": bad}));
            let e = number_argument(Some(&a), "limit", 25, 1..=100).unwrap_err();
            assert_eq!(e.code, ErrorCode::INVALID_PARAMS, "{bad}");
            assert_eq!(
                e.message, "limit must be a whole number from 1 to 100",
                "{bad}"
            );
        }
    }

    #[test]
    fn a_prompt_is_one_user_message() {
        let r = user_prompt("Describe it.", "Do this.".to_string());
        assert_eq!(r.description.as_deref(), Some("Describe it."));
        assert_eq!(r.messages.len(), 1);
        assert_eq!(r.messages[0].role, Role::User);
        assert_eq!(r.messages[0].content.as_text().unwrap().text, "Do this.");
    }

    #[test]
    fn unknown_prompts_are_invalid_params() {
        let e = not_found("nope");
        assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(e.message, "prompt 'nope' not found");
    }

    #[test]
    fn the_unavailable_sentence_says_to_stop_the_step() {
        assert!(UNAVAILABLE.contains("not available"));
        assert!(UNAVAILABLE.contains("stop that step"));
    }
}
