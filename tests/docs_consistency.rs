//! The documentation site in `docs/src` must match the code: every environment variable a server
//! reads is in the configuration reference, and the reference names nothing the code does not
//! read. Names are recorded from `Server::load` at runtime, so a new variable fails this test
//! until it is documented.
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::combined::DynHandler;
use mcp_server_core::credential::{CheckFuture, CredentialCheck, CredentialVerifier};
use mcp_server_core::rmcp::ServerHandler;
use mcp_server_core::service::{Service, ServiceEnv};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// The prefix the test server uses; the docs write it as `<PREFIX>`.
const PREFIX: &str = "DOCS";

fn page(path: &str) -> String {
    let full = format!("{}/docs/src/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("cannot read {full}: {e}"))
}

/// The backticked names in the first cell of every table row of a page.
fn first_column_names(markdown: &str) -> BTreeSet<String> {
    markdown
        .lines()
        .filter_map(|line| line.strip_prefix('|'))
        .filter_map(|rest| rest.split('|').next())
        .flat_map(|cell| {
            cell.split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn is_variable(name: &str) -> bool {
    name.len() > 1
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The variables the configuration reference documents, with `<PREFIX>_` read as the test
/// server's prefix.
fn documented() -> BTreeSet<String> {
    first_column_names(&page("configuration.md"))
        .into_iter()
        .map(|n| n.replace("<PREFIX>_", &format!("{PREFIX}_")))
        .filter(|n| is_variable(n))
        .collect()
}

#[derive(Clone)]
struct Tools;

impl ServerHandler for Tools {}

struct Plain;

impl Service for Plain {
    fn name(&self) -> &'static str {
        "plain"
    }
    fn handler(&self) -> DynHandler {
        DynHandler::new(Tools)
    }
}

fn plain(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(Plain))
}

struct Key;

impl CredentialVerifier for Key {
    fn label(&self) -> &str {
        "API key"
    }
    fn check<'a>(&'a self, _: &'a str) -> CheckFuture<'a> {
        Box::pin(async { CredentialCheck::Valid })
    }
}

struct Keyed;

impl Service for Keyed {
    fn name(&self) -> &'static str {
        "keyed"
    }
    fn handler(&self) -> DynHandler {
        DynHandler::new(Tools)
    }
    fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
        Some(Arc::new(Key))
    }
}

fn keyed(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(Keyed))
}

/// Values that let the server read its whole configuration.
fn value(name: &str) -> Option<String> {
    let v = match name {
        "PUBLIC_URL" => "https://mcp.example.com",
        "OAUTH_SIGNING_KEY" => "0123456789abcdef0123456789abcdef",
        "OAUTH_ADMIN_PASSWORD" => "a long enough password",
        "INSECURE_HTTP" => "true",
        _ => return None,
    };
    Some(v.to_string())
}

/// Every variable `server` reads while loading, without the `_FILE` variants.
fn read_by(server: Server) -> BTreeSet<String> {
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    let record = seen.clone();
    let mut env = ServiceEnv::new(Box::new(move |k: &str| {
        record.lock().unwrap().insert(k.to_string());
        value(k)
    }));
    server
        .load(&mut env)
        .unwrap_or_else(|| panic!("{:?}", env.errors));
    let read = seen.lock().unwrap();
    read.iter()
        .filter(|k| !k.ends_with("_FILE"))
        .cloned()
        .collect()
}

/// Every variable a server reads in either sign-in mode.
fn read_by_the_server() -> BTreeSet<String> {
    let owner = Server::new("mcp-docs", "1")
        .env_prefix(PREFIX)
        .service("plain", plain)
        .sign_in(SignIn::OwnerPassword);
    let keys = Server::new("mcp-docs", "1")
        .env_prefix(PREFIX)
        .service("keyed", keyed)
        .sign_in(SignIn::ServiceCredential);
    let mut read = read_by(owner);
    read.extend(read_by(keys));
    read
}

#[test]
fn every_variable_the_server_reads_is_documented() {
    let documented = documented();
    let read = read_by_the_server();
    let missing: Vec<&String> = read.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "read by the server but missing from docs/src/configuration.md: {missing:?}"
    );
    let stale: Vec<&String> = documented.difference(&read).collect();
    assert!(
        stale.is_empty(),
        "in docs/src/configuration.md but never read by the server: {stale:?}"
    );
}

#[test]
fn the_first_column_parser_reads_backticked_names() {
    let names = first_column_names(
        "| Variable | Default |\n|---|---|\n| `A_B` | `x` |\n| `C`, `D_E` | none |\nnot `F` a row",
    );
    assert_eq!(
        names,
        ["A_B", "C", "D_E"].iter().map(|s| s.to_string()).collect()
    );
}
