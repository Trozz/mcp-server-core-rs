# Examples

The repository has two complete servers in [`examples/`](https://github.com/Trozz/mcp-server-core-rs/tree/main/examples). This page says what each one shows, how to run it, and what to try against it.

| Example | Sign-in | Shows |
|---|---|---|
| [`notes`](#notes-a-server-for-its-owner) | The owner's password | A read tool and a write tool, tool arguments, tool errors, read-only mode, the static token and the audit log |
| [`api_keys`](#api_keys-a-server-shared-by-many-people) | Each person's own API key | A `CredentialVerifier`, a tool that reads the caller's key, keys sent directly as bearer tokens, sessions bound to a key |

With the commands below, both listen on `0.0.0.0:8443` and serve plain HTTP for `localhost`, so nothing needs a certificate. Run them from a clone of the repository:

```sh
git clone https://github.com/Trozz/mcp-server-core-rs
cd mcp-server-core-rs
```

## notes: a server for its owner

[`examples/notes.rs`](https://github.com/Trozz/mcp-server-core-rs/blob/main/examples/notes.rs) keeps short notes for one person. It is the [quick start](quick-start.md) server with more in it:

- The service `notes`, at `/notes`, with environment prefix `NOTES`.
- `list_notes`, marked `read_only_hint = true`, and `add_note`, marked `read_only_hint = false`, which takes a `text` argument through `Parameters<AddNote>`.
- `add_note` returns the tool error `invalid_argument: text is empty` for blank text, so the audit log records the kind `invalid_argument`.
- The notes live in an `Arc<Mutex<Vec<String>>>` held by the service and cloned into each session's handler, so every session sees the same notes. They are lost when the server stops.
- `tool_names` lists both tools for the startup log, and the handler sets the instructions `Keeps short notes.`

Run it:

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
LOG_FORMAT=pretty cargo run --example notes
```

Then add `http://localhost:8443/notes` to an MCP client, or open the MCP Inspector with `npx @modelcontextprotocol/inspector` and connect to that URL over Streamable HTTP. The client registers itself and opens the sign-in page in your browser; enter `a long password`. Ask it to add a note and list them.

### Things to try with notes

**Every tool on one path.** Connect to `http://localhost:8443/mcp` instead. The tools are `notes_add_note` and `notes_list_notes`, and the instructions start with the paragraph about prefixes described in [Several services and /mcp](combined.md).

**Read-only mode.** Restart with `NOTES_READ_ONLY=notes`. `tools/list` now offers only `list_notes` (`notes_list_notes` on `/mcp`), and calling `add_note` anyway returns the tool error:

```text
read_only: the notes service is read-only on this server
```

**The static token and curl.** Restart with a static token and an audit log:

```sh
export MCP_AUTH_TOKEN=$(openssl rand -hex 32)
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
AUDIT_LOG_PATH=./audit.jsonl LOG_FORMAT=pretty cargo run --example notes
```

In another terminal with the same `MCP_AUTH_TOKEN`, open a session and call the tools. Each request after `initialize` names the session in `Mcp-Session-Id`:

```sh
URL=http://localhost:8443/notes
H=(-H "Authorization: Bearer $MCP_AUTH_TOKEN" -H 'Content-Type: application/json'
   -H 'Accept: application/json, text/event-stream')
SESSION=$(curl -s -D - -o /dev/null "${H[@]}" $URL \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}' \
  | awk 'tolower($1) == "mcp-session-id:" {print $2}' | tr -d '\r')
H+=(-H "Mcp-Session-Id: $SESSION" -H 'MCP-Protocol-Version: 2025-06-18')
curl -s "${H[@]}" $URL -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
curl -s "${H[@]}" $URL \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add_note","arguments":{"text":"Buy milk"}}}'
curl -s "${H[@]}" $URL \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add_note","arguments":{"text":" "}}}'
curl -s "${H[@]}" $URL \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_notes","arguments":{}}}'
```

Each answer is a short server-sent event stream whose last `data:` line holds the JSON-RPC response, such as `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"added"}],"isError":false}}`. `audit.jsonl` now has one line for each `add_note` call, and none for `list_notes`, which only reads:

```json
{"ts":"2026-10-18T13:49:04.714Z","service":"notes","endpoint":"/notes","tool":"add_note","outcome":"ok","error_kind":null,"caller":"static","subject":"static","elapsed_ms":0}
{"ts":"2026-10-18T13:49:04.724Z","service":"notes","endpoint":"/notes","tool":"add_note","outcome":"error","error_kind":"invalid_argument","caller":"static","subject":"static","elapsed_ms":0}
```

A call signed in through OAuth records `caller` as `oauth:<client_id>` and `subject` as `owner`. [Read-only mode and the audit log](read-only-and-audit.md) explains every field.

**The binary's flags and configuration errors.** `cargo run --example notes -- --version` prints the name and version, such as `mcp-notes 0.1.0`. Run it without any environment and it lists every missing variable, then exits with status 1:

```text
configuration error: PUBLIC_URL is required
configuration error: OAUTH_SIGNING_KEY is required
configuration error: OAUTH_ADMIN_PASSWORD is required
```

## api_keys: a server shared by many people

[`examples/api_keys.rs`](https://github.com/Trozz/mcp-server-core-rs/blob/main/examples/api_keys.rs) is a server where each person signs in with their own key for an upstream API, so one deployment serves many people without holding anyone's key. The "upstream API" is imaginary: it accepts any key that starts with `demo-` and has something after it.

- `SignIn::ServiceCredential`, with environment prefix `DEMO`. There is no owner's password, so `OAUTH_ADMIN_PASSWORD` is not needed.
- The service `account`, at `/account`, returns a `CredentialVerifier` from `credential_verifier`:

  | Method | In the example |
  |---|---|
  | `label` | `Demo API key`, shown on the sign-in page |
  | `help` | `Any key starting demo- works, such as demo-1234.`, shown under the field |
  | `plausible` | Starts with `demo-` and is at most 64 bytes. Anything else is refused locally, without asking upstream and without counting as a failed attempt |
  | `check` | `Valid` when something follows `demo-`, otherwise `Invalid` with the reason `That key is empty after demo-.` A real verifier makes one cheap authenticated request upstream here, and answers `Unavailable` when the upstream cannot be reached |

- The tool `whoami` takes `Extension<Parts>` and reads the caller's key as a `Credential`, answering with its last four characters.

Run it:

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) LOG_FORMAT=pretty \
cargo run --example api_keys
```

Then add `http://localhost:8443/account` to an MCP client and sign in with `demo-1234`. Calling `whoami` answers `You are using the key ending 1234.`

### Things to try with api_keys

**The sign-in page.** It asks for a "Demo API key" and says the key is checked once and then kept only in encrypted form inside the connection's tokens. Enter `abc` and it answers `That is not a Demo API key.`, without counting the attempt. Enter `demo-` and it shows the verifier's reason, `That key is empty after demo-.`; that one counts. After five rejected attempts from your address within a minute, the next is refused with `429`: `Too many attempts from this address: credentials were rejected, or several are being checked at once. Wait a little and try again.` See [Limits and abuse protection](limits.md).

**The key as the bearer token.** A client that can send a header may skip OAuth and send the key itself:

```sh
claude mcp add --transport http account http://localhost:8443/account \
  --header "Authorization: Bearer demo-1234"
```

The server checks the key with the verifier and remembers the verdict for a while under the key's SHA-256 (ten minutes for a valid key, one minute for a rejected one), so it does not ask upstream on every request (see [Credentials sent as bearer tokens](sign-in.md#credentials-sent-as-bearer-tokens)). A rejected or implausible key gets `401` with a `WWW-Authenticate` header naming the service's metadata and `error="invalid_token"`.

**Sessions belong to a key.** Open a session with `demo-1234`, then send a request in that session (the same `Mcp-Session-Id`) with `demo-9999`: it gets `404`, as if the session did not exist, so one person can never use another's session.

**No static token.** Start it with `MCP_AUTH_TOKEN` set and it refuses:

```text
configuration error: MCP_AUTH_TOKEN cannot be used when people sign in with their own Demo API key
```

Requests made with a fixed token would carry no key for the tools to call upstream with. [The static token](sign-in.md#the-static-token) explains the rules.

## From an example to your own server

Copy the example closest to what you need, rename the service and the prefix, and replace the tools. Each example starts with `use mcp_server_core::rmcp;` so rmcp's macros find the crate in your own project too (see [Writing tools with rmcp](writing-a-service.md#writing-tools-with-rmcp)); for `notes`, also `cargo add serde --features derive`. [Writing a service](writing-a-service.md) covers reading your service's configuration, and [The CredentialVerifier trait](sign-in.md#the-credentialverifier-trait) writing a verifier for a real upstream API. The two servers built on this crate are larger examples of the same shapes: [mcp-icloud](https://github.com/Trozz/mcp-icloud) signs its owner in with a password, and [mcp-companies-house](https://github.com/Trozz/mcp-companies-house) signs each person in with their own Companies House API key.

Next: [Sign-in modes](sign-in.md).
