# Tunnel Relay

A minimal HTTP-to-WebSocket relay for exposing local services to the internet.

## Architecture

```
[Internet] → POST https://relay.example.com/{tunnel_id}/path
                         │
                         ▼
               ┌─────────────────┐
               │  Relay Server   │
               │   (your VPS)    │
               └────────┬────────┘
                        │ WebSocket
                        ▼
               ┌─────────────────┐
               │  Desktop App    │
               │ (behind NAT)    │
               └─────────────────┘
```

## Components

- **protocol/** - Shared types for request/response serialization
- **server/** - Relay server (deploy to VPS)
- **client/** - Client library (use in your desktop app)

## Quick Start

### 1. Deploy the Server

```bash
cd server
cargo build --release
./target/release/tunnel-server
# Listens on :7187
```

For production, put this behind nginx/caddy with TLS.

### 2. Use the Client in Your App

Add to your `Cargo.toml`:

```toml
[dependencies]
tunnel-client = { path = "path/to/client" }
tokio = { version = "1.0", features = ["rt-multi-thread", "macros"] }
```

Basic usage:

```rust
use tunnel_client::{TunnelClient, TunnelRequest, TunnelResponse};

#[tokio::main]
async fn main() {
    let client = TunnelClient::new("wss://relay.example.com", "my-unique-id");
    
    client.connect(|req: TunnelRequest| async move {
        // Handle the incoming HTTP request
        println!("Got {} {}", req.method, req.path);
        
        TunnelResponse {
            id: req.id,
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"ok": true}"#.to_vec(),
        }
    }).await.unwrap();
}
```

### 3. Tauri Integration Example

```rust
use tunnel_client::{TunnelClient, TunnelRequest, TunnelResponse, json_response};
use tauri::Manager;

pub fn start_tunnel(app_handle: tauri::AppHandle) {
    let client = TunnelClient::new(
        "wss://relay.example.com",
        "user_abc123"  // Use user ID or generate unique tunnel ID
    );
    
    tauri::async_runtime::spawn(async move {
        client.connect(move |req| {
            let app = app_handle.clone();
            async move {
                // Route based on path
                match req.path.as_str() {
                    "webhook/slack" => handle_slack(req, &app).await,
                    "webhook/github" => handle_github(req, &app).await,
                    _ => TunnelResponse {
                        id: req.id,
                        status: 404,
                        headers: vec![],
                        body: b"Not found".to_vec(),
                    },
                }
            }
        }).await
    });
}

async fn handle_slack(req: TunnelRequest, app: &tauri::AppHandle) -> TunnelResponse {
    // Parse body, emit event to frontend, etc.
    let payload: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
    app.emit("slack-action", &payload).ok();
    
    json_response(req.id, 200, serde_json::json!({"ok": true}))
}
```

## Production Considerations

### Server Deployment

1. **TLS**: Use a reverse proxy (nginx, caddy) for HTTPS/WSS
2. **Authentication**: Add a secret token check in `ws_handler`
3. **Rate limiting**: Add middleware to prevent abuse

Example nginx config:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:7187;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Client Considerations

1. **Tunnel ID**: Use something unique per user (user ID, or generate UUID on first run)
2. **Reconnection**: The `connect()` method auto-reconnects; `connect_once()` doesn't
3. **Timeouts**: Server has 30s timeout; adjust if you need longer processing

### Security

- Use WSS (TLS) in production
- Validate incoming requests in your handler
- Consider adding HMAC signature verification for webhooks
- Don't trust the `path` blindly—validate/sanitize it

## Slack Events API Runbook

### Required Environment Variables

- `SLACK_SIGNING_SECRET`: Slack app signing secret used for request verification.
- `SLACK_CLIENT_ID`: Slack app OAuth client ID.
- `SLACK_CLIENT_SECRET`: Slack app OAuth client secret.
- `SLACK_SCOPES`: OAuth scopes (default `chat:write`).
- `TUNNEL_HMAC_KEYS`: comma-delimited base64/base64url keys for OAuth state signing.

### Server Endpoint

- Events endpoint: `POST /webhook/slack/events`
- Session bind endpoint: `POST /webhook/slack/session-bind`
- Existing interactive endpoint: `POST /slack/interact`
- Existing OAuth endpoints:
  - `GET /slack/oauth/start`
  - `GET /slack/oauth/callback`

Session bind payload:

```json
{
  "team_id": "T123",
  "slack_user_id": "U123",
  "client_id": "desktop-client-id"
}
```

### Slack App Setup

1. In **Event Subscriptions**, enable events and set Request URL to:
   - `https://<relay-host>/webhook/slack/events`
2. Subscribe to bot event:
   - `message.im`
3. In OAuth scopes, include needed DM read scopes for your app configuration.
4. Install/reinstall app after event or scope changes.

### Inbound Event (example)

```json
{
  "type": "event_callback",
  "event_id": "Ev03ABC",
  "team_id": "T123",
  "event": {
    "type": "message",
    "channel_type": "im",
    "channel": "D123",
    "user": "U123",
    "text": "hello from DM",
    "thread_ts": "1730000000.000100",
    "ts": "1730000001.000200"
  }
}
```

### Forwarded Payload to Desktop Tunnel

Forward path inside tunnel request: `webhook/slack/events`

```json
{
  "type": "slack_message_input",
  "event_id": "Ev03ABC",
  "text": "hello from DM",
  "thread_ts": "1730000000.000100",
  "message_ts": "1730000001.000200"
}
```
