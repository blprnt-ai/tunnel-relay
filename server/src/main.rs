use std::env;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::WebSocketUpgrade;
use axum::extract::ws::WebSocket;
use axum::http::HeaderMap;
use axum::http::Method;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::routing::any;
use axum::routing::get;
use axum::routing::post;
use base64::Engine;
use bytes::Bytes;
use dashmap::DashMap;
use futures::SinkExt;
use futures::StreamExt;
use hmac::Hmac;
use hmac::Mac;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tunnel_protocol::SlackMessageInput;
use tunnel_protocol::TunnelRequest;
use url::Url;
use uuid::Uuid;

type Tunnels = Arc<DashMap<String, mpsc::Sender<TunnelRequest>>>;

type HmacSha256 = Hmac<Sha256>;

const SLACK_REDIRECT_URI: &str = "https://relay.blprnt.ai/slack/oauth/callback";
const SLACK_OAUTH_SUCCESS_REDIRECT: &str = "https://blprnt.ai/slack/success";
const SLACK_OAUTH_ERROR_REDIRECT: &str = "https://blprnt.ai/slack/error";
const SLACK_OAUTH_FORWARD_PATH: &str = "webhook/slack/oauth";
const SLACK_INTERACT_FORWARD_PATH: &str = "webhook/slack/interact";
const SLACK_EVENTS_FORWARD_PATH: &str = "webhook/slack/events";
const SLACK_TIMESTAMP_TOLERANCE_SECS: i64 = 60 * 5;

#[derive(Clone)]
struct AppState {
  tunnels:             Tunnels,
  slack_oauth:         Option<SlackOauthConfig>,
  slack_events_dedupe: Arc<DashMap<String, ()>>,
  slack_session_binds: Arc<DashMap<String, String>>,
}

#[derive(Clone)]
struct SlackOauthConfig {
  client_id:     String,
  client_secret: String,
  scopes:        String,
  hmac_keys:     Vec<Vec<u8>>,
  http:          Client,
}

impl SlackOauthConfig {
  fn from_env() -> Result<Self, String> {
    let client_id = env::var("SLACK_CLIENT_ID").map_err(|_| "Missing env SLACK_CLIENT_ID".to_string())?;
    let client_secret = env::var("SLACK_CLIENT_SECRET").map_err(|_| "Missing env SLACK_CLIENT_SECRET".to_string())?;
    let scopes = env::var("SLACK_SCOPES").unwrap_or_else(|_| "chat:write".to_string());
    let hmac_keys = parse_hmac_keys()?;
    let http = Client::new();

    Ok(Self { client_id, client_secret, scopes, hmac_keys, http })
  }
}

fn parse_hmac_keys() -> Result<Vec<Vec<u8>>, String> {
  let raw = env::var("TUNNEL_HMAC_KEYS").map_err(|_| "Missing env TUNNEL_HMAC_KEYS".to_string())?;
  let keys: Vec<Vec<u8>> = raw
    .split(',')
    .map(|s| s.trim())
    .filter(|s| !s.is_empty())
    .map(|material| {
      base64::engine::general_purpose::STANDARD
        .decode(material)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(material))
        .map_err(|_| "Invalid base64 in TUNNEL_HMAC_KEYS".to_string())
    })
    .collect::<Result<Vec<_>, _>>()?;

  if keys.is_empty() {
    return Err("TUNNEL_HMAC_KEYS must include at least one key".to_string());
  }
  Ok(keys)
}

fn sign_state(desktop_state: &str, hmac_keys: &[Vec<u8>]) -> Result<String, String> {
  let key = hmac_keys.first().ok_or_else(|| "No HMAC keys".to_string())?;
  let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "Invalid HMAC key".to_string())?;
  mac.update(desktop_state.as_bytes());
  let sig = mac.finalize().into_bytes();
  let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
  Ok(format!("{desktop_state}.{sig_b64}"))
}

fn verify_state(signed_state: &str, hmac_keys: &[Vec<u8>]) -> Result<String, String> {
  let (desktop_state, sig_b64) = signed_state.rsplit_once('.').ok_or_else(|| "Invalid state format".to_string())?;
  let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(sig_b64)
    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(sig_b64))
    .map_err(|_| "Invalid state signature encoding".to_string())?;

  for key in hmac_keys {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "Invalid HMAC key".to_string())?;
    mac.update(desktop_state.as_bytes());
    if mac.verify_slice(&sig).is_ok() {
      return Ok(desktop_state.to_string());
    }
  }

  Err("State signature verification failed".to_string())
}

fn extract_tunnel_id(desktop_state: &str) -> Result<String, String> {
  let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(desktop_state)
    .map_err(|_| "Desktop state must be base64url JSON".to_string())?;
  let value: Value = serde_json::from_slice(&decoded).map_err(|_| "Desktop state JSON parse failed".to_string())?;
  let tunnel_id = value
    .get("tunnel_id")
    .and_then(|v| v.as_str())
    .filter(|s| !s.is_empty())
    .ok_or_else(|| "Desktop state missing tunnel_id".to_string())?;
  Ok(tunnel_id.to_string())
}

#[tokio::main]
async fn main() {
  tracing_subscriber::registry()
    .with(tracing_subscriber::EnvFilter::new(env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())))
    .with(tracing_subscriber::fmt::layer())
    .init();

  let slack_oauth = match SlackOauthConfig::from_env() {
    Ok(cfg) => Some(cfg),
    Err(err) => {
      tracing::warn!("Slack OAuth disabled: {err}");
      None
    }
  };

  let state = AppState {
    tunnels: Arc::new(DashMap::new()),
    slack_oauth,
    slack_events_dedupe: Arc::new(DashMap::new()),
    slack_session_binds: Arc::new(DashMap::new()),
  };

  let app = Router::new()
    .route("/register/{tunnel_id}", get(ws_handler))
    .route("/slack/oauth/start", get(slack_oauth_start))
    .route("/slack/oauth/callback", get(slack_oauth_callback))
    .route("/slack/interact", post(slack_interact))
    .route("/webhook/slack/events", post(slack_events))
    .route("/webhook/slack/session-bind", post(slack_session_bind))
    .route("/{tunnel_id}/", any(proxy_handler_root))
    .route("/{tunnel_id}/{*path}", any(proxy_handler))
    .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
    .with_state(state);

  let listener = tokio::net::TcpListener::bind("0.0.0.0:7187").await.unwrap();
  tracing::info!("Relay server listening on :7187");
  axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct SlackOauthStartQuery {
  state: String,
}

async fn slack_oauth_start(
  State(state): State<AppState>,
  Query(query): Query<SlackOauthStartQuery>,
) -> impl IntoResponse {
  let Some(cfg) = &state.slack_oauth else {
    return (StatusCode::INTERNAL_SERVER_ERROR, "Slack OAuth not configured").into_response();
  };

  let signed_state = match sign_state(&query.state, &cfg.hmac_keys) {
    Ok(v) => v,
    Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err).into_response(),
  };

  let mut url = Url::parse("https://slack.com/oauth/v2/authorize").unwrap();
  url
    .query_pairs_mut()
    .append_pair("client_id", &cfg.client_id)
    .append_pair("scope", &cfg.scopes)
    .append_pair("redirect_uri", SLACK_REDIRECT_URI)
    .append_pair("state", &signed_state);

  Redirect::temporary(url.as_str()).into_response()
}

#[derive(Deserialize)]
struct SlackOauthCallbackQuery {
  code:              Option<String>,
  state:             Option<String>,
  error:             Option<String>,
  error_description: Option<String>,
}

async fn slack_oauth_callback(
  State(state): State<AppState>,
  Query(query): Query<SlackOauthCallbackQuery>,
) -> impl IntoResponse {
  let Some(cfg) = &state.slack_oauth else {
    tracing::warn!("Slack OAuth not configured");
    return redirect_to_slack_oauth_error("slack_oauth_not_configured").into_response();
  };

  let Some(signed_state) = query.state.as_deref() else {
    tracing::warn!("Slack OAuth callback missing state");
    return redirect_to_slack_oauth_error("missing_state").into_response();
  };

  let desktop_state = match verify_state(signed_state, &cfg.hmac_keys) {
    Ok(v) => v,
    Err(err) => {
      tracing::warn!("Slack OAuth callback state verification failed: {err}");
      return redirect_to_slack_oauth_error("invalid_state").into_response();
    }
  };

  let tunnel_id = match extract_tunnel_id(&desktop_state) {
    Ok(v) => v,
    Err(err) => {
      tracing::warn!("Slack OAuth callback tunnel_id extraction failed: {err}");
      return redirect_to_slack_oauth_error("invalid_tunnel").into_response();
    }
  };

  let (body_bytes, redirect) = if let Some(error) = query.error {
    let msg = query.error_description.as_deref().filter(|s| !s.is_empty()).unwrap_or(&error);

    (
      serde_json::to_vec(&serde_json::json!({
        "ok": false,
        "error": error,
        "error_description": query.error_description,
        "state": desktop_state,
      }))
      .unwrap(),
      redirect_to_slack_oauth_error(msg),
    )
  } else if let Some(code) = query.code {
    let bytes = exchange_slack_code(cfg, &code).await;
    let redirect = slack_oauth_redirect_from_exchange(&bytes);
    (bytes, redirect)
  } else {
    (
      serde_json::to_vec(&serde_json::json!({
        "ok": false,
        "error": "missing_code",
        "state": desktop_state,
      }))
      .unwrap(),
      redirect_to_slack_oauth_error("missing_code"),
    )
  };

  if let Err(err) = forward_slack_oauth_to_tunnel(&state, &tunnel_id, body_bytes).await {
    tracing::warn!("Slack OAuth forward failed: {err}");
  }

  redirect.into_response()
}

fn redirect_to_slack_oauth_error(message: &str) -> Redirect {
  let mut url = Url::parse(SLACK_OAUTH_ERROR_REDIRECT).unwrap();
  url.query_pairs_mut().append_pair("message", message);
  Redirect::temporary(url.as_str())
}

fn slack_oauth_redirect_from_exchange(exchange_bytes: &[u8]) -> Redirect {
  let Ok(value) = serde_json::from_slice::<Value>(exchange_bytes) else {
    return redirect_to_slack_oauth_error("slack_oauth_failed");
  };

  if value.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
    Redirect::temporary(SLACK_OAUTH_SUCCESS_REDIRECT)
  } else {
    let msg = value.get("error").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("slack_oauth_failed");
    redirect_to_slack_oauth_error(msg)
  }
}

async fn exchange_slack_code(cfg: &SlackOauthConfig, code: &str) -> Vec<u8> {
  let resp = cfg
    .http
    .post("https://slack.com/api/oauth.v2.access")
    .form(&[
      ("client_id", cfg.client_id.as_str()),
      ("client_secret", cfg.client_secret.as_str()),
      ("code", code),
      ("redirect_uri", SLACK_REDIRECT_URI),
    ])
    .send()
    .await;

  match resp {
    Ok(r) => {
      let status = r.status();
      match r.bytes().await {
        Ok(bytes) if status.is_success() => bytes.to_vec(),
        Ok(bytes) => serde_json::to_vec(&serde_json::json!({
          "ok": false,
          "error": "slack_http_error",
          "status": status.as_u16(),
          "body": String::from_utf8_lossy(&bytes),
        }))
        .unwrap(),
        Err(_) => serde_json::to_vec(&serde_json::json!({
          "ok": false,
          "error": "slack_read_error",
          "status": status.as_u16(),
        }))
        .unwrap(),
      }
    }
    Err(err) => serde_json::to_vec(&serde_json::json!({
      "ok": false,
      "error": "slack_request_error",
      "message": err.to_string(),
    }))
    .unwrap(),
  }
}

async fn forward_slack_oauth_to_tunnel(state: &AppState, tunnel_id: &str, body: Vec<u8>) -> Result<(), String> {
  let Some(tx) = state.tunnels.get(tunnel_id) else {
    return Err("Tunnel not connected".to_string());
  };

  let req = TunnelRequest {
    id: Uuid::new_v4(),
    method: "POST".to_string(),
    path: SLACK_OAUTH_FORWARD_PATH.to_string(),
    headers: vec![("content-type".to_string(), "application/json".to_string())],
    body,
  };

  tx.send(req).await.map_err(|_| "Tunnel send failed".to_string())
}

async fn slack_interact(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
  tracing::info!("Slack interact received");
  let raw_body_str = match std::str::from_utf8(&body) {
    Ok(v) => v,
    Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
  };

  tracing::info!("Slack interact raw_body_str: {raw_body_str}");

  if verify_slack_request(&headers, raw_body_str).is_err() {
    tracing::error!("Slack interact verify_slack_request failed");
    return StatusCode::UNAUTHORIZED.into_response();
  }

  tracing::info!("Slack interact verify_slack_request passed");

  let payload_str = match extract_form_field(raw_body_str, "payload") {
    Some(v) if !v.is_empty() => v,
    _ => return (StatusCode::BAD_REQUEST, "Missing payload").into_response(),
  };

  tracing::info!("Slack interact payload_str: {payload_str}");

  let slack_payload: Value = match serde_json::from_str(&payload_str) {
    Ok(v) => v,
    Err(_) => return (StatusCode::BAD_REQUEST, "Invalid payload JSON").into_response(),
  };

  tracing::info!("Slack interact slack_payload: {slack_payload}");

  let action_value_str =
    slack_payload.get("actions").and_then(|v| v.get(0)).and_then(|v| v.get("value")).and_then(|v| v.as_str());

  tracing::info!("Slack interact action_value_str: {:?}", action_value_str);

  let action_value_str = match action_value_str {
    Some(v) if !v.is_empty() => v,
    _ => return (StatusCode::BAD_REQUEST, "Missing actions[0].value").into_response(),
  };

  tracing::info!("Slack interact action_value_str: {action_value_str}");

  let action_value_json: Value = match serde_json::from_str(action_value_str) {
    Ok(v) => v,
    Err(_) => return (StatusCode::BAD_REQUEST, "Invalid actions[0].value JSON").into_response(),
  };

  tracing::info!("Slack interact action_value_json: {action_value_json}");

  let client_id = action_value_json.get("client_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty());

  tracing::info!("Slack interact client_id: {:?}", client_id);

  let Some(client_id) = client_id else {
    tracing::error!("Slack interact missing client_id");
    return (StatusCode::BAD_REQUEST, "Missing client_id").into_response();
  };

  tracing::info!("Slack interact client_id: {client_id}");

  let body_bytes = match serde_json::to_vec(&action_value_json) {
    Ok(v) => v,
    Err(_) => return (StatusCode::BAD_REQUEST, "Failed to encode JSON").into_response(),
  };

  tracing::info!("Slack interact body_bytes");

  if let Some(tx) = state.tunnels.get(client_id).map(|v| v.value().clone()) {
    let req = TunnelRequest {
      id:      Uuid::new_v4(),
      method:  "POST".to_string(),
      path:    SLACK_INTERACT_FORWARD_PATH.to_string(),
      headers: vec![("content-type".to_string(), "application/json".to_string())],
      body:    body_bytes,
    };

    tokio::spawn(async move {
      let _ = tokio::time::timeout(Duration::from_millis(250), tx.send(req)).await;
    });
  } else {
    tracing::warn!("Slack interact: tunnel not connected: {client_id}");
  }

  (StatusCode::OK, Json(serde_json::json!({ "response_action": "clear" }))).into_response()
}

#[derive(Deserialize)]
struct SlackEventsEnvelope {
  #[serde(rename = "type")]
  kind:      String,
  event_id:  Option<String>,
  team_id:   Option<String>,
  challenge: Option<String>,
  event:     Option<SlackMessageEvent>,
}

#[derive(Deserialize)]
struct SlackMessageEvent {
  #[serde(rename = "type")]
  kind:         String,
  channel:      Option<String>,
  channel_type: Option<String>,
  user:         Option<String>,
  text:         Option<String>,
  ts:           Option<String>,
  thread_ts:    Option<String>,
  bot_id:       Option<String>,
  subtype:      Option<String>,
  client_id:    Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackSessionBindInput {
  team_id:       String,
  slack_user_id: String,
  client_id:     String,
}

async fn slack_session_bind(
  State(state): State<AppState>,
  Json(payload): Json<SlackSessionBindInput>,
) -> impl IntoResponse {
  tracing::info!("Slack session bind: {payload:#?}");
  if payload.team_id.trim().is_empty() || payload.slack_user_id.trim().is_empty() || payload.client_id.trim().is_empty()
  {
    return (StatusCode::BAD_REQUEST, "team_id, slack_user_id, client_id are required").into_response();
  }

  state.slack_session_binds.insert(session_bind_key(&payload.team_id, &payload.slack_user_id), payload.client_id);
  StatusCode::OK.into_response()
}

async fn slack_events(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
  let raw_body = match std::str::from_utf8(&body) {
    Ok(v) => v,
    Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
  };

  if verify_slack_request(&headers, raw_body).is_err() {
    return StatusCode::UNAUTHORIZED.into_response();
  }

  let envelope: SlackEventsEnvelope = match serde_json::from_slice(&body) {
    Ok(v) => v,
    Err(_) => return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response(),
  };

  if envelope.kind == "url_verification" {
    let Some(challenge) = envelope.challenge else {
      return (StatusCode::BAD_REQUEST, "Missing challenge").into_response();
    };
    return (StatusCode::OK, Json(serde_json::json!({ "challenge": challenge }))).into_response();
  }

  if envelope.kind != "event_callback" {
    return StatusCode::OK.into_response();
  }

  let Some(ref event) = envelope.event else {
    return StatusCode::OK.into_response();
  };

  let tunnel_id = resolve_slack_event_tunnel_id(&state, &envelope, event);

  let normalized = match normalize_dm_message_event(&envelope, event) {
    Some(v) => v,
    None => return StatusCode::OK.into_response(),
  };

  tracing::info!("Slack events normalized: {normalized:#?}");

  let dedupe_key = dedupe_key(&normalized);
  match state.slack_events_dedupe.entry(dedupe_key.clone()) {
    dashmap::mapref::entry::Entry::Occupied(_) => return StatusCode::OK.into_response(),
    dashmap::mapref::entry::Entry::Vacant(v) => {
      v.insert(());
    }
  }

  let body = match serde_json::to_vec(&normalized) {
    Ok(v) => v,
    Err(_) => {
      state.slack_events_dedupe.remove(&dedupe_key);
      return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
  };

  match forward_slack_events_to_tunnel(&state, &tunnel_id, body).await {
    Ok(()) => StatusCode::OK.into_response(),
    Err(e) => {
      tracing::error!("Slack events forward_slack_events_to_tunnel failed: {e:#?}");
      state.slack_events_dedupe.remove(&dedupe_key);
      StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
  }
}

fn normalize_dm_message_event(envelope: &SlackEventsEnvelope, event: &SlackMessageEvent) -> Option<SlackMessageInput> {
  if event.kind != "message" {
    return None;
  }
  if event.channel_type.as_deref() != Some("im") {
    return None;
  }
  if event.subtype.is_some() || event.bot_id.is_some() {
    return None;
  }

  let _team_id = envelope.team_id.as_deref().filter(|v| !v.is_empty())?;
  let channel_id = event.channel.as_deref().filter(|v| !v.is_empty())?;
  let _slack_user_id = event.user.as_deref().filter(|v| !v.is_empty())?;
  let text = event.text.as_deref().unwrap_or_default().to_string();
  let message_ts = event.ts.as_deref().filter(|v| !v.is_empty())?;
  let event_id = envelope
    .event_id
    .as_ref()
    .filter(|v| !v.is_empty())
    .cloned()
    .unwrap_or_else(|| format!("{channel_id}:{message_ts}"));
  let thread_ts = event.thread_ts.as_ref().filter(|v| !v.is_empty()).cloned();

  Some(SlackMessageInput {
    kind: "slack_message_input".to_string(),
    event_id,
    text,
    thread_ts,
    message_ts: message_ts.to_string(),
  })
}

fn dedupe_key(input: &SlackMessageInput) -> String {
  input.event_id.clone()
}

fn resolve_slack_event_tunnel_id(
  state: &AppState,
  envelope: &SlackEventsEnvelope,
  event: &SlackMessageEvent,
) -> String {
  if let Some(client_id) = event.client_id.as_ref().filter(|v| !v.is_empty()) {
    return client_id.to_string();
  }
  if let (Some(team_id), Some(slack_user_id)) =
    (envelope.team_id.as_ref().filter(|v| !v.is_empty()), event.user.as_ref().filter(|v| !v.is_empty()))
  {
    if let Some(mapped_client_id) =
      state.slack_session_binds.get(&session_bind_key(team_id, slack_user_id)).map(|v| v.value().clone())
    {
      return mapped_client_id;
    }
    return slack_user_id.to_string();
  }
  String::new()
}

fn session_bind_key(team_id: &str, slack_user_id: &str) -> String {
  format!("{team_id}:{slack_user_id}")
}

async fn forward_slack_events_to_tunnel(state: &AppState, tunnel_id: &str, body: Vec<u8>) -> Result<(), String> {
  let Some(tx) = state.tunnels.get(tunnel_id) else {
    return Err("Tunnel not connected".to_string());
  };

  let req = TunnelRequest {
    id: Uuid::new_v4(),
    method: "POST".to_string(),
    path: SLACK_EVENTS_FORWARD_PATH.to_string(),
    headers: vec![("content-type".to_string(), "application/json".to_string())],
    body,
  };

  tx.try_send(req).map_err(|err| format!("Tunnel send failed: {err}"))
}

fn verify_slack_request(headers: &HeaderMap, raw_body: &str) -> Result<(), ()> {
  let signing_secret = env::var("SLACK_SIGNING_SECRET").map_err(|_| ())?;
  verify_slack_request_with_secret_and_now(headers, raw_body, &signing_secret, current_unix_ts()?)
}

fn verify_slack_request_with_secret_and_now(
  headers: &HeaderMap,
  raw_body: &str,
  signing_secret: &str,
  now: i64,
) -> Result<(), ()> {
  let ts = headers.get("X-Slack-Request-Timestamp").and_then(|v| v.to_str().ok()).ok_or(())?;
  let ts: i64 = ts.parse().map_err(|_| ())?;

  if (now - ts).abs() > SLACK_TIMESTAMP_TOLERANCE_SECS {
    return Err(());
  }

  let sig = headers.get("X-Slack-Signature").and_then(|v| v.to_str().ok()).ok_or(())?;
  let sig_hex = sig.strip_prefix("v0=").ok_or(())?;
  let sig_bytes = decode_hex(sig_hex).ok_or(())?;

  let base = format!("v0:{ts}:{raw_body}");
  let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes()).map_err(|_| ())?;
  mac.update(base.as_bytes());
  mac.verify_slice(&sig_bytes).map_err(|_| ())
}

fn current_unix_ts() -> Result<i64, ()> {
  Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| ())?.as_secs() as i64)
}

fn extract_form_field(body: &str, key: &str) -> Option<String> {
  url::form_urlencoded::parse(body.as_bytes()).find_map(|(k, v)| if k == key { Some(v.into_owned()) } else { None })
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
  let bytes = input.as_bytes();
  if bytes.len() % 2 != 0 {
    return None;
  }
  let mut out = Vec::with_capacity(bytes.len() / 2);
  let mut i = 0;
  while i < bytes.len() {
    let hi = hex_nibble(bytes[i])?;
    let lo = hex_nibble(bytes[i + 1])?;
    out.push((hi << 4) | lo);
    i += 2;
  }
  Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
  match b {
    b'0'..=b'9' => Some(b - b'0'),
    b'a'..=b'f' => Some(b - b'a' + 10),
    b'A'..=b'F' => Some(b - b'A' + 10),
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use axum::http::HeaderValue;

  use super::*;

  fn slack_signed_headers(secret: &str, body: &str, ts: i64) -> HeaderMap {
    let base = format!("v0:{ts}:{body}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(base.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_hex = sig.iter().map(|b| format!("{b:02x}")).collect::<String>();

    let mut headers = HeaderMap::new();
    headers.insert("X-Slack-Request-Timestamp", HeaderValue::from_str(&ts.to_string()).unwrap());
    headers.insert("X-Slack-Signature", HeaderValue::from_str(&format!("v0={sig_hex}")).unwrap());
    headers
  }

  fn test_state() -> (AppState, mpsc::Receiver<TunnelRequest>) {
    let tunnels = Arc::new(DashMap::new());
    let (tx, rx) = mpsc::channel(2);
    tunnels.insert("U123".to_string(), tx);
    (
      AppState {
        tunnels,
        slack_oauth: None,
        slack_events_dedupe: Arc::new(DashMap::new()),
        slack_session_binds: Arc::new(DashMap::new()),
      },
      rx,
    )
  }

  #[test]
  fn signature_verify_pass_fail() {
    let secret = "test-secret";
    let body = r#"{"type":"url_verification","challenge":"abc"}"#;
    let ts = 1_700_000_000_i64;
    let headers = slack_signed_headers(secret, body, ts);
    assert!(verify_slack_request_with_secret_and_now(&headers, body, secret, ts).is_ok());
    assert!(verify_slack_request_with_secret_and_now(&headers, body, "wrong", ts).is_err());
    assert!(
      verify_slack_request_with_secret_and_now(&headers, body, secret, ts + SLACK_TIMESTAMP_TOLERANCE_SECS + 1)
        .is_err()
    );
  }

  #[tokio::test]
  async fn url_verification_challenge() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let body = Bytes::from_static(br#"{"type":"url_verification","challenge":"xyz"}"#);
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, std::str::from_utf8(&body).unwrap(), ts);

    let (state, _) = test_state();
    let response = slack_events(State(state), headers, body).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);
  }

  #[tokio::test]
  async fn dedupe_prevents_double_forward() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev1",
      "team_id": "T1",
      "event": {
        "type": "message",
        "channel_type": "im",
        "channel": "D1",
        "user": "U123",
        "text": "hello",
        "ts": "1700000000.000100"
      }
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let (state, mut rx) = test_state();
    let _ = slack_events(State(state.clone()), headers.clone(), Bytes::from(body_text.clone())).await;
    let _ = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await;

    let first = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await.unwrap();
    let first = first.unwrap();
    let first_json: Value = serde_json::from_slice(&first.body).unwrap();
    assert!(first_json.get("event_id").is_some());
    assert!(first_json.get("thread_ts").is_some());
    assert!(first_json.get("thread_ts").unwrap().is_null());
    assert!(first_json.get("team_id").is_none());
    assert!(first_json.get("channel_id").is_none());
    assert!(first_json.get("slack_user_id").is_none());
    assert!(first_json.get("client_id").is_none());
    let second = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(second.is_err());
  }

  #[tokio::test]
  async fn message_im_forward_shape() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev2",
      "team_id": "T2",
      "event": {
        "type": "message",
        "channel_type": "im",
        "channel": "D2",
        "user": "U123",
        "text": "thread reply",
        "thread_ts": "1700000000.000000",
        "ts": "1700000000.000200"
      }
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let (state, mut rx) = test_state();
    let response = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let req = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await.unwrap().unwrap();
    assert_eq!(req.path, SLACK_EVENTS_FORWARD_PATH);
    let json: Value = serde_json::from_slice(&req.body).unwrap();
    assert!(json.get("client_id").is_none());
    assert!(json.get("team_id").is_none());
    assert!(json.get("channel_id").is_none());
    assert!(json.get("slack_user_id").is_none());
    let forwarded: SlackMessageInput = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(forwarded.kind, "slack_message_input");
    assert_eq!(forwarded.event_id, "Ev2");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("1700000000.000000"));
    assert_eq!(forwarded.message_ts, "1700000000.000200");
  }

  #[tokio::test]
  async fn bot_and_subtype_filtered() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev3",
      "team_id": "T3",
      "event": {
        "type": "message",
        "channel_type": "im",
        "channel": "D3",
        "user": "U123",
        "text": "bot msg",
        "ts": "1700000000.000300",
        "subtype": "bot_message",
        "bot_id": "B1"
      }
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let (state, mut rx) = test_state();
    let response = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(received.is_err());
  }

  #[tokio::test]
  async fn transient_forward_failure_returns_5xx_and_dedupe_rollback() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev5",
      "team_id": "T5",
      "event": {
        "type": "message",
        "channel_type": "im",
        "channel": "D5",
        "user": "U123",
        "text": "retry me",
        "ts": "1700000000.000500"
      }
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let tunnels = Arc::new(DashMap::new());
    let (tx, mut rx) = mpsc::channel(1);
    tunnels.insert("U123".to_string(), tx);
    let state = AppState {
      tunnels,
      slack_oauth: None,
      slack_events_dedupe: Arc::new(DashMap::new()),
      slack_session_binds: Arc::new(DashMap::new()),
    };

    // Fill channel so try_send fails as transient backpressure
    let filler = TunnelRequest {
      id:      Uuid::new_v4(),
      method:  "POST".to_string(),
      path:    "filler".to_string(),
      headers: vec![],
      body:    vec![],
    };
    state.tunnels.get("U123").unwrap().try_send(filler).unwrap();

    let first =
      slack_events(State(state.clone()), headers.clone(), Bytes::from(body_text.clone())).await.into_response();
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!state.slack_events_dedupe.contains_key("Ev5"));

    // Drain filler; retry must succeed and forward once
    let drained = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await.unwrap();
    assert!(drained.is_some());

    let second = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(second.status(), StatusCode::OK);
    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await.unwrap();
    assert!(forwarded.is_some());
  }

  #[tokio::test]
  async fn ignore_non_event_callback_envelope() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "app_rate_limited",
      "team_id": "T9"
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let (state, mut rx) = test_state();
    let response = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(!matches!(received, Ok(Some(_))));
  }

  #[tokio::test]
  async fn ignore_non_message_event_type() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev6",
      "team_id": "T6",
      "event": {
        "type": "reaction_added",
        "user": "U123",
        "item": {"type": "message"}
      }
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let (state, mut rx) = test_state();
    let response = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(!matches!(received, Ok(Some(_))));
  }

  #[tokio::test]
  async fn ignore_message_non_im_channel_type() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev7",
      "team_id": "T7",
      "event": {
        "type": "message",
        "channel_type": "channel",
        "channel": "C123",
        "user": "U123",
        "text": "public channel message",
        "ts": "1700000000.000700"
      }
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let (state, mut rx) = test_state();
    let response = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(!matches!(received, Ok(Some(_))));
  }

  #[tokio::test]
  async fn ignore_event_callback_missing_event_object() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev8",
      "team_id": "T8"
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let (state, mut rx) = test_state();
    let response = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(!matches!(received, Ok(Some(_))));
  }

  #[tokio::test]
  async fn session_bind_upsert_success() {
    let (state, _) = test_state();

    let response = slack_session_bind(
      State(state.clone()),
      Json(SlackSessionBindInput {
        team_id:       "T1".to_string(),
        slack_user_id: "U1".to_string(),
        client_id:     "C1".to_string(),
      }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      state.slack_session_binds.get(&session_bind_key("T1", "U1")).map(|v| v.value().clone()),
      Some("C1".to_string())
    );

    let response = slack_session_bind(
      State(state.clone()),
      Json(SlackSessionBindInput {
        team_id:       "T1".to_string(),
        slack_user_id: "U1".to_string(),
        client_id:     "C2".to_string(),
      }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      state.slack_session_binds.get(&session_bind_key("T1", "U1")).map(|v| v.value().clone()),
      Some("C2".to_string())
    );
  }

  #[tokio::test]
  async fn session_bind_invalid_payload_returns_400() {
    let (state, _) = test_state();
    let response = slack_session_bind(
      State(state),
      Json(SlackSessionBindInput {
        team_id:       "T1".to_string(),
        slack_user_id: " ".to_string(),
        client_id:     "C1".to_string(),
      }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn event_without_client_id_uses_session_bind_mapping() {
    let secret = "test-secret";
    unsafe { env::set_var("SLACK_SIGNING_SECRET", secret) };
    let tunnels = Arc::new(DashMap::new());
    let (tx, mut rx) = mpsc::channel(2);
    tunnels.insert("CLIENT-9".to_string(), tx);
    let state = AppState {
      tunnels,
      slack_oauth: None,
      slack_events_dedupe: Arc::new(DashMap::new()),
      slack_session_binds: Arc::new(DashMap::new()),
    };
    state.slack_session_binds.insert(session_bind_key("T9", "U9"), "CLIENT-9".to_string());

    let payload = serde_json::json!({
      "type": "event_callback",
      "event_id": "Ev9",
      "team_id": "T9",
      "event": {
        "type": "message",
        "channel_type": "im",
        "channel": "D9",
        "user": "U9",
        "text": "mapped",
        "ts": "1700000000.000900"
      }
    });
    let body_text = payload.to_string();
    let ts = current_unix_ts().unwrap();
    let headers = slack_signed_headers(secret, &body_text, ts);

    let response = slack_events(State(state.clone()), headers, Bytes::from(body_text)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let req = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await.unwrap().unwrap();
    let forwarded: SlackMessageInput = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(forwarded.thread_ts, None);
    let json: Value = serde_json::from_slice(&req.body).unwrap();
    assert!(json.get("client_id").is_none());
    assert!(json.get("team_id").is_none());
    assert!(json.get("channel_id").is_none());
    assert!(json.get("slack_user_id").is_none());
  }
}

async fn ws_handler(
  Path(tunnel_id): Path<String>,
  State(state): State<AppState>,
  ws: WebSocketUpgrade,
) -> impl IntoResponse {
  ws.on_upgrade(move |socket| handle_tunnel(socket, tunnel_id, state))
}

async fn handle_tunnel(socket: WebSocket, tunnel_id: String, state: AppState) {
  let (sink, mut stream) = socket.split();
  let sink = Arc::new(Mutex::new(sink));
  let (tx, mut rx) = mpsc::channel::<TunnelRequest>(32);

  state.tunnels.insert(tunnel_id.clone(), tx);
  tracing::info!("Tunnel registered: {tunnel_id}");

  // Task: send requests to desktop client
  let sink_for_send = Arc::clone(&sink);
  let send_task = tokio::spawn(async move {
    while let Some(req) = rx.recv().await {
      let data = serde_json::to_vec(&req).unwrap();
      let msg = axum::extract::ws::Message::Binary(data.into());
      let mut guard = sink_for_send.lock().await;
      if guard.send(msg).await.is_err() {
        break;
      }
    }
  });

  // Task: keep the connection alive
  let sink_for_ping = Arc::clone(&sink);
  let ping_task = tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    loop {
      interval.tick().await;
      let mut guard = sink_for_ping.lock().await;
      if guard.send(axum::extract::ws::Message::Ping(Bytes::new())).await.is_err() {
        break;
      }
    }
  });

  // Receive responses from desktop client
  while let Some(Ok(msg)) = stream.next().await {
    match msg {
      axum::extract::ws::Message::Ping(data) => {
        let mut guard = sink.lock().await;
        let _ = guard.send(axum::extract::ws::Message::Pong(data)).await;
      }
      axum::extract::ws::Message::Close(_) => {
        break;
      }
      _ => {}
    }
  }

  send_task.abort();
  ping_task.abort();
  state.tunnels.remove(&tunnel_id);
  tracing::info!("Tunnel disconnected: {tunnel_id}");
}

async fn proxy_handler_root(
  Path(tunnel_id): Path<String>,
  state: State<AppState>,
  method: Method,
  headers: HeaderMap,
  body: Bytes,
) -> impl IntoResponse {
  proxy_request(tunnel_id, String::new(), state, method, headers, body).await
}

async fn proxy_handler(
  Path((tunnel_id, path)): Path<(String, String)>,
  state: State<AppState>,
  method: Method,
  headers: HeaderMap,
  body: Bytes,
) -> impl IntoResponse {
  proxy_request(tunnel_id, path, state, method, headers, body).await
}

async fn proxy_request(
  tunnel_id: String,
  path: String,
  State(state): State<AppState>,
  method: Method,
  headers: HeaderMap,
  body: Bytes,
) -> impl IntoResponse {
  let Some(tx) = state.tunnels.get(&tunnel_id) else {
    return (StatusCode::BAD_GATEWAY, "Tunnel not connected").into_response();
  };

  let req = TunnelRequest {
    id: Uuid::new_v4(),
    method: method.to_string(),
    path,
    headers: headers.iter().filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string()))).collect(),
    body: body.to_vec(),
  };

  if tx.send(req).await.is_err() {
    return (StatusCode::BAD_GATEWAY, "Tunnel send failed").into_response();
  }

  (StatusCode::NO_CONTENT).into_response()
}
