use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
  pub id:      Uuid,
  pub method:  String,
  pub path:    String,
  pub headers: Vec<(String, String)>,
  pub body:    Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelResponse {
  pub id:      Uuid,
  pub status:  u16,
  pub headers: Vec<(String, String)>,
  pub body:    Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackMessageInput {
  #[serde(rename = "type")]
  pub kind:       String,
  pub event_id:   String,
  pub text:       String,
  pub thread_ts:  Option<String>,
  pub message_ts: String,
}
