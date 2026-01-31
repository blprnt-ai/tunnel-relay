use std::future::Future;
use std::time::Duration;

use futures::SinkExt;
use futures::StreamExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
pub use tunnel_protocol::TunnelRequest;
pub use tunnel_protocol::TunnelResponse;

pub struct TunnelClient {
  tunnel_id:       String,
  relay_url:       String,
  reconnect_delay: Duration,
}

impl TunnelClient {
  pub fn new(relay_url: impl Into<String>, tunnel_id: impl Into<String>) -> Self {
    Self {
      tunnel_id:       tunnel_id.into(),
      relay_url:       relay_url.into(),
      reconnect_delay: Duration::from_secs(5),
    }
  }

  pub fn with_reconnect_delay(mut self, delay: Duration) -> Self {
    self.reconnect_delay = delay;
    self
  }

  pub fn tunnel_id(&self) -> &str {
    &self.tunnel_id
  }

  /// Connect to the relay server and handle incoming requests.
  ///
  /// The handler receives each incoming HTTP request and must return a response.
  /// This function loops forever, automatically reconnecting on disconnect.
  pub async fn connect<F, Fut>(&self, handler: F) -> anyhow::Result<()>
  where
    F: Fn(TunnelRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = TunnelResponse> + Send,
  {
    self.connect_with_lifecycle(handler, || async {}).await
  }

  /// Connect to the relay server and handle incoming requests.
  ///
  /// Calls `on_connected` every time a websocket connection is successfully established,
  /// including the initial connect and every reconnect.
  pub async fn connect_with_lifecycle<F, Fut, C, CFut>(&self, handler: F, on_connected: C) -> anyhow::Result<()>
  where
    F: Fn(TunnelRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = TunnelResponse> + Send,
    C: Fn() -> CFut + Send + Sync + 'static,
    CFut: Future<Output = ()> + Send,
  {
    let url = format!("{}/register/{}", self.relay_url, self.tunnel_id);

    loop {
      tracing::trace!("Connecting to relay server...");

      match connect_async(&url).await {
        Ok((socket, _)) => {
          tracing::info!(
            "Connected! Tunnel active at: {}/{}/",
            self.relay_url.replace("ws://", "http://").replace("wss://", "https://"),
            self.tunnel_id
          );

          on_connected().await;

          let (mut sink, mut stream) = socket.split();

          while let Some(msg_result) = stream.next().await {
            match msg_result {
              Ok(Message::Binary(data)) => match serde_json::from_slice::<TunnelRequest>(&data) {
                Ok(req) => {
                  let req_id = req.id;
                  tracing::trace!("Received request: {} {} (id: {})", req.method, req.path, req_id);

                  let resp = handler(req).await;

                  let resp_data = serde_json::to_vec(&resp).unwrap();
                  if sink.send(Message::Binary(resp_data.into())).await.is_err() {
                    tracing::error!("Failed to send response, connection lost");
                    break;
                  }

                  tracing::trace!("Sent response: {} (id: {})", resp.status, req_id);
                }
                Err(e) => {
                  tracing::error!("Failed to parse request: {e}");
                }
              },
              Ok(Message::Ping(data)) => {
                let _ = sink.send(Message::Pong(data)).await;
              }
              Ok(Message::Close(_)) => {
                tracing::info!("Server closed connection");
                break;
              }
              Err(e) => {
                tracing::error!("WebSocket error: {e}");
                break;
              }
              _ => {}
            }
          }
        }
        Err(e) => {
          tracing::error!("Connection failed: {e}");
        }
      }

      tracing::info!("Disconnected. Reconnecting in {:?}...", self.reconnect_delay);
      tokio::time::sleep(self.reconnect_delay).await;
    }
  }

  /// Connect once without automatic reconnection.
  /// Returns when the connection is closed or an error occurs.
  pub async fn connect_once<F, Fut>(&self, handler: F) -> anyhow::Result<()>
  where
    F: Fn(TunnelRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = TunnelResponse> + Send,
  {
    let url = format!("{}/register/{}", self.relay_url, self.tunnel_id);
    let (socket, _) = connect_async(&url).await?;

    tracing::info!(
      "Connected! Tunnel active at: {}/{}/",
      self.relay_url.replace("ws://", "http://").replace("wss://", "https://"),
      self.tunnel_id
    );

    let (mut sink, mut stream) = socket.split();

    while let Some(msg_result) = stream.next().await {
      match msg_result {
        Ok(Message::Binary(data)) => {
          let req: TunnelRequest = serde_json::from_slice(&data)?;
          let resp = handler(req).await;
          let resp_data = serde_json::to_vec(&resp)?;
          sink.send(Message::Binary(resp_data.into())).await?;
        }
        Ok(Message::Ping(data)) => {
          sink.send(Message::Pong(data)).await?;
        }
        Ok(Message::Close(_)) => break,
        Err(e) => return Err(e.into()),
        _ => {}
      }
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;
  use std::sync::atomic::AtomicUsize;
  use std::sync::atomic::Ordering;
  use std::time::Duration;

  use tokio::net::TcpListener;
  use tokio::sync::oneshot;
  use tokio_tungstenite::accept_async;

  use super::TunnelClient;

  #[tokio::test]
  async fn connect_with_lifecycle_invokes_callback_on_reconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
      for _ in 0..2 {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        ws.close(None).await.unwrap();
      }
    });

    let connected_count = Arc::new(AtomicUsize::new(0));
    let (done_tx, done_rx) = oneshot::channel();
    let done_tx = Arc::new(tokio::sync::Mutex::new(Some(done_tx)));

    let client = TunnelClient::new(format!("ws://{addr}"), "test-client").with_reconnect_delay(Duration::from_millis(10));

    let callback_count = connected_count.clone();
    let callback_done_tx = done_tx.clone();
    let client_task = tokio::spawn(async move {
      let _ = client
        .connect_with_lifecycle(
          |_req| async move {
            unreachable!("server does not send requests in this test");
          },
          move || {
            let callback_count = callback_count.clone();
            let callback_done_tx = callback_done_tx.clone();
            async move {
              let next = callback_count.fetch_add(1, Ordering::SeqCst) + 1;
              if next >= 2 {
                if let Some(tx) = callback_done_tx.lock().await.take() {
                  let _ = tx.send(());
                }
              }
            }
          },
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(2), done_rx).await.unwrap().unwrap();

    client_task.abort();
    let _ = client_task.await;
    server_task.await.unwrap();

    assert!(connected_count.load(Ordering::SeqCst) >= 2);
  }
}

/// Helper to create a simple JSON response
pub fn json_response(request_id: uuid::Uuid, status: u16, body: impl serde::Serialize) -> TunnelResponse {
  TunnelResponse {
    id: request_id,
    status,
    headers: vec![("content-type".to_string(), "application/json".to_string())],
    body: serde_json::to_vec(&body).unwrap_or_default(),
  }
}

/// Helper to create a plain text response
pub fn text_response(request_id: uuid::Uuid, status: u16, body: impl Into<String>) -> TunnelResponse {
  TunnelResponse {
    id: request_id,
    status,
    headers: vec![("content-type".to_string(), "text/plain".to_string())],
    body: body.into().into_bytes(),
  }
}
