//! Optional stdio-only MCP adapter. No listener or CLI subprocess is created.
mod executor;
mod schema;
mod server;

use rmcp::ServiceExt;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::sync::CancellationToken;

/// Only `mcp` starts this runtime; drop waits for running queries.
pub fn run() -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let executor = executor::Executor::new(parallelism);
        let shutdown = executor.shutdown_token();
        let input = StopOnEof {
            reader: tokio::io::stdin(),
            shutdown: shutdown.clone(),
        };
        let result = async {
            let service = server::Server::new(executor)
                .serve((input, tokio::io::stdout()))
                .await
                .map_err(|error| error.to_string())?;
            service.waiting().await.map_err(|error| error.to_string())?;
            Ok(())
        }
        .await;
        shutdown.cancel();
        result
    })
}

/// Stop queued work as soon as stdin closes, before the SDK drains replies.
struct StopOnEof<R> {
    reader: R,
    shutdown: CancellationToken,
}

impl<R: AsyncRead + Unpin> AsyncRead for StopOnEof<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let remaining = buf.remaining();
        let result = Pin::new(&mut self.reader).poll_read(cx, buf);
        match &result {
            Poll::Ready(Err(_)) => self.shutdown.cancel(),
            Poll::Ready(Ok(())) if remaining > 0 && buf.filled().len() == before => {
                self.shutdown.cancel()
            }
            _ => {}
        }
        result
    }
}
