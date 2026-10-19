//! Stdio MCP adapter for the existing command-line interface.
mod schema;
mod server;

use rmcp::ServiceExt;

pub fn run() -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let service = server::Server::new()
            .serve((tokio::io::stdin(), tokio::io::stdout()))
            .await
            .map_err(|error| error.to_string())?;
        service.waiting().await.map_err(|error| error.to_string())?;
        Ok(())
    })
}
