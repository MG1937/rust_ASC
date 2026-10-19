use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::Value;

use super::schema;

pub(super) struct Server {
    tools: Vec<Tool>,
}

impl Server {
    pub(super) fn new() -> Self {
        Self {
            tools: schema::tools(),
        }
    }
}

impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("rust_ASC", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Inspect local Android APK files. Calls are stateless. Paths use the server \
                 filesystem. Output files may be overwritten. Failures return CLI stderr.",
            )
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if request.is_some_and(|request| request.cursor.is_some()) {
            return Err(ErrorData::invalid_params(
                "tool list has no continuation cursor",
                None,
            ));
        }
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools.iter().find(|tool| tool.name == name).cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if self.get_tool(&request.name).is_none() {
            return Err(ErrorData::invalid_params(
                format!("unknown tool: {}", request.name),
                None,
            ));
        }
        let args = Value::Object(request.arguments.unwrap_or_default());
        let query = match schema::Query::parse(&request.name, args) {
            Ok(query) => query,
            Err(error) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(error)]).into());
            }
        };
        let result = tokio::task::spawn_blocking(move || schema::execute(query)).await;
        let result = match result {
            Ok(Ok(stdout)) => CallToolResult::success(vec![ContentBlock::text(stdout)]),
            Ok(Err(error)) => CallToolResult::error(vec![ContentBlock::text(error)]),
            Err(error) => CallToolResult::error(vec![ContentBlock::text(format!(
                "CLI task failed: {error}"
            ))]),
        };
        Ok(result.into())
    }
}
