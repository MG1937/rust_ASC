use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::Value;

use super::{executor::Executor, schema};

pub(super) struct Server {
    pub executor: Executor,
    tools: Vec<Tool>,
}

impl Server {
    pub(super) fn new(executor: Executor) -> Self {
        Self {
            executor,
            tools: schema::tools(),
        }
    }
}

impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("rust_ASC", env!("CARGO_PKG_VERSION")))
            .with_instructions("Read-only, stateless local APK queries: getclass, listclass, getmanifest and findrefs. Pass an absolute apk_path on this machine. No open/close, cache, file writes, pagination or JavaScript execution. Keep input files unchanged during each query. Results are complete and can be large. CodeMode callers should check isError and consume structuredContent; tool errors resolve rather than throw. Concurrent calls share an automatic CPU budget. Cancellation does not interrupt already-running computation. Parser aborts can terminate this process.")
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
        context: RequestContext<RoleServer>,
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
            Err(error) => return Ok(schema::error_result(error).into()),
        };
        let result = self
            .executor
            .run(context.ct, move |threads| {
                // Keep large-result serialization off the protocol loop.
                query.execute(threads).map(CallToolResult::structured)
            })
            .await;
        Ok(match result {
            Ok(result) => result,
            Err(error) => schema::error_result(error),
        }
        .into())
    }
}
