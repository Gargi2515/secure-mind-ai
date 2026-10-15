"""MCP gateway client with safe synthetic demo tools.

The demo mode never connects to real services or performs real financial actions.
For real MCP mode, server URL/command must be configured by the operator only.
"""
import json
from contextlib import asynccontextmanager
from typing import Any

from .config import settings
from .policies import SCHEMAS, TOOL_DESCRIPTIONS

DEMO_TOOLS = [
    {"name": name, "description": TOOL_DESCRIPTIONS.get(name, "MCP tool"), "inputSchema": schema}
    for name, schema in SCHEMAS.items()
]


class MCPGateway:
    async def list_tools(self) -> list[dict[str, Any]]:
        if settings.mcp_transport == "demo":
            return [dict(tool) for tool in DEMO_TOOLS]
        async with self._session() as session:
            result = await session.list_tools()
            return [
                {"name": tool.name, "description": tool.description or "", "inputSchema": tool.inputSchema or {"type": "object", "properties": {}}}
                for tool in result.tools
            ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if settings.mcp_transport == "demo":
            return self._call_demo_tool(name, arguments)
        async with self._session() as session:
            result = await session.call_tool(name, arguments)
            content = [item.text for item in (result.content or []) if getattr(item, "text", None)]
            return {
                "isError": bool(getattr(result, "isError", False)),
                "content": content,
                "structuredContent": getattr(result, "structuredContent", None),
            }

    def _call_demo_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Return deterministic synthetic results only; no side effects or disk access."""
        if name == "get_my_balance":
            return {"balance": 1284.50, "currency": "USD", "source": "synthetic demo data"}
        if name == "get_support_ticket":
            tickets = {
                "TICKET-1001": {"ticket_id": "TICKET-1001", "owner": "demo-user", "status": "open", "summary": "Example support ticket about account access"},
                "TICKET-1002": {"ticket_id": "TICKET-1002", "owner": "demo-user", "status": "pending", "summary": "Demo billing question awaiting review"},
                "TICKET-1003": {"ticket_id": "TICKET-1003", "owner": "demo-agent", "status": "closed", "summary": "Synthetic password-reset guidance request"},
            }
            ticket_id = args.get("ticket_id")
            if ticket_id not in tickets:
                return {"error": "Ticket not found in synthetic demo data", "ticket_id": ticket_id}
            return dict(tickets[ticket_id])
        if name == "transfer_funds":
            return {"simulation": True, "message": "Approved demo transfer simulated; no money was moved", "to_account": args["to_account"], "amount": args["amount"]}
        if name == "search_customer":
            return {"query": args["query"], "matches": [{"customer_id": "CUST-1001", "name": "Demo Customer", "email": "customer@example.test"}], "synthetic": True}
        if name == "update_customer":
            return {"simulation": True, "message": "Customer update simulated; demo data was not persisted", "customer_id": args["customer_id"], "field": args["field"], "value": args["value"]}
        if name == "create_ticket":
            return {"simulation": True, "ticket_id": "TICKET-DEMO-0002", "status": "created_in_demo", "subject": args["subject"], "message": "Synthetic ticket only; no external service changed"}
        if name == "search_documents":
            return {"query": args["query"], "results": [{"document_id": "DOC-001", "title": "Security Handbook", "snippet": "Follow least privilege and review sensitive actions."}], "synthetic": True}
        if name == "get_document":
            if args["document_id"] != "DOC-001":
                return {"error": "Document not found in synthetic demo data"}
            return {"document_id": "DOC-001", "title": "Security Handbook", "content": "Demo document: use least privilege, validate inputs, and audit sensitive tool calls."}
        if name == "get_transaction_history":
            limit = args.get("limit", 10)
            rows = [
                {"transaction_id": "TX-DEMO-001", "type": "credit", "amount": 150.00, "currency": "USD"},
                {"transaction_id": "TX-DEMO-002", "type": "debit", "amount": 24.50, "currency": "USD"},
            ]
            return {"transactions": rows[:limit], "synthetic": True}
        if name == "search_repository":
            return {"query": args["query"], "matches": [{"path": "src/security.py", "snippet": "Example repository result"}], "synthetic": True}
        if name == "get_build_status":
            build_id = args.get("build_id", "BUILD-DEMO-001")
            return {"build_id": build_id, "status": "success", "synthetic": True}
        if name == "create_issue":
            return {"simulation": True, "issue_id": "ISSUE-DEMO-0001", "title": args["title"], "message": "Synthetic issue created; no repository service was changed"}
        if name == "read_file":
            safe_virtual_files = {
                "README.md": "# Synthetic repository\nThis is demo-only virtual file content.",
                "src/security.py": "# Synthetic security module\ndef validate_request():\n    return True\n",
            }
            path = args["path"].replace("\\", "/").lstrip("./")
            if path not in safe_virtual_files:
                return {"error": "Path is not in the demo virtual file allowlist"}
            return {"path": path, "content": safe_virtual_files[path], "synthetic": True}
        return {"error": "Tool is not implemented in demo mode"}

    @asynccontextmanager
    async def _session(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
        from mcp.client.stdio import stdio_client, StdioServerParameters

        if settings.mcp_transport == "streamable_http":
            headers = {"Authorization": f"Bearer {settings.mcp_server_token}"} if settings.mcp_server_token else {}
            async with streamablehttp_client(settings.mcp_server_url, headers=headers) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    yield session
        elif settings.mcp_transport == "stdio":
            if not settings.mcp_stdio_command:
                raise RuntimeError("MCP_STDIO_COMMAND is required for stdio transport")
            args = json.loads(settings.mcp_stdio_args or "[]")
            if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
                raise RuntimeError("MCP_STDIO_ARGS must be a JSON array of strings")
            params = StdioServerParameters(command=settings.mcp_stdio_command, args=args)
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    yield session
        else:
            raise RuntimeError("MCP_TRANSPORT must be demo, streamable_http, or stdio")
