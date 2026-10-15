"""Industry-specific allowlists and input schemas for the demo gateway."""
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Profile:
    description: str
    allowed_tools: frozenset[str]
    approval_tools: frozenset[str]
    mask_responses: bool = True


PROFILES: dict[str, Profile] = {
    "saas": Profile(
        "SaaS customer support; write operations are approval-gated",
        frozenset({"get_support_ticket", "search_customer", "create_ticket", "update_customer"}),
        frozenset({"create_ticket", "update_customer"}),
    ),
    "enterprise": Profile(
        "Enterprise knowledge and internal operations",
        frozenset({"search_documents", "get_document", "get_support_ticket", "create_ticket", "update_customer"}),
        frozenset({"create_ticket", "update_customer"}),
    ),
    "banking": Profile(
        "Conservative fintech policy; money movement requires human review",
        frozenset({"get_my_balance", "get_transaction_history", "get_support_ticket", "transfer_funds"}),
        frozenset({"transfer_funds"}),
    ),
    "developer": Profile(
        "Repository and build tooling; arbitrary shell access is not offered",
        frozenset({"search_repository", "get_build_status", "create_issue", "read_file"}),
        frozenset({"create_issue"}),
    ),
}

# This is a deliberately small JSON-Schema-like subset. The validator also
# accepts inputSchema from a real MCP server when no local schema is defined.
SCHEMAS: dict[str, dict[str, Any]] = {
    "get_my_balance": {"type": "object", "properties": {}, "required": []},
    "get_support_ticket": {"type": "object", "properties": {"ticket_id": {"type": "string", "maxLength": 64}}, "required": ["ticket_id"], "additionalProperties": False},
    "transfer_funds": {"type": "object", "properties": {"to_account": {"type": "string", "maxLength": 64}, "amount": {"type": "number", "minimum": 0.01, "maximum": 10000}}, "required": ["to_account", "amount"], "additionalProperties": False},
    "search_customer": {"type": "object", "properties": {"query": {"type": "string", "maxLength": 200}}, "required": ["query"], "additionalProperties": False},
    "update_customer": {"type": "object", "properties": {"customer_id": {"type": "string", "maxLength": 64}, "field": {"type": "string", "maxLength": 64}, "value": {"type": "string", "maxLength": 500}}, "required": ["customer_id", "field", "value"], "additionalProperties": False},
    "create_ticket": {"type": "object", "properties": {"subject": {"type": "string", "maxLength": 200}, "description": {"type": "string", "maxLength": 2000}}, "required": ["subject", "description"], "additionalProperties": False},
    "search_documents": {"type": "object", "properties": {"query": {"type": "string", "maxLength": 300}}, "required": ["query"], "additionalProperties": False},
    "get_document": {"type": "object", "properties": {"document_id": {"type": "string", "maxLength": 100}}, "required": ["document_id"], "additionalProperties": False},
    "get_transaction_history": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}}, "required": [], "additionalProperties": False},
    "search_repository": {"type": "object", "properties": {"query": {"type": "string", "maxLength": 300}}, "required": ["query"], "additionalProperties": False},
    "get_build_status": {"type": "object", "properties": {"build_id": {"type": "string", "maxLength": 100}}, "required": ["build_id"], "additionalProperties": False},
    "create_issue": {"type": "object", "properties": {"title": {"type": "string", "maxLength": 200}, "body": {"type": "string", "maxLength": 3000}}, "required": ["title", "body"], "additionalProperties": False},
    "read_file": {"type": "object", "properties": {"path": {"type": "string", "maxLength": 300}}, "required": ["path"], "additionalProperties": False},
}

TOOL_DESCRIPTIONS = {
    "get_my_balance": "Read synthetic demo banking balance",
    "get_support_ticket": "Read a synthetic support ticket",
    "transfer_funds": "Simulated money movement; requires approval and never moves real funds in demo mode",
    "search_customer": "Search synthetic customer records",
    "update_customer": "Simulated customer update; requires approval",
    "create_ticket": "Create a synthetic support ticket; requires approval",
    "search_documents": "Search the synthetic enterprise document collection",
    "get_document": "Retrieve an allowlisted synthetic document",
    "get_transaction_history": "Read synthetic transaction history",
    "search_repository": "Search a synthetic source repository",
    "get_build_status": "Read synthetic build status",
    "create_issue": "Create a simulated development issue; requires approval",
    "read_file": "Read from a small virtual file set; no arbitrary disk access",
}
