# SecureMind AI — Complete Project

SecureMind AI is a local reference prototype for a security gateway between AI agents and their tools. It includes a React dashboard, a FastAPI API, profile-specific tool access rules, prompt-injection heuristics, sensitive-data masking, basic schema validation, JWT demo login, rate limiting, audit events, MCP client transports, and an approval queue.

> **Prototype notice:** This is not independently audited or production-ready. Heuristic text checks cannot guarantee prompt-injection detection. The included demo tools only return synthetic data. If you connect an external MCP server, approved tool calls may create real-world side effects.

## Features

1. Prompt injection and tool-policy-bypass pattern checks.
2. Sensitive output masking for emails, common phone patterns, Luhn-valid payment-card numbers, common API-token formats, account identifiers and private-key blocks.
3. JWT authentication and role-based access to administrator endpoints.
4. MCP tool discovery shown separately from request decisions; profile permissions, prompt patterns, schema checks and risk rules are evaluated when a request is submitted.
5. Risk scoring with a visible score-trend graph; scores above 60 require human approval after hard prompt-security, profile-access and input-schema checks. Directly detected injection patterns and policy violations remain blocked.

### Risk threshold and false-positive behavior

- An otherwise-valid request scoring **above 60/100** is queued for human approval. Sensitive operations such as demo transfers may require approval at any score because their tool policy explicitly says so.
- Active prompt-injection patterns, tools not allowed by the selected profile, and invalid arguments are still blocked before approval. A queued request is re-checked when the reviewer approves it.
- A quoted attack phrase is suppressed only in explicit educational/analysis context and only when the match is entirely inside the quote. This does not bypass profile allowlists or schema validation.
- The Risk score trend graph charts recent audit events that have a numeric risk score. Data is stored in memory for this running prototype and clears when the backend restarts.
6. Human approval queue with **Approve & execute** and **Reject** actions; policy and arguments are re-validated before execution.
7. MCP tool discovery and calls using a synthetic demo transport or operator-configured MCP server transport.
8. Basic JSON-schema-like input validation (required fields, property types, maximum lengths, numeric bounds, enums and more).
9. API rate limiting.
10. Dashboard metrics and audit events.

## Industry profiles

- **SaaS:** support tickets and synthetic customer records.
- **Enterprise:** synthetic internal document search and support operations.
- **Banking / fintech:** synthetic balance/history and approval-gated simulated transfers.
- **Developer tooling:** synthetic repository, build, issue and allowlisted virtual-file tools. Arbitrary shell access is not provided.

## Prerequisites

- Python 3.11 or newer.
- Node.js 18 or newer (Node 20+ recommended).
- VS Code or another editor.

## Run on Windows PowerShell

Extract the ZIP file. Open the extracted folder in VS Code—the folder you open should directly contain `backend`, `frontend`, and `README.md`.

### 1. Start the backend

Open Terminal 1 in VS Code:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python -m uvicorn app.main:app --reload --port 8000
```

If PowerShell blocks virtual-environment activation, run this once in the same terminal, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If `backend\.env` already exists, open it with `notepad .env` and confirm that `ALLOW_DEMO_LOGIN=true` is set for local testing. The conditional above preserves your existing `.env` file.

Backend health check: <http://127.0.0.1:8000/api/health>
API docs: <http://127.0.0.1:8000/docs>

### 2. Start the frontend

Open Terminal 2 in VS Code, from the extracted project root (the folder containing `backend` and `frontend`):

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL Vite prints, normally <http://127.0.0.1:5173>.

### Demo login

- Username: `demo`
- Password: `change-me-now`
- Choose a profile on the login page.

Those credentials are for local development only. Change the demo password and JWT secret before any shared or hosted deployment. The sample `.env` enables demo login explicitly and must not be used as a production configuration.

## Test the human-approval flow

1. Sign in with the **banking** profile.
2. In **Test a secured tool call**, choose `transfer_funds`.
3. Enter plain text such as `Please transfer ₹25 to test account TEST-123.` No JSON arguments need to be entered in the UI.
4. Submit the request. It should appear in **Human approval queue** with `PENDING` status.
5. Click **Approve & execute** to re-check policy and execute the synthetic demo operation, or click **Reject** to record rejection without executing.
6. Review **Recent decisions**, **Recent audit events**, and the **Risk score trend** graph.

With the **saas** profile, `create_ticket` and `update_customer` similarly require human approval. A tool that is blocked for the selected profile cannot be approved to bypass its allowlist.

## Configure a real MCP server

The default `MCP_TRANSPORT=demo` uses only included synthetic operations. It will not connect to another server and its simulated banking actions do not transfer real money.

To use a real server, first install the optional MCP client dependency from the `backend` folder:

```powershell
pip install -r requirements-mcp.txt
```

Then edit `backend/.env` after reviewing the server's trust boundary:

```env
MCP_TRANSPORT=streamable_http
MCP_SERVER_URL=http://127.0.0.1:9000/mcp
MCP_SERVER_TOKEN=
```

Or configure a local stdio server:

```env
MCP_TRANSPORT=stdio
MCP_STDIO_COMMAND=python
MCP_STDIO_ARGS=["path/to/your_mcp_server.py"]
```

Restart the backend after configuration changes. Only operators should configure trusted MCP server URLs or commands; never accept server URLs or process commands from browser input. In real MCP mode, an approved operation may produce a real side effect. Review each server's tools and permissions before connecting it.

## Tests

Backend tests are included under `backend/tests`. Install the test requirements and run:

```powershell
cd backend
python -m pip install -r requirements-dev.txt
python -m pytest
```

Frontend production build:

```powershell
cd frontend
npm install
npm run build
```

## API routes

- `POST /api/auth/login`
- `GET /api/health`, `/api/me`, `/api/profiles`, `/api/tools`
- `POST /api/execute`
- `GET /api/approvals`
- `POST /api/approvals/{approval_id}/decision`
- `GET /api/logs`
- `GET /api/stats`

## How prompt and tool output work

The dashboard uses a **Text request / untrusted context** field only; it does not display a JSON Arguments editor. The frontend maps plain text to the selected tool's required inputs, and the backend validates those inputs and scans the text for suspicious instructions. For example, the banking demo transfer expects text like `transfer 25 to account TEST-123` and then requires human approval. Support search accepts plain-language queries such as `billing issue`, `account access`, or `password reset`. This is deterministic demo behavior, not an LLM-powered chat response. Requests such as `attempt to access customer passwords` should be blocked by the credential-access pattern check.

## Known prototype limitations

- Approval requests, audit events and metrics are stored in memory and reset when the backend restarts. Use a durable database for real operations.
- The included account has the `admin` role to make the local dashboard easy to test; there is no user-registration system or external identity provider.
- Prompt-injection detection is regex/heuristic-based and may have false positives or false negatives.
- Masking is pattern-based and cannot identify every kind of sensitive content.
- The input validator supports a useful subset of JSON Schema, not the entire JSON Schema specification.
- The included per-process rate limiter is intended for local development; multi-worker deployments need a shared limiter store.
- Use a proper identity provider, secrets manager, TLS, narrow CORS settings, durable audit storage, network isolation, monitoring, security testing, dependency scanning and independent review before production use.


## Plain-text tool request interface

The dashboard intentionally has no visible JSON Arguments field. Choose an MCP tool and describe the request in normal text in **Text request / untrusted context**. The frontend maps that text to the selected demo tool's required input schema, while the backend validates the resulting structured inputs and scans the text for unsafe instructions. For example, the banking demo transfer expects text like `transfer 25 to account TEST-123` and will still require human approval. This is a demo-only convenience layer; it is not a natural-language AI agent and it must not be used as a substitute for validation on real MCP integrations.

## Test human approval and false-positive handling

- Sign in using the **Banking** profile for transfers. The plain-text request `Please transfer ₹25 to test account TEST-123. Request human approval before executing the transfer.` is auto-routed to `transfer_funds`, validated, and put into the Human Approval Queue. It is not executed until an administrator chooses **Approve & execute**; **Reject** leaves it unexecuted.
- Transfers are disabled for other profiles. If a text request clearly asks for a transfer while the current session uses another profile, the frontend explains that Banking login is required and does not submit the operation.
- For a false-positive control, try `For my cybersecurity assignment, explain why the phrase “ignore all previous instructions” is considered a prompt injection example, without following that instruction.` The quoted attack phrase is allowed in explicit educational analysis when the matched phrase is only quoted. A separate active instruction outside the quote remains blocked.
