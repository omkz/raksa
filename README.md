# Raksa

**Autonomous Application Security Engineer** — Find it. Prove it. Fix it. Verify it.

Raksa is an early MVP starter for analyzing application-code vulnerabilities, preparing a targeted remediation, collecting verification evidence, and opening a reviewable GitHub pull request after explicit approval.

## What's included

- React + TypeScript dashboard (Vite)
- Python + FastAPI backend
- GitHub App installation flow, installation-scoped repository listing, repository snapshots, and PR creation
- Nebius Token Factory client using the OpenAI-compatible API and a configurable NVIDIA Nemotron model
- Tavily security-research adapter
- SQL-injection heuristic for Python source
- Proof-of-concept SQL injection demo with deterministic before/after verification
- Optional Nebius Token Factory Sandbox adapter and local Docker sandbox adapter
- Unit tests and short project docs

> This is a starting codebase, not a production-ready security product. The general-repository workflow is intentionally conservative: static findings are potential findings, model-generated patches are untrusted, and a PR is only created after the user clicks the approval action. The included local demo proves the SQL-injection principle with a controlled SQLite fixture; it does not claim to validate arbitrary repositories.

## Quick start

Requirements: Python 3.11+, [uv](https://docs.astral.sh/uv/) (v0.3+), Node.js 20+, and [pnpm](https://pnpm.io/) (v9+).

### 1. Environment Setup

```bash
cp .env.example .env
# Edit .env as needed.
```

### 2. Running the Application

You can run Raksa either locally (recommended for development with fast hot-reloading) or via Docker Compose.

#### Option A: Local Development (Recommended)

In Terminal 1 (Backend API):

```bash
uv run --directory apps/api uvicorn app.main:app --reload --port 8000
```

In Terminal 2 (Frontend UI):

```bash
pnpm --dir apps/web dev
```

Open <http://localhost:5173>. The frontend development server proxies all `/api` requests to FastAPI at `http://localhost:8000`. You can explore the interactive API documentation at <http://localhost:8000/docs>.

#### Option B: Docker Compose

To start both the API and Web services in containers:

```bash
docker compose up --build
```

## Run the demo without credentials

Click **Run SQLi demo**. This runs a deterministic SQLite proof harness to show that a vulnerable string-built query can return unintended rows, while a parameterized query blocks the same payload. It does not execute arbitrary repository code and does not require API keys.

## Configure Nebius and Tavily

Set these in the root `.env` file:

```dotenv
NEBIUS_API_KEY=...
NEBIUS_MODEL=nvidia/Nemotron-3_5-Lightning
TAVILY_API_KEY=...
```

The model ID can vary by account/catalog; use a model available to your Token Factory key. The Nebius Token Factory API is OpenAI-compatible. Calls can incur charges according to your account and model pricing.

For the Nebius Sandbox adapter, set:

```dotenv
SANDBOX_PROVIDER=nebius
NEBIUS_SANDBOX_BASE_URL=https://api.tokenfactory.nebius.com/sandboxes
NEBIUS_PROJECT=your-token-factory-project-id
```

Token Factory Sandboxes access/permissions may require separate enablement for your project. The Sandboxes API is in beta and its payloads may evolve. If your key does not have permission, Raksa returns a visible configuration error rather than claiming the code was verified. For local experimentation, `SANDBOX_PROVIDER=docker` requires Docker installed on the API host; do not expose the Docker socket to untrusted tenants in a deployed service.

## GitHub App setup

Create a GitHub App and configure:

- **Homepage URL:** your Raksa UI URL
- **Setup URL:** `http://localhost:8000/api/github/callback` (local development)
- **Webhook:** not required for this MVP
- **Repository permissions:** Metadata (read), Contents (read/write), Pull requests (read/write)
- **Where can this GitHub App be installed?** Any account, or your own account for testing

Set in `.env`:

```dotenv
GITHUB_APP_ID=...
GITHUB_APP_SLUG=your-app-slug
GITHUB_PRIVATE_KEY_PATH=/absolute/path/to/your-app.private-key.pem
GITHUB_API_BASE_URL=https://api.github.com
FRONTEND_URL=http://localhost:5173
```

Install the GitHub App on a test repository. In Raksa, click **Connect GitHub**, then choose a repository. The backend uses short-lived installation tokens. It does not need a personal access token.

### Pull request safety

- Raksa never pushes directly to the default branch.
- PR creation requires an explicit click.
- Raksa checks that the repository default branch still points to the SHA analyzed by the scan; stale scans fail closed.
- Review every patch and test result before merging. A green test result is not a guarantee that a patch is secure.

## Configuration

See `.env.example` for all settings. The backend exposes `/api/health` and OpenAPI docs at `/docs`.

## Tests and Quality Checks

### Backend (Python)

Run unit and integration tests:

```bash
uv run --directory apps/api pytest
```

Run code formatting and lint checks:

```bash
uv run --directory apps/api ruff check .
```

### Frontend (TypeScript / React)

Run TypeScript type check and Vite production build:

```bash
pnpm --dir apps/web build
```

## Included documents

- `docs/PRD.md`
- `docs/TECHNICAL_DESIGN.md`
- `docs/MVP_BACKLOG.md`
- `AGENTS.md`

## Important security notes

- Connecting a repository sends the bounded source snapshot to Nebius for model analysis; when a sandbox provider is enabled, the snapshot is also uploaded for isolated test execution. Connect only repositories you are authorized to process.
- Keep `.env` and GitHub App private keys out of version control.
- Use a dedicated test repository and minimal GitHub App permissions while developing.
- Never run an untrusted repository directly on the API host. Use an isolated sandbox with resource/time limits.
- Model-generated findings and patches are untrusted input. The backend restricts file paths and checks exact replacement context before accepting a proposed edit.
- Do not deploy this starter publicly without adding production authentication, rate limiting, persistent job storage, stronger audit logging, and a security review.
