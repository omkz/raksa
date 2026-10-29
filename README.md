# Raksa

**Your AI Security Engineer**

### Security fixes. Proven.

Raksa is an open-source, AI-assisted application security engineer for developers and engineering teams. It investigates potential vulnerabilities, proposes focused fixes, and surfaces verification evidence before a developer approves a GitHub pull request.

**Investigate → Remediate → Verify → Review.** Raksa focuses on actionable fixes backed by the checks that actually ran—not more alert noise.

> **Current scope:** Python SQL injection (CWE-89) detection and remediation. Findings are potential issues until tested. Verified results are specific to the executed checks, not a guarantee that the repository is fully secure. Human review remains required.

[Explore the demo repository](https://github.com/omkz/raksa-vulnerable-demo/pulls) · [Get started locally](#run-locally)

## Why Raksa?

- **From findings to fixes:** Instead of stopping at an alert, Raksa prepares narrowly scoped, reviewable code changes.
- **Evidence over assertions:** Static rechecks and optional isolated exploit/regression checks distinguish a proposed fix from a tested one.
- **Developers stay in control:** Repository permissions are GitHub App-scoped. Patch approval is explicit, and Raksa never merges or pushes to the default branch.
- **Open and inspectable:** Review the generated diff, check results, and open-source implementation.



## How Raksa works

1. **Connect a repository.** Raksa uses a GitHub App to access repositories within an installation and takes a bounded snapshot of the selected source.
2. **Find a potential issue.** The current analysis focuses on possible SQL injection in Python code. Findings are leads to investigate, not proof of exploitability.
3. **Prepare a fix.** NVIDIA Nemotron, accessed through Nebius Token Factory, summarizes findings and proposes a focused patch.
4. **Validate the patch.** Raksa checks the patch structure, file path, and exact source context before accepting a change. Invalid or unrelated replacements are rejected.
5. **Verify the result.** Raksa performs a static recheck and can run security and regression checks through a configured sandbox. Checks that did not run are reported as such.
6. **Review before creating a PR.** A developer reviews the proposed diff and evidence, then explicitly approves creation of a Draft GitHub pull request. Raksa checks that the default branch has not changed since the analyzed snapshot.

Raksa does not push directly to the default branch.

## Capabilities

- GitHub App installation flow and repository selection
- Bounded repository snapshots for analysis
- Heuristic detection of potential Python SQL injection
- Nemotron-assisted finding summaries and remediation proposals
- Exact-context patch validation
- Static rechecks and sandbox-based verification
- Optional Tavily research for SQL injection prevention guidance
- Reviewable Draft pull requests after explicit approval

## Verification and sandbox configuration

Raksa distinguishes between a proposed fix and a verified result. A green check is evidence from the checks that ran; it is not a guarantee that the whole application is secure.

The default `SANDBOX_PROVIDER=demo` setting does **not** execute tests from an arbitrary repository. It keeps repository-test execution disabled and reports that status explicitly. To enable isolated repository test execution, configure one of these providers:

- **Docker:** runs tests in a resource-limited container with networking disabled. Docker must be installed on the API host.
- **Nebius Sandbox:** uses the Nebius Token Factory Sandbox API. Your project may need separate access or permissions.

Raksa also includes a deterministic SQLite SQL injection demonstration that does not require external credentials. It illustrates how a string-built query can return unintended rows and how parameterized SQL blocks the same payload. This controlled demonstration is separate from scanning and executing arbitrary repository code.

## Technology

- **Python, FastAPI** — backend and workflow orchestration
- **React, TypeScript, Vite** — web dashboard
- **Nebius Token Factory + NVIDIA Nemotron** — AI-assisted analysis and remediation
- **GitHub App** — scoped repository access and pull-request workflow
- **Tavily** — optional security research
- **Docker / Nebius Sandbox** — configurable isolated test execution

## Run locally

Requirements: Python 3.11+, [uv](https://docs.astral.sh/uv/) (v0.3+), Node.js 20+, and [pnpm](https://pnpm.io/) (v9+).

### 1. Configure environment variables

From the repository root:

```bash
cp .env.example .env
```

Edit `.env` and add the credentials for the integrations you intend to use.

### 2. Start the API

```bash
uv run --directory apps/api uvicorn app.main:app --reload --port 8000
```

The API health endpoint is available at <http://localhost:8000/api/health>, with interactive API documentation at <http://localhost:8000/docs>.

### 3. Start the web dashboard

In a separate terminal:

```bash
pnpm --dir apps/web dev
```

Open <http://localhost:5173>. The Vite development server proxies `/api` requests to the API.

### Alternative: Docker Compose

```bash
docker compose up --build
```

## Run the SQL injection demonstration

Start the application and click **Run SQLi demo**. The proof harness uses a controlled SQLite fixture to compare a vulnerable string-built query with a parameterized query. It runs locally and does not require GitHub, Nebius, or Tavily credentials.

## Configure Nebius and optional research

Add the following to the root `.env` file to enable model calls:

```dotenv
NEBIUS_API_KEY=...
NEBIUS_MODEL=nvidia/Nemotron-3_5-Lightning
```

The model ID must be available to your Token Factory account. Raksa uses the OpenAI-compatible Token Factory API; inference usage may incur charges according to your account and model pricing.

To enable Tavily research, configure:

```dotenv
TAVILY_API_KEY=...
```

When a finding is available and Tavily is configured, Raksa can retrieve SQL injection prevention guidance from established security references.

For Nebius Sandbox, configure:

```dotenv
SANDBOX_PROVIDER=nebius
NEBIUS_SANDBOX_BASE_URL=https://api.tokenfactory.nebius.com/sandboxes
NEBIUS_PROJECT=your-token-factory-project-id
```

For local Docker-based test execution, set `SANDBOX_PROVIDER=docker`. The available providers are `demo`, `docker`, and `nebius`. If sandbox access is unavailable or misconfigured, Raksa reports an error rather than claiming that tests passed.

## Connect GitHub & OAuth

Raksa uses your GitHub App for both human OAuth authentication and fine-grained repository scanning:

- **OAuth User Authorization Callback URL:** `http://localhost:8000/api/auth/callback`
- **Setup URL (GitHub App Installation):** `http://localhost:8000/api/github/callback`
- **Webhook URL:** `http://localhost:8000/api/github/webhook` (subscribe to `Pull request` events)
- **Repository permissions:**
  - `Repository contents`: Read-only (or Read/Write if creating draft PRs)
  - `Pull requests`: Read/Write
  - `Checks`: Read/Write (for automated PR reviews)

Configure these variables in `.env`:

```dotenv
# GitHub App & OAuth (from GitHub App settings under General)
GITHUB_APP_ID=...
GITHUB_APP_SLUG=your-app-slug
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GITHUB_PRIVATE_KEY_PATH=/absolute/path/to/your-app.private-key.pem
GITHUB_WEBHOOK_SECRET=...
GITHUB_API_BASE_URL=https://api.github.com
FRONTEND_URL=http://localhost:5173
```

Sign in with **Continue with GitHub** on the dashboard. Then click **Connect GitHub** to link repositories via the GitHub App. Raksa uses short-lived installation tokens for repository operations and never stores user personal access tokens.

### Pull-request safeguards

- Creating a Draft PR requires an explicit approval action.
- Raksa does not push directly to the default branch.
- Before PR creation, Raksa checks that the default branch still points to the revision analyzed by the scan; a stale snapshot fails closed.
- Review the patch and checks before merging.

## Development checks

### Backend

```bash
uv run --directory apps/api pytest
uv run --directory apps/api ruff check .
```

### Frontend

```bash
pnpm --dir apps/web build
```

## Security and deployment considerations

Repository source is sent to Nebius for model analysis when model features are enabled. If a sandbox provider is configured, the repository snapshot is also sent to that provider for isolated test execution. Only connect repositories you are authorized to process.

Before operating Raksa as a shared or public service, review deployment-appropriate authentication and authorization, rate limiting, audit logging, secret management, retention policies, and resource limits. PostgreSQL-backed job storage, GitHub OAuth sessions, and audit events exist in the codebase, but a production deployment still requires security review and hardening. Review the security properties of the entire deployment, especially sandbox isolation and access to GitHub credentials. Keep `.env` files and GitHub App private keys out of version control.

## Brand

Raksa uses **Your AI Security Engineer** as its product positioning and **Security fixes. Proven.** as its primary tagline. The proof claim always refers to the scope of checks actually executed. See [Brand Guidelines](docs/BRAND.md).

## License

See [LICENSE](LICENSE).
