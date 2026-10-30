# Raksa

**Your AI Security Engineer**

### Security fixes. Proven.

Raksa is an open-source, autonomous application-security engineer for software teams. Instead of drowning developers in alerts, Raksa investigates potential vulnerabilities, proposes focused, exact-context code remediations using AI reasoning, strictly validates proposed patches, and surfaces transparent verification evidence before an engineer approves a review-only Draft Pull Request.

**Investigate → Remediate → Verify → Review.** Raksa focuses on actionable fixes backed by concrete evidence—not alert noise.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Demonstration Draft PR](https://img.shields.io/badge/GitHub%20App-Draft%20PR%20%235-blue?logo=github)](https://github.com/omkz/raksa-vulnerable-demo/pull/5)

---

## Architecture & Workflow

Raksa operates as an end-to-end security remediation pipeline with strict safety gates at every step:

```
┌─────────────────┐       ┌──────────────────────┐       ┌────────────────────────┐
│   GitHub App    │ ───►  │  Repository Scan     │ ───►  │ Vulnerability Findings │
│ (Scoped Access) │       │ (Bounded Snapshot)   │       │ (Static AST / OpenGrep)│
└─────────────────┘       └──────────────────────┘       └────────────────────────┘
                                                                     │
                                                                     ▼
┌─────────────────┐       ┌──────────────────────┐       ┌────────────────────────┐
│ Developer Review│ ◄───  │ Verification Gates   │ ◄───  │ Nemotron Patch Proposal│
│ (Draft PR Only) │       │ (Static & Sandbox)   │       │ (Exact-Context Diff)   │
└─────────────────┘       └──────────────────────┘       └────────────────────────┘
```

1. **GitHub App Connection & Bounded Snapshot**
   - Connects to repositories with fine-grained, short-lived GitHub App installation tokens.
   - Takes bounded repository snapshots governed by strict limits (max file count, max file size, max repository byte budget) to prevent resource exhaustion and denial-of-service.
2. **Finding Investigation**
   - Combines AST-based Python heuristics (e.g. string formatting in SQL queries) with optional containerized OpenGrep pattern rules (command injection, dynamic eval, DOM XSS, path traversal).
   - Findings represent potential leads to investigate, clearly distinguished from verified exploits.
3. **Nemotron Patch Proposals**
   - Uses **NVIDIA Nemotron 3 Super 120B-A12B** (`nvidia/nemotron-3-super-120b-a12b`) hosted on **Nebius Token Factory** (`https://api.tokenfactory.nebius.com/v1`).
   - Generates minimal, exact-context replacement patches targeting the root cause without touching unrelated code.
4. **Safety Checks & AST Contract Guard**
   - Rejects path traversal, absolute paths, symlinks, and files outside the repository.
   - Enforces single-replacement boundaries and syntactic validity (e.g. AST parsing). Patches that fail structural validation or alter unrelated regions are rejected immediately.
5. **Verification Pipeline & Proof Engine**
   - Runs static rechecks against patched code to verify the sink pattern is eliminated.
   - Can execute isolated differential dynamic tests (confirming exploit payload failure and characterization test preservation) when an isolated sandbox is enabled.
   - Distinctly tracks verification outcomes (`verification.status`) separately from PR publication eligibility (`verification.eligible_for_pr`).
6. **Developer Review & Safe Draft PR Creation**
   - Developers inspect the exact unified diff, technical diagnostics, and verification logs in the dashboard.
   - Draft Pull Requests are created **only after explicit human approval**.
   - Includes a fail-closed stale-base check that confirms the target branch has not moved since the analyzed commit.
   - **Never pushes directly to the default branch and never automatically merges pull requests.**

---

## Live Demonstration & Real PR Proof

Raksa was evaluated against a realistic multi-language, multi-vulnerability benchmark repository ([omkz/raksa-vulnerable-demo](https://github.com/omkz/raksa-vulnerable-demo)).

### Scan Results & Model Behavior

The scan identified **5 potential findings** across Python and JavaScript codebases, demonstrating both focused remediation and responsible AI restraint:

| Finding | Vulnerability | File | Action / Status | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **1** | SQL Injection (CWE-89) | `app/db.py` | `Patch Proposed` (`UNVERIFIED`) | Nemotron parameterized raw query formatting; validated & proposed. |
| **2** | DOM XSS (CWE-79) | `client/render.js` | `Patch Proposed` (`UNVERIFIED`) | Nemotron replaced unsafe `innerHTML` with safe `textContent` sink. |
| **3** | Path Traversal (CWE-22) | `app/storage.py` | `Needs Context` | Model abstained; requires human architectural policy for allowed root directory. |
| **4** | Command Injection (CWE-78) | `app/tasks.py` | `Needs Review` | Model abstained; requires system allowlist or safe subprocess wrapper. |
| **5** | Code Injection / Eval (CWE-94) | `client/calc.js` | `Needs Review` | Model abstained; dynamic expression evaluation requires architecture redesign. |

### Real Draft Pull Request

The proposed remediations were reviewed and published via Raksa's GitHub App as a review-only Draft PR:
👉 **[View Draft PR #5 on omkz/raksa-vulnerable-demo](https://github.com/omkz/raksa-vulnerable-demo/pull/5)**

The Draft PR contains:
- Transparent disclosure of the AI model and inference provider (NVIDIA Nemotron 3 Super 120B-A12B via Nebius Token Factory).
- Explicit `UNVERIFIED` status disclosure noting that live repository tests were not executed and developer testing is required.
- Individual remediation summaries and reproducible instructions.

> [!IMPORTANT]
> **Controlled Demonstration vs. Vulnerable Benchmark Repository:**
> - Raksa includes an **in-memory SQLite proof harness** ("Run SQLi demo" on the dashboard or `/api/scans/demo/run`) that safely demonstrates differential exploit blocking and parameterized query verification without external credentials or executing untrusted code.
> - The demo repository (`omkz/raksa-vulnerable-demo`) is an intentionally vulnerable benchmark fixture for static scanning only. **Never execute or deploy `raksa-vulnerable-demo` on a production or unsandboxed host.**

---

## Status Definitions

Raksa maintains absolute honesty regarding what has been statically checked, what has been proposed, and what has been dynamically verified:

- **`Patch Proposed`**: Nemotron generated an exact-context replacement that passed syntax, AST, and structural boundary guards.
- **`UNVERIFIED`**: A patch proposal is available, but isolated sandbox execution was not performed (or the sandbox was in demo/disabled mode). The patch is flagged prominently in both the UI and the generated Draft PR as unverified, requiring developer testing prior to merging.
- **`Verified`**: The patch passed dynamic differential verification inside an isolated sandbox (exploit test confirmed blocked + characterization/regression test passed + static recheck clean).
- **`Needs Context` / `Needs Review`**: Raksa flagged a potential issue, but safely abstained from guessing a fix because remediation requires developer policy (such as permitted base directories or command whitelists). Raksa prevents hallucinations by refusing to emit ungrounded patches.

---

## Technology Stack

- **Backend:** Python 3.11+, [FastAPI](https://fastapi.tiangolo.com/), [Pydantic v2](https://docs.pydantic.dev/), [SQLAlchemy](https://www.sqlalchemy.org/) + [asyncpg](https://github.com/MagicStack/asyncpg), PostgreSQL, [uv](https://docs.astral.sh/uv/)
- **Frontend:** React 19, TypeScript (strict mode), [Vite](https://vitejs.dev/)
- **Model & Inference:** **NVIDIA Nemotron 3 Super 120B-A12B** (`nvidia/nemotron-3-super-120b-a12b`) hosted on **Nebius Token Factory** (`https://api.tokenfactory.nebius.com/v1`)
- **Static Analysis:** Containerized [OpenGrep](https://github.com/opengrep/opengrep) rules + AST heuristic scanners
- **Sandbox Providers:** Configurable isolated execution:
  - `demo`: In-memory controlled demonstration (safe, default)
  - `docker`: Local Docker daemon container with networking disabled and resource limits
  - `nebius`: Remote Nebius Token Factory Sandbox API
- **External Guidance:** Optional [Tavily](https://tavily.com/) security research for authoritative remediation references

---

## Quickstart & Local Setup

### Prerequisites

- **Python:** 3.11 or newer with [uv](https://docs.astral.sh/uv/) (v0.3+)
- **Node.js:** 20 or newer with [pnpm](https://pnpm.io/) (v9+)
- **PostgreSQL:** (optional for full job queue; in-memory SQLite demo available)
- **Docker:** (optional, for Docker sandbox provider or containerized OpenGrep)

### 1. Clone & Configure Environment

```bash
git clone https://github.com/omkz/raksa.git
cd raksa
cp .env.example .env
```

Edit `.env` to configure your credentials:

```dotenv
# App Settings
APP_ENV=development
SESSION_SECRET=replace-with-a-long-random-secret-at-least-32-chars
FRONTEND_URL=http://localhost:5173
CORS_ORIGINS=http://localhost:5173

# Nebius Token Factory (NVIDIA Nemotron 3 Super 120B-A12B)
NEBIUS_API_KEY=your-nebius-token-factory-key
NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1
NEBIUS_MODEL=nvidia/nemotron-3-super-120b-a12b

# GitHub App Configuration (for OAuth & repository access)
GITHUB_APP_ID=your-github-app-id
GITHUB_APP_SLUG=your-app-slug
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
GITHUB_PRIVATE_KEY_PATH=/absolute/path/to/your-app.private-key.pem
GITHUB_WEBHOOK_SECRET=your-webhook-secret

# Sandbox Provider (demo | docker | nebius)
SANDBOX_PROVIDER=demo
```

### 2. Start the Backend API

```bash
uv run --directory apps/api uvicorn app.main:app --reload --port 8000
```

- API health endpoint: <http://localhost:8000/api/health>
- Interactive OpenAPI docs: <http://localhost:8000/docs>

### 3. Start the Web Dashboard

In a separate terminal:

```bash
pnpm --dir apps/web dev
```

Open <http://localhost:5173> in your browser. The Vite dev server proxies `/api` calls directly to the FastAPI backend.

### 4. (Optional) Run the Asynchronous Worker

To process background queue jobs asynchronously with PostgreSQL:

```bash
uv run --directory apps/api python -m app.worker
```

### Alternative: Docker Compose

```bash
docker compose up --build
```

---

## Development Checks & Testing

Run the full automated test and linting suite:

### Frontend Verification

```bash
# Run unit tests (patch association & fallback ambiguity checks)
pnpm --dir apps/web test

# Run TypeScript type check and production build
pnpm --dir apps/web build
```

### Backend Verification

```bash
# Run test suite (184 unit & integration tests)
uv run --directory apps/api pytest -q --disable-warnings

# Run Ruff linter and code formatting validation
uv run --directory apps/api ruff check .
```

---

## Security Safeguards & Limitations

Raksa is built with strict defensive security principles:

1. **Untrusted Code Isolation:**
   Repository files, model outputs, and external search results are treated as untrusted data. Repository code is never executed directly on the host machine.
2. **Path & Context Integrity:**
   All patch paths and file operations reject path traversal (`../`), symlinks, and absolute paths. Patches must match the target file's exact existing line context.
3. **No Automatic Merge or Default Branch Pushes:**
   Raksa never pushes to the default branch (`main` or `master`) and never automatically merges any pull request.
4. **Stale-Base Detection:**
   Before creating a Draft PR, Raksa verifies that the default branch HEAD commit matches the analyzed snapshot commit. If the branch has diverged, the operation fails closed.
5. **Human-in-the-Loop Requirement:**
   AI-generated remediation proposals are aids for engineering teams, not autonomous substitutes for security engineers. All patches—especially those flagged as `UNVERIFIED`—must be reviewed, tested, and approved by human developers before deployment.

---

## Brand

Raksa uses **Your AI Security Engineer** as its product positioning and **Security fixes. Proven.** as its primary tagline. See [Brand Guidelines](docs/BRAND.md).

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
