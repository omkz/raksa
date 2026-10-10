# Raksa — Technical Design

## Stack
- Frontend: React + TypeScript + Vite
- API/orchestrator: Python + FastAPI
- Model: NVIDIA Nemotron through Nebius Token Factory's OpenAI-compatible API
- Research: Tavily Search API
- Repository operations: GitHub App installation tokens + GitHub REST API
- Execution: Nebius Token Factory Sandbox (preferred for the hackathon); optional local Docker runner; deterministic SQLite proof harness for the demo

## Workflow
1. Connect/install the GitHub App and select a repository.
2. Fetch the default-branch SHA and a bounded source snapshot.
3. Detect likely SQL injection and optionally enrich findings with model reasoning/security research.
4. Generate a constrained replacement proposal and validate file path/context.
5. Run bounded checks in an isolated sandbox where configured.
6. Show findings, patch diff, and evidence.
7. After explicit approval, check the base SHA again and create an isolated branch + pull request.

## Components
- GitHub service: app JWT, installation token, repository snapshots, branch/commit/PR creation
- Analyzer: deterministic source heuristic; LLM output is advisory, not trusted
- Nebius service: model reasoning and constrained patch proposal
- Tavily service: cited security guidance
- Sandbox service: isolated execution adapter
- Demo proof harness: deterministic SQLite test that demonstrates SQLi before and after parameterization

## Safety
- Never run an untrusted repository on the API host.
- Apply file-count/size limits and path validation.
- Treat source code and model output as untrusted.
- Do not auto-merge or deploy.
- Fail closed if the default branch advances after analysis.
