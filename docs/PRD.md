# Raksa — Product Requirements Document

## Product
Raksa is an AI-assisted security engineer that identifies application-code vulnerabilities, reproduces them through security tests, proposes fixes, and verifies results.

**Positioning:** Your AI Security Engineer

**Tagline:** Security fixes. Proven.

**Brand promise:** Investigate → Remediate → Verify → Review, with transparent evidence from checks actually executed and developer approval before PR creation.

## Users
Software developers and engineering teams who want to remediate application vulnerabilities faster and review evidence before merging.

## MVP
- Connect a GitHub App and select a repository.
- Analyze supported source files for potential SQL injection.
- Use NVIDIA Nemotron through Nebius Token Factory for contextual analysis and patch proposals.
- Use an isolated sandbox for repository test execution when configured.
- Show findings, diff, logs, and verification state.
- Create a branch and pull request only after explicit approval.

## Initial demo
A controlled Python/SQLite SQL-injection example demonstrating the same payload against a vulnerable string-built query and a parameterized query.

## Out of scope
- All vulnerability classes at launch.
- Automatic production deployment.
- Automated merging.
- Multi-user production authentication and enterprise tenancy.

## Success criteria
The demo shows a reproducible SQL-injection behavior, a targeted remediation, verification evidence, and safe PR creation without modifying the default branch.
