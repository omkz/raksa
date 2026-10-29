# Raksa Brand Guidelines

## Brand platform

- **Product name:** Raksa (working name; trademark and domain clearance still pending).
- **Positioning:** Your AI Security Engineer
- **Primary tagline:** Security fixes. Proven.
- **Supporting message:** Investigate potential vulnerabilities. Prepare focused fixes. Review verification evidence.
- **Workflow:** Investigate → Remediate → Verify → Review.
- **Audience:** Developers and engineering teams who want reviewable security fixes with evidence.

## Voice and tone

Write in clear, confident, developer-first English. Be precise, calm, and evidence-led rather than alarmist. Prefer “potential vulnerability” until exploitability is demonstrated. Say “verified against the checks run,” not “guaranteed secure.”

## Visual identity

- Midnight: `#0B1220` — main background.
- Teal: `#2DD4BF` — action, accent, verification emphasis.
- Slate: `#64748B` — secondary copy and metadata.
- Off-white: `#F8FAFC` — primary headings.
- Typography: DM Sans / Manrope for current UI; DM Mono for code and technical labels.

Use a restrained, high-contrast developer-tools aesthetic. Keep code diffs and execution evidence prominent. Avoid generic hacking imagery, fear-based marketing, and unqualified security guarantees.

## Messaging examples

**Hero heading:** Security fixes. Proven.

**Hero description:** Meet Raksa, your AI security engineer. Investigate potential vulnerabilities, generate focused remediation patches, and review verification evidence before opening a pull request.

**Short description:** Open-source, AI-assisted security remediation with transparent verification and developer approval.

**Important limitation:** At this stage, Raksa focuses on potential Python SQL injection. Isolated repository tests require a configured sandbox; demo mode does not execute arbitrary repository code. A successful targeted test is not proof of application-wide security.

## Product versus implementation

Brand Raksa around the developer problem and outcome, not any single model or inference vendor. NVIDIA Nemotron and Nebius Token Factory are accurate technical credits in implementation documentation, not part of the core tagline.

## Approval and safety

Never imply Raksa can auto-merge code or guarantee a fix is secure. Humans review changes and approve draft PR creation. Explain whether checks passed, failed, were skipped, or were not run.

## Commercial-readiness note

The brand positioning describes the long-term product direction. Do not call this prototype enterprise-ready or production-hardened until security controls and deployment validation are complete.
