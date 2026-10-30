import { type ReactNode, useCallback, useEffect, useMemo, useState } from 'react';
import { associateFindingsAndPatches } from './patchAssociation.ts';

type Repo = {
  full_name: string;
  private: boolean;
  default_branch: string;
  html_url: string;
  description?: string | null;
};

type Finding = {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe?: string | null;
  path: string;
  line: number;
  evidence: string;
  description: string;
  confidence: number;
  status?: string;
  scanner?: string;
  rule_id?: string | null;
};

type Patch = { path: string; old_text: string; new_text: string; reason: string; scanner?: string; cwe?: string; finding_id?: string };
type FindingOutcome = { status: string; message: string };

type Scan = {
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  stage: string;
  message: string;
  full_name?: string | null;
  default_branch?: string | null;
  base_sha?: string | null;
  findings?: Finding[];
  patches?: Patch[];
  diff?: string | null;
  summary?: string | null;
  research?: { title: string; url: string; content: string }[];
  verification?: Record<string, any> & { finding_outcomes?: Record<string, FindingOutcome> };
  pull_request_url?: string | null;
  error?: string | null;
  patch_messages?: string[];
};

type ContextPreview = {
  decision: 'patch' | 'needs_context' | 'abstain' | 'rejected';
  finding_id: string;
  path: string;
  authorized_root: string;
  base_sha: string;
  patch: Patch | null;
  diff: string;
  diagnostics: string[];
  verification: { status: 'unverified'; eligible_for_pr: false; message: string };
};
type Health = { status: string; integrations: Record<string, boolean> };
type GithubStatus = { configured: boolean; connected: boolean; app_slug?: string | null };

type AuthUser = {
  id: string;
  github_user_id: number;
  login: string;
  name?: string | null;
  avatar_url?: string | null;
  email?: string | null;
};

type AuthWorkspace = {
  id: string;
  name: string;
  role: string;
  installation_id?: string | null;
};

type AuthResponse = {
  authenticated: boolean;
  user: AuthUser;
  workspace: AuthWorkspace;
};

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, {
    credentials: 'include',
    ...init,
    headers,
  });
  if (!response.ok) {
    const message = await response.text();
    let human = message;
    try {
      const body = JSON.parse(message) as { detail?: string };
      human = body.detail || message;
    } catch { /* keep raw message */ }
    throw new Error(human || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

type ProposalNote = {
  id: string;
  finding?: Finding;
  outcome?: FindingOutcome;
  patch?: Patch;
  messages: string[];
  policyRequested: boolean;
};

function outcomePresentation(status?: string): { label: string; tone: string } {
  const statuses: Record<string, { label: string; tone: string }> = {
    patch_proposed: { label: 'Patch Proposed', tone: 'proposed' },
    rejected: { label: 'Rejected', tone: 'rejected' },
    needs_context: { label: 'Needs Context', tone: 'context' },
    needs_review: { label: 'Needs Review', tone: 'review' },
    blocked: { label: 'Blocked', tone: 'blocked' },
    not_attempted: { label: 'Not Attempted', tone: 'neutral' },
    verified: { label: 'Verified', tone: 'verified' },
  };
  return status && Object.hasOwn(statuses, status) ? statuses[status] : {
    label: status ? `Unknown Status (${status})` : 'Diagnostics Only', tone: 'neutral',
  };
}

function verificationCheckPresentation(check: { status?: string; passed?: boolean }): { label: string; tone: string } {
  const status = check.status;
  if (status === 'passed') return check.passed === true
    ? { label: '✓ PASSED', tone: 'good-text' }
    : { label: '— PASSED STATUS · PASS FLAG NOT CONFIRMED', tone: '' };
  if (status === 'failed' || status === 'error') return { label: `✕ ${status.toUpperCase()}`, tone: 'bad-text' };
  // A false passed flag also accompanies not_run, skipped, and unavailable.
  // Display the actual check state instead of labeling every false flag FAILED.
  if (status) return { label: `— ${status.replaceAll('_', ' ').toUpperCase()}`, tone: '' };
  return check.passed === true ? { label: '✓ PASSED', tone: 'good-text' } : { label: '— NOT REPORTED', tone: '' };
}

function verificationStatusPresentation(status: string, scanStatus?: string): { label: string; tone: string } {
  if (scanStatus === 'failed') {
    return { label: 'FAILED', tone: 'bad' };
  }
  switch (status) {
    case 'verified':
      return { label: 'VERIFIED', tone: 'good' };
    case 'failed':
      return { label: 'FAILED', tone: 'bad' };
    case 'error':
      return { label: 'ERROR', tone: 'bad' };
    case 'unverified':
      return { label: 'UNVERIFIED', tone: 'pending' };
    case 'not_run':
    case 'not-run':
      return { label: 'NOT RUN', tone: 'pending' };
    default:
      return { label: status.replaceAll('_', ' ').toUpperCase(), tone: 'pending' };
  }
}

function buildProposalNotes(scan: Scan): ProposalNote[] {
  const findings = scan.findings || [];
  const patches = scan.patches || [];
  const outcomes = scan.verification?.finding_outcomes || {};
  const association = associateFindingsAndPatches(findings, patches);
  const notes = findings.map((finding): ProposalNote => ({
    id: finding.id,
    finding,
    outcome: outcomes[finding.id],
    patch: association.findingToPatch.get(finding.id),
    messages: [],
    policyRequested: false,
  }));
  const unassigned: ProposalNote[] = [];
  for (const [index, message] of (scan.patch_messages || []).entries()) {
    // Legacy diagnostics contain paths, not finding IDs. Never guess between
    // multiple findings in one file; preserve ambiguous messages separately.
    const matches = notes.filter(({ finding }) => finding && (
      message.startsWith(`${finding.path}:`) || message.startsWith(`Patch rejected by context validation for ${finding.path}:`)
    ));
    if (matches.length === 1) matches[0].messages.push(message);
    else unassigned.push({ id: `diagnostic-${index}`, messages: [message], policyRequested: false });
  }
  for (const note of notes) {
    // The current API uses needs_review for both abstention and context requests.
    // This legacy marker only enables the optional preview; it never overrides
    // the structured remediation status or any PR/verification eligibility.
    note.policyRequested = note.outcome?.status === 'needs_context' || (
      note.outcome?.status === 'needs_review'
      && note.messages.some((message) => message.startsWith(`${note.finding?.path}: AI needs context:`))
    );
  }
  return [...notes, ...unassigned];
}

function Icon({ children }: { children: ReactNode }) {
  return <span className="icon" aria-hidden="true">{children}</span>;
}

export default function App() {
  const [auth, setAuth] = useState<AuthResponse | null>(null);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [authError, setAuthError] = useState('');
  const [health, setHealth] = useState<Health | null>(null);
  const [github, setGithub] = useState<GithubStatus | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState<'connect' | 'repos' | 'scan' | 'demo' | 'pr' | 'context' | null>(null);
  const [authorizedRoots, setAuthorizedRoots] = useState<Record<string, string>>({});
  const [contextPreview, setContextPreview] = useState<ContextPreview | null>(null);
  const [error, setError] = useState('');
  const [prUrl, setPrUrl] = useState('');

  const loadGithub = useCallback(async () => {
    try {
      const value = await api<GithubStatus>('/api/github/status');
      setGithub(value);
      if (value.connected) {
        const list = await api<Repo[]>('/api/github/repositories');
        setRepos(list);
        setSelectedRepo((current) => current || list[0]?.full_name || '');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load GitHub status.');
    }
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const authErr = params.get('auth_error');
    if (authErr) {
      setAuthError(authErr === 'state_mismatch' ? 'Security check failed (OAuth state mismatch). Please try signing in again.' : authErr);
      window.history.replaceState({}, '', window.location.pathname);
    } else if (params.get('auth') === 'success' || params.get('github') === 'connected') {
      window.history.replaceState({}, '', window.location.pathname);
    }

    api<AuthResponse>('/api/auth/me')
      .then((data) => {
        setAuth(data);
        setCheckingAuth(false);
        void Promise.all([
          api<Health>('/api/health').then(setHealth).catch(() => undefined),
          loadGithub(),
        ]);
      })
      .catch(() => {
        setAuth(null);
        setCheckingAuth(false);
      });
  }, [loadGithub]);

  const signOut = async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } catch {
      /* ignore network errors on logout */
    }
    setAuth(null);
    setGithub(null);
    setRepos([]);
    setSelectedRepo('');
    setScan(null);
    setContextPreview(null);
  };

  const connectGithub = async () => {
    setError('');
    setLoading('connect');
    try {
      const result = await api<{ url: string }>('/api/github/install-url');
      window.location.href = result.url;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start GitHub installation.');
      setLoading(null);
    }
  };

  const disconnectGithub = async () => {
    try {
      await api('/api/github/disconnect', { method: 'POST' });
      setGithub((value) => (value ? { ...value, connected: false } : value));
      setRepos([]);
      setSelectedRepo('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not disconnect GitHub.');
    }
  };

  const runDemo = async () => {
    setAuthorizedRoots({});
    setContextPreview(null);
    setError('');
    setLoading('demo');
    setPrUrl('');
    try {
      const result = await api<Scan>('/api/scans/demo/run', { method: 'POST' });
      setScan(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Controlled walkthrough failed.');
    } finally {
      setLoading(null);
    }
  };

  const runScan = async () => {
    if (!selectedRepo) return;
    setError('');
    setLoading('scan');
    setPrUrl('');
    setScan(null);
    setContextPreview(null);
    setAuthorizedRoots({});
    try {
      const created = await api<{ id: string }>('/api/scans', {
        method: 'POST',
        body: JSON.stringify({ full_name: selectedRepo }),
      });
      for (let attempt = 0; attempt < 240; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1800));
        const result = await api<Scan>(`/api/scans/${created.id}`);
        setScan(result);
        if (result.status === 'completed' || result.status === 'failed') break;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Repository scan failed.');
    } finally {
      setLoading(null);
    }
  };

  const previewCwe22Fix = async (finding: Finding) => {
    const authorizedRoot = authorizedRoots[finding.id]?.trim();
    if (!scan?.id || !authorizedRoot) return;
    setError('');
    setContextPreview(null);
    setLoading('context');
    try {
      const preview = await api<ContextPreview>(
        `/api/scans/${scan.id}/context-remediation`,
        {
          method: 'POST',
          body: JSON.stringify({
            finding_id: finding.id,
            authorized_root: authorizedRoot.trim(),
          }),
        },
      );
      setContextPreview(preview);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not preview a context-aware patch.');
    } finally {
      setLoading(null);
    }
  };

  const createPr = async () => {
    if (!scan?.id) return;
    setError('');
    setLoading('pr');
    try {
      const result = await api<{ url: string }>('/api/scans/' + scan.id + '/pull-request', {
        method: 'POST',
        body: JSON.stringify({
          review_only: !eligibleForPr,
          title: `security: review Raksa candidate fixes (${scan.full_name})`,
          body: `## Summary\nPrepared by Raksa for review.\n\n## ${eligibleForPr ? 'Verification evidence' : 'UNVERIFIED review candidate'}\n${scan.verification?.message || 'See attached scan evidence.'}\n\nPlease review the diff and test results carefully before merging.`,
        }),
      });
      setPrUrl(result.url);
      setScan((current) => (current ? { ...current, pull_request_url: result.url } : current));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create pull request.');
    } finally {
      setLoading(null);
    }
  };

  const patchAssociation = useMemo(
    () => associateFindingsAndPatches(scan?.findings, scan?.patches),
    [scan?.findings, scan?.patches]
  );
  const proposalNotes = scan ? buildProposalNotes(scan) : [];
  const diagnosticNotes = proposalNotes.filter((note) => note.messages.length > 0 || note.policyRequested || !note.patch);
  const existingPrUrl = prUrl || scan?.pull_request_url;
  const findingCount = scan?.findings?.length || 0;
  const patchCount = scan?.patches?.length || 0;
  const verificationStatus = String(scan?.verification?.status || 'not_run');
  const isVerificationPassed = verificationStatus === 'verified';
  const isVerificationFailed = verificationStatus === 'failed' || verificationStatus === 'error';
  const eligibleForPr = Boolean(scan?.verification?.eligible_for_pr);
  const reviewPrCount = Array.isArray(scan?.verification?.review_pr_finding_ids)
    ? scan.verification.review_pr_finding_ids.length : 0;
  const canCreatePr = eligibleForPr || reviewPrCount > 0;
  const integrationCount = useMemo(() => Object.values(health?.integrations || {}).filter(Boolean).length, [health]);

  if (checkingAuth) {
    return (
      <div className="login-shell login-shell-loading">
        <div className="login-loading">
          <span className="spinner" />
          <span>Connecting to workspace…</span>
        </div>
      </div>
    );
  }

  if (!auth) {
    return (
      <div className="login-shell">
        <section className="login-showcase" aria-labelledby="welcome-heading">
          <div className="login-showcase-kicker"><span aria-hidden="true" /> YOUR AI SECURITY ENGINEER</div>
          <h1 id="welcome-heading" className="login-marketing-title">Security fixes.<br /><em>Proven.</em></h1>
          <p className="login-marketing-copy">
            Meet Raksa, your AI security engineer. Investigate potential vulnerabilities, prepare focused code fixes, and review the evidence before opening a pull request.
          </p>
          <div className="login-proof-flow" aria-label="How Raksa works">
            <div className="login-proof-step"><span>01</span><strong>Investigate</strong><small>Surface potential code vulnerabilities</small></div>
            <div className="login-proof-step"><span>02</span><strong>Remediate</strong><small>Propose focused, reviewable patches</small></div>
            <div className="login-proof-step"><span>03</span><strong>Verify</strong><small>Check the fix with available test evidence</small></div>
            <div className="login-proof-step"><span>04</span><strong>Review</strong><small>Keep the final decision with developers</small></div>
          </div>
          <p className="login-showcase-footnote">Starting with Python SQL injection · Built for developer review</p>
          <a className="login-repo-link" href="https://github.com/omkz/raksa" target="_blank" rel="noreferrer">
            Explore the open-source project <span aria-hidden="true">↗</span>
          </a>
        </section>
        <div className="login-card">
          <div className="login-brand">
            <div className="brand-mark">
              <span>R</span>
              <i aria-hidden="true" />
            </div>
            <div>
              <div className="brand-name">raksa<span>.</span></div>
              <div className="brand-caption">AI SECURITY ENGINEER</div>
            </div>
          </div>

          <h2 className="login-title">Continue to Raksa</h2>
          <p className="login-subtitle">
            Sign in with GitHub to access your security workspace. You choose which repositories Raksa can inspect.
          </p>

          {authError && (
            <div className="login-error" role="alert">
              <span aria-hidden="true">⚠</span>
              <span>{authError}</span>
              <button
                type="button"
                className="login-error-dismiss"
                onClick={() => setAuthError('')}
                aria-label="Dismiss error"
              >
                ×
              </button>
            </div>
          )}

          <a href="/api/auth/login" className="login-github-button">
            <svg
              className="github-svg"
              viewBox="0 0 24 24"
              width="20"
              height="20"
              fill="currentColor"
              aria-hidden="true"
            >
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            <span>Continue with GitHub</span>
          </a>

          <div className="login-features">
            <div className="login-feature-row">
              <span className="check" aria-hidden="true">✓</span>
              <span>Identify potential Python SQL injection issues (CWE-89)</span>
            </div>
            <div className="login-feature-row">
              <span className="check" aria-hidden="true">✓</span>
              <span>Generate focused, exact-context patches with Nemotron</span>
            </div>
            <div className="login-feature-row">
              <span className="check" aria-hidden="true">✓</span>
              <span>Review test evidence before approving a draft PR</span>
            </div>
          </div>

          <p className="login-disclaimer">
            <strong>Security boundary:</strong> Raksa uses OAuth solely to verify your GitHub identity. Source repository access is governed separately through explicit GitHub App installations.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark">
            <span>R</span>
            <i aria-hidden="true" />
          </div>
          <div>
            <div className="brand-name">raksa<span>.</span></div>
            <div className="brand-caption">AI SECURITY ENGINEER</div>
          </div>
        </div>

        <div className="side-section-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main Navigation">
          <div className="nav-item active">
            <Icon>◈</Icon>
            <span>Security workspace</span>
            <span className="nav-dot" aria-hidden="true" />
          </div>
          <div className="nav-item muted">
            <Icon>⌘</Icon>
            <span>Repository scans</span>
          </div>
        </nav>

        <div className="side-bottom">
          <div className="provider-card">
            <div className="provider-heading">
              <span className="pulse" aria-hidden="true" /> INTEGRATIONS
            </div>
            <div className="provider-row">
              <span className="provider-symbol neb">N</span>
              <span>Nebius Token Factory</span>
              <span className={health?.integrations.nebius_token_factory ? 'tiny-check ready' : 'tiny-check'}>
                {health?.integrations.nebius_token_factory ? '✓' : '·'}
              </span>
            </div>
            <div className="provider-row">
              <span className="provider-symbol git">⌘</span>
              <span>GitHub App</span>
              <span className={github?.connected ? 'tiny-check ready' : 'tiny-check'}>
                {github?.connected ? '✓' : '·'}
              </span>
            </div>
            <div className="provider-row">
              <span className="provider-symbol tav">T</span>
              <span>Tavily Research</span>
              <span className={health?.integrations.tavily ? 'tiny-check ready' : 'tiny-check'}>
                {health?.integrations.tavily ? '✓' : '·'}
              </span>
            </div>
            <div className="provider-foot">{integrationCount} integrations operational</div>
          </div>
          <div className="user-note">
            <div className="avatar" aria-hidden="true">
              {auth.user.avatar_url ? (
                <img src={auth.user.avatar_url} alt="" className="avatar-img" />
              ) : (
                (auth.user.login || 'RK').slice(0, 2).toUpperCase()
              )}
            </div>
            <div>
              <strong>{auth.user.name || `@${auth.user.login}`}</strong>
              <span>{auth.workspace.name}</span>
            </div>
            <span className="local-tag">{auth.workspace.role.toUpperCase()}</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Workspace</span>
            <b aria-hidden="true">/</b>
            <strong>Security overview</strong>
          </div>
          <div className="topbar-right">
            <span className="system-status">
              <i aria-hidden="true" /> API {health?.status === 'ok' ? 'operational' : 'checking'}
            </span>
            <button
              type="button"
              className="signout-button"
              onClick={signOut}
              title="Sign out of Raksa"
            >
              Sign out
            </button>
          </div>
        </header>

        <section className="hero-row">
          <div className="hero-content">
            <div className="eyebrow">
              <span aria-hidden="true" /> AI-ASSISTED SECURITY ENGINEERING
            </div>
            <h1>Security fixes.<br /><em>Proven.</em></h1>
            <p className="hero-copy">
              Meet your AI security engineer. Raksa investigates potential SQL injection in Python code, proposes focused fixes with NVIDIA Nemotron, and shows verification evidence when an isolated sandbox is configured. Developers review every change before a draft PR is created.
            </p>
          </div>
          <div className="hero-art" aria-hidden="true">
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <div className="orbit orbit-three" />
            <div className="shield">
              <div className="shield-inner">R</div>
            </div>
            <div className="art-label art-label-one">AST ANALYSIS <span>●</span></div>
            <div className="art-label art-label-two"><span>●</span> SANDBOX GATE</div>
          </div>
        </section>

        <div className="workflow-strip" role="region" aria-label="Remediation workflow">
          <div className="workflow-step">
            <div className="step-badge">01</div>
            <div className="step-body">
              <strong className="step-title">Investigate</strong>
              <p className="step-desc">Static analysis flags potentially unsafe SQL queries.</p>
            </div>
          </div>
          <div className="workflow-divider" aria-hidden="true">→</div>
          <div className="workflow-step">
            <div className="step-badge">02</div>
            <div className="step-body">
              <strong className="step-title">Remediate</strong>
              <p className="step-desc">Nemotron proposes targeted patches for developer review.</p>
            </div>
          </div>
          <div className="workflow-divider" aria-hidden="true">→</div>
          <div className="workflow-step">
            <div className="step-badge">03</div>
            <div className="step-body">
              <strong className="step-title">Verify</strong>
              <p className="step-desc">Configured sandboxes run security and regression checks.</p>
            </div>
          </div>
          <div className="workflow-divider" aria-hidden="true">→</div>
          <div className="workflow-step">
            <div className="step-badge">04</div>
            <div className="step-body">
              <strong className="step-title">Review</strong>
              <p className="step-desc">Developers inspect the diff and evidence before PR creation.</p>
            </div>
          </div>
        </div>

        {error && (
          <div className="alert-error" role="alert">
            <span aria-hidden="true">!</span>
            <div>
              <strong>Action required</strong>
              <p>{error}</p>
            </div>
            <button type="button" onClick={() => setError('')} aria-label="Dismiss error">×</button>
          </div>
        )}

        <section className="section-heading">
          <div>
            <span className="section-index">01</span>
            <h2>Select target or walkthrough</h2>
          </div>
          <span className="section-hint">Installed repository or controlled proof</span>
        </section>

        <div className="workspace-grid">
          <section className="panel repo-panel" aria-labelledby="repo-heading">
            <div className="panel-top">
              <div className="panel-icon purple"><Icon>⌘</Icon></div>
              <div>
                <h3 id="repo-heading">GitHub repository</h3>
                <p>Analyze default branch snapshots for Python SQL injection patterns.</p>
              </div>
              <span className={github?.connected ? 'status-chip good' : 'status-chip'}>
                {github?.connected ? 'CONNECTED' : 'NOT CONNECTED'}
              </span>
            </div>

            {github?.connected ? (
              <div className="panel-body">
                <label className="field-label" htmlFor="repository">TARGET REPOSITORY</label>
                <div className="select-wrap">
                  <select
                    id="repository"
                    value={selectedRepo}
                    onChange={(event) => setSelectedRepo(event.target.value)}
                    aria-label="Select an installed GitHub repository"
                  >
                    <option value="">Select an installed repository…</option>
                    {repos.map((repo) => (
                      <option key={repo.full_name} value={repo.full_name}>
                        {repo.full_name}{repo.private ? ' · private' : ''}
                      </option>
                    ))}
                  </select>
                  <span aria-hidden="true">⌄</span>
                </div>
                <div className="repo-meta">
                  <span>
                    <i aria-hidden="true" /> {repos.length} {repos.length === 1 ? 'repository' : 'repositories'} available
                  </span>
                  <button
                    type="button"
                    className="text-button"
                    onClick={() => loadGithub()}
                    disabled={loading === 'repos'}
                  >
                    {loading === 'repos' ? 'Refreshing…' : 'Refresh list ↻'}
                  </button>
                </div>
                <button
                  type="button"
                  className="button primary full"
                  onClick={runScan}
                  disabled={!selectedRepo || loading !== null}
                >
                  <span>{loading === 'scan' ? <span className="spinner" /> : '⌕'}</span>
                  {loading === 'scan' ? 'Analyzing repository…' : 'Analyze repository'}
                  <span className="button-arrow" aria-hidden="true">↗</span>
                </button>
                <button
                  type="button"
                  className="text-button disconnect"
                  onClick={disconnectGithub}
                >
                  Disconnect GitHub
                </button>
                <p className="panel-boundary-note">
                  <span>🔒</span> Bounded text snapshot via installation token. Host shell execution is strictly prevented.
                </p>
              </div>
            ) : (
              <div className="panel-body">
                <div className="connect-empty">
                  <div className="connect-graphic" aria-hidden="true">⌘<span>↗</span></div>
                  <strong>Connect GitHub App</strong>
                  <p>Raksa uses installation-scoped GitHub App tokens with read access to source metadata. Personal access tokens are never accepted or stored.</p>
                </div>
                <button
                  type="button"
                  className="button primary full"
                  onClick={connectGithub}
                  disabled={loading !== null || !github?.configured}
                >
                  <span>⌘</span>
                  {loading === 'connect' ? 'Opening GitHub…' : 'Connect GitHub'}
                  <span className="button-arrow" aria-hidden="true">↗</span>
                </button>
                {!github?.configured && (
                  <p className="inline-warning">
                    Configure <code>GITHUB_APP_ID</code> and credentials in <code>.env</code> to enable repository integration.
                  </p>
                )}
                <p className="panel-boundary-note">
                  <span>🔒</span> PR creation is strictly gated: fixes require passing verification and explicit human approval.
                </p>
              </div>
            )}
          </section>

          <section className="panel demo-panel" aria-labelledby="demo-heading">
            <div className="panel-top">
              <div className="panel-icon amber"><Icon>⌁</Icon></div>
              <div>
                <h3 id="demo-heading">Controlled SQLi walkthrough</h3>
                <p>Deterministic in-memory proof harness. No repository connection required.</p>
              </div>
              <span className="status-chip demo-chip">CONTROLLED FIXTURE</span>
            </div>

            <div className="panel-body">
              <div className="demo-code" role="region" aria-label="Vulnerable code snippet">
                <div className="code-top">
                  <span><i aria-hidden="true" /> vulnerable_query.py</span>
                  <span>PYTHON 3</span>
                </div>
                <pre><code><span className="code-line-num">01</span> <span className="code-purple">query</span> = <span className="code-orange">f"SELECT * FROM users</span>{'\n'}<span className="code-line-num">02</span>         <span className="code-orange">WHERE name = '{'{'}</span><span className="code-pink">name</span><span className="code-orange">{' }'}</span><span className="code-orange">'"</span>{'\n'}<span className="code-line-num">03</span> connection.<span className="code-blue">execute</span>(query)</code></pre>
                <div className="code-alert">
                  <span aria-hidden="true">!</span>
                  <div>
                    <strong>Dynamic query construction (CWE-89)</strong>
                    <small>String interpolation permits payload injection. Mitigated via parameterized <code>?</code> placeholders.</small>
                  </div>
                </div>
              </div>
              <button
                type="button"
                className="button secondary full"
                onClick={runDemo}
                disabled={loading !== null}
              >
                <span>{loading === 'demo' ? <span className="spinner dark" /> : '▷'}</span>
                {loading === 'demo' ? 'Executing proof harness…' : 'Run controlled walkthrough'}
                <span className="button-arrow" aria-hidden="true">↗</span>
              </button>
              <p className="panel-boundary-note">
                <span>◈</span> Runs exclusively in an ephemeral in-memory SQLite sandbox. Target systems are untouched.
              </p>
            </div>
          </section>
        </div>

        {loading === 'scan' && (
          <div className="progress-panel" role="status">
            <div className="progress-orbit" aria-hidden="true"><span /></div>
            <div className="progress-copy">
              <div className="eyebrow">INVESTIGATION IN PROGRESS</div>
              <h3>{scan?.message || 'Preparing secure repository snapshot…'}</h3>
              <p>Raksa is moving through bounded analysis stages: snapshot fetch → AST detection → patch proposal → differential verification.</p>
            </div>
            <div className="progress-stage">{(scan?.stage || 'queued').replaceAll('_', ' ').toUpperCase()}</div>
          </div>
        )}

        {scan && (() => {
          const statusBadge = verificationStatusPresentation(verificationStatus, scan.status);
          return (
          <section className="results-section" aria-labelledby="results-heading">
            <div className="section-heading results-heading">
              <div>
                <span className="section-index">02</span>
                <h2 id="results-heading">Investigation results</h2>
              </div>
              <span className={`result-status ${statusBadge.tone}`}>
                <i aria-hidden="true" /> {statusBadge.label}
              </span>
            </div>

            {scan.status === 'failed' ? (
              <div className="alert-error" role="alert">
                <span aria-hidden="true">!</span>
                <div>
                  <strong>Investigation could not complete</strong>
                  <p>{scan.error || scan.message}</p>
                </div>
              </div>
            ) : (
              <>
                <div className="metrics-row">
                  <div className="metric-card">
                    <span>FINDINGS</span>
                    <strong>{findingCount.toString().padStart(2, '0')}</strong>
                    <small>Potential vulnerabilities</small>
                  </div>
                  <div className="metric-card">
                    <span>PATCH PROPOSALS</span>
                    <strong>{patchCount.toString().padStart(2, '0')}</strong>
                    <small>Exact-context replacements</small>
                  </div>
                  <div className="metric-card">
                    <span>VERIFICATION</span>
                    <strong className={isVerificationPassed ? 'green-number' : isVerificationFailed ? 'bad-text' : ''}>
                      {isVerificationPassed ? '✓' : isVerificationFailed ? '✕' : '—'}
                    </strong>
                    <small>
                      {isVerificationPassed
                        ? 'Evidence verified'
                        : isVerificationFailed
                          ? (verificationStatus === 'failed' ? 'Verification failed' : 'Verification error')
                          : verificationStatus === 'unverified'
                            ? 'Not fully verified'
                            : 'Not run'}
                    </small>
                  </div>
                  <div className="metric-card">
                    <span>REPOSITORY</span>
                    <strong className="repo-metric">{scan.full_name ? scan.full_name.split('/').pop() : 'Demo'}</strong>
                    <small>{scan.default_branch ? `Base: ${scan.default_branch}` : 'SQLite in-memory harness'}</small>
                  </div>
                </div>

                <nav className="results-nav" aria-label="Investigation result sections">
                  <a href="#findings"><span>01</span> Findings <b>{findingCount}</b></a>
                  <a href="#remediation"><span>02</span> Remediation <b>{patchCount} proposed</b></a>
                  <a href="#verification"><span>03</span> Verification &amp; Pull Request</a>
                </nav>
                <section className="results-area" id="findings" aria-labelledby="findings-heading">
                  <div className="results-area-heading"><span>01</span><div><h3 id="findings-heading">Findings</h3><p>Detection results and final per-finding remediation outcomes.</p></div></div>
                    <div className="autopilot-status-summary" aria-label="Remediation outcome counts">
                      {[...new Set(proposalNotes.filter((note) => note.outcome).map((note) => note.outcome!.status))].map((status) => {
                        const presentation = outcomePresentation(status);
                        return (
                          <span className={`autopilot-status ${presentation.tone}`} key={status}>
                            {presentation.label}<b>{proposalNotes.filter((note) => note.outcome?.status === status).length}</b>
                          </span>
                        );
                      })}
                    </div>
                {scan.findings?.map((finding) => {
                  const note = proposalNotes.find((item) => item.finding?.id === finding.id);
                  const presentation = outcomePresentation(note?.outcome?.status);
                  const patchIndex = patchAssociation.findingToPatchIndex.get(finding.id) ?? -1;
                  const hasPatch = patchIndex >= 0;
                  const hasDiagnostics = diagnosticNotes.some((item) => item.finding?.id === finding.id);
                  const remediationLink = hasPatch
                    ? `#patch-${patchIndex}`
                    : hasDiagnostics
                      ? `#remediation-note-${encodeURIComponent(finding.id)}`
                      : '#remediation';
                  return (
                  <article className="finding-card" id={`finding-${encodeURIComponent(finding.id)}`} key={finding.id}>
                    <div className="finding-top">
                      <div className="finding-symbol" aria-hidden="true">!</div>
                      <div className="finding-title">
                        <div>
                          <span className={`severity ${finding.severity}`}>{finding.severity.toUpperCase()}</span>
                          <span className="finding-cwe">{finding.cwe || 'APPSEC'}</span>
                          <span className="finding-cwe">{finding.scanner || 'Scanner not reported'}</span>
                        </div>
                        <h4>{finding.title}</h4>
                        <p>{finding.description}</p>
                        <div className="finding-remediation">
                          <span className={`autopilot-status ${presentation.tone}`}>
                            {note?.outcome ? presentation.label : 'Remediation Not Reported'}
                          </span>
                          {note?.outcome?.status === 'patch_proposed' && <span className="autopilot-unverified">UNVERIFIED</span>}
                          {note?.outcome?.message && <span>{note.outcome.message}</span>}
                        </div>
                        {note?.policyRequested && note.messages.filter((message) => message.startsWith(`${finding.path}: AI needs context:`)).map((message, index) => (
                          <p className="finding-policy-context" key={index}>{message}</p>
                        ))}
                        <div className="finding-reference">
                          <code>ID: {finding.id}</code>
                          {finding.rule_id && <code>Rule: {finding.rule_id}</code>}
                          <a href={remediationLink}>Review remediation <span aria-hidden="true">↓</span></a>
                          {hasPatch && hasDiagnostics && (
                            <a href={`#remediation-note-${encodeURIComponent(finding.id)}`}>Diagnostic history <span aria-hidden="true">↓</span></a>
                          )}
                        </div>
                      </div>
                      <div className="finding-detection">
                        <span className="confidence">{Math.round(finding.confidence * 100)}% Detection Confidence</span>
                        {finding.status === 'reproduced' && <span className="confidence proven">EXPLOIT REPRODUCED</span>}
                      </div>
                    </div>
                    <div className="finding-evidence">
                      <div className="evidence-path">
                        <span aria-hidden="true">⌁</span>
                        <code>{finding.path}</code>
                        <span className="line-tag">LINE {finding.line}</span>
                      </div>
                      <pre><code>{finding.evidence}</code></pre>
                    </div>
                  </article>
                );
                })}

                {findingCount === 0 && <p className="results-empty">{scan.status === 'completed' ? 'No findings reported by the configured scanners.' : 'Detection results will appear as the investigation progresses.'}</p>}
                {Array.isArray(scan.verification?.scanner_runs) && scan.verification.scanner_runs.length > 0 && (
                  <details className="scanner-details results-disclosure">
                    <summary>Scanner execution details</summary>
                {Array.isArray(scan.verification?.scanner_runs) && scan.verification.scanner_runs.map((runner: { name: string; status: string; finding_count: number; message: string }) => (
                  <div className="summary-box" key={runner.name}>
                    <div className="summary-head"><strong>{runner.name.toUpperCase()} SCANNER</strong><small>{runner.status.toUpperCase()}</small></div>
                    <p>{runner.message} · {runner.finding_count} potential finding(s)</p>
                  </div>
                ))}

                  </details>
                )}
                </section>
                <section className="results-area" id="remediation" aria-labelledby="remediation-heading">
                  <div className="results-area-heading"><span>02</span><div><h3 id="remediation-heading">Remediation</h3><p>Review candidate changes, model analysis, and diagnostic history. A proposed patch is not verification evidence.</p></div></div>
                {scan.summary && (
                  <details className="summary-box results-disclosure">
                    <summary className="summary-head">
                      <span aria-hidden="true">✳</span>
                      <strong>Model reasoning &amp; analysis</strong>
                      <small>NEBIUS / NEMOTRON</small>
                    </summary>
                    <p>{scan.summary}</p>
                  </details>
                )}

                {(scan.diff || patchCount > 0) && (
                  <div className="diff-panel" id="remediation-diff">
                    <div className="diff-header">
                      <div>
                        <span className="diff-icon" aria-hidden="true">±</span>
                        <strong>Proposed code changes</strong>
                      </div>
                      <span>{patchCount ? `${patchCount} proposed patch${patchCount === 1 ? '' : 'es'}` : 'DEMO DIFF'}</span>
                    </div>
                    {scan.diff && <pre className="diff-code">
                      {scan.diff.split('\n').map((line, index) => (
                        <div
                          key={`${index}-${line}`}
                          className={line.startsWith('+') ? 'diff-added' : line.startsWith('-') ? 'diff-removed' : ''}
                        >
                          {line || ' '}
                        </div>
                      ))}
                    </pre>}
                    {scan.patches?.map((patch, index) => {
                      const patchFindingId = patchAssociation.patchToFindingId.get(index);
                      const hasDiagnosticHistory = patchFindingId ? diagnosticNotes.some((item) => item.finding?.id === patchFindingId) : false;
                      return (
                      <div className="patch-reason" id={`patch-${index}`} key={`${patch.path}-${index}`}>
                        <span>CANDIDATE RATIONALE · {patch.cwe || 'APPSEC'}</span>
                        <div className="patch-reference">
                          <code>{patch.path}</code>
                          {patchFindingId ? (
                            scan.findings?.some((finding) => finding.id === patchFindingId)
                              ? <a href={`#finding-${encodeURIComponent(patchFindingId)}`}>Finding {patchFindingId} ↑</a>
                              : <code>Finding ID: {patchFindingId}</code>
                          ) : (
                            <code>Unassigned patch proposal</code>
                          )}
                          {hasDiagnosticHistory && (
                            <a href={`#remediation-note-${encodeURIComponent(patchFindingId!)}`}>Diagnostic history ↓</a>
                          )}
                        </div>
                        <p>{patch.reason}</p>
                        {!scan.diff && (
                          <details className="patch-source results-disclosure">
                            <summary>Exact source replacement</summary>
                            <div className="patch-source-block"><strong>Original source</strong><pre><code>{patch.old_text}</code></pre></div>
                            <div className="patch-source-block"><strong>Proposed replacement · unverified</strong><pre><code>{patch.new_text}</code></pre></div>
                          </details>
                        )}
                        <small>{patch.scanner || 'AI'} · PROPOSAL — NOT AUTOMATICALLY VERIFIED</small>
                      </div>
                    );
                    })}
                  </div>
                )}

                {!scan.diff && patchCount === 0 && <p className="results-empty">No candidate code changes were prepared. Review finding outcomes and available diagnostics.</p>}
                {diagnosticNotes.length > 0 && (
                  <section className="autopilot-notices" aria-labelledby="autopilot-notes-title">
                    <div className="autopilot-notices-head">
                      <div>
                        <span className="autopilot-eyebrow">POLICY & DIAGNOSTIC HISTORY</span>
                        <h3 id="autopilot-notes-title">Remediation context & history</h3>
                        <p>Policy previews and original model diagnostics. Retry history does not change the final finding outcome.</p>
                      </div>
                      <span className="autopilot-notes-count">{diagnosticNotes.length} {diagnosticNotes.length === 1 ? 'NOTE' : 'NOTES'}</span>
                    </div>
                    {diagnosticNotes.map((note) => {
                      const cwe22 = note.policyRequested && note.finding?.cwe === 'CWE-22'
                        && note.finding.scanner === 'opengrep' && !note.patch
                        && scan.status === 'completed' ? note.finding : undefined;
                      const patchIndex = note.finding
                        ? (patchAssociation.findingToPatchIndex.get(note.finding.id) ?? -1)
                        : -1;
                      const presentation = outcomePresentation(note.outcome?.status);
                      return (
                        <div className="autopilot-notice" id={note.finding ? `remediation-note-${encodeURIComponent(note.finding.id)}` : undefined} key={note.id}>
                          <div className="remediation-reference">
                            {note.finding ? <>
                              <span className="autopilot-cwe">{note.finding.cwe || 'APPSEC'}</span>
                              <code>{note.finding.path}:{note.finding.line}</code>
                              <a href={`#finding-${encodeURIComponent(note.finding.id)}`}>Finding {note.finding.id} ↑</a>
                              {patchIndex >= 0 && (
                                <a href={`#patch-${patchIndex}`}>Patch candidate ↓</a>
                              )}
                            </> : <strong>Unassigned diagnostic</strong>}
                          </div>
                          {note.policyRequested ? (
                            <p className="autopilot-outcome-message">Policy context requested. The remediation status remains {presentation.label}.</p>
                          ) : note.outcome ? (
                            <p className="autopilot-outcome-message">
                              <strong className={`autopilot-status-inline ${presentation.tone}`}>{presentation.label}:</strong> {note.outcome.message}
                            </p>
                          ) : null}
                          {!note.outcome && note.messages.length > 0 && <p className="autopilot-technical-message">{note.messages[note.messages.length - 1]}</p>}
                          {note.messages.length > 0 && (
                            <details className="diagnostic-history">
                              <summary>Raw diagnostic history <span>{note.messages.length} {note.messages.length === 1 ? 'entry' : 'entries'}</span></summary>
                              {note.messages.map((message, index) => (
                                <p className="autopilot-technical-message" key={index}>{message}</p>
                              ))}
                            </details>
                          )}
                          {cwe22 && scan.full_name && scan.base_sha && (
                            <form
                              className="autopilot-policy-form"
                              onSubmit={(event) => { event.preventDefault(); void previewCwe22Fix(cwe22); }}
                            >
                              <div className="autopilot-policy-heading">
                                <strong>File-access policy</strong><span>OPTIONAL · PREVIEW ONLY</span>
                              </div>
                              <label htmlFor={`authorized-root-${cwe22.id}`}>Authorized root (repository-relative path)</label>
                              <div className="autopilot-policy-controls">
                                <input
                                  id={`authorized-root-${cwe22.id}`}
                                  aria-describedby={`authorized-root-help-${cwe22.id}`}
                                  value={authorizedRoots[cwe22.id] || ''}
                                  maxLength={256}
                                  onChange={(event) => setAuthorizedRoots((current) => ({ ...current, [cwe22.id]: event.target.value }))}
                                  placeholder="uploads/"
                                  autoCapitalize="none"
                                  spellCheck={false}
                                  disabled={loading !== null}
                                />
                                <button type="submit" disabled={loading !== null || !authorizedRoots[cwe22.id]?.trim()}>
                                  {loading === 'context' ? 'Generating preview…' : 'Generate policy-scoped preview'}
                                </button>
                              </div>
                              <small id={`authorized-root-help-${cwe22.id}`}>The scan completes independently of this input. Set the application's authorized directory to request a candidate preview at the pinned commit. Previewing does not publish changes or verify remediation.</small>
                            </form>
                          )}
                        </div>
                      );
                    })}
                    <p className="autopilot-notices-foot">Static acceptance is not security verification. Review the diff and security/regression evidence before merging.</p>
                  </section>
                )}

                {contextPreview && (
                  <div className="summary-box">
                    <div className="summary-head">
                      <strong>Optional Path Traversal patch preview</strong>
                      <small>UNVERIFIED · PREVIEW ONLY</small>
                    </div>
                    <p>
                      {contextPreview.path} · developer-authorized root:
                      {' '}{contextPreview.authorized_root}
                    </p>
                    <p>{contextPreview.verification.message}</p>
                    <small>Decision: {contextPreview.decision} · pinned commit {contextPreview.base_sha.slice(0, 12)}</small>
                    {contextPreview.patch && (
                      <div className="patch-reason">
                        <span>AI CANDIDATE — NOT SECURITY VERIFIED</span>
                        <p>{contextPreview.patch.reason}</p>
                      </div>
                    )}
                    {contextPreview.diff && (
                      <pre className="diff-code" style={{ overflowX: 'auto' }}>{contextPreview.diff}</pre>
                    )}
                    {contextPreview.diagnostics.map((message, index) => (
                      <p className="small-warning" key={index}>{message}</p>
                    ))}
                  </div>
                )}

                {scan.research && scan.research.length > 0 && (
                  <details className="research-panel results-disclosure">
                    <summary className="diff-header">
                      <div>
                        <span className="diff-icon" aria-hidden="true">↗</span>
                        <strong>Security research context</strong>
                      </div>
                      <span>TAVILY</span>
                    </summary>
                    {scan.research.map((item) => (
                      <a className="research-item" key={item.url || item.title} href={item.url || undefined} target="_blank" rel="noreferrer">
                        <div>
                          <strong>{item.title}</strong>
                          <p>{item.content}</p>
                        </div>
                        <span aria-hidden="true">↗</span>
                      </a>
                    ))}
                  </details>
                )}

                </section>
                <section className="results-area" id="verification" aria-labelledby="verification-heading">
                  <div className="results-area-heading"><span>03</span><div><h3 id="verification-heading">Verification &amp; Pull Request</h3><p>Executed checks and publication eligibility. Draft PR creation always requires an explicit action.</p></div></div>
                {scan.verification && (
                  <div className={`verification-panel ${isVerificationPassed ? 'verified good' : isVerificationFailed ? 'failed bad' : 'unverified'}`}>
                    <div className="verification-icon" aria-hidden="true">
                      {isVerificationPassed ? '✓' : isVerificationFailed ? '✕' : '◷'}
                    </div>
                    <div className="verification-copy">
                      <strong>
                        {isVerificationPassed
                          ? scan.verification.regression_tests?.status === 'skipped'
                            ? 'Verification gate passed (regression tests skipped)'
                            : scan.verification.regression_tests?.status === 'unavailable'
                            ? 'Security verified (regression coverage unavailable)'
                            : 'Verification gate passed'
                          : isVerificationFailed
                            ? (verificationStatus === 'failed' ? 'Verification gate failed' : 'Verification execution error')
                            : 'Remediation unverified'}
                      </strong>
                      <p>{String(scan.verification.message || scan.verification.evidence || 'No verification details available.')}</p>

                      {(scan.verification.static_recheck || scan.verification.security_exploit || scan.verification.regression_tests) && (
                        <div className="proof-results" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(min(180px, 100%), 1fr))' }}>
                          {([
                            ['static_recheck', 'STATIC RECHECK'],
                            ['security_exploit', 'SECURITY EXPLOIT TEST'],
                            ['regression_tests', 'REGRESSION TESTS'],
                          ] as const).map(([key, label]) => {
                            const check = scan.verification?.[key];
                            if (!check) return null;
                            const presentation = verificationCheckPresentation(check);
                            return (
                              <div key={key}>
                                <span>{label}</span>
                                <strong className={presentation.tone}>{presentation.label}</strong>
                                <small>{String(check.message || '')}</small>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {!isVerificationPassed && !isVerificationFailed && (
                        <p className="verification-boundary-note">
                          Passing an individual check (such as static recheck or unrelated tests) does not constitute full verification. Differential exploit reproduction and regression testing are required to prove remediation.
                        </p>
                      )}

                      {scan.verification.before && scan.verification.after && (
                        <div className="proof-results">
                          <div>
                            <span>BEFORE (VULNERABLE BASELINE)</span>
                            <strong className="bad-text">
                              {scan.verification.before.result_count !== undefined
                                ? `${scan.verification.before.result_count} rows returned`
                                : scan.verification.before.exploit_reproduced
                                ? 'Exploit reproduced'
                                : 'Not reproduced'}
                            </strong>
                            <small>{scan.verification.before.exploit_reproduced ? 'Vulnerability triggered successfully' : (scan.verification.before.message || 'Not reproduced')}</small>
                          </div>
                          <div>
                            <span>AFTER (PATCHED CODE)</span>
                            <strong className={scan.verification.after.exploit_blocked ? 'good-text' : ''}>
                              {scan.verification.after.result_count !== undefined
                                ? `${scan.verification.after.result_count} rows returned`
                                : scan.verification.after.exploit_blocked
                                ? 'Payload blocked'
                                : 'Not verified'}
                            </strong>
                            <small>{scan.verification.after.exploit_blocked ? 'Payload neutralized via parameterization' : (scan.verification.after.message || 'Not verified')}</small>
                          </div>
                        </div>
                      )}

                      {scan.verification.tests && (
                        <div className="test-terminal">
                          <div className="terminal-title">
                            <span aria-hidden="true" /> SANDBOX TEST OUTPUT <small>{scan.verification.tests.provider || ''}</small>
                          </div>
                          <pre>
                            {String(scan.verification.tests.stdout || '')}
                            {scan.verification.tests.stderr ? `\n${String(scan.verification.tests.stderr)}` : ''}
                            {!scan.verification.tests.stdout && !scan.verification.tests.stderr ? String(scan.verification.tests.message || '') : ''}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {!scan.verification && <p className="results-empty">Verification evidence has not been reported for this scan.</p>}
                {existingPrUrl ? (
                  <div className="action-footer">
                    <div>
                      <strong>Draft pull request available</strong>
                      <p>Review the candidate diff and verification evidence on GitHub before merging.</p>
                    </div>
                    <a className="button primary" href={existingPrUrl} target="_blank" rel="noreferrer">View Draft PR <span aria-hidden="true">↗</span></a>
                  </div>
                ) : scan.full_name && patchCount > 0 ? (
                  <div className="action-footer">
                    <div>
                      <strong>
                        {eligibleForPr
                          ? scan.verification?.regression_tests?.status === 'unavailable'
                            ? 'Ready for human review (regression unverified)'
                            : 'Ready for human review'
                          : reviewPrCount > 0 ? 'Review-only Draft PR available' : 'No eligible review-only patches'}
                      </strong>
                      <p>
                        {eligibleForPr
                          ? scan.verification?.regression_tests?.status === 'unavailable'
                            ? 'Security verified. A draft PR is ready for human review without automated regression coverage.'
                            : 'A verified patch is ready to publish as a draft PR.'
                          : reviewPrCount > 0
                            ? `${reviewPrCount} selected candidate(s) can be sent to a DRAFT PR for human review. UNVERIFIED: do not merge without tests. Other candidates are excluded.`
                            : 'No candidate meets the conservative review-only policy. Verification is still required for standard PRs.'}
                      </p>
                    </div>
                    <button
                      type="button"
                      className="button primary"
                      onClick={createPr}
                      disabled={!canCreatePr || loading !== null}
                    >
                      {loading === 'pr' ? 'Creating draft PR…' : eligibleForPr ? 'Create verified draft PR' : 'Create UNVERIFIED review draft'}
                      <span aria-hidden="true">↗</span>
                    </button>
                  </div>
                ) : (
                  <p className="results-empty">
                    {scan.full_name
                      ? 'Draft PR creation is unavailable for this scan. An eligible candidate and explicit approval are required.'
                      : 'Draft PR creation is unavailable for in-memory walkthroughs. Connect a GitHub repository to publish review PRs.'}
                  </p>
                )}
                </section>
              </>
            )}
          </section>
        );
        })()}

        <footer className="footer">
          <span>RAKSA © 2026</span>
          <span>SECURITY FIXES. PROVEN. <b>•</b> REVIEW BEFORE MERGE</span>
          <span>YOUR AI SECURITY ENGINEER</span>
        </footer>
      </main>
    </div>
  );
}
