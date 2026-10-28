import { type ReactNode, useCallback, useEffect, useMemo, useState } from 'react';

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
};

type Patch = { path: string; old_text: string; new_text: string; reason: string };
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
  verification?: Record<string, any>;
  pull_request_url?: string | null;
  error?: string | null;
  patch_messages?: string[];
};

type Health = { status: string; integrations: Record<string, boolean> };
type GithubStatus = { configured: boolean; connected: boolean; app_slug?: string | null };

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

function Icon({ children }: { children: ReactNode }) {
  return <span className="icon" aria-hidden="true">{children}</span>;
}

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [github, setGithub] = useState<GithubStatus | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState<'connect' | 'repos' | 'scan' | 'demo' | 'pr' | null>(null);
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
    void Promise.all([
      api<Health>('/api/health').then(setHealth).catch(() => undefined),
      loadGithub(),
    ]);
    if (new URLSearchParams(window.location.search).get('github') === 'connected') {
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, [loadGithub]);

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

  const createPr = async () => {
    if (!scan?.id) return;
    setError('');
    setLoading('pr');
    try {
      const result = await api<{ url: string }>('/api/scans/' + scan.id + '/pull-request', {
        method: 'POST',
        body: JSON.stringify({
          title: `security: remediate potential SQL injection (${scan.full_name})`,
          body: `## Summary\nPrepared by Raksa for review.\n\n## Verification evidence\n${scan.verification?.message || 'See attached scan evidence.'}\n\nPlease review the diff and test results carefully before merging.`,
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

  const findingCount = scan?.findings?.length || 0;
  const patchCount = scan?.patches?.length || 0;
  const verificationStatus = String(scan?.verification?.status || 'not-run');
  const verified = Boolean(scan?.verification?.eligible_for_pr);
  const integrationCount = useMemo(() => Object.values(health?.integrations || {}).filter(Boolean).length, [health]);

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
            <div className="brand-caption">AUTONOMOUS APPSEC</div>
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
            <div className="avatar" aria-hidden="true">RK</div>
            <div>
              <strong>Local workspace</strong>
              <span>Security review session</span>
            </div>
            <span className="local-tag">ACTIVE</span>
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
          </div>
        </header>

        <section className="hero-row">
          <div className="hero-content">
            <div className="eyebrow">
              <span aria-hidden="true" /> APPLICATION SECURITY WORKFLOW
            </div>
            <h1>Find the flaw.<br /><em>Verify the fix.</em></h1>
            <p className="hero-copy">
              Raksa analyzes Python repositories for SQL injection vulnerabilities (CWE-89), synthesizes exact-context parameterized remediations with Nemotron, and proves the fix in an isolated test sandbox before human review.
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
              <strong className="step-title">Find</strong>
              <p className="step-desc">Static AST heuristics identify unparameterized SQL queries.</p>
            </div>
          </div>
          <div className="workflow-divider" aria-hidden="true">→</div>
          <div className="workflow-step">
            <div className="step-badge">02</div>
            <div className="step-body">
              <strong className="step-title">Fix</strong>
              <p className="step-desc">Nemotron crafts minimal, exact-context parameterized driver fixes.</p>
            </div>
          </div>
          <div className="workflow-divider" aria-hidden="true">→</div>
          <div className="workflow-step">
            <div className="step-badge">03</div>
            <div className="step-body">
              <strong className="step-title">Verify</strong>
              <p className="step-desc">Isolated sandbox runs differential exploit and regression tests.</p>
            </div>
          </div>
          <div className="workflow-divider" aria-hidden="true">→</div>
          <div className="workflow-step">
            <div className="step-badge">04</div>
            <div className="step-body">
              <strong className="step-title">Review</strong>
              <p className="step-desc">Human verifies test evidence before approving a draft PR.</p>
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

        {scan && (
          <section className="results-section" aria-labelledby="results-heading">
            <div className="section-heading results-heading">
              <div>
                <span className="section-index">02</span>
                <h2 id="results-heading">Investigation results &amp; verification</h2>
              </div>
              <span className={`result-status ${scan.status === 'failed' ? 'bad' : verified || verificationStatus === 'verified' ? 'good' : 'pending'}`}>
                <i aria-hidden="true" /> {scan.status === 'failed' ? 'FAILED' : verificationStatus.replaceAll('_', ' ').toUpperCase()}
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
                    <strong className={verified || verificationStatus === 'verified' ? 'green-number' : ''}>
                      {verified || verificationStatus === 'verified' ? '✓' : '—'}
                    </strong>
                    <small>{verified ? 'Evidence verified' : 'Not fully verified'}</small>
                  </div>
                  <div className="metric-card">
                    <span>REPOSITORY</span>
                    <strong className="repo-metric">{scan.full_name ? scan.full_name.split('/').pop() : 'Demo'}</strong>
                    <small>{scan.default_branch ? `Base: ${scan.default_branch}` : 'SQLite in-memory harness'}</small>
                  </div>
                </div>

                {scan.findings?.map((finding) => (
                  <article className="finding-card" key={finding.id}>
                    <div className="finding-top">
                      <div className="finding-symbol" aria-hidden="true">!</div>
                      <div className="finding-title">
                        <div>
                          <span className={`severity ${finding.severity}`}>{finding.severity.toUpperCase()}</span>
                          <span className="finding-cwe">{finding.cwe || 'APPSEC'}</span>
                        </div>
                        <h3>{finding.title}</h3>
                        <p>{finding.description}</p>
                      </div>
                      <span className={`confidence ${finding.status === 'reproduced' ? 'proven' : ''}`}>
                        {finding.status === 'reproduced' ? 'REPRODUCED' : `${Math.round(finding.confidence * 100)}% CONFIDENCE`}
                      </span>
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
                ))}

                {scan.summary && (
                  <div className="summary-box">
                    <div className="summary-head">
                      <span aria-hidden="true">✳</span>
                      <strong>Model reasoning &amp; analysis</strong>
                      <small>NEBIUS / NEMOTRON</small>
                    </div>
                    <p>{scan.summary}</p>
                  </div>
                )}

                {scan.diff && (
                  <div className="diff-panel">
                    <div className="diff-header">
                      <div>
                        <span className="diff-icon" aria-hidden="true">±</span>
                        <strong>Proposed code change</strong>
                      </div>
                      <span>{patchCount ? `${patchCount} proposed patch${patchCount === 1 ? '' : 'es'}` : 'DEMO DIFF'}</span>
                    </div>
                    <pre className="diff-code">
                      {scan.diff.split('\n').map((line, index) => (
                        <div
                          key={`${index}-${line}`}
                          className={line.startsWith('+') ? 'diff-added' : line.startsWith('-') ? 'diff-removed' : ''}
                        >
                          {line || ' '}
                        </div>
                      ))}
                    </pre>
                    {scan.patches?.map((patch, index) => (
                      <div className="patch-reason" key={`${patch.path}-${index}`}>
                        <span>REMEDIATION RATIONALE</span>
                        <p>{patch.reason}</p>
                        <small>{patch.path}</small>
                      </div>
                    ))}
                  </div>
                )}

                {scan.verification && (
                  <div className="verification-panel">
                    <div className="verification-icon" aria-hidden="true">
                      {verificationStatus === 'verified' ? '✓' : '◷'}
                    </div>
                    <div className="verification-copy">
                      <strong>
                        {verificationStatus === 'verified'
                          ? scan.verification.regression_tests?.status === 'skipped'
                            ? 'Verification gate passed (regression tests skipped)'
                            : scan.verification.regression_tests?.status === 'unavailable'
                            ? 'Security verified (regression coverage unavailable)'
                            : 'Verification gate passed'
                          : 'Verification evidence'}
                      </strong>
                      <p>{String(scan.verification.message || scan.verification.evidence || 'No verification details available.')}</p>

                      {scan.verification.static_recheck && (
                        <div className="proof-results" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
                          <div>
                            <span>STATIC RECHECK</span>
                            <strong className={scan.verification.static_recheck.passed ? 'good-text' : 'bad-text'}>
                              {scan.verification.static_recheck.passed ? '✓ PASSED' : '✕ FAILED'}
                            </strong>
                            <small>{String(scan.verification.static_recheck.message || '')}</small>
                          </div>
                          {scan.verification.security_exploit && (
                            <div>
                              <span>SECURITY EXPLOIT TEST</span>
                              <strong className={scan.verification.security_exploit.passed ? 'good-text' : scan.verification.security_exploit.status === 'unavailable' ? '' : 'bad-text'}>
                                {scan.verification.security_exploit.passed ? '✓ PASSED' : scan.verification.security_exploit.status === 'unavailable' ? '— UNAVAILABLE' : '✕ FAILED'}
                              </strong>
                              <small>{String(scan.verification.security_exploit.message || '')}</small>
                            </div>
                          )}
                          {scan.verification.regression_tests && (
                            <div>
                              <span>REGRESSION TESTS</span>
                              <strong className={scan.verification.regression_tests.status === 'skipped' || scan.verification.regression_tests.status === 'unavailable' ? '' : scan.verification.regression_tests.passed ? 'good-text' : 'bad-text'}>
                                {scan.verification.regression_tests.status === 'skipped' ? '— SKIPPED' : scan.verification.regression_tests.status === 'unavailable' ? '— UNAVAILABLE' : scan.verification.regression_tests.passed ? '✓ PASSED' : '✕ FAILED'}
                              </strong>
                              <small>{String(scan.verification.regression_tests.message || '')}</small>
                            </div>
                          )}
                        </div>
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
                            <strong className="good-text">
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

                {scan.research && scan.research.length > 0 && (
                  <div className="research-panel">
                    <div className="diff-header">
                      <div>
                        <span className="diff-icon" aria-hidden="true">↗</span>
                        <strong>Security research context</strong>
                      </div>
                      <span>TAVILY</span>
                    </div>
                    {scan.research.map((item) => (
                      <a className="research-item" key={item.url || item.title} href={item.url || undefined} target="_blank" rel="noreferrer">
                        <div>
                          <strong>{item.title}</strong>
                          <p>{item.content}</p>
                        </div>
                        <span aria-hidden="true">↗</span>
                      </a>
                    ))}
                  </div>
                )}

                {scan.patch_messages?.map((message) => (
                  <p className="small-warning" key={message}>⚠ {message}</p>
                ))}

                {prUrl && (
                  <div className="pr-success">
                    <span aria-hidden="true">✓</span>
                    <div>
                      <strong>Draft pull request created</strong>
                      <p>Review the patch and CI checks on GitHub before merging.</p>
                    </div>
                    <a href={prUrl} target="_blank" rel="noreferrer">Open PR ↗</a>
                  </div>
                )}

                {scan.full_name && patchCount > 0 && (
                  <div className="action-footer">
                    <div>
                      <strong>
                        {verified
                          ? scan.verification?.regression_tests?.status === 'unavailable'
                            ? 'Ready for human review (regression unverified)'
                            : 'Ready for human review'
                          : 'Review required before publishing'}
                      </strong>
                      <p>
                        {verified
                          ? scan.verification?.regression_tests?.status === 'unavailable'
                            ? 'Security verified. A draft PR is ready for human review without automated regression coverage.'
                            : 'A verified patch is ready to publish as a draft PR.'
                          : 'PR creation stays disabled until isolated tests pass and the static recheck clears.'}
                      </p>
                    </div>
                    <button
                      type="button"
                      className="button primary"
                      onClick={createPr}
                      disabled={!verified || loading !== null || Boolean(prUrl)}
                    >
                      {loading === 'pr' ? 'Creating draft PR…' : 'Create draft PR'}
                      <span aria-hidden="true">↗</span>
                    </button>
                  </div>
                )}
              </>
            )}
          </section>
        )}

        <footer className="footer">
          <span>RAKSA © 2026</span>
          <span>PROVE WITH EVIDENCE <b>•</b> REVIEW BEFORE MERGE</span>
          <span>AUTONOMOUS APPLICATION SECURITY</span>
        </footer>
      </main>
    </div>
  );
}
