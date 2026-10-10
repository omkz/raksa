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
      setGithub((value) => value ? { ...value, connected: false } : value);
      setRepos([]);
      setSelectedRepo('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not disconnect GitHub.');
    }
  };

  const runDemo = async () => {
    setError(''); setLoading('demo'); setPrUrl('');
    try {
      const result = await api<Scan>('/api/scans/demo/run', { method: 'POST' });
      setScan(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Demo failed.');
    } finally {
      setLoading(null);
    }
  };

  const runScan = async () => {
    if (!selectedRepo) return;
    setError(''); setLoading('scan'); setPrUrl(''); setScan(null);
    try {
      const created = await api<{ id: string }>('/api/scans', {
        method: 'POST', body: JSON.stringify({ full_name: selectedRepo }),
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
    setError(''); setLoading('pr');
    try {
      const result = await api<{ url: string }>('/api/scans/' + scan.id + '/pull-request', {
        method: 'POST',
        body: JSON.stringify({
          title: `security: remediate potential SQL injection (${scan.full_name})`,
          body: `## Summary\nPrepared by Raksa for review.\n\n## Verification evidence\n${scan.verification?.message || 'See attached scan evidence.'}\n\nPlease review the diff and test results carefully before merging.`,
        }),
      });
      setPrUrl(result.url);
      setScan((current) => current ? { ...current, pull_request_url: result.url } : current);
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
          <div className="brand-mark"><span>R</span><i /></div>
          <div><div className="brand-name">raksa<span>.</span></div><div className="brand-caption">AUTONOMOUS APPSEC</div></div>
        </div>
        <div className="side-section-label">WORKSPACE</div>
        <div className="nav-item active"><Icon>◈</Icon><span>Security workspace</span><span className="nav-dot" /></div>
        <div className="nav-item muted"><Icon>⌘</Icon><span>Repository scans</span><span className="soon">MVP</span></div>
        <div className="side-bottom">
          <div className="provider-card">
            <div className="provider-heading"><span className="pulse" /> PROVIDERS</div>
            <div className="provider-row"><span className="provider-symbol neb">N</span><span>Nebius Token Factory</span><span className={health?.integrations.nebius_token_factory ? 'tiny-check ready' : 'tiny-check'}>{health?.integrations.nebius_token_factory ? '✓' : '·'}</span></div>
            <div className="provider-row"><span className="provider-symbol git">⌘</span><span>GitHub App</span><span className={github?.connected ? 'tiny-check ready' : 'tiny-check'}>{github?.connected ? '✓' : '·'}</span></div>
            <div className="provider-row"><span className="provider-symbol tav">T</span><span>Tavily Research</span><span className={health?.integrations.tavily ? 'tiny-check ready' : 'tiny-check'}>{health?.integrations.tavily ? '✓' : '·'}</span></div>
            <div className="provider-foot">{integrationCount} integrations configured</div>
          </div>
          <div className="user-note"><div className="avatar">RK</div><div><strong>Local workspace</strong><span>Development mode</span></div><span className="local-tag">LOCAL</span></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>Security overview</strong></div>
          <div className="topbar-right"><span className="system-status"><i /> API {health?.status === 'ok' ? 'operational' : 'checking'}</span><span className="top-separator" /><a href="http://localhost:8000/docs" target="_blank" rel="noreferrer">API docs ↗</a></div>
        </header>

        <section className="hero-row">
          <div>
            <div className="eyebrow"><span /> APPSEC AGENT <span className="eyebrow-divider">/</span> EARLY ACCESS</div>
            <h1>Make vulnerabilities<br /><em>provable.</em></h1>
            <p className="hero-copy">Raksa investigates application code, prepares focused remediations, and collects evidence before a human reviews the pull request.</p>
          </div>
          <div className="hero-art" aria-hidden="true">
            <div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="orbit orbit-three" />
            <div className="shield"><div className="shield-inner">R</div></div><div className="art-label art-label-one">SOURCE ANALYSIS <span>●</span></div><div className="art-label art-label-two"><span>●</span> PROOF ENGINE</div><div className="art-coordinate">-7.7956° / 110.3695°</div>
          </div>
        </section>

        {error && <div className="alert-error"><span>!</span><div><strong>Something needs attention</strong><p>{error}</p></div><button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}

        <section className="section-heading"><div><span className="section-index">01</span><h2>Start an investigation</h2></div><span className="section-hint">Choose a repo or run the guided demo</span></section>
        <div className="workspace-grid">
          <section className="panel repo-panel">
            <div className="panel-top"><div className="panel-icon purple"><Icon>⌘</Icon></div><div><h3>GitHub repository</h3><p>Analyze source code from an installed repository.</p></div><span className={github?.connected ? 'status-chip good' : 'status-chip'}>{github?.connected ? 'CONNECTED' : 'NOT CONNECTED'}</span></div>
            {github?.connected ? <>
              <label className="field-label" htmlFor="repository">REPOSITORY</label>
              <div className="select-wrap"><select id="repository" value={selectedRepo} onChange={(event) => setSelectedRepo(event.target.value)}><option value="">Select an installed repository…</option>{repos.map((repo) => <option key={repo.full_name} value={repo.full_name}>{repo.full_name}{repo.private ? ' · private' : ''}</option>)}</select><span>⌄</span></div>
              <div className="repo-meta"><span><i /> {repos.length} repositories available</span><button className="text-button" onClick={() => loadGithub()} disabled={loading === 'repos'}>{loading === 'repos' ? 'Refreshing…' : 'Refresh list ↻'}</button></div>
              <button className="button primary full" onClick={runScan} disabled={!selectedRepo || loading !== null}><span>{loading === 'scan' ? <span className="spinner" /> : '⌕'}</span>{loading === 'scan' ? 'Investigating repository…' : 'Analyze repository'}<span className="button-arrow">↗</span></button>
              <button className="text-button disconnect" onClick={disconnectGithub}>Disconnect GitHub</button>
            </> : <>
              <div className="connect-empty"><div className="connect-graphic">⌘<span>↗</span></div><strong>Connect a repository to begin</strong><p>Raksa uses a GitHub App installation token. It never needs your personal access token.</p></div>
              <button className="button primary full" onClick={connectGithub} disabled={loading !== null || !github?.configured}><span>⌘</span>{loading === 'connect' ? 'Opening GitHub…' : 'Connect GitHub'}<span className="button-arrow">↗</span></button>
              {!github?.configured && <p className="inline-warning">Configure the GitHub App in <code>.env</code> to enable repository access.</p>}
            </>}
          </section>

          <section className="panel demo-panel">
            <div className="panel-top"><div className="panel-icon amber"><Icon>⌁</Icon></div><div><h3>Try the SQLi demo</h3><p>A controlled proof. No external credentials needed.</p></div><span className="status-chip demo-chip">GUIDED DEMO</span></div>
            <div className="demo-code">
              <div className="code-top"><span><i /> vulnerable_query.py</span><span>PYTHON</span></div>
              <pre><code><span className="code-line-num">01</span> <span className="code-purple">query</span> = <span className="code-orange">f"SELECT * FROM users</span>{'\n'}<span className="code-line-num">02</span>         <span className="code-orange">WHERE name = '{'{'}</span><span className="code-pink">name</span><span className="code-orange">{' }'}</span><span className="code-orange">'"</span>{'\n'}<span className="code-line-num">03</span> connection.<span className="code-blue">execute</span>(query)</code></pre>
              <div className="code-alert"><span>!</span><div><strong>Potential SQL injection</strong><small>Unsanitized input changes query semantics.</small></div></div>
            </div>
            <button className="button secondary full" onClick={runDemo} disabled={loading !== null}><span>{loading === 'demo' ? <span className="spinner dark" /> : '▷'}</span>{loading === 'demo' ? 'Running proof harness…' : 'Run SQLi demo'}<span className="button-arrow">↗</span></button>
            <p className="safe-note"><span>◈</span> Runs a deterministic in-memory SQLite test. No target repo is executed.</p>
          </section>
        </div>

        {loading === 'scan' && <div className="progress-panel"><div className="progress-orbit"><span /></div><div className="progress-copy"><div className="eyebrow">INVESTIGATION IN PROGRESS</div><h3>{scan?.message || 'Preparing secure repository snapshot…'}</h3><p>Raksa is moving through bounded analysis stages. This can take a minute.</p></div><div className="progress-stage">{(scan?.stage || 'queued').replaceAll('_', ' ').toUpperCase()}</div></div>}

        {scan && <section className="results-section">
          <div className="section-heading results-heading"><div><span className="section-index">02</span><h2>Investigation results</h2></div><span className={`result-status ${scan.status === 'failed' ? 'bad' : verified || verificationStatus === 'verified' ? 'good' : 'pending'}`}><i /> {scan.status === 'failed' ? 'FAILED' : verificationStatus.replaceAll('_', ' ').toUpperCase()}</span></div>
          {scan.status === 'failed' ? <div className="alert-error"><span>!</span><div><strong>Investigation could not complete</strong><p>{scan.error || scan.message}</p></div></div> : <>
            <div className="metrics-row">
              <div className="metric-card"><span>FINDINGS</span><strong>{findingCount.toString().padStart(2, '0')}</strong><small>Potential vulnerabilities</small></div>
              <div className="metric-card"><span>PATCH PROPOSALS</span><strong>{patchCount.toString().padStart(2, '0')}</strong><small>Exact-context replacements</small></div>
              <div className="metric-card"><span>VERIFICATION</span><strong className={verified || verificationStatus === 'verified' ? 'green-number' : ''}>{verified || verificationStatus === 'verified' ? '✓' : '—'}</strong><small>{verified ? 'Evidence available' : 'Not fully verified'}</small></div>
              <div className="metric-card"><span>REPOSITORY</span><strong className="repo-metric">{scan.full_name ? scan.full_name.split('/').pop() : 'Demo'}</strong><small>{scan.default_branch ? `Base: ${scan.default_branch}` : 'SQLite proof harness'}</small></div>
            </div>
            {scan.findings?.map((finding) => <article className="finding-card" key={finding.id}>
              <div className="finding-top"><div className="finding-symbol">!</div><div className="finding-title"><div><span className={`severity ${finding.severity}`}>{finding.severity.toUpperCase()}</span><span className="finding-cwe">{finding.cwe || 'APPSEC'}</span></div><h3>{finding.title}</h3><p>{finding.description}</p></div><span className={`confidence ${finding.status === 'reproduced' ? 'proven' : ''}`}>{finding.status === 'reproduced' ? 'REPRODUCED' : `${Math.round(finding.confidence * 100)}% CONFIDENCE`}</span></div>
              <div className="finding-evidence"><div className="evidence-path"><span>⌁</span><code>{finding.path}</code><span className="line-tag">LINE {finding.line}</span></div><pre>{finding.evidence}</pre></div>
            </article>)}
            {scan.summary && <div className="summary-box"><div className="summary-head"><span>✳</span><strong>Agent analysis</strong><small>NEBIUS / NEMOTRON</small></div><p>{scan.summary}</p></div>}
            {scan.diff && <div className="diff-panel"><div className="diff-header"><div><span className="diff-icon">±</span><strong>Proposed code change</strong></div><span>{patchCount ? `${patchCount} proposed patch${patchCount === 1 ? '' : 'es'}` : 'DEMO DIFF'}</span></div><pre className="diff-code">{scan.diff.split('\n').map((line, index) => <div key={`${index}-${line}`} className={line.startsWith('+') ? 'diff-added' : line.startsWith('-') ? 'diff-removed' : ''}>{line || ' '}</div>)}</pre>{scan.patches?.map((patch, index) => <div className="patch-reason" key={`${patch.path}-${index}`}><span>WHY THIS CHANGE</span><p>{patch.reason}</p><small>{patch.path}</small></div>)}</div>}
            {scan.verification && <div className="verification-panel"><div className="verification-icon">{verificationStatus === 'verified' ? '✓' : '◷'}</div><div className="verification-copy"><strong>{verificationStatus === 'verified' ? 'Verification gate passed' : 'Verification evidence'}</strong><p>{String(scan.verification.message || scan.verification.evidence || 'No verification details available.')}</p>{scan.verification.static_recheck && <div className="proof-results" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}><div><span>STATIC RECHECK</span><strong className={scan.verification.static_recheck.passed ? 'good-text' : 'bad-text'}>{scan.verification.static_recheck.passed ? '✓ PASSED' : '✕ FAILED'}</strong><small>{String(scan.verification.static_recheck.message || '')}</small></div>{scan.verification.security_exploit && <div><span>SECURITY EXPLOIT TEST</span><strong className={scan.verification.security_exploit.passed ? 'good-text' : scan.verification.security_exploit.status === 'unavailable' ? '' : 'bad-text'}>{scan.verification.security_exploit.passed ? '✓ PASSED' : scan.verification.security_exploit.status === 'unavailable' ? '— UNAVAILABLE' : '✕ FAILED'}</strong><small>{String(scan.verification.security_exploit.message || '')}</small></div>}{scan.verification.regression_tests && <div><span>REGRESSION TESTS</span><strong className={scan.verification.regression_tests.passed ? 'good-text' : scan.verification.regression_tests.status === 'skipped' ? '' : 'bad-text'}>{scan.verification.regression_tests.passed ? '✓ PASSED' : scan.verification.regression_tests.status === 'skipped' ? '— SKIPPED' : '✕ FAILED'}</strong><small>{String(scan.verification.regression_tests.message || '')}</small></div>}</div>}{scan.verification.before && scan.verification.after && <div className="proof-results"><div><span>BEFORE</span><strong className="bad-text">{scan.verification.before.result_count !== undefined ? `${scan.verification.before.result_count} rows returned` : (scan.verification.before.exploit_reproduced ? 'Exploit reproduced' : 'Not reproduced')}</strong><small>{scan.verification.before.exploit_reproduced ? 'Exploit reproduced' : (scan.verification.before.message || 'Not reproduced')}</small></div><div><span>AFTER</span><strong className="good-text">{scan.verification.after.result_count !== undefined ? `${scan.verification.after.result_count} rows returned` : (scan.verification.after.exploit_blocked ? 'Payload blocked' : 'Not verified')}</strong><small>{scan.verification.after.exploit_blocked ? 'Payload blocked' : (scan.verification.after.message || 'Not verified')}</small></div></div>}{scan.verification.tests && <div className="test-terminal"><div className="terminal-title"><span /> SANDBOX TEST OUTPUT <small>{scan.verification.tests.provider || ''}</small></div><pre>{String(scan.verification.tests.stdout || '')}{scan.verification.tests.stderr ? `\n${String(scan.verification.tests.stderr)}` : ''}{!scan.verification.tests.stdout && !scan.verification.tests.stderr ? String(scan.verification.tests.message || '') : ''}</pre></div>}</div></div>}
            {scan.research && scan.research.length > 0 && <div className="research-panel"><div className="diff-header"><div><span className="diff-icon">↗</span><strong>Security research</strong></div><span>TAVILY</span></div>{scan.research.map((item) => <a className="research-item" key={item.url || item.title} href={item.url || undefined} target="_blank" rel="noreferrer"><div><strong>{item.title}</strong><p>{item.content}</p></div><span>↗</span></a>)}</div>}
            {scan.patch_messages?.map((message) => <p className="small-warning" key={message}>⚠ {message}</p>)}
            {prUrl && <div className="pr-success"><span>✓</span><div><strong>Draft pull request created</strong><p>Review the patch and CI status on GitHub before merging.</p></div><a href={prUrl} target="_blank" rel="noreferrer">Open PR ↗</a></div>}
            {scan.full_name && patchCount > 0 && <div className="action-footer"><div><strong>{verified ? 'Ready for human review' : 'Review required before publishing'}</strong><p>{verified ? 'A verified patch is ready to publish as a draft PR.' : 'PR creation stays disabled until isolated tests pass and the static recheck clears.'}</p></div><button className="button primary" onClick={createPr} disabled={!verified || loading !== null || Boolean(prUrl)}>{loading === 'pr' ? 'Creating draft PR…' : 'Create draft PR'} <span>↗</span></button></div>}
          </>}
        </section>}

        <footer className="footer"><span>RAKSA © 2026</span><span>PROVE WITH EVIDENCE <b>•</b> REVIEW BEFORE MERGE</span><span>V0.1.0 / MVP</span></footer>
      </main>
    </div>
  );
}
