import { useState } from 'react';
import { scanTarget } from './services/api';
import type { ScanSummary } from './types';

function App() {
  const [targetUrl, setTargetUrl] = useState('https://example.com');
  const [skipPorts, setSkipPorts] = useState(false);
  const [result, setResult] = useState<ScanSummary | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await scanTarget(targetUrl, skipPorts);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unexpected error');
    } finally {
      setLoading(false);
    }
  }

  const scoreLabel =
    result && result.score >= 80
      ? 'Strong'
      : result && result.score >= 60
        ? 'Moderate'
        : result && result.score >= 40
          ? 'Needs improvement'
          : 'High risk';

  return (
    <main className="page">
      <section className="hero">
        <div className="badge">Security Portfolio Tool</div>

        <h1>Cyber Hygiene Scanner</h1>

        <p>
          Analyze HTTPS usage, security headers, exposed technology headers and
          common ports from a clean web dashboard.
        </p>

        <form onSubmit={handleSubmit} className="scan-form">
          <input
            type="url"
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://example.com"
            required
          />

          <label className="checkbox">
            <input
              type="checkbox"
              checked={skipPorts}
              onChange={(event) => setSkipPorts(event.target.checked)}
            />
            Skip ports
          </label>

          <button type="submit" disabled={loading}>
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </form>

        {error && <p className="error">{error}</p>}
      </section>

      {result && (
        <section className="dashboard">
          <article className="score-card">
            <span>Security Score</span>
            <strong>{result.score}/100</strong>
            <p>{scoreLabel}</p>
          </article>

          <article className="card">
            <h2>Target</h2>
            <p>{result.normalized_url}</p>
            <div className="status-grid">
              <div>
                <span>HTTPS</span>
                <strong className={result.https_enabled ? 'ok' : 'bad'}>
                  {result.https_enabled ? 'Enabled' : 'Disabled'}
                </strong>
              </div>

              <div>
                <span>HTTP → HTTPS</span>
                <strong className={result.redirects_to_https ? 'ok' : 'bad'}>
                  {result.redirects_to_https ? 'Yes' : 'No'}
                </strong>
              </div>

              <div>
                <span>Risk level</span>
                <strong>{result.risk_level}</strong>
              </div>
            </div>
          </article>

          <article className="card">
            <h2>Security Headers</h2>
            <div className="list">
              {result.headers.map((header) => (
                <div key={header.name} className="list-item">
                  <div>
                    <strong>{header.name}</strong>
                    <p>{header.present ? header.value : header.recommendation}</p>
                  </div>
                  <span className={header.present ? 'ok' : 'bad'}>
                    {header.present ? 'Present' : 'Missing'}
                  </span>
                </div>
              ))}
            </div>
          </article>

          <article className="card">
            <h2>Common Ports</h2>
            {result.ports.length === 0 ? (
              <p className="muted">Port scan skipped.</p>
            ) : (
              <div className="ports">
                {result.ports.map((port) => (
                  <div key={port.port} className="port-item">
                    <strong>{port.port}</strong>
                    <span>{port.service}</span>
                    <em className={port.open ? 'warning' : 'muted'}>
                      {port.open ? 'Open' : 'Closed'}
                    </em>
                  </div>
                ))}
              </div>
            )}
          </article>

          <article className="card recommendations">
            <h2>Recommendations</h2>
            <ul>
              {result.recommendations.map((recommendation) => (
                <li key={recommendation}>{recommendation}</li>
              ))}
            </ul>
          </article>
        </section>
      )}
    </main>
  );
}

export default App;
