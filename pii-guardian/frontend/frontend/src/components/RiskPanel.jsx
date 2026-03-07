function riskColor(score) {
  if (score >= 80) return "#dc2626";
  if (score >= 60) return "#ea580c";
  if (score >= 30) return "#ca8a04";
  return "#16a34a";
}

export default function RiskPanel({ data, isAdmin, loading, onRefresh }) {
  const overall = data?.overall || {
    file_count: 0,
    pii_count: 0,
    risk_score: 0,
    risk_level: "low",
  };
  const topEntities = data?.top_entities || [];
  const perFile = data?.per_file_scores || [];
  const perUser = data?.per_user_scores || [];
  const ringAngle = Math.max(0, Math.min(100, overall.risk_score)) * 3.6;
  const circumference = 2 * Math.PI * 52;
  const strokeOffset = circumference - (Math.max(0, Math.min(100, overall.risk_score)) / 100) * circumference;
  const riskBuckets = perFile.reduce(
    (acc, row) => {
      if (row.risk_score >= 80) acc.high += 1;
      else if (row.risk_score >= 60) acc.medium += 1;
      else acc.low += 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0 },
  );
  const topFileBars = [...perFile].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);
  const maxTopFileScore = topFileBars[0]?.risk_score || 1;

  return (
    <section className="panel">
      <div className="audit-head">
        <h3>{isAdmin ? "Global Risk Dashboard" : "Personal Risk Dashboard"}</h3>
        <button type="button" onClick={onRefresh} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      <div className="stats-grid">
        <article>
          <span>Risk Score</span>
          <strong style={{ color: riskColor(overall.risk_score) }}>
            {overall.risk_score}
          </strong>
        </article>
        <article>
          <span>Total PII</span>
          <strong>{overall.pii_count}</strong>
        </article>
        <article>
          <span>Files Analyzed</span>
          <strong>{overall.file_count}</strong>
        </article>
      </div>

      <div className="risk-visual-grid">
        <article className="risk-visual-card">
          <h4>Overall Risk Meter</h4>
          <div className="risk-ring-wrap">
            <svg className="risk-ring" width="140" height="140" viewBox="0 0 140 140">
              <circle cx="70" cy="70" r="52" fill="none" stroke="#e9edf3" strokeWidth="12" />
              <circle
                cx="70"
                cy="70"
                r="52"
                fill="none"
                stroke={riskColor(overall.risk_score)}
                strokeWidth="12"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={strokeOffset}
                transform="rotate(-90 70 70)"
              />
            </svg>
            <div className="risk-ring-center">
              <strong>{overall.risk_score}</strong>
              <span>{overall.risk_level}</span>
            </div>
          </div>
          <div
            className="risk-needle"
            style={{ transform: `rotate(${Math.max(0, Math.min(180, ringAngle / 2))}deg)` }}
          />
        </article>

        <article className="risk-visual-card">
          <h4>File Risk Distribution</h4>
          <div className="risk-dist-list">
            <div className="risk-dist-row">
              <label>High (80+)</label>
              <div className="risk-dist-track">
                <span
                  className="risk-dist-fill risk-dist-high"
                  style={{ width: `${overall.file_count ? (riskBuckets.high / overall.file_count) * 100 : 0}%` }}
                />
              </div>
              <strong>{riskBuckets.high}</strong>
            </div>
            <div className="risk-dist-row">
              <label>Medium (60-79)</label>
              <div className="risk-dist-track">
                <span
                  className="risk-dist-fill risk-dist-medium"
                  style={{ width: `${overall.file_count ? (riskBuckets.medium / overall.file_count) * 100 : 0}%` }}
                />
              </div>
              <strong>{riskBuckets.medium}</strong>
            </div>
            <div className="risk-dist-row">
              <label>Low (&lt;60)</label>
              <div className="risk-dist-track">
                <span
                  className="risk-dist-fill risk-dist-low"
                  style={{ width: `${overall.file_count ? (riskBuckets.low / overall.file_count) * 100 : 0}%` }}
                />
              </div>
              <strong>{riskBuckets.low}</strong>
            </div>
          </div>
        </article>
      </div>

      <h4 style={{ marginTop: 16 }}>Highest Risk Files</h4>
      <div className="risk-bars-card">
        {topFileBars.length === 0 ? (
          <p>No file risk data yet.</p>
        ) : (
          topFileBars.map((row) => (
            <div className="risk-bar-row" key={row.file_id}>
              <div className="risk-bar-meta">
                <strong>{row.filename}</strong>
                <span>Score: {row.risk_score}</span>
              </div>
              <div className="risk-bar-track">
                <span
                  className="risk-bar-fill"
                  style={{
                    width: `${(row.risk_score / maxTopFileScore) * 100}%`,
                    background: riskColor(row.risk_score),
                  }}
                />
              </div>
            </div>
          ))
        )}
      </div>

      <h4>Most Exposed PII Types </h4>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Entity</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {topEntities.length === 0 ? (
              <tr>
                <td colSpan={2}>No entities detected yet.</td>
              </tr>
            ) : (
              topEntities.map((item) => (
                <tr key={item.entity}>
                  <td>{item.entity}</td>
                  <td>{item.count}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {isAdmin && (
        <>
          <h4 style={{ marginTop: 16 }}>Per-user Risk Scores</h4>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>User ID</th>
                  <th>PII Count</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                </tr>
              </thead>
              <tbody>
                {perUser.length === 0 ? (
                  <tr>
                    <td colSpan={5}>No user risk data yet.</td>
                  </tr>
                ) : (
                  perUser.map((row) => (
                    <tr key={row.user_id}>
                      <td>{row.username}</td>
                      <td>{row.user_id}</td>
                      <td>{row.pii_count}</td>
                      <td>{row.risk_score}</td>
                      <td
                        style={{
                          color: riskColor(row.risk_score),
                          fontWeight: 700,
                        }}
                      >
                        {row.risk_level}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      <h4 style={{ marginTop: 16 }}>Per-file Risk Scores</h4>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>File ID</th>
              <th>Filename</th>
              <th>PII Count</th>
              <th>Risk Score</th>
              <th>Risk Level</th>
            </tr>
          </thead>
          <tbody>
            {perFile.length === 0 ? (
              <tr>
                <td colSpan={5}>No file risk data yet.</td>
              </tr>
            ) : (
              perFile.map((row) => (
                <tr key={row.file_id}>
                  <td>{row.file_id}</td>
                  <td>{row.filename}</td>
                  <td>{row.pii_count}</td>
                  <td>{row.risk_score}</td>
                  <td
                    style={{
                      color: riskColor(row.risk_score),
                      fontWeight: 700,
                    }}
                  >
                    {row.risk_level}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
