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
