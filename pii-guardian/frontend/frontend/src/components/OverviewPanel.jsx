export default function OverviewPanel({ me, files, logs }) {
  const totalFiles = files.length;
  const totalPII = files.reduce((sum, item) => sum + (item.pii_count || 0), 0);
  const recentLogs = logs.slice(0, 6);

  return (
    <section className="panel">
      <h3>Dashboard Overview</h3>
      <div className="stats-grid">
        <article>
          <span>Total Files</span>
          <strong>{totalFiles}</strong>
        </article>
        <article>
          <span>Total PII Detections</span>
          <strong>{totalPII}</strong>
        </article>
        <article>
          <span>Your Role</span>
          <strong>{me?.role?.toUpperCase()}</strong>
        </article>
      </div>

      <h4>Latest Activity</h4>
      <div className="activity-list">
        {recentLogs.length === 0 && <p>No activity yet.</p>}
        {recentLogs.map((log) => (
          <div key={log.id} className="activity-item">
            <strong>{log.action}</strong>
            <p>{log.details}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
