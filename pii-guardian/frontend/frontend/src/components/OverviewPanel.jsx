export default function OverviewPanel({ me, files, logs }) {
  const totalFiles = files.length;
  const totalPII = files.reduce((sum, item) => sum + (item.pii_count || 0), 0);
  const isAdmin = me?.role === "admin";

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

      <h4>Data Access Scope</h4>
      <div className="activity-list">
        {isAdmin ? (
          <div className="activity-item">
            <strong>Admin Access</strong>
            <p>You can access all uploaded files (original + sanitized).</p>
          </div>
        ) : (
          <div className="activity-item">
            <strong>User Access</strong>
            <p>
              You can access only your own uploaded files (original +
              sanitized). Other users' files are blocked.
            </p>
          </div>
        )}
        <div className="activity-item">
          <strong>Visible Files</strong>
          <p>One user can see all other user's sanitized files.</p>
        </div>
      </div>
    </section>
  );
}
