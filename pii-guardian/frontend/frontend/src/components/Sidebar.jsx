const items = [
  { id: "overview", label: "Overview" },
  { id: "risk", label: "Risk Dashboard" },
  { id: "files", label: "Files" },
  { id: "sanitized", label: "Sanitized Data" },
  { id: "upload", label: "Upload" },
  { id: "users", label: "Users", adminOnly: true },
  { id: "audit", label: "Audit", adminOnly: true },
];

export default function Sidebar({ me, activeTab, onTabChange, onLogout }) {
  const isAdmin = me?.role === "admin";

  return (
    <aside className="sidebar">
      <div className="brand-block">
        <h2>PII Guardian</h2>
        <p>
          {me?.username} ({me?.role})
        </p>
      </div>
      <nav>
        {items.map((item) => (
          <button
            key={item.id}
            className={`tab-button ${activeTab === item.id ? "active" : ""} ${
              item.adminOnly && !isAdmin ? "restricted" : ""
            }`}
            onClick={() => onTabChange(item.id)}
          >
            {item.label} {item.adminOnly && !isAdmin ? "(Admin)" : ""}
          </button>
        ))}
      </nav>
      <button className="logout-button" onClick={onLogout}>
        Logout
      </button>
    </aside>
  );
}
