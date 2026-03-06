import { useEffect, useState } from "react";
import "./App.css";
import AuditPanel from "./components/AuditPanel";
import AuthView from "./components/AuthView";
import FileCenter from "./components/FileCenter";
import OverviewPanel from "./components/OverviewPanel";
import RiskPanel from "./components/RiskPanel";
import SanitizedHub from "./components/SanitizedHub";
import Sidebar from "./components/Sidebar";
import UploadPanel from "./components/UploadPanel";
import UsersPanel from "./components/UsersPanel";
import { apiRequest } from "./lib/api";

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [me, setMe] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [files, setFiles] = useState([]);
  const [sharedSanitizedFiles, setSharedSanitizedFiles] = useState([]);
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [riskData, setRiskData] = useState(null);
  const [riskLoading, setRiskLoading] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const isAdmin = me?.role === "admin";

  const handleTabChange = (tabId) => {
    const adminOnly = ["users", "audit"];
    if (!isAdmin && adminOnly.includes(tabId)) {
      setError("This section is admin-only. Login with an admin account to access it.");
      return;
    }
    setError("");
    setActiveTab(tabId);
  };

  const logout = () => {
    localStorage.removeItem("token");
    setToken("");
    setMe(null);
    setFiles([]);
    setSharedSanitizedFiles([]);
    setUsers([]);
    setLogs([]);
    setRiskData(null);
    setActiveTab("overview");
    setNotice("Logged out.");
    setError("");
  };

  const fetchMe = async () => {
    const response = await apiRequest("/auth/me", { token });
    const data = await response.json();
    setMe(data);
    return data;
  };

  const fetchFiles = async () => {
    const response = await apiRequest("/files", { token });
    const data = await response.json();
    const visibleFiles = me?.role === "admin" ? data : data.filter((item) => item.uploaded_by === me?.id);
    setFiles(visibleFiles);
  };

  const fetchSharedSanitizedFiles = async () => {
    const response = await apiRequest("/files/sanitized-catalog", { token });
    const data = await response.json();
    setSharedSanitizedFiles(data);
  };

  const fetchUsers = async () => {
    if (!isAdmin) return;
    const response = await apiRequest("/auth/users", { token });
    const data = await response.json();
    setUsers(data);
  };

  const fetchLogs = async () => {
    if (!isAdmin) return;
    const response = await apiRequest("/audit/logs?limit=200", { token });
    const data = await response.json();
    setLogs(data);
  };

  const fetchRiskDashboard = async () => {
    setRiskLoading(true);
    try {
      const response = await apiRequest("/files/risk-dashboard?months=12", { token });
      const data = await response.json();
      setRiskData(data);
    } catch {
      setRiskData(null);
    } finally {
      setRiskLoading(false);
    }
  };

  const initialize = async () => {
    try {
      const user = await fetchMe();
      const response = await apiRequest("/files", { token });
      const data = await response.json();
      const visibleFiles = user.role === "admin" ? data : data.filter((item) => item.uploaded_by === user.id);
      setFiles(visibleFiles);
      await fetchSharedSanitizedFiles();
      await fetchRiskDashboard();
      if (user.role === "admin") {
        await fetchUsers();
        await fetchLogs();
      }
      setError("");
    } catch {
      logout();
    }
  };

  useEffect(() => {
    if (!token) return;
    initialize();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  useEffect(() => {
    if (!token || !isAdmin) return;
    if (activeTab === "users") fetchUsers();
    if (activeTab === "audit") fetchLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  useEffect(() => {
    if (!token) return;
    if (activeTab === "risk") fetchRiskDashboard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, token]);

  if (!token) {
    return (
      <AuthView
        onLogin={(newToken) => {
          localStorage.setItem("token", newToken);
          setToken(newToken);
          setNotice("Login successful.");
        }}
      />
    );
  }

  return (
    <div className="app-shell">
      <Sidebar
        me={me}
        activeTab={activeTab}
        onTabChange={handleTabChange}
        onLogout={logout}
      />

      <main className="content">
        <header className="content-head">
          <h1>Data Privacy Dashboard</h1>
          <p>Upload, detect PII, sanitize, audit and download secure outputs.</p>
        </header>

        {notice && <div className="notice success" key={notice}>{notice}</div>}
        {error && <div className="notice error" key={error}>{error}</div>}

        <div className="panel-fade" key={activeTab}>
          {activeTab === "overview" && <OverviewPanel me={me} files={files} logs={logs} />}
          {activeTab === "risk" && (
            <RiskPanel
              data={riskData}
              isAdmin={isAdmin}
              loading={riskLoading}
              onRefresh={fetchRiskDashboard}
            />
          )}
          {activeTab === "files" && (
            <FileCenter
              token={token}
              files={files}
              isAdmin={isAdmin}
              reloadFiles={fetchFiles}
              onDeleted={fetchFiles}
              setNotice={setNotice}
              setError={setError}
            />
          )}
          {activeTab === "sanitized" && (
            <SanitizedHub
              token={token}
              files={sharedSanitizedFiles}
              setNotice={setNotice}
              setError={setError}
            />
          )}
          {activeTab === "upload" && (
            <UploadPanel
              token={token}
              onUploaded={async () => {
                await fetchFiles();
                await fetchSharedSanitizedFiles();
                await fetchRiskDashboard();
                if (isAdmin) await fetchLogs();
              }}
              setNotice={setNotice}
              setError={setError}
            />
          )}
          {activeTab === "users" && isAdmin && (
            <UsersPanel token={token} users={users} reloadUsers={fetchUsers} setNotice={setNotice} setError={setError} />
          )}
          {activeTab === "audit" && isAdmin && (
            <AuditPanel logs={logs} token={token} setNotice={setNotice} setError={setError} />
          )}
        </div>
      </main>
    </div>
  );
}
