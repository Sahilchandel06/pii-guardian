import { useState } from "react";

import { apiRequest } from "../lib/api";

export default function AuditPanel({ logs, token, setNotice, setError }) {
  const [downloading, setDownloading] = useState(false);
  const [downloadFormat, setDownloadFormat] = useState("jsonl");

  const downloadLogs = async () => {
    try {
      setDownloading(true);
      setError("");
      const response = await apiRequest(`/audit/logs/download?format=${encodeURIComponent(downloadFormat)}`, { token });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const contentDisposition = response.headers.get("Content-Disposition") || "";
      const match = contentDisposition.match(/filename=\"?([^\";]+)\"?/i);
      const filename = match?.[1] || "audit_logs.csv";

      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      setNotice("Audit logs downloaded.");
    } catch (err) {
      setError(err.message || "Failed to download audit logs.");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <section className="panel">
      <div className="audit-head">
        <h3>Audit Logs</h3>
        <div style={{ display: "flex", gap: 8 }}>
          <select
            value={downloadFormat}
            onChange={(event) => setDownloadFormat(event.target.value)}
            disabled={downloading}
          >
            <option value="jsonl">JSONL (SIEM)</option>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
          </select>
          <button type="button" onClick={downloadLogs} disabled={downloading}>
          {downloading ? "Downloading..." : "Download Logs"}
          </button>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>User ID</th>
              <th>Action</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td>{new Date(log.timestamp).toLocaleString()}</td>
                <td>{log.user_id}</td>
                <td>{log.action}</td>
                <td>{log.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
