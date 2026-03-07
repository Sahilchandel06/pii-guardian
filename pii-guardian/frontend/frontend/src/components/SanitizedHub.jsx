import { useState } from "react";
import { apiRequest } from "../lib/api";

export default function SanitizedHub({ token, files, setNotice, setError }) {
  const [preview, setPreview] = useState("");

  const loadSanitizedPreview = async (fileId) => {
    setNotice("");
    setError("");
    try {
      const response = await apiRequest(`/files/${fileId}/sanitized-preview`, { token });
      const data = await response.json();
      setPreview(data.sanitized_preview || "");
    } catch (err) {
      setError(err.message);
    }
  };

  const downloadSanitizedTxt = async (fileId, filename) => {
    setNotice("");
    setError("");
    try {
      const response = await apiRequest(`/files/${fileId}/download`, { token });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const contentDisposition = response.headers.get("content-disposition") || "";
      const match = contentDisposition.match(/filename="([^"]+)"/i);
      const resolvedFilename = match?.[1] || `${filename}.sanitized.txt`;
      link.href = url;
      link.download = resolvedFilename;
      link.click();
      URL.revokeObjectURL(url);
      setNotice("Sanitized TXT download started.");
    } catch (err) {
      setError(err.message);
    }
  };

  const downloadSanitizedOriginal = async (fileId, filename) => {
    setNotice("");
    setError("");
    try {
      const response = await apiRequest(`/files/${fileId}/download-sanitized-original`, { token });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const contentDisposition = response.headers.get("content-disposition") || "";
      const match = contentDisposition.match(/filename="([^"]+)"/i);
      const resolvedFilename = match?.[1] || `${filename}.sanitized`;
      link.href = url;
      link.download = resolvedFilename;
      link.click();
      URL.revokeObjectURL(url);
      setNotice("Sanitized original-format download started.");
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="panel">
      <h3>Shared Sanitized Data</h3>
      <p>All users can view and download sanitized files only.</p>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Filename</th>
              <th>Uploaded By</th>
              <th>Mode</th>
              <th>PII</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {files.map((item) => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td>{item.filename}</td>
                <td>{item.uploaded_by}</td>
                <td>{item.sanitization_mode}</td>
                <td>{item.pii_count}</td>
                <td className="action-cell">
                  <button className="action-btn action-btn-preview" onClick={() => loadSanitizedPreview(item.id)}>
                    Sanitized Preview
                  </button>
                  <button
                    className="action-btn action-btn-safe"
                    onClick={() => downloadSanitizedOriginal(item.id, item.filename)}
                  >
                    Safe (Original)
                  </button>
                  <button className="action-btn action-btn-safe" onClick={() => downloadSanitizedTxt(item.id, item.filename)}>
                    Safe (TXT)
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="compare-grid">
        <div>
          <h4>Sanitized Preview</h4>
          <textarea readOnly rows={12} value={preview} />
        </div>
      </div>
    </section>
  );
}
