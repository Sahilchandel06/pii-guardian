import { useMemo, useState } from "react";
import { apiRequest } from "../lib/api";

export default function FileCenter({ token, files, isAdmin, reloadFiles, onDeleted, setNotice, setError }) {
  const [search, setSearch] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [rawPreview, setRawPreview] = useState("");
  const [sanitizedPreview, setSanitizedPreview] = useState("");

  const rows = useMemo(() => files || [], [files]);

  const loadPreview = async (fileId, raw) => {
    setNotice("");
    setError("");
    try {
      const endpoint = raw ? `/files/${fileId}/raw-preview` : `/files/${fileId}/sanitized-preview`;
      const response = await apiRequest(endpoint, { token });
      const data = await response.json();
      if (raw) setRawPreview(data.raw_preview);
      else {
        setSanitizedPreview(data.sanitized_preview);
        if (reloadFiles) await reloadFiles();
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const download = async (fileId, filename, original) => {
    setNotice("");
    setError("");
    try {
      const endpoint = original ? `/files/${fileId}/download-original` : `/files/${fileId}/download`;
      const headers = {};
      if (original) {
        const stepupPassword = window.prompt("Enter your password to confirm original file download:");
        if (!stepupPassword) return;
        headers["X-Stepup-Password"] = stepupPassword;
      }
      const response = await apiRequest(endpoint, { token, headers });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const contentDisposition = response.headers.get("content-disposition") || "";
      const match = contentDisposition.match(/filename="([^"]+)"/i);
      const resolvedFilename = match?.[1];
      link.href = url;
      link.download = resolvedFilename || (original ? filename : `${filename}.sanitized.txt`);
      link.click();
      URL.revokeObjectURL(url);
      setNotice("Download started.");
      if (!original && reloadFiles) await reloadFiles();
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
      const resolvedFilename = match?.[1];
      const dot = filename.lastIndexOf(".");
      const fallbackName =
        dot > 0 ? `${filename.slice(0, dot)}.sanitized${filename.slice(dot)}` : `${filename}.sanitized`;
      link.href = url;
      link.download = resolvedFilename || fallbackName;
      link.click();
      URL.revokeObjectURL(url);
      setNotice("Sanitized original-format download started.");
      if (reloadFiles) await reloadFiles();
    } catch (err) {
      setError(err.message);
    }
  };

  const runSearch = async () => {
    setNotice("");
    setError("");
    if (search.trim().length < 2) {
      setError("Search requires at least 2 characters.");
      return;
    }
    try {
      const response = await apiRequest(`/files/search?q=${encodeURIComponent(search.trim())}`, { token });
      const data = await response.json();
      setSearchResults(data.results || []);
    } catch (err) {
      setError(err.message);
    }
  };

  const deleteFile = async (fileId, filename) => {
    setNotice("");
    setError("");
    const confirmed = window.confirm(`Delete "${filename}" permanently? This cannot be undone.`);
    if (!confirmed) return;
    try {
      await apiRequest(`/files/${fileId}`, { token, method: "DELETE" });
      setNotice(`Deleted ${filename}`);
      if (onDeleted) await onDeleted();
      setRawPreview("");
      setSanitizedPreview("");
      setSearchResults((prev) => prev.filter((item) => item.id !== fileId));
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="panel">
      <h3>File & Sanitization Center</h3>
      <div className="search-line">
        <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search sanitized records" />
        <button onClick={runSearch}>Search</button>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Filename</th>
              <th>Mode</th>
              <th>PII</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td>{item.filename}</td>
                <td>{item.sanitization_mode}</td>
                <td>{item.pii_count}</td>
                <td className="action-cell">
                  <button className="action-btn action-btn-preview" onClick={() => loadPreview(item.id, false)}>
                    Sanitized
                  </button>
                  <button
                    className="action-btn action-btn-safe"
                    onClick={() => downloadSanitizedOriginal(item.id, item.filename)}
                  >
                    Safe (Original)
                  </button>
                  <button className="action-btn action-btn-safe" onClick={() => download(item.id, item.filename, false)}>
                    Safe (TXT)
                  </button>
                  <button className="action-btn action-btn-preview" onClick={() => loadPreview(item.id, true)}>
                    Original Preview
                  </button>
                  <button className="action-btn action-btn-original" onClick={() => download(item.id, item.filename, true)}>
                    Download Original
                  </button>
                  {isAdmin && (
                    <button className="action-btn action-btn-danger" onClick={() => deleteFile(item.id, item.filename)}>
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {searchResults.length > 0 && (
        <div className="search-results">
          <h4>Search Results</h4>
          {searchResults.map((item) => (
            <article key={item.id} className="search-item">
              <strong>{item.filename}</strong>
              <p>{item.preview}</p>
            </article>
          ))}
        </div>
      )}

      <div className="compare-grid">
        <div>
          <h4>Original Preview</h4>
          <textarea readOnly rows={12} value={rawPreview} />
        </div>
        <div>
          <h4>Sanitized Preview</h4>
          <textarea readOnly rows={12} value={sanitizedPreview} />
        </div>
      </div>
    </section>
  );
}
