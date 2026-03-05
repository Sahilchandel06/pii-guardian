import { useMemo, useState } from "react";
import { apiRequest } from "../lib/api";

export default function FileCenter({ token, files, isAdmin, setNotice, setError }) {
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
      else setSanitizedPreview(data.sanitized_preview);
    } catch (err) {
      setError(err.message);
    }
  };

  const download = async (fileId, filename, original) => {
    setNotice("");
    setError("");
    try {
      const endpoint = original ? `/files/${fileId}/download-original` : `/files/${fileId}/download`;
      const response = await apiRequest(endpoint, { token });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = original ? filename : `${filename}.sanitized.txt`;
      link.click();
      URL.revokeObjectURL(url);
      setNotice("Download started.");
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
                  <button onClick={() => loadPreview(item.id, false)}>Sanitized</button>
                  <button onClick={() => download(item.id, item.filename, false)}>Download Safe</button>
                  {isAdmin && <button onClick={() => loadPreview(item.id, true)}>Raw</button>}
                  {isAdmin && <button onClick={() => download(item.id, item.filename, true)}>Download Raw</button>}
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
        {isAdmin && (
          <div>
            <h4>Original Preview (Admin)</h4>
            <textarea readOnly rows={12} value={rawPreview} />
          </div>
        )}
        <div>
          <h4>Sanitized Preview</h4>
          <textarea readOnly rows={12} value={sanitizedPreview} />
        </div>
      </div>
    </section>
  );
}
