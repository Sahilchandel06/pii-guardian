import { useState } from "react";
import { apiRequest } from "../lib/api";

export default function UploadPanel({ token, onUploaded, setNotice, setError }) {
  const [mode, setMode] = useState("mask");
  const [file, setFile] = useState(null);

  const onSubmit = async (event) => {
    event.preventDefault();
    setNotice("");
    setError("");

    if (!file) {
      setError("Select a file to upload.");
      return;
    }

    try {
      const payload = new FormData();
      payload.append("file", file);
      payload.append("mode", mode);

      const response = await apiRequest("/files/upload", {
        token,
        method: "POST",
        body: payload,
      });
      const data = await response.json();
      setNotice(`Processed ${data.filename}. PII found: ${data.pii_count}`);
      setFile(null);
      onUploaded();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="panel">
      <h3>Admin Upload Center</h3>
      <p>Supported formats: SQL, CSV, JSON, PDF, DOCX, TXT, PNG, JPG</p>
      <form className="upload-grid" onSubmit={onSubmit}>
        <input type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} required />
        <select value={mode} onChange={(event) => setMode(event.target.value)}>
          <option value="mask">Mask</option>
          <option value="redact">Redact</option>
          <option value="tokenize">Tokenize</option>
        </select>
        <button type="submit">Upload & Sanitize</button>
      </form>
    </section>
  );
}
