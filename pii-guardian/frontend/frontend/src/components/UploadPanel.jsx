import { useState } from "react";
import { apiRequest } from "../lib/api";

export default function UploadPanel({
  token,
  onUploaded,
  setNotice,
  setError,
}) {
  const [mode, setMode] = useState("mask");
  const [file, setFile] = useState(null);
  const isPdf = (file?.name || "").toLowerCase().endsWith(".pdf");

  const onFileChange = (event) => {
    const selected = event.target.files?.[0] || null;
    setFile(selected);
    if (selected && selected.name.toLowerCase().endsWith(".pdf")) {
      setMode("redact");
    }
  };

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
      payload.append("mode", isPdf ? "redact" : mode);

      const response = await apiRequest("/files/upload", {
        token,
        method: "POST",
        body: payload,
      });
      const data = await response.json();
      setNotice(`Processed ${data.filename}`);
      setFile(null);
      onUploaded();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="panel">
      <h3>Upload Center</h3>
      <p>
        Supported formats: SQL, CSV, JSON, PDF (including image-based), DOCX,
        TXT, PNG, JPG, JPEG, XLSX, XLSM, XLTX, XLTM, XLS
      </p>
      <form className="upload-grid" onSubmit={onSubmit}>
        <input type="file" onChange={onFileChange} required />
        {isPdf ? (
          <select value="redact" disabled>
            <option value="redact">Redact (PDF required)</option>
          </select>
        ) : (
          <select
            value={mode}
            onChange={(event) => setMode(event.target.value)}
          >
            <option value="mask">Mask</option>
            <option value="redact">Redact</option>
            <option value="tokenize">Tokenize</option>
          </select>
        )}
        <button type="submit">Upload & Sanitize</button>
      </form>
    </section>
  );
}
