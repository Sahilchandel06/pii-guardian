import { useState } from "react";
import { apiRequest } from "../lib/api";

const initialForm = {
  username: "",
  email: "",
  password: "",
  role: "user",
  admin_token: "",
};

export default function AuthView({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState(initialForm);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const update = (field, value) => setForm((prev) => ({ ...prev, [field]: value }));

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setMessage("");

    try {
      if (mode === "signup") {
        await apiRequest("/auth/signup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(form),
        });
        setMessage("Signup successful. Continue with login.");
        setMode("login");
        return;
      }

      const response = await apiRequest("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: form.username, password: form.password }),
      });
      const data = await response.json();
      onLogin(data.access_token);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <h1>PII Guardian</h1>
        <p>Secure Sanitization Platform</p>
        <form onSubmit={submit} key={mode}>
          <input
            placeholder="Username"
            value={form.username}
            onChange={(event) => update("username", event.target.value)}
            required
          />
          {mode === "signup" && (
            <>
              <input
                type="email"
                placeholder="Email"
                value={form.email}
                onChange={(event) => update("email", event.target.value)}
                required
              />
              <select value={form.role} onChange={(event) => update("role", event.target.value)}>
                <option value="user">Standard User</option>
                <option value="admin">Admin</option>
              </select>
              {form.role === "admin" && (
                <input
                  placeholder="Admin Registration Token"
                  value={form.admin_token}
                  onChange={(event) => update("admin_token", event.target.value)}
                />
              )}
            </>
          )}
          <input
            type="password"
            placeholder="Password"
            value={form.password}
            onChange={(event) => update("password", event.target.value)}
            required
          />
          <button type="submit">{mode === "signup" ? "Create Account" : "Login"}</button>
        </form>

        <button className="ghost-button" onClick={() => setMode(mode === "login" ? "signup" : "login")}>
          {mode === "login" ? "Create new account" : "Back to login"}
        </button>

        {message && <div className="notice success">{message}</div>}
        {error && <div className="notice error">{error}</div>}
      </div>
    </div>
  );
}
