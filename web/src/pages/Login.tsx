/**
 * Login page — Phase 0 stub with a simple form.
 *
 * In production this would redirect to SSO/SAML/OIDC.
 * For development, it accepts any credentials and creates a dev token.
 */

import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuthHook";

/**
 * Create a minimal dev JWT (unsigned, for local development only).
 * The real token would come from the API's /auth/login endpoint.
 */
function createDevToken(username: string): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(
    JSON.stringify({
      sub: username,
      tenant_id: "00000000-0000-0000-0000-000000000001",
      role: "admin",
    }),
  );
  return `${header}.${payload}.dev-signature`;
}

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const { login } = useAuth();
  const navigate = useNavigate();

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");

    if (!username.trim()) {
      setError("Username is required");
      return;
    }

    // Phase 0: accept any login with a dev token
    const token = createDevToken(username);
    login(token);
    navigate("/discover", { replace: true });
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        height: "100vh",
        background: "#0f1117",
        color: "#e0e0e0",
      }}
    >
      <form
        onSubmit={handleSubmit}
        style={{
          width: 360,
          padding: 32,
          background: "#161a23",
          borderRadius: 8,
          border: "1px solid #2a2e39",
        }}
      >
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8, letterSpacing: 1 }}>
          SENTINEL
        </h1>
        <p style={{ color: "#9ca3af", marginBottom: 24, fontSize: 14 }}>
          Sign in to your account
        </p>

        {error && (
          <div
            style={{
              background: "rgba(239, 68, 68, 0.1)",
              border: "1px solid #ef4444",
              borderRadius: 4,
              padding: "8px 12px",
              marginBottom: 16,
              color: "#ef4444",
              fontSize: 14,
            }}
          >
            {error}
          </div>
        )}

        <label
          htmlFor="username"
          style={{ display: "block", marginBottom: 4, fontSize: 14, color: "#9ca3af" }}
        >
          Username
        </label>
        <input
          id="username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          style={{
            width: "100%",
            padding: "8px 12px",
            marginBottom: 16,
            background: "#0f1117",
            border: "1px solid #2a2e39",
            borderRadius: 4,
            color: "#e0e0e0",
            fontSize: 14,
            boxSizing: "border-box",
          }}
        />

        <label
          htmlFor="password"
          style={{ display: "block", marginBottom: 4, fontSize: 14, color: "#9ca3af" }}
        >
          Password
        </label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          style={{
            width: "100%",
            padding: "8px 12px",
            marginBottom: 24,
            background: "#0f1117",
            border: "1px solid #2a2e39",
            borderRadius: 4,
            color: "#e0e0e0",
            fontSize: 14,
            boxSizing: "border-box",
          }}
        />

        <button
          type="submit"
          style={{
            width: "100%",
            padding: "10px 16px",
            background: "#2563eb",
            color: "#fff",
            border: "none",
            borderRadius: 4,
            fontSize: 14,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Sign in
        </button>

        <p style={{ marginTop: 16, fontSize: 12, color: "#6b7280", textAlign: "center" }}>
          Phase 0 — any username works for local development
        </p>
      </form>
    </div>
  );
}
