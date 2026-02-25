/**
 * Top header bar with page title and user menu.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../hooks/useAuthHook";

export function Header({ title }: { title: string }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <header
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 0 16px",
        borderBottom: "1px solid #2a2e39",
        marginBottom: 24,
      }}
    >
      <h1 style={{ fontSize: 20, fontWeight: 600, margin: 0 }}>{title}</h1>

      {user && (
        <div style={{ position: "relative" }}>
          <button
            type="button"
            onClick={() => setMenuOpen(!menuOpen)}
            style={{
              background: "#2a2e39",
              border: "1px solid #3a3f4b",
              borderRadius: 4,
              color: "#e0e0e0",
              padding: "6px 12px",
              fontSize: 13,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span style={{ color: "#9ca3af" }}>{user.role}</span>
            <span>{user.sub}</span>
          </button>

          {menuOpen && (
            <div
              style={{
                position: "absolute",
                right: 0,
                top: "100%",
                marginTop: 4,
                background: "#1e2230",
                border: "1px solid #2a2e39",
                borderRadius: 4,
                minWidth: 160,
                zIndex: 50,
              }}
            >
              <div
                style={{
                  padding: "8px 12px",
                  fontSize: 12,
                  color: "#6b7280",
                  borderBottom: "1px solid #2a2e39",
                }}
              >
                {user.tenant_id.slice(0, 8)}...
              </div>
              <button
                type="button"
                onClick={handleLogout}
                style={{
                  display: "block",
                  width: "100%",
                  padding: "8px 12px",
                  background: "none",
                  border: "none",
                  color: "#ef4444",
                  fontSize: 13,
                  textAlign: "left",
                  cursor: "pointer",
                }}
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      )}
    </header>
  );
}
