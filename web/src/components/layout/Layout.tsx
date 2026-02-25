import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";

export function Layout() {
  return (
    <div style={{ display: "flex", height: "100vh", background: "#0f1117", color: "#e0e0e0" }}>
      <Sidebar />
      <main style={{ flex: 1, padding: "24px", overflowY: "auto" }}>
        <Outlet />
      </main>
    </div>
  );
}
