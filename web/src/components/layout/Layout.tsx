import { Outlet, useLocation } from "react-router-dom";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";

const routeTitles: Record<string, string> = {
  "/discover": "Discover",
  "/defend": "Defend",
  "/govern": "Govern",
  "/observe": "Observe",
};

export function Layout() {
  const location = useLocation();
  const title = routeTitles[location.pathname] ?? "Sentinel";

  return (
    <div style={{ display: "flex", height: "100vh", background: "#0f1117", color: "#e0e0e0" }}>
      <Sidebar />
      <main style={{ flex: 1, padding: "24px", overflowY: "auto" }}>
        <Header title={title} />
        <Outlet />
      </main>
    </div>
  );
}
