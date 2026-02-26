import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App } from "./App";
import { AuthProvider } from "./hooks/useAuth";

function renderApp(route = "/") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[route]}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function setFakeAuth() {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(
    JSON.stringify({ sub: "test", tenant_id: "00000000-0000-0000-0000-000000000001", role: "admin" }),
  );
  localStorage.setItem("sentinel_token", `${header}.${payload}.sig`);
  localStorage.setItem(
    "sentinel_user",
    JSON.stringify({ sub: "test", tenant_id: "00000000-0000-0000-0000-000000000001", role: "admin" }),
  );
}

describe("App routing", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("redirects to login when not authenticated", () => {
    renderApp("/discover");
    expect(screen.getByText("Sign in to your account")).toBeDefined();
  });

  it("shows login page at /login", () => {
    renderApp("/login");
    expect(screen.getByRole("button", { name: "Sign in" })).toBeDefined();
  });

  it("shows Discover page when authenticated", () => {
    setFakeAuth();
    renderApp("/discover");
    expect(screen.getByRole("heading", { name: "Discover" })).toBeDefined();
    expect(screen.getByText(/Network digital twin/)).toBeDefined();
  });

  it("shows Defend page when authenticated", () => {
    setFakeAuth();
    renderApp("/defend");
    expect(screen.getByRole("heading", { name: "Defend" })).toBeDefined();
    expect(screen.getAllByText("Attack Paths").length).toBeGreaterThan(0);
  });

  it("shows Govern page when authenticated", () => {
    setFakeAuth();
    renderApp("/govern");
    expect(screen.getByRole("heading", { name: "Govern" })).toBeDefined();
    expect(screen.getByText("Policy Dashboard")).toBeDefined();
  });

  it("shows Observe page when authenticated", () => {
    setFakeAuth();
    renderApp("/observe");
    expect(screen.getByRole("heading", { name: "Observe" })).toBeDefined();
    expect(screen.getByText("Engram Timeline")).toBeDefined();
  });
});
