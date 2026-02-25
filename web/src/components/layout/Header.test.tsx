import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../../hooks/useAuth";
import { Header } from "./Header";

function renderHeader(title: string) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <Header title={title} />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("Header", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("renders the page title", () => {
    renderHeader("Discover");
    expect(screen.getByText("Discover")).toBeDefined();
  });

  it("shows user button when authenticated", () => {
    localStorage.setItem(
      "sentinel_user",
      JSON.stringify({ sub: "alice", tenant_id: "t1", role: "admin" }),
    );
    localStorage.setItem("sentinel_token", "fake.token.sig");

    renderHeader("Defend");
    expect(screen.getByText("alice")).toBeDefined();
    expect(screen.getByText("admin")).toBeDefined();
  });
});
