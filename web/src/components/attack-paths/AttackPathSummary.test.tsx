import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AttackPathSummary } from "./AttackPathSummary";

vi.mock("../../services/api", () => ({
  fetchAttackPathSummary: vi.fn().mockResolvedValue({
    tenant_id: "t-1",
    total_paths: 10,
    by_risk_tier: { critical: 2, high: 3, medium: 3, low: 2 },
    top_paths: [],
  }),
}));

function renderWithQuery(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

describe("AttackPathSummary", () => {
  it("renders risk tier cards", async () => {
    renderWithQuery(<AttackPathSummary />);
    await waitFor(() => {
      expect(screen.getAllByText("2").length).toBe(2);
    });
    expect(screen.getAllByText("3").length).toBe(2);
  });

  it("renders total paths card", async () => {
    renderWithQuery(<AttackPathSummary />);
    await waitFor(() => {
      expect(screen.getByText("10")).toBeDefined();
    });
    expect(screen.getByText("Total")).toBeDefined();
  });

  it("renders all tier labels", () => {
    renderWithQuery(<AttackPathSummary />);
    expect(screen.getByText("Critical")).toBeDefined();
    expect(screen.getByText("High")).toBeDefined();
    expect(screen.getByText("Medium")).toBeDefined();
    expect(screen.getByText("Low")).toBeDefined();
  });
});
