import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HuntSummary } from "./HuntSummary";

vi.mock("../../services/api", () => ({
  fetchHuntSummary: vi.fn().mockResolvedValue({
    tenant_id: "t-1",
    by_severity: [
      { severity: "critical", count: 1 },
      { severity: "high", count: 2 },
      { severity: "medium", count: 0 },
      { severity: "low", count: 0 },
    ],
    total_findings: 3,
    active_hunts: 1,
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

describe("HuntSummary", () => {
  it("renders severity cards", async () => {
    renderWithQuery(<HuntSummary />);
    await waitFor(() => {
      expect(screen.getByText("2")).toBeDefined();
    });
    // critical=1 and active_hunts=1 both show "1"
    const ones = screen.getAllByText("1");
    expect(ones.length).toBe(2);
  });

  it("renders Active Hunts card", async () => {
    renderWithQuery(<HuntSummary />);
    await waitFor(() => {
      expect(screen.getByText("Active Hunts")).toBeDefined();
    });
  });

  it("renders all severity labels", () => {
    renderWithQuery(<HuntSummary />);
    expect(screen.getByText("Critical")).toBeDefined();
    expect(screen.getByText("High")).toBeDefined();
    expect(screen.getByText("Medium")).toBeDefined();
    expect(screen.getByText("Low")).toBeDefined();
  });
});
