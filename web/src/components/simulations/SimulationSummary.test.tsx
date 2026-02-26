import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SimulationSummary } from "./SimulationSummary";

vi.mock("../../services/api", () => ({
  fetchSimulationSummary: vi.fn().mockResolvedValue({
    tenant_id: "t-1",
    total_runs: 12,
    techniques_tested: 45,
    total_findings: 8,
    highest_risk_score: 85,
    by_tactic: {
      initial_access: 3,
      lateral_movement: 5,
      privilege_escalation: 2,
      exfiltration: 2,
    },
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

describe("SimulationSummary", () => {
  it("renders KPI cards", async () => {
    renderWithQuery(<SimulationSummary />);
    await waitFor(() => {
      expect(screen.getByText("12")).toBeDefined();
    });
    expect(screen.getByText("45")).toBeDefined();
    expect(screen.getByText("8")).toBeDefined();
    expect(screen.getByText("85")).toBeDefined();
  });

  it("renders all card labels", async () => {
    renderWithQuery(<SimulationSummary />);
    await waitFor(() => {
      expect(screen.getByText("Total Runs")).toBeDefined();
    });
    expect(screen.getByText("Techniques Tested")).toBeDefined();
    expect(screen.getByText("Findings")).toBeDefined();
    expect(screen.getByText("Highest Risk")).toBeDefined();
  });
});
