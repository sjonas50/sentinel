import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SimulationList } from "./SimulationList";

vi.mock("../../services/api", () => ({
  listSimulations: vi.fn().mockResolvedValue({
    simulations: [
      {
        id: "sim-1",
        tactic: "lateral_movement",
        techniques_tested: 5,
        techniques_with_findings: 2,
        findings_count: 3,
        highest_risk_score: 78,
        duration_seconds: 120,
        summary: "Tested lateral movement techniques",
        created_at: "2024-06-01",
      },
      {
        id: "sim-2",
        tactic: "initial_access",
        techniques_tested: 8,
        techniques_with_findings: 1,
        findings_count: 1,
        highest_risk_score: 45,
        duration_seconds: 65,
        summary: "Tested initial access vectors",
        created_at: "2024-06-02",
      },
    ],
    total: 2,
    limit: 50,
    offset: 0,
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

describe("SimulationList", () => {
  it("renders simulation rows", async () => {
    renderWithQuery(<SimulationList />);
    await waitFor(() => {
      expect(screen.getByText("2024-06-01")).toBeDefined();
    });
    expect(screen.getByText("2024-06-02")).toBeDefined();
  });

  it("renders filter control", () => {
    renderWithQuery(<SimulationList />);
    expect(screen.getByLabelText("Filter by tactic")).toBeDefined();
  });

  it("calls onSelectSimulation on click", async () => {
    const onSelect = vi.fn();
    renderWithQuery(<SimulationList onSelectSimulation={onSelect} />);
    await waitFor(() => {
      expect(screen.getByText("2024-06-01")).toBeDefined();
    });
    fireEvent.click(screen.getByText("2024-06-01").closest("tr")!);
    expect(onSelect).toHaveBeenCalledWith("sim-1");
  });

  it("renders pagination", async () => {
    renderWithQuery(<SimulationList />);
    await waitFor(() => {
      expect(screen.getByText(/Showing 1/)).toBeDefined();
    });
  });
});
