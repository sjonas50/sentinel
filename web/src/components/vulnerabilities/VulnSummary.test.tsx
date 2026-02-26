import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { VulnSummary } from "./VulnSummary";

vi.mock("../../services/api", () => ({
  fetchVulnSummary: vi.fn().mockResolvedValue({
    tenant_id: "t-1",
    by_severity: [
      { severity: "critical", count: 3 },
      { severity: "high", count: 12 },
      { severity: "medium", count: 25 },
      { severity: "low", count: 8 },
    ],
    total: 48,
    exploitable_count: 5,
    kev_count: 2,
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

describe("VulnSummary", () => {
  it("renders severity cards", async () => {
    renderWithQuery(<VulnSummary />);
    await waitFor(() => {
      expect(screen.getByText("3")).toBeDefined();
    });
    expect(screen.getByText("12")).toBeDefined();
    expect(screen.getByText("25")).toBeDefined();
    expect(screen.getByText("8")).toBeDefined();
  });

  it("renders KEV count card", async () => {
    renderWithQuery(<VulnSummary />);
    await waitFor(() => {
      expect(screen.getByText("2")).toBeDefined();
    });
    expect(screen.getByText("CISA KEV")).toBeDefined();
  });

  it("renders all severity labels", () => {
    renderWithQuery(<VulnSummary />);
    expect(screen.getByText("Critical")).toBeDefined();
    expect(screen.getByText("High")).toBeDefined();
    expect(screen.getByText("Medium")).toBeDefined();
    expect(screen.getByText("Low")).toBeDefined();
  });
});
