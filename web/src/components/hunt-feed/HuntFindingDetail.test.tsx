import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HuntFindingDetail } from "./HuntFindingDetail";

vi.mock("../../services/api", () => ({
  getHuntFinding: vi.fn().mockResolvedValue({
    finding: {
      id: "hf-1",
      playbook: "credential_abuse",
      severity: "critical",
      title: "Brute force login detected",
      description: "Multiple failed logins from single IP",
      evidence: { source_ip: "10.0.0.5", attempts: "42" },
      recommendations: ["Block the source IP", "Reset affected passwords"],
      affected_hosts: ["web-01", "web-02"],
      affected_users: ["admin"],
      mitre_technique_ids: ["T1110", "T1078"],
      mitre_tactic: "credential_access",
      timestamp: "2024-06-01T12:00:00Z",
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

describe("HuntFindingDetail", () => {
  it("renders the detail panel", () => {
    renderWithQuery(
      <HuntFindingDetail findingId="hf-1" onClose={vi.fn()} />,
    );
    expect(screen.getByTestId("finding-detail-panel")).toBeDefined();
  });

  it("displays title and severity", async () => {
    renderWithQuery(
      <HuntFindingDetail findingId="hf-1" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("Brute force login detected")).toBeDefined();
    });
    expect(screen.getByText("critical")).toBeDefined();
  });

  it("renders MITRE techniques", async () => {
    renderWithQuery(
      <HuntFindingDetail findingId="hf-1" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("T1110")).toBeDefined();
    });
    expect(screen.getByText("T1078")).toBeDefined();
    const techniques = screen.getAllByTestId("mitre-technique");
    expect(techniques.length).toBe(2);
  });

  it("renders recommendations", async () => {
    renderWithQuery(
      <HuntFindingDetail findingId="hf-1" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("Block the source IP")).toBeDefined();
    });
    expect(screen.getByText("Reset affected passwords")).toBeDefined();
  });

  it("calls onClose when close button is clicked", () => {
    const onClose = vi.fn();
    renderWithQuery(
      <HuntFindingDetail findingId="hf-1" onClose={onClose} />,
    );
    fireEvent.click(screen.getByLabelText("Close detail panel"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
