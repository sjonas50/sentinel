import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AttackPathDetail } from "./AttackPathDetail";

vi.mock("../../services/api", () => ({
  getAttackPath: vi.fn().mockResolvedValue({
    path: {
      id: "ap-1",
      tenant_id: "t-1",
      steps: [
        {
          node_id: "n-1",
          edge_id: "e-1",
          technique: "T1190",
          description: "Exploit public-facing application",
          exploitability: 8.5,
        },
        {
          node_id: "n-2",
          edge_id: "e-2",
          description: "Lateral movement via SSH",
          exploitability: 6.0,
        },
      ],
      risk_score: 9.2,
      source_node: "web-server",
      target_node: "db-server",
      computed_at: "2024-06-01",
      remediation: [
        {
          title: "Patch web server",
          description: "Apply CVE-2024-1234 patch to the web server",
          priority: "critical",
          effort: "low",
          automated: true,
        },
      ],
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

describe("AttackPathDetail", () => {
  it("renders the detail panel", () => {
    renderWithQuery(
      <AttackPathDetail pathId="ap-1" onClose={vi.fn()} />,
    );
    expect(screen.getByTestId("path-detail-panel")).toBeDefined();
  });

  it("displays risk score", async () => {
    renderWithQuery(
      <AttackPathDetail pathId="ap-1" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getAllByText("9.2").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("renders steps", async () => {
    renderWithQuery(
      <AttackPathDetail pathId="ap-1" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("n-1")).toBeDefined();
    });
    expect(screen.getByText("n-2")).toBeDefined();
    expect(screen.getByText("T1190")).toBeDefined();
    expect(screen.getByText("Exploit public-facing application")).toBeDefined();
    expect(screen.getByText("Lateral movement via SSH")).toBeDefined();
  });

  it("renders remediation", async () => {
    renderWithQuery(
      <AttackPathDetail pathId="ap-1" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("Patch web server")).toBeDefined();
    });
    expect(
      screen.getByText("Apply CVE-2024-1234 patch to the web server"),
    ).toBeDefined();
    expect(screen.getByText("critical")).toBeDefined();
  });

  it("renders Show on Map button", async () => {
    renderWithQuery(
      <AttackPathDetail pathId="ap-1" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("Show on Map")).toBeDefined();
    });
  });

  it("calls onClose when close button is clicked", () => {
    const onClose = vi.fn();
    renderWithQuery(
      <AttackPathDetail pathId="ap-1" onClose={onClose} />,
    );
    fireEvent.click(screen.getByLabelText("Close detail panel"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onShowOnMap when Show on Map is clicked", async () => {
    const onShowOnMap = vi.fn();
    renderWithQuery(
      <AttackPathDetail
        pathId="ap-1"
        onClose={vi.fn()}
        onShowOnMap={onShowOnMap}
      />,
    );
    await waitFor(() => {
      expect(screen.getByText("Show on Map")).toBeDefined();
    });
    fireEvent.click(screen.getByText("Show on Map"));
    expect(onShowOnMap).toHaveBeenCalledWith("ap-1");
  });
});
