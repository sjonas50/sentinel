import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AttackPathList } from "./AttackPathList";

vi.mock("../../services/api", () => ({
  listAttackPaths: vi.fn().mockResolvedValue({
    paths: [
      {
        id: "ap-1",
        tenant_id: "t-1",
        steps: [
          { node_id: "n-1", edge_id: "e-1", description: "step 1", exploitability: 8 },
          { node_id: "n-2", edge_id: "e-2", description: "step 2", exploitability: 6 },
        ],
        risk_score: 9.2,
        source_node: "web-server",
        target_node: "db-server",
        computed_at: "2024-06-01",
      },
      {
        id: "ap-2",
        tenant_id: "t-1",
        steps: [
          { node_id: "n-3", edge_id: "e-3", description: "step 1", exploitability: 3 },
        ],
        risk_score: 4.5,
        source_node: "app-server",
        target_node: "cache-server",
        computed_at: "2024-06-02",
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

describe("AttackPathList", () => {
  it("renders attack path rows", async () => {
    renderWithQuery(<AttackPathList />);
    await waitFor(() => {
      expect(screen.getByText("web-server")).toBeDefined();
    });
    expect(screen.getByText("app-server")).toBeDefined();
  });

  it("renders risk badges with scores", async () => {
    renderWithQuery(<AttackPathList />);
    await waitFor(() => {
      expect(screen.getByText("9.2")).toBeDefined();
    });
    const badges = screen.getAllByTestId("risk-badge");
    expect(badges.length).toBe(2);
    expect(badges[0]!.textContent).toBe("9.2");
    expect(badges[1]!.textContent).toBe("4.5");
  });

  it("calls onSelectPath when row is clicked", async () => {
    const onSelect = vi.fn();
    renderWithQuery(<AttackPathList onSelectPath={onSelect} />);
    await waitFor(() => {
      expect(screen.getByText("web-server")).toBeDefined();
    });
    fireEvent.click(screen.getByText("web-server").closest("tr")!);
    expect(onSelect).toHaveBeenCalledWith("ap-1");
  });

  it("renders pagination info", async () => {
    renderWithQuery(<AttackPathList />);
    await waitFor(() => {
      expect(screen.getByText(/Showing 1/)).toBeDefined();
    });
  });

  it("renders risk level filter", () => {
    renderWithQuery(<AttackPathList />);
    expect(screen.getByLabelText("Filter by risk level")).toBeDefined();
  });
});
