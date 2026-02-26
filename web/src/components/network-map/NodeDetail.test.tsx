import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NodeDetail } from "./NodeDetail";

vi.mock("../../services/api", () => ({
  getNode: vi.fn().mockResolvedValue({
    node: {
      id: "host-1",
      hostname: "web-01",
      ip: "10.0.0.1",
      os: "Ubuntu 22.04",
      tenant_id: "t-1",
    },
  }),
  getNeighbors: vi.fn().mockResolvedValue({
    neighbors: [
      {
        node: { id: "svc-1", name: "nginx" },
        relationship: "RUNS_ON",
        labels: ["Service"],
      },
      {
        node: { id: "subnet-1", cidr: "10.0.0.0/24" },
        relationship: "BELONGS_TO_SUBNET",
        labels: ["Subnet"],
      },
    ],
    count: 2,
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

describe("NodeDetail", () => {
  it("renders the detail panel", () => {
    renderWithQuery(
      <NodeDetail nodeId="host-1" label="Host" onClose={vi.fn()} />,
    );
    expect(screen.getByTestId("node-detail-panel")).toBeDefined();
  });

  it("displays the label badge", () => {
    renderWithQuery(
      <NodeDetail nodeId="host-1" label="Host" onClose={vi.fn()} />,
    );
    expect(screen.getByText("Host")).toBeDefined();
  });

  it("shows properties after loading", async () => {
    renderWithQuery(
      <NodeDetail nodeId="host-1" label="Host" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getAllByText("web-01").length).toBeGreaterThan(0);
    });
    expect(screen.getByText("10.0.0.1")).toBeDefined();
    expect(screen.getByText("Ubuntu 22.04")).toBeDefined();
  });

  it("hides tenant_id from properties", async () => {
    renderWithQuery(
      <NodeDetail nodeId="host-1" label="Host" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getAllByText("web-01").length).toBeGreaterThan(0);
    });
    expect(screen.queryByText("t-1")).toBeNull();
  });

  it("shows neighbors grouped by relationship", async () => {
    renderWithQuery(
      <NodeDetail nodeId="host-1" label="Host" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("RUNS_ON")).toBeDefined();
    });
    expect(screen.getByText("BELONGS_TO_SUBNET")).toBeDefined();
    expect(screen.getByText("nginx")).toBeDefined();
  });

  it("calls onClose when close button is clicked", () => {
    const onClose = vi.fn();
    renderWithQuery(
      <NodeDetail nodeId="host-1" label="Host" onClose={onClose} />,
    );
    fireEvent.click(screen.getByLabelText("Close detail panel"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onSelectNode when a neighbor is clicked", async () => {
    const onSelect = vi.fn();
    renderWithQuery(
      <NodeDetail
        nodeId="host-1"
        label="Host"
        onClose={vi.fn()}
        onSelectNode={onSelect}
      />,
    );
    await waitFor(() => {
      expect(screen.getByText("nginx")).toBeDefined();
    });
    fireEvent.click(screen.getByText("nginx"));
    expect(onSelect).toHaveBeenCalledWith("svc-1", "Service");
  });
});
