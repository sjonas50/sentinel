import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NetworkGraph } from "./NetworkGraph";
import type { TopologyNode, TopologyEdge } from "../../services/api";

// Mock ResizeObserver
beforeEach(() => {
  vi.stubGlobal(
    "ResizeObserver",
    vi.fn(() => ({
      observe: vi.fn(),
      unobserve: vi.fn(),
      disconnect: vi.fn(),
    })),
  );
});

function renderWithQuery(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

const mockNodes: TopologyNode[] = [
  { id: "host-1", label: "Host", properties: { hostname: "web-01", ip: "10.0.0.1" } },
  { id: "svc-1", label: "Service", properties: { name: "nginx", port: 443 } },
  { id: "subnet-1", label: "Subnet", properties: { cidr: "10.0.0.0/24" } },
];

const mockEdges: TopologyEdge[] = [
  { id: "e-1", source_id: "host-1", target_id: "svc-1", edge_type: "RUNS_ON" },
  { id: "e-2", source_id: "host-1", target_id: "subnet-1", edge_type: "BELONGS_TO_SUBNET" },
];

describe("NetworkGraph", () => {
  it("renders an SVG element", () => {
    renderWithQuery(<NetworkGraph nodes={mockNodes} edges={mockEdges} />);
    expect(screen.getByTestId("network-graph-svg")).toBeDefined();
  });

  it("renders correct number of node groups", () => {
    renderWithQuery(<NetworkGraph nodes={mockNodes} edges={mockEdges} />);
    const svg = screen.getByTestId("network-graph-svg");
    const nodeGroups = svg.querySelectorAll(".nodes > g");
    expect(nodeGroups.length).toBe(3);
  });

  it("renders correct number of edge lines", () => {
    renderWithQuery(<NetworkGraph nodes={mockNodes} edges={mockEdges} />);
    const svg = screen.getByTestId("network-graph-svg");
    const lines = svg.querySelectorAll(".edges > line");
    expect(lines.length).toBe(2);
  });

  it("fires onSelectNode when a node group is clicked", () => {
    const onSelect = vi.fn();
    renderWithQuery(
      <NetworkGraph
        nodes={mockNodes}
        edges={mockEdges}
        onSelectNode={onSelect}
      />,
    );
    const svg = screen.getByTestId("network-graph-svg");
    const nodeGroup = svg.querySelector(".nodes > g");
    if (nodeGroup) fireEvent.click(nodeGroup);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it("renders with empty data", () => {
    renderWithQuery(<NetworkGraph nodes={[]} edges={[]} />);
    const svg = screen.getByTestId("network-graph-svg");
    expect(svg.querySelectorAll(".nodes > g").length).toBe(0);
  });

  it("ignores edges with missing node references", () => {
    const badEdge: TopologyEdge = {
      id: "e-bad",
      source_id: "nonexistent",
      target_id: "host-1",
      edge_type: "CONNECTS_TO",
    };
    renderWithQuery(
      <NetworkGraph nodes={mockNodes} edges={[...mockEdges, badEdge]} />,
    );
    const svg = screen.getByTestId("network-graph-svg");
    // Bad edge should be filtered out
    expect(svg.querySelectorAll(".edges > line").length).toBe(2);
  });
});
