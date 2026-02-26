import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AssetTable } from "./AssetTable";

vi.mock("../../services/api", () => ({
  listNodes: vi.fn().mockImplementation((label: string) => {
    if (label === "Host") {
      return Promise.resolve({
        nodes: [
          { id: "h-1", hostname: "web-01", ip: "10.0.0.1", os: "Ubuntu", cloud_provider: "aws", criticality: "high" },
          { id: "h-2", hostname: "db-01", ip: "10.0.0.2", os: "RHEL", cloud_provider: "aws", criticality: "critical" },
        ],
        total: 2,
        limit: 25,
        offset: 0,
      });
    }
    if (label === "Service") {
      return Promise.resolve({
        nodes: [
          { id: "s-1", name: "nginx", port: 443, protocol: "https", state: "running" },
        ],
        total: 1,
        limit: 25,
        offset: 0,
      });
    }
    return Promise.resolve({ nodes: [], total: 0, limit: 25, offset: 0 });
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

describe("AssetTable", () => {
  it("renders tab buttons for each label", () => {
    renderWithQuery(<AssetTable />);
    expect(screen.getByText("Host")).toBeDefined();
    expect(screen.getByText("Service")).toBeDefined();
    expect(screen.getByText("User")).toBeDefined();
    expect(screen.getByText("Subnet")).toBeDefined();
    expect(screen.getByText("Vpc")).toBeDefined();
  });

  it("shows Host table data by default", async () => {
    renderWithQuery(<AssetTable />);
    await waitFor(() => {
      expect(screen.getAllByText("web-01").length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText("db-01").length).toBeGreaterThan(0);
    expect(screen.getByText("10.0.0.1")).toBeDefined();
  });

  it("switches to Service tab", async () => {
    renderWithQuery(<AssetTable />);
    fireEvent.click(screen.getAllByText("Service")[0]!);
    await waitFor(() => {
      expect(screen.getAllByText("nginx").length).toBeGreaterThan(0);
    });
  });

  it("calls onSelectNode when a row is clicked", async () => {
    const onSelect = vi.fn();
    renderWithQuery(<AssetTable onSelectNode={onSelect} />);
    await waitFor(() => {
      expect(screen.getAllByText("web-01").length).toBeGreaterThan(0);
    });
    // Click the first data row
    fireEvent.click(screen.getAllByText("web-01")[0]!.closest("tr")!);
    expect(onSelect).toHaveBeenCalledWith("h-1", "Host");
  });

  it("shows empty state for tabs with no data", async () => {
    renderWithQuery(<AssetTable />);
    fireEvent.click(screen.getByText("User"));
    await waitFor(() => {
      expect(screen.getByText("No User nodes found.")).toBeDefined();
    });
  });
});
