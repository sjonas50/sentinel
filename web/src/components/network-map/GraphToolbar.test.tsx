import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { GraphToolbar } from "./GraphToolbar";

vi.mock("../../hooks/useGraphSearch", () => ({
  useGraphSearch: vi.fn().mockReturnValue({
    data: null,
    isLoading: false,
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

describe("GraphToolbar", () => {
  const defaultProps = {
    viewMode: "graph" as const,
    onViewModeChange: vi.fn(),
    activeLabels: ["Host", "Service"],
    onActiveLabelsChange: vi.fn(),
  };

  it("renders search input", () => {
    renderWithQuery(<GraphToolbar {...defaultProps} />);
    expect(screen.getByPlaceholderText("Search nodes...")).toBeDefined();
  });

  it("renders view toggle buttons", () => {
    renderWithQuery(<GraphToolbar {...defaultProps} />);
    expect(screen.getByLabelText("Graph view")).toBeDefined();
    expect(screen.getByLabelText("Table view")).toBeDefined();
  });

  it("calls onViewModeChange when Table is clicked", () => {
    const onViewModeChange = vi.fn();
    renderWithQuery(
      <GraphToolbar {...defaultProps} onViewModeChange={onViewModeChange} />,
    );
    fireEvent.click(screen.getByLabelText("Table view"));
    expect(onViewModeChange).toHaveBeenCalledWith("table");
  });

  it("renders label filter pills", () => {
    renderWithQuery(<GraphToolbar {...defaultProps} />);
    expect(screen.getByText("Host")).toBeDefined();
    expect(screen.getByText("Service")).toBeDefined();
    expect(screen.getByText("User")).toBeDefined();
    expect(screen.getByText("Subnet")).toBeDefined();
    expect(screen.getByText("Vpc")).toBeDefined();
  });

  it("toggles label filters on click", () => {
    const onLabelsChange = vi.fn();
    renderWithQuery(
      <GraphToolbar
        {...defaultProps}
        onActiveLabelsChange={onLabelsChange}
      />,
    );
    // Click "User" to add it
    fireEvent.click(screen.getByText("User"));
    expect(onLabelsChange).toHaveBeenCalledWith(["Host", "Service", "User"]);
  });

  it("removes a label when clicking an active label", () => {
    const onLabelsChange = vi.fn();
    renderWithQuery(
      <GraphToolbar
        {...defaultProps}
        onActiveLabelsChange={onLabelsChange}
      />,
    );
    // Click "Host" to remove it (Service still active so it's allowed)
    fireEvent.click(screen.getByText("Host"));
    expect(onLabelsChange).toHaveBeenCalledWith(["Service"]);
  });

  it("prevents removing the last active label", () => {
    const onLabelsChange = vi.fn();
    renderWithQuery(
      <GraphToolbar
        {...defaultProps}
        activeLabels={["Host"]}
        onActiveLabelsChange={onLabelsChange}
      />,
    );
    fireEvent.click(screen.getByText("Host"));
    expect(onLabelsChange).not.toHaveBeenCalled();
  });
});
