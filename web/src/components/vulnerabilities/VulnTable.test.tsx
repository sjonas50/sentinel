import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { VulnTable } from "./VulnTable";

vi.mock("../../services/api", () => ({
  listVulnerabilities: vi.fn().mockResolvedValue({
    vulnerabilities: [
      {
        id: "v-1",
        cve_id: "CVE-2024-1234",
        severity: "critical",
        cvss_score: 9.8,
        epss_score: 0.95,
        exploitable: true,
        in_cisa_kev: true,
        published_date: "2024-01-15",
        first_seen: "2024-02-01",
        last_seen: "2024-02-10",
      },
      {
        id: "v-2",
        cve_id: "CVE-2024-5678",
        severity: "medium",
        cvss_score: 5.3,
        epss_score: 0.02,
        exploitable: false,
        in_cisa_kev: false,
        published_date: "2024-03-10",
        first_seen: "2024-03-15",
        last_seen: "2024-03-20",
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

describe("VulnTable", () => {
  it("renders vulnerability rows", async () => {
    renderWithQuery(<VulnTable />);
    await waitFor(() => {
      expect(screen.getByText("CVE-2024-1234")).toBeDefined();
    });
    expect(screen.getByText("CVE-2024-5678")).toBeDefined();
  });

  it("renders severity badges", async () => {
    renderWithQuery(<VulnTable />);
    await waitFor(() => {
      expect(screen.getByText("CVE-2024-1234")).toBeDefined();
    });
    const badges = screen.getAllByTestId("severity-badge");
    expect(badges.length).toBe(2);
    expect(badges[0]!.textContent).toBe("critical");
    expect(badges[1]!.textContent).toBe("medium");
  });

  it("renders KEV badge for KEV vulnerabilities", async () => {
    renderWithQuery(<VulnTable />);
    await waitFor(() => {
      expect(screen.getByText("CVE-2024-1234")).toBeDefined();
    });
    const kevBadges = screen.getAllByTestId("kev-badge");
    expect(kevBadges.length).toBe(1);
  });

  it("renders CVSS and EPSS scores", async () => {
    renderWithQuery(<VulnTable />);
    await waitFor(() => {
      expect(screen.getByText("9.8")).toBeDefined();
    });
    expect(screen.getByText("95.0%")).toBeDefined();
    expect(screen.getByText("5.3")).toBeDefined();
    expect(screen.getByText("2.0%")).toBeDefined();
  });

  it("renders filter controls", () => {
    renderWithQuery(<VulnTable />);
    expect(screen.getByLabelText("Filter by severity")).toBeDefined();
    expect(screen.getByText("Exploitable")).toBeDefined();
    expect(screen.getByText("CISA KEV")).toBeDefined();
  });

  it("renders Export CSV button", () => {
    renderWithQuery(<VulnTable />);
    expect(screen.getByLabelText("Export CSV")).toBeDefined();
  });

  it("calls onSelectVuln when row is clicked", async () => {
    const onSelect = vi.fn();
    renderWithQuery(<VulnTable onSelectVuln={onSelect} />);
    await waitFor(() => {
      expect(screen.getByText("CVE-2024-1234")).toBeDefined();
    });
    fireEvent.click(screen.getByText("CVE-2024-1234").closest("tr")!);
    expect(onSelect).toHaveBeenCalledWith("CVE-2024-1234");
  });

  it("renders pagination info", async () => {
    renderWithQuery(<VulnTable />);
    await waitFor(() => {
      expect(screen.getByText(/Showing 1/)).toBeDefined();
    });
  });
});
