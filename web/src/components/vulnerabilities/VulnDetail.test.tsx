import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { VulnDetail } from "./VulnDetail";

vi.mock("../../services/api", () => ({
  getVulnerability: vi.fn().mockResolvedValue({
    vulnerability: {
      id: "v-1",
      cve_id: "CVE-2024-1234",
      severity: "critical",
      cvss_score: 9.8,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      epss_score: 0.95,
      description: "Remote code execution in Example Library",
      exploitable: true,
      in_cisa_kev: true,
      published_date: "2024-01-15",
      first_seen: "2024-02-01",
      last_seen: "2024-02-10",
    },
  }),
  getVulnAssets: vi.fn().mockResolvedValue({
    assets: [
      { id: "svc-1", name: "nginx" },
      { id: "svc-2", name: "apache" },
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

describe("VulnDetail", () => {
  it("renders the detail panel", () => {
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={vi.fn()} />,
    );
    expect(screen.getByTestId("vuln-detail-panel")).toBeDefined();
  });

  it("displays CVE ID", async () => {
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("CVE-2024-1234")).toBeDefined();
    });
  });

  it("shows severity badge after loading", async () => {
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("critical")).toBeDefined();
    });
  });

  it("shows CVSS and EPSS scores", async () => {
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("9.8")).toBeDefined();
    });
    expect(screen.getByText("95.0%")).toBeDefined();
  });

  it("shows KEV warning", async () => {
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText(/Known Exploited Vulnerability/)).toBeDefined();
    });
  });

  it("shows description", async () => {
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("Remote code execution in Example Library")).toBeDefined();
    });
  });

  it("shows affected assets", async () => {
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={vi.fn()} />,
    );
    await waitFor(() => {
      expect(screen.getByText("nginx")).toBeDefined();
    });
    expect(screen.getByText("apache")).toBeDefined();
  });

  it("calls onClose when close button is clicked", () => {
    const onClose = vi.fn();
    renderWithQuery(
      <VulnDetail cveId="CVE-2024-1234" onClose={onClose} />,
    );
    fireEvent.click(screen.getByLabelText("Close detail panel"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onNavigateToAsset when an asset is clicked", async () => {
    const onNav = vi.fn();
    renderWithQuery(
      <VulnDetail
        cveId="CVE-2024-1234"
        onClose={vi.fn()}
        onNavigateToAsset={onNav}
      />,
    );
    await waitFor(() => {
      expect(screen.getByText("nginx")).toBeDefined();
    });
    fireEvent.click(screen.getByText("nginx"));
    expect(onNav).toHaveBeenCalledWith("svc-1");
  });
});
