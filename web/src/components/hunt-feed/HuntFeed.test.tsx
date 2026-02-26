import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HuntFeed } from "./HuntFeed";

vi.mock("../../services/api", () => ({
  listHuntFindings: vi.fn().mockResolvedValue({
    findings: [
      {
        id: "hf-1",
        playbook: "credential_abuse",
        severity: "critical",
        title: "Brute force login detected",
        description: "Multiple failed logins from single IP",
        evidence: { source_ip: "10.0.0.5" },
        recommendations: ["Block IP", "Reset passwords"],
        affected_hosts: ["web-01"],
        affected_users: ["admin"],
        mitre_technique_ids: ["T1110"],
        mitre_tactic: "credential_access",
        timestamp: "2024-06-01T12:00:00Z",
      },
      {
        id: "hf-2",
        playbook: "lateral_movement",
        severity: "high",
        title: "Unusual SMB activity",
        description: "SMB connections to multiple hosts",
        evidence: { dest_count: 15 },
        recommendations: ["Investigate source host"],
        affected_hosts: ["dc-01"],
        affected_users: ["svc-account"],
        mitre_technique_ids: ["T1021"],
        mitre_tactic: "lateral_movement",
        timestamp: "2024-06-01T13:00:00Z",
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

describe("HuntFeed", () => {
  it("renders finding rows", async () => {
    renderWithQuery(<HuntFeed />);
    await waitFor(() => {
      expect(screen.getByText("Brute force login detected")).toBeDefined();
    });
    expect(screen.getByText("Unusual SMB activity")).toBeDefined();
  });

  it("renders severity badges", async () => {
    renderWithQuery(<HuntFeed />);
    await waitFor(() => {
      expect(screen.getByText("Brute force login detected")).toBeDefined();
    });
    const badges = screen.getAllByTestId("severity-badge");
    expect(badges.length).toBe(2);
    expect(badges[0]!.textContent).toBe("critical");
    expect(badges[1]!.textContent).toBe("high");
  });

  it("renders filter controls", () => {
    renderWithQuery(<HuntFeed />);
    expect(screen.getByLabelText("Filter by severity")).toBeDefined();
    expect(screen.getByLabelText("Filter by playbook")).toBeDefined();
  });

  it("calls onSelectFinding on click", async () => {
    const onSelect = vi.fn();
    renderWithQuery(<HuntFeed onSelectFinding={onSelect} />);
    await waitFor(() => {
      expect(screen.getByText("Brute force login detected")).toBeDefined();
    });
    fireEvent.click(
      screen.getByText("Brute force login detected").closest("tr")!,
    );
    expect(onSelect).toHaveBeenCalledWith("hf-1");
  });

  it("renders pagination", async () => {
    renderWithQuery(<HuntFeed />);
    await waitFor(() => {
      expect(screen.getByText(/Showing 1/)).toBeDefined();
    });
  });
});
