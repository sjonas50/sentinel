/**
 * Filterable, paginated vulnerability table with CSV export.
 */

import { useState, useCallback } from "react";
import { useVulnerabilities } from "../../hooks/useVulnerabilities";
import type { VulnListParams } from "../../services/api";

const PAGE_SIZE = 50;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  none: "#6b7280",
};

export interface VulnTableProps {
  onSelectVuln?: (cveId: string) => void;
}

export function VulnTable({ onSelectVuln }: VulnTableProps) {
  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [exploitableFilter, setExploitableFilter] = useState(false);
  const [kevFilter, setKevFilter] = useState(false);

  const params: VulnListParams = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };
  if (severityFilter) params.severity = severityFilter;
  if (exploitableFilter) params.exploitable = true;
  if (kevFilter) params.in_cisa_kev = true;

  const { data, isLoading } = useVulnerabilities(params);

  const vulns = data?.vulnerabilities ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const exportCsv = useCallback(() => {
    const items = data?.vulnerabilities ?? [];
    if (items.length === 0) return;
    const headers = [
      "CVE ID",
      "Severity",
      "CVSS",
      "EPSS",
      "Exploitable",
      "CISA KEV",
      "Published",
      "Description",
    ];
    const rows = items.map((v) => [
      v.cve_id,
      v.severity,
      v.cvss_score ?? "",
      v.epss_score ?? "",
      v.exploitable ? "Yes" : "No",
      v.in_cisa_kev ? "Yes" : "No",
      v.published_date ?? "",
      `"${(v.description ?? "").replace(/"/g, '""')}"`,
    ]);
    const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join(
      "\n",
    );
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vulnerabilities.csv";
    a.click();
    URL.revokeObjectURL(url);
  }, [data]);

  const thStyle: React.CSSProperties = {
    padding: "8px 12px",
    fontSize: 11,
    fontWeight: 600,
    color: "#9ca3af",
    textTransform: "uppercase",
    letterSpacing: 0.5,
    textAlign: "left",
    borderBottom: "1px solid #2a2e39",
  };

  const tdStyle: React.CSSProperties = {
    padding: "8px 12px",
    fontSize: 13,
    color: "#d1d5db",
    borderBottom: "1px solid #1e2230",
  };

  const selectStyle: React.CSSProperties = {
    padding: "5px 8px",
    fontSize: 12,
    background: "#1e2230",
    border: "1px solid #2a2e39",
    borderRadius: 4,
    color: "#d1d5db",
  };

  const toggleStyle = (active: boolean): React.CSSProperties => ({
    padding: "5px 10px",
    fontSize: 12,
    fontWeight: 500,
    border: `1px solid ${active ? "#3b82f6" : "#374151"}`,
    borderRadius: 4,
    cursor: "pointer",
    background: active ? "rgba(59, 130, 246, 0.15)" : "transparent",
    color: active ? "#60a5fa" : "#6b7280",
  });

  return (
    <div>
      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          marginBottom: 12,
          flexWrap: "wrap",
        }}
      >
        <select
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(0);
          }}
          style={selectStyle}
          aria-label="Filter by severity"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <button
          onClick={() => {
            setExploitableFilter((v) => !v);
            setPage(0);
          }}
          style={toggleStyle(exploitableFilter)}
        >
          Exploitable
        </button>

        <button
          onClick={() => {
            setKevFilter((v) => !v);
            setPage(0);
          }}
          style={toggleStyle(kevFilter)}
        >
          CISA KEV
        </button>

        <div style={{ flex: 1 }} />

        <button
          onClick={exportCsv}
          disabled={vulns.length === 0}
          aria-label="Export CSV"
          style={{
            padding: "5px 12px",
            fontSize: 12,
            background: "#1e2230",
            border: "1px solid #2a2e39",
            borderRadius: 4,
            color: vulns.length === 0 ? "#374151" : "#d1d5db",
            cursor: vulns.length === 0 ? "default" : "pointer",
          }}
        >
          Export CSV
        </button>
      </div>

      {/* Table */}
      {isLoading ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          Loading...
        </div>
      ) : vulns.length === 0 ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          No vulnerabilities found.
        </div>
      ) : (
        <>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={thStyle}>CVE ID</th>
                <th style={thStyle}>Severity</th>
                <th style={thStyle}>CVSS</th>
                <th style={thStyle}>EPSS</th>
                <th style={thStyle}>KEV</th>
                <th style={thStyle}>Published</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map((v) => (
                <tr
                  key={v.cve_id}
                  onClick={() => onSelectVuln?.(v.cve_id)}
                  style={{ cursor: "pointer" }}
                  onMouseOver={(e) => {
                    (e.currentTarget as HTMLElement).style.background =
                      "#1e2230";
                  }}
                  onMouseOut={(e) => {
                    (e.currentTarget as HTMLElement).style.background =
                      "transparent";
                  }}
                >
                  <td style={tdStyle}>
                    <span style={{ fontWeight: 500 }}>{v.cve_id}</span>
                  </td>
                  <td style={tdStyle}>
                    <SeverityBadge severity={v.severity} />
                  </td>
                  <td style={tdStyle}>
                    {v.cvss_score != null ? v.cvss_score.toFixed(1) : "—"}
                  </td>
                  <td style={tdStyle}>
                    {v.epss_score != null
                      ? `${(v.epss_score * 100).toFixed(1)}%`
                      : "—"}
                  </td>
                  <td style={tdStyle}>
                    {v.in_cisa_kev && <KevBadge />}
                  </td>
                  <td style={tdStyle}>
                    {v.published_date ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "12px 0",
              fontSize: 12,
              color: "#6b7280",
            }}
          >
            <span>
              Showing {page * PAGE_SIZE + 1}–
              {Math.min((page + 1) * PAGE_SIZE, total)} of {total}
            </span>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => p - 1)}
                style={{
                  padding: "4px 10px",
                  fontSize: 12,
                  background: "#1e2230",
                  border: "1px solid #2a2e39",
                  borderRadius: 4,
                  color: page === 0 ? "#374151" : "#d1d5db",
                  cursor: page === 0 ? "default" : "pointer",
                }}
              >
                Prev
              </button>
              <span style={{ padding: "4px 0" }}>
                {page + 1} / {totalPages}
              </span>
              <button
                disabled={page + 1 >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                style={{
                  padding: "4px 10px",
                  fontSize: 12,
                  background: "#1e2230",
                  border: "1px solid #2a2e39",
                  borderRadius: 4,
                  color: page + 1 >= totalPages ? "#374151" : "#d1d5db",
                  cursor: page + 1 >= totalPages ? "default" : "pointer",
                }}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? "#6b7280";
  return (
    <span
      data-testid="severity-badge"
      style={{
        display: "inline-block",
        padding: "2px 8px",
        fontSize: 11,
        fontWeight: 600,
        borderRadius: 4,
        background: `${color}22`,
        color,
        textTransform: "uppercase",
      }}
    >
      {severity}
    </span>
  );
}

function KevBadge() {
  return (
    <span
      data-testid="kev-badge"
      style={{
        display: "inline-block",
        padding: "2px 8px",
        fontSize: 10,
        fontWeight: 600,
        borderRadius: 4,
        background: "rgba(239, 68, 68, 0.15)",
        color: "#ef4444",
      }}
    >
      KEV
    </span>
  );
}
