/**
 * Filterable, paginated hunt findings table.
 */

import { useState } from "react";
import { useHuntFindings } from "../../hooks/useHuntFindings";
import type { HuntFindingListParams } from "../../services/api";

const PAGE_SIZE = 50;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export interface HuntFeedProps {
  onSelectFinding?: (findingId: string) => void;
}

export function HuntFeed({ onSelectFinding }: HuntFeedProps) {
  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [playbookFilter, setPlaybookFilter] = useState<string>("");

  const params: HuntFindingListParams = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };
  if (severityFilter) params.severity = severityFilter;
  if (playbookFilter) params.playbook = playbookFilter;

  const { data, isLoading } = useHuntFindings(params);

  const findings = data?.findings ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

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

        <select
          value={playbookFilter}
          onChange={(e) => {
            setPlaybookFilter(e.target.value);
            setPage(0);
          }}
          style={selectStyle}
          aria-label="Filter by playbook"
        >
          <option value="">All Playbooks</option>
          <option value="credential_abuse">Credential Abuse</option>
          <option value="lateral_movement">Lateral Movement</option>
          <option value="data_exfiltration">Data Exfiltration</option>
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          Loading...
        </div>
      ) : findings.length === 0 ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          No hunt findings found.
        </div>
      ) : (
        <>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={thStyle}>Severity</th>
                <th style={thStyle}>Title</th>
                <th style={thStyle}>Playbook</th>
                <th style={thStyle}>MITRE Tactic</th>
                <th style={thStyle}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => onSelectFinding?.(f.id)}
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
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td style={tdStyle}>
                    <span style={{ fontWeight: 500 }}>{f.title}</span>
                  </td>
                  <td style={tdStyle}>{f.playbook}</td>
                  <td style={tdStyle}>{f.mitre_tactic}</td>
                  <td style={tdStyle}>{f.timestamp}</td>
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
