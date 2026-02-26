/**
 * Filterable, paginated attack path table.
 */

import { useState } from "react";
import { useAttackPaths } from "../../hooks/useAttackPaths";
import type { AttackPathListParams } from "../../services/api";

const PAGE_SIZE = 50;

function riskColor(score: number): string {
  if (score >= 9) return "#ef4444";
  if (score >= 7) return "#f97316";
  if (score >= 4) return "#eab308";
  return "#3b82f6";
}

export interface AttackPathListProps {
  onSelectPath?: (pathId: string) => void;
}

export function AttackPathList({ onSelectPath }: AttackPathListProps) {
  const [page, setPage] = useState(0);
  const [riskFilter, setRiskFilter] = useState<string>("");

  const params: AttackPathListParams = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };
  if (riskFilter) params.min_risk = Number(riskFilter);

  const { data, isLoading } = useAttackPaths(params);

  const paths = data?.paths ?? [];
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
          value={riskFilter}
          onChange={(e) => {
            setRiskFilter(e.target.value);
            setPage(0);
          }}
          style={selectStyle}
          aria-label="Filter by risk level"
        >
          <option value="">All Risk Levels</option>
          <option value="9">Critical (&ge;9)</option>
          <option value="7">High (&ge;7)</option>
          <option value="4">Medium (&ge;4)</option>
          <option value="0">Low (&lt;4)</option>
        </select>

        <div style={{ flex: 1 }} />
      </div>

      {/* Table */}
      {isLoading ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          Loading...
        </div>
      ) : paths.length === 0 ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          No attack paths found.
        </div>
      ) : (
        <>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={thStyle}>Risk Score</th>
                <th style={thStyle}>Source</th>
                <th style={thStyle}>Target</th>
                <th style={thStyle}>Steps</th>
                <th style={thStyle}>Computed</th>
              </tr>
            </thead>
            <tbody>
              {paths.map((p) => (
                <tr
                  key={p.id}
                  onClick={() => onSelectPath?.(p.id)}
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
                    <RiskBadge score={p.risk_score} />
                  </td>
                  <td style={tdStyle}>{p.source_node}</td>
                  <td style={tdStyle}>{p.target_node}</td>
                  <td style={tdStyle}>{p.steps.length}</td>
                  <td style={tdStyle}>{p.computed_at}</td>
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

function RiskBadge({ score }: { score: number }) {
  const color = riskColor(score);
  return (
    <span
      data-testid="risk-badge"
      style={{
        display: "inline-block",
        padding: "2px 8px",
        fontSize: 11,
        fontWeight: 600,
        borderRadius: 4,
        background: `${color}22`,
        color,
      }}
    >
      {score.toFixed(1)}
    </span>
  );
}
