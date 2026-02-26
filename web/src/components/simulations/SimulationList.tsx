/**
 * Filterable, paginated simulation results table.
 */

import { useState } from "react";
import { useSimulations } from "../../hooks/useSimulations";
import type { SimulationListParams } from "../../services/api";

const PAGE_SIZE = 50;

const TACTIC_LABELS: Record<string, string> = {
  initial_access: "Initial Access",
  lateral_movement: "Lateral Movement",
  privilege_escalation: "Privilege Escalation",
  exfiltration: "Exfiltration",
};

export interface SimulationListProps {
  onSelectSimulation?: (simId: string) => void;
}

export function SimulationList({ onSelectSimulation }: SimulationListProps) {
  const [page, setPage] = useState(0);
  const [tacticFilter, setTacticFilter] = useState<string>("");

  const params: SimulationListParams = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };
  if (tacticFilter) params.tactic = tacticFilter;

  const { data, isLoading } = useSimulations(params);

  const simulations = data?.simulations ?? [];
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

  function formatTactic(tactic: string): string {
    return TACTIC_LABELS[tactic] ?? tactic;
  }

  function formatDuration(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return s > 0 ? `${m}m ${s}s` : `${m}m`;
  }

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
          value={tacticFilter}
          onChange={(e) => {
            setTacticFilter(e.target.value);
            setPage(0);
          }}
          style={selectStyle}
          aria-label="Filter by tactic"
        >
          <option value="">All Tactics</option>
          <option value="initial_access">Initial Access</option>
          <option value="lateral_movement">Lateral Movement</option>
          <option value="privilege_escalation">Privilege Escalation</option>
          <option value="exfiltration">Exfiltration</option>
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          Loading...
        </div>
      ) : simulations.length === 0 ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          No simulation results found.
        </div>
      ) : (
        <>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={thStyle}>Tactic</th>
                <th style={thStyle}>Techniques</th>
                <th style={thStyle}>Findings</th>
                <th style={thStyle}>Highest Risk</th>
                <th style={thStyle}>Duration</th>
                <th style={thStyle}>Date</th>
              </tr>
            </thead>
            <tbody>
              {simulations.map((sim) => (
                <tr
                  key={sim.id}
                  onClick={() => onSelectSimulation?.(sim.id)}
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
                    <span style={{ fontWeight: 500 }}>
                      {formatTactic(sim.tactic)}
                    </span>
                  </td>
                  <td style={tdStyle}>{sim.techniques_tested}</td>
                  <td style={tdStyle}>{sim.findings_count}</td>
                  <td style={tdStyle}>{sim.highest_risk_score}</td>
                  <td style={tdStyle}>
                    {formatDuration(sim.duration_seconds)}
                  </td>
                  <td style={tdStyle}>{sim.created_at}</td>
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
