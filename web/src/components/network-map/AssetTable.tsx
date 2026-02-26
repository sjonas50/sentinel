/**
 * Tabbed table view of graph nodes by label.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listNodes } from "../../services/api";
import { getNodeVisual, getNodeDisplayName } from "./graph-utils";

const TABS = ["Host", "Service", "User", "Subnet", "Vpc"] as const;
type TabLabel = (typeof TABS)[number];

const COLUMNS: Record<TabLabel, { key: string; label: string }[]> = {
  Host: [
    { key: "ip", label: "IP" },
    { key: "hostname", label: "Hostname" },
    { key: "os", label: "OS" },
    { key: "cloud_provider", label: "Cloud" },
    { key: "criticality", label: "Criticality" },
  ],
  Service: [
    { key: "name", label: "Name" },
    { key: "port", label: "Port" },
    { key: "protocol", label: "Protocol" },
    { key: "state", label: "State" },
  ],
  User: [
    { key: "username", label: "Username" },
    { key: "email", label: "Email" },
    { key: "source", label: "Source" },
    { key: "mfa_enabled", label: "MFA" },
    { key: "enabled", label: "Enabled" },
  ],
  Subnet: [
    { key: "cidr", label: "CIDR" },
    { key: "name", label: "Name" },
    { key: "cloud_provider", label: "Cloud" },
    { key: "is_public", label: "Public" },
  ],
  Vpc: [
    { key: "vpc_id", label: "VPC ID" },
    { key: "name", label: "Name" },
    { key: "cidr", label: "CIDR" },
    { key: "cloud_provider", label: "Cloud" },
    { key: "region", label: "Region" },
  ],
};

const PAGE_SIZE = 25;

export interface AssetTableProps {
  onSelectNode?: (nodeId: string, label: string) => void;
}

export function AssetTable({ onSelectNode }: AssetTableProps) {
  const [activeTab, setActiveTab] = useState<TabLabel>("Host");
  const [page, setPage] = useState(0);

  const { data, isLoading } = useQuery({
    queryKey: ["nodes", activeTab, page],
    queryFn: () => listNodes(activeTab, PAGE_SIZE, page * PAGE_SIZE),
  });

  const columns = COLUMNS[activeTab];
  const nodes = data?.nodes ?? [];
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

  return (
    <div>
      {/* Tab bar */}
      <div
        style={{
          display: "flex",
          gap: 0,
          borderBottom: "1px solid #2a2e39",
          marginBottom: 16,
        }}
      >
        {TABS.map((tab) => {
          const visual = getNodeVisual(tab);
          const active = tab === activeTab;
          return (
            <button
              key={tab}
              onClick={() => {
                setActiveTab(tab);
                setPage(0);
              }}
              style={{
                padding: "8px 16px",
                fontSize: 13,
                fontWeight: 500,
                background: "transparent",
                border: "none",
                borderBottom: active ? `2px solid ${visual.color}` : "2px solid transparent",
                color: active ? visual.color : "#6b7280",
                cursor: "pointer",
              }}
            >
              {tab}
            </button>
          );
        })}
      </div>

      {/* Table */}
      {isLoading ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          Loading...
        </div>
      ) : nodes.length === 0 ? (
        <div style={{ padding: 24, color: "#6b7280", fontSize: 13 }}>
          No {activeTab} nodes found.
        </div>
      ) : (
        <>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={thStyle}>Name</th>
                {columns.map((col) => (
                  <th key={col.key} style={thStyle}>
                    {col.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {nodes.map((node) => {
                const id = String((node as Record<string, unknown>).id ?? "");
                return (
                  <tr
                    key={id}
                    onClick={() => onSelectNode?.(id, activeTab)}
                    style={{ cursor: "pointer" }}
                    onMouseOver={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "#1e2230";
                    }}
                    onMouseOut={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "transparent";
                    }}
                  >
                    <td style={tdStyle}>
                      {getNodeDisplayName(activeTab, node as Record<string, unknown>)}
                    </td>
                    {columns.map((col) => (
                      <td key={col.key} style={tdStyle}>
                        {formatCell((node as Record<string, unknown>)[col.key])}
                      </td>
                    ))}
                  </tr>
                );
              })}
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

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}
