/**
 * Slide-in detail panel for a selected graph node.
 */

import { useQuery } from "@tanstack/react-query";
import { getNode, getNeighbors } from "../../services/api";
import { getNodeVisual, getNodeDisplayName } from "./graph-utils";

export interface NodeDetailProps {
  nodeId: string;
  label: string;
  onClose: () => void;
  onSelectNode?: (nodeId: string, label: string) => void;
}

export function NodeDetail({
  nodeId,
  label,
  onClose,
  onSelectNode,
}: NodeDetailProps) {
  const { data: nodeData, isLoading: nodeLoading } = useQuery({
    queryKey: ["node", label, nodeId],
    queryFn: () => getNode(label, nodeId),
  });

  const { data: neighborsData, isLoading: neighborsLoading } = useQuery({
    queryKey: ["neighbors", label, nodeId],
    queryFn: () => getNeighbors(label, nodeId),
  });

  const visual = getNodeVisual(label);
  const props = nodeData?.node ?? {};
  const displayName = getNodeDisplayName(label, props);

  // Group neighbors by relationship type
  const neighbors = neighborsData?.neighbors ?? [];
  const grouped: Record<string, typeof neighbors> = {};
  for (const n of neighbors) {
    const key = n.relationship;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(n);
  }

  const HIDDEN_PROPS = new Set(["tenant_id"]);

  return (
    <div
      data-testid="node-detail-panel"
      style={{
        width: 360,
        background: "#161a23",
        borderLeft: "1px solid #2a2e39",
        height: "100%",
        overflowY: "auto",
        padding: 20,
        flexShrink: 0,
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          marginBottom: 16,
        }}
      >
        <div>
          <span
            style={{
              display: "inline-block",
              padding: "2px 8px",
              fontSize: 11,
              fontWeight: 600,
              borderRadius: 4,
              background: `${visual.color}22`,
              color: visual.color,
              marginBottom: 6,
            }}
          >
            {label}
          </span>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>
            {nodeLoading ? "Loading..." : displayName}
          </h3>
        </div>
        <button
          onClick={onClose}
          aria-label="Close detail panel"
          style={{
            background: "transparent",
            border: "none",
            color: "#6b7280",
            fontSize: 18,
            cursor: "pointer",
            padding: 4,
          }}
        >
          ×
        </button>
      </div>

      {/* Properties */}
      {nodeLoading ? (
        <div style={{ color: "#6b7280", fontSize: 13 }}>
          Loading properties...
        </div>
      ) : (
        <div style={{ marginBottom: 20 }}>
          <h4
            style={{
              fontSize: 12,
              color: "#9ca3af",
              textTransform: "uppercase",
              letterSpacing: 0.5,
              marginBottom: 8,
            }}
          >
            Properties
          </h4>
          <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
            <tbody>
              {Object.entries(props)
                .filter(([k]) => !HIDDEN_PROPS.has(k))
                .map(([key, value]) => (
                  <tr key={key}>
                    <td
                      style={{
                        padding: "4px 8px 4px 0",
                        color: "#9ca3af",
                        verticalAlign: "top",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {key}
                    </td>
                    <td
                      style={{
                        padding: "4px 0",
                        color: "#d1d5db",
                        wordBreak: "break-all",
                      }}
                    >
                      {String(value ?? "—")}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Connections */}
      <div>
        <h4
          style={{
            fontSize: 12,
            color: "#9ca3af",
            textTransform: "uppercase",
            letterSpacing: 0.5,
            marginBottom: 8,
          }}
        >
          Connections
          {neighborsData && (
            <span style={{ fontWeight: 400, marginLeft: 4 }}>
              ({neighborsData.count})
            </span>
          )}
        </h4>
        {neighborsLoading ? (
          <div style={{ color: "#6b7280", fontSize: 13 }}>Loading...</div>
        ) : neighborsData && neighborsData.neighbors.length === 0 ? (
          <div style={{ color: "#6b7280", fontSize: 13 }}>
            No connections found.
          </div>
        ) : (
          Object.entries(grouped).map(([relType, neighbors]) => (
            <div key={relType} style={{ marginBottom: 12 }}>
              <div
                style={{
                  fontSize: 11,
                  color: "#6b7280",
                  fontWeight: 600,
                  marginBottom: 4,
                }}
              >
                {relType}
              </div>
              {neighbors.map((n) => {
                const nLabel = n.labels[0] ?? "Unknown";
                const nVisual = getNodeVisual(nLabel);
                const nName = getNodeDisplayName(
                  nLabel,
                  n.node as Record<string, unknown>,
                );
                const nId = (n.node as Record<string, string>).id ?? "";
                return (
                  <button
                    key={nId}
                    onClick={() => onSelectNode?.(nId, nLabel)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      width: "100%",
                      padding: "4px 6px",
                      background: "transparent",
                      border: "none",
                      borderRadius: 4,
                      color: "#d1d5db",
                      fontSize: 12,
                      cursor: "pointer",
                      textAlign: "left",
                    }}
                  >
                    <span
                      style={{
                        width: 8,
                        height: 8,
                        borderRadius: "50%",
                        background: nVisual.color,
                        flexShrink: 0,
                      }}
                    />
                    <span style={{ flex: 1 }}>{nName}</span>
                    <span style={{ color: "#6b7280", fontSize: 10 }}>
                      {nLabel}
                    </span>
                  </button>
                );
              })}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
