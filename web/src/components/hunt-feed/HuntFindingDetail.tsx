/**
 * Slide-in detail panel for a selected hunt finding.
 */

import { useHuntFindingDetail } from "../../hooks/useHuntFindings";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export interface HuntFindingDetailProps {
  findingId: string;
  onClose: () => void;
}

export function HuntFindingDetail({
  findingId,
  onClose,
}: HuntFindingDetailProps) {
  const { data, isLoading } = useHuntFindingDetail(findingId);

  const finding = data?.finding;
  const sevColor = SEVERITY_COLORS[finding?.severity ?? ""] ?? "#6b7280";

  return (
    <div
      data-testid="finding-detail-panel"
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
          {finding && (
            <span
              data-testid="severity-badge"
              style={{
                display: "inline-block",
                padding: "2px 8px",
                fontSize: 11,
                fontWeight: 600,
                borderRadius: 4,
                background: `${sevColor}22`,
                color: sevColor,
                marginBottom: 6,
                textTransform: "uppercase",
              }}
            >
              {finding.severity}
            </span>
          )}
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>
            {isLoading ? "Loading..." : finding?.title ?? findingId}
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

      {isLoading ? (
        <div style={{ color: "#6b7280", fontSize: 13 }}>Loading...</div>
      ) : finding ? (
        <>
          {/* Description */}
          {finding.description && (
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
                Description
              </h4>
              <p
                style={{
                  fontSize: 13,
                  color: "#d1d5db",
                  lineHeight: 1.5,
                  margin: 0,
                }}
              >
                {finding.description}
              </p>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence &&
            Object.keys(finding.evidence).length > 0 && (
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
                  Evidence
                </h4>
                <table
                  style={{
                    width: "100%",
                    fontSize: 12,
                    borderCollapse: "collapse",
                  }}
                >
                  <tbody>
                    {Object.entries(finding.evidence).map(([key, value]) => (
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
                          {String(value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

          {/* MITRE */}
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
              MITRE ATT&CK
            </h4>
            <div style={{ fontSize: 13, color: "#d1d5db", marginBottom: 8 }}>
              <span style={{ color: "#9ca3af" }}>Tactic: </span>
              {finding.mitre_tactic}
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {finding.mitre_technique_ids.map((tid) => (
                <span
                  key={tid}
                  data-testid="mitre-technique"
                  style={{
                    display: "inline-block",
                    padding: "2px 8px",
                    fontSize: 11,
                    fontWeight: 500,
                    borderRadius: 4,
                    background: "rgba(59, 130, 246, 0.15)",
                    color: "#60a5fa",
                  }}
                >
                  {tid}
                </span>
              ))}
            </div>
          </div>

          {/* Affected Hosts */}
          {finding.affected_hosts.length > 0 && (
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
                Affected Hosts
              </h4>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 18,
                  fontSize: 13,
                  color: "#d1d5db",
                  lineHeight: 1.6,
                }}
              >
                {finding.affected_hosts.map((host) => (
                  <li key={host}>{host}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Affected Users */}
          {finding.affected_users.length > 0 && (
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
                Affected Users
              </h4>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 18,
                  fontSize: 13,
                  color: "#d1d5db",
                  lineHeight: 1.6,
                }}
              >
                {finding.affected_users.map((user) => (
                  <li key={user}>{user}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommendations */}
          {finding.recommendations.length > 0 && (
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
                Recommendations
              </h4>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 18,
                  fontSize: 13,
                  color: "#d1d5db",
                  lineHeight: 1.6,
                }}
              >
                {finding.recommendations.map((rec, i) => (
                  <li key={i}>{rec}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}
