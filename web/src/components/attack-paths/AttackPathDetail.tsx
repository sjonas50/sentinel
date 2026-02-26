/**
 * Slide-in detail panel for a selected attack path.
 */

import { useAttackPathDetail } from "../../hooks/useAttackPaths";

function riskColor(score: number): string {
  if (score >= 9) return "#ef4444";
  if (score >= 7) return "#f97316";
  if (score >= 4) return "#eab308";
  return "#3b82f6";
}

const PRIORITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export interface AttackPathDetailProps {
  pathId: string;
  onClose: () => void;
  onShowOnMap?: (pathId: string) => void;
}

export function AttackPathDetail({
  pathId,
  onClose,
  onShowOnMap,
}: AttackPathDetailProps) {
  const { data, isLoading } = useAttackPathDetail(pathId);

  const path = data?.path;
  const remediation = path?.remediation ?? [];
  const color = riskColor(path?.risk_score ?? 0);

  return (
    <div
      data-testid="path-detail-panel"
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
          {path && (
            <span
              style={{
                display: "inline-block",
                padding: "2px 8px",
                fontSize: 11,
                fontWeight: 600,
                borderRadius: 4,
                background: `${color}22`,
                color,
                marginBottom: 6,
              }}
            >
              {path.risk_score.toFixed(1)}
            </span>
          )}
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>
            {isLoading ? "Loading..." : "Attack Path"}
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
      ) : path ? (
        <>
          {/* Score cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 12,
              marginBottom: 20,
            }}
          >
            <ScoreCard
              label="Risk Score"
              value={path.risk_score.toFixed(1)}
              color={riskColor(path.risk_score)}
            />
            <ScoreCard
              label="Steps"
              value={String(path.steps.length)}
              color="#d1d5db"
            />
          </div>

          {/* Source / Target */}
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
              Details
            </h4>
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <tbody>
                <DetailRow label="Source" value={path.source_node} />
                <DetailRow label="Target" value={path.target_node} />
                <DetailRow label="Computed" value={path.computed_at} />
              </tbody>
            </table>
          </div>

          {/* Steps */}
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
              Steps
            </h4>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {path.steps.map((step, index) => (
                <div
                  key={index}
                  style={{
                    background: "#1e2230",
                    borderRadius: 6,
                    padding: "10px 12px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      marginBottom: 4,
                    }}
                  >
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        justifyContent: "center",
                        width: 20,
                        height: 20,
                        borderRadius: "50%",
                        background: "#2a2e39",
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#d1d5db",
                        flexShrink: 0,
                      }}
                    >
                      {index + 1}
                    </span>
                    <span
                      style={{
                        fontSize: 12,
                        fontWeight: 500,
                        color: "#e0e0e0",
                      }}
                    >
                      {step.node_id}
                    </span>
                  </div>
                  {step.technique && (
                    <div
                      style={{
                        fontSize: 11,
                        color: "#9ca3af",
                        marginBottom: 4,
                        marginLeft: 28,
                      }}
                    >
                      {step.technique}
                    </div>
                  )}
                  <div
                    style={{
                      fontSize: 12,
                      color: "#d1d5db",
                      marginBottom: 6,
                      marginLeft: 28,
                    }}
                  >
                    {step.description}
                  </div>
                  <div style={{ marginLeft: 28 }}>
                    <div
                      style={{
                        fontSize: 10,
                        color: "#9ca3af",
                        marginBottom: 2,
                      }}
                    >
                      Exploitability
                    </div>
                    <div
                      style={{
                        height: 4,
                        borderRadius: 2,
                        background: "#2a2e39",
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${(step.exploitability / 10) * 100}%`,
                          height: "100%",
                          borderRadius: 2,
                          background: riskColor(step.exploitability),
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Remediation */}
          {remediation.length > 0 && (
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
                Remediation
              </h4>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {remediation.map((r, index) => {
                  const prioColor = PRIORITY_COLORS[r.priority] ?? "#6b7280";
                  return (
                    <div
                      key={index}
                      style={{
                        background: "#1e2230",
                        borderRadius: 6,
                        padding: "10px 12px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          marginBottom: 4,
                        }}
                      >
                        <span
                          style={{
                            fontSize: 12,
                            fontWeight: 500,
                            color: "#e0e0e0",
                            flex: 1,
                          }}
                        >
                          {r.title}
                        </span>
                        <span
                          style={{
                            display: "inline-block",
                            padding: "1px 6px",
                            fontSize: 10,
                            fontWeight: 600,
                            borderRadius: 4,
                            background: `${prioColor}22`,
                            color: prioColor,
                            textTransform: "uppercase",
                          }}
                        >
                          {r.priority}
                        </span>
                      </div>
                      <div
                        style={{
                          fontSize: 12,
                          color: "#d1d5db",
                          lineHeight: 1.5,
                        }}
                      >
                        {r.description}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Show on Map button */}
          <button
            onClick={() => onShowOnMap?.(pathId)}
            style={{
              width: "100%",
              padding: "10px 0",
              fontSize: 13,
              fontWeight: 600,
              background: "#3b82f6",
              border: "none",
              borderRadius: 6,
              color: "#ffffff",
              cursor: "pointer",
            }}
          >
            Show on Map
          </button>
        </>
      ) : null}
    </div>
  );
}

function ScoreCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div
      style={{
        background: "#1e2230",
        borderRadius: 6,
        padding: "10px 12px",
        textAlign: "center",
      }}
    >
      <div
        style={{
          fontSize: 11,
          color: "#9ca3af",
          textTransform: "uppercase",
          marginBottom: 4,
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value}</div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <tr>
      <td
        style={{
          padding: "4px 8px 4px 0",
          color: "#9ca3af",
          verticalAlign: "top",
          whiteSpace: "nowrap",
        }}
      >
        {label}
      </td>
      <td
        style={{
          padding: "4px 0",
          color: "#d1d5db",
          wordBreak: "break-all",
        }}
      >
        {value}
      </td>
    </tr>
  );
}
