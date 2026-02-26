/**
 * Slide-in detail panel for a selected vulnerability.
 */

import { useVulnDetail, useVulnAssets } from "../../hooks/useVulnerabilities";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  none: "#6b7280",
};

export interface VulnDetailProps {
  cveId: string;
  onClose: () => void;
  onNavigateToAsset?: (assetId: string) => void;
}

export function VulnDetail({
  cveId,
  onClose,
  onNavigateToAsset,
}: VulnDetailProps) {
  const { data: vulnData, isLoading: vulnLoading } = useVulnDetail(cveId);
  const { data: assetsData, isLoading: assetsLoading } = useVulnAssets(cveId);

  const vuln = vulnData?.vulnerability;
  const assets = assetsData?.assets ?? [];
  const sevColor = SEVERITY_COLORS[vuln?.severity ?? ""] ?? "#6b7280";

  return (
    <div
      data-testid="vuln-detail-panel"
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
          {vuln && (
            <span
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
              {vuln.severity}
            </span>
          )}
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>
            {vulnLoading ? "Loading..." : cveId}
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

      {vulnLoading ? (
        <div style={{ color: "#6b7280", fontSize: 13 }}>Loading...</div>
      ) : vuln ? (
        <>
          {/* Scores */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 12,
              marginBottom: 20,
            }}
          >
            <ScoreCard
              label="CVSS"
              value={
                vuln.cvss_score != null ? vuln.cvss_score.toFixed(1) : "N/A"
              }
              color={cvssColor(vuln.cvss_score)}
            />
            <ScoreCard
              label="EPSS"
              value={
                vuln.epss_score != null
                  ? `${(vuln.epss_score * 100).toFixed(1)}%`
                  : "N/A"
              }
              color={epssColor(vuln.epss_score)}
            />
          </div>

          {/* KEV status */}
          {vuln.in_cisa_kev && (
            <div
              style={{
                padding: "8px 12px",
                marginBottom: 16,
                borderRadius: 6,
                background: "rgba(239, 68, 68, 0.1)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                fontSize: 12,
                color: "#ef4444",
                fontWeight: 500,
              }}
            >
              CISA Known Exploited Vulnerability — active exploitation observed
            </div>
          )}

          {/* Description */}
          {vuln.description && (
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
              <p style={{ fontSize: 13, color: "#d1d5db", lineHeight: 1.5, margin: 0 }}>
                {vuln.description}
              </p>
            </div>
          )}

          {/* Properties */}
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
                {vuln.cvss_vector && (
                  <DetailRow label="CVSS Vector" value={vuln.cvss_vector} />
                )}
                <DetailRow
                  label="Exploitable"
                  value={vuln.exploitable ? "Yes" : "No"}
                />
                <DetailRow
                  label="Published"
                  value={vuln.published_date ?? "Unknown"}
                />
                <DetailRow label="First Seen" value={vuln.first_seen} />
                <DetailRow label="Last Seen" value={vuln.last_seen} />
              </tbody>
            </table>
          </div>

          {/* Affected Assets */}
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
              Affected Assets
              {assetsData && (
                <span style={{ fontWeight: 400, marginLeft: 4 }}>
                  ({assetsData.count})
                </span>
              )}
            </h4>
            {assetsLoading ? (
              <div style={{ color: "#6b7280", fontSize: 13 }}>Loading...</div>
            ) : assets.length === 0 ? (
              <div style={{ color: "#6b7280", fontSize: 13 }}>
                No linked assets found.
              </div>
            ) : (
              assets.map((asset) => {
                const id = String(asset.id ?? "");
                const name =
                  (asset.name as string) ?? (asset.id as string) ?? "Service";
                return (
                  <button
                    key={id}
                    onClick={() => onNavigateToAsset?.(id)}
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
                        background: "#22c55e",
                        flexShrink: 0,
                      }}
                    />
                    <span style={{ flex: 1 }}>{name}</span>
                    <span style={{ color: "#6b7280", fontSize: 10 }}>
                      Service
                    </span>
                  </button>
                );
              })
            )}
          </div>
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

function cvssColor(score: number | undefined | null): string {
  if (score == null) return "#6b7280";
  if (score >= 9) return "#ef4444";
  if (score >= 7) return "#f97316";
  if (score >= 4) return "#eab308";
  return "#22c55e";
}

function epssColor(score: number | undefined | null): string {
  if (score == null) return "#6b7280";
  if (score >= 0.5) return "#ef4444";
  if (score >= 0.1) return "#f97316";
  return "#22c55e";
}
