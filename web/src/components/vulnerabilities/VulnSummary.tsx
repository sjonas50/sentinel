/**
 * Vulnerability severity summary KPI cards.
 */

import { StatusCard } from "../ui/StatusCard";
import { useVulnSummary } from "../../hooks/useVulnerabilities";

const SEVERITY_STATUS: Record<string, "ok" | "warning" | "error" | "pending"> = {
  critical: "error",
  high: "warning",
  medium: "warning",
  low: "ok",
};

export function VulnSummary() {
  const { data } = useVulnSummary();

  const severityMap: Record<string, number> = {};
  if (data) {
    for (const row of data.by_severity) {
      severityMap[row.severity] = row.count;
    }
  }

  const cards = [
    {
      label: "Critical",
      value: formatCount(severityMap.critical),
      status: cardStatus(severityMap.critical, "critical"),
    },
    {
      label: "High",
      value: formatCount(severityMap.high),
      status: cardStatus(severityMap.high, "high"),
    },
    {
      label: "Medium",
      value: formatCount(severityMap.medium),
      status: cardStatus(severityMap.medium, "medium"),
    },
    {
      label: "Low",
      value: formatCount(severityMap.low),
      status: cardStatus(severityMap.low, "low"),
    },
    {
      label: "CISA KEV",
      value: data ? String(data.kev_count) : "--",
      status: data
        ? data.kev_count > 0
          ? ("error" as const)
          : ("ok" as const)
        : ("pending" as const),
    },
  ];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
        gap: 12,
        marginBottom: 20,
      }}
    >
      {cards.map((c) => (
        <StatusCard key={c.label} {...c} />
      ))}
    </div>
  );
}

function formatCount(n: number | undefined): string {
  if (n === undefined) return "--";
  return String(n);
}

function cardStatus(
  n: number | undefined,
  severity: string,
): "ok" | "warning" | "error" | "pending" {
  if (n === undefined) return "pending";
  if (n === 0) return "ok";
  return SEVERITY_STATUS[severity] ?? "warning";
}
