/**
 * Attack path risk tier summary KPI cards.
 */

import { StatusCard } from "../ui/StatusCard";
import { useAttackPathSummary } from "../../hooks/useAttackPaths";

const RISK_STATUS: Record<string, "ok" | "warning" | "error" | "pending"> = {
  critical: "error",
  high: "warning",
  medium: "warning",
  low: "ok",
};

export function AttackPathSummary() {
  const { data } = useAttackPathSummary();

  const tiers = data?.by_risk_tier ?? {};

  const cards = [
    {
      label: "Critical",
      value: formatCount(tiers.critical),
      status: cardStatus(tiers.critical, "critical"),
    },
    {
      label: "High",
      value: formatCount(tiers.high),
      status: cardStatus(tiers.high, "high"),
    },
    {
      label: "Medium",
      value: formatCount(tiers.medium),
      status: cardStatus(tiers.medium, "medium"),
    },
    {
      label: "Low",
      value: formatCount(tiers.low),
      status: cardStatus(tiers.low, "low"),
    },
    {
      label: "Total",
      value: data ? String(data.total_paths) : "--",
      status: data
        ? data.total_paths > 0
          ? ("warning" as const)
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
  tier: string,
): "ok" | "warning" | "error" | "pending" {
  if (n === undefined) return "pending";
  if (n === 0) return "ok";
  return RISK_STATUS[tier] ?? "warning";
}
