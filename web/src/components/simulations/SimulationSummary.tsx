/**
 * Simulation summary KPI cards.
 */

import { StatusCard } from "../ui/StatusCard";
import { useSimulationSummary } from "../../hooks/useSimulations";

export function SimulationSummary() {
  const { data } = useSimulationSummary();

  const cards = [
    {
      label: "Total Runs",
      value: data ? String(data.total_runs) : "--",
      status: data
        ? data.total_runs > 0
          ? ("ok" as const)
          : ("pending" as const)
        : ("pending" as const),
    },
    {
      label: "Techniques Tested",
      value: data ? String(data.techniques_tested) : "--",
      status: data
        ? data.techniques_tested > 0
          ? ("ok" as const)
          : ("pending" as const)
        : ("pending" as const),
    },
    {
      label: "Findings",
      value: data ? String(data.total_findings) : "--",
      status: data
        ? data.total_findings > 0
          ? ("warning" as const)
          : ("ok" as const)
        : ("pending" as const),
    },
    {
      label: "Highest Risk",
      value: data ? String(data.highest_risk_score) : "--",
      status: data
        ? data.highest_risk_score >= 80
          ? ("error" as const)
          : data.highest_risk_score >= 50
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
