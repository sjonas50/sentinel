/**
 * Dashboard stats card for displaying KPI metrics.
 */

interface StatusCardProps {
  label: string;
  value: string;
  status: "ok" | "warning" | "error" | "pending";
}

const statusColors: Record<StatusCardProps["status"], string> = {
  ok: "#22c55e",
  warning: "#eab308",
  error: "#ef4444",
  pending: "#6b7280",
};

export function StatusCard({ label, value, status }: StatusCardProps) {
  return (
    <div
      style={{
        background: "#161a23",
        border: "1px solid #2a2e39",
        borderRadius: 8,
        padding: "16px 20px",
        borderTop: `3px solid ${statusColors[status]}`,
      }}
    >
      <div style={{ fontSize: 12, color: "#9ca3af", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.5 }}>
        {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 700 }}>{value}</div>
    </div>
  );
}
