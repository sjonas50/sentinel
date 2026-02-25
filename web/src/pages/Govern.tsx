import { StatusCard } from "../components/ui/StatusCard";

const cards = [
  { label: "AI Agents", value: "--", status: "pending" as const },
  { label: "MCP Servers", value: "--", status: "pending" as const },
  { label: "Policy Violations", value: "--", status: "pending" as const },
  { label: "Shadow AI", value: "--", status: "pending" as const },
];

export function Govern() {
  return (
    <div>
      <p style={{ color: "#9ca3af", marginBottom: 24 }}>
        AI agent governance, shadow AI discovery, MCP security, data loss prevention.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 16, marginBottom: 32 }}>
        {cards.map((c) => (
          <StatusCard key={c.label} {...c} />
        ))}
      </div>

      <section style={{ background: "#161a23", borderRadius: 8, border: "1px solid #2a2e39", padding: 24 }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>Policy Dashboard</h2>
        <p style={{ color: "#6b7280", fontSize: 14 }}>
          Agent behavior monitoring and policy compliance overview will display here.
        </p>
      </section>
    </div>
  );
}
