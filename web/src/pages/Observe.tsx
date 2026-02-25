import { StatusCard } from "../components/ui/StatusCard";

const cards = [
  { label: "Engram Sessions", value: "--", status: "pending" as const },
  { label: "Actions Logged", value: "--", status: "pending" as const },
  { label: "Compliance Score", value: "--", status: "pending" as const },
  { label: "Audit Events", value: "--", status: "pending" as const },
];

export function Observe() {
  return (
    <div>
      <p style={{ color: "#9ca3af", marginBottom: 24 }}>
        Engram audit trail, compliance reporting, cyber insurance evidence.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 16, marginBottom: 32 }}>
        {cards.map((c) => (
          <StatusCard key={c.label} {...c} />
        ))}
      </div>

      <section style={{ background: "#161a23", borderRadius: 8, border: "1px solid #2a2e39", padding: 24 }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>Engram Timeline</h2>
        <p style={{ color: "#6b7280", fontSize: 14 }}>
          Chronological reasoning trail for all agent decisions will be rendered here.
        </p>
      </section>
    </div>
  );
}
