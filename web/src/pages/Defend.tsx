import { StatusCard } from "../components/ui/StatusCard";

const cards = [
  { label: "Attack Paths", value: "--", status: "pending" as const },
  { label: "Active Hunts", value: "--", status: "pending" as const },
  { label: "Simulations", value: "--", status: "pending" as const },
  { label: "Findings", value: "--", status: "pending" as const },
];

export function Defend() {
  return (
    <div>
      <p style={{ color: "#9ca3af", marginBottom: 24 }}>
        Attack path analysis, threat hunting, adversarial simulation, automated response.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 16, marginBottom: 32 }}>
        {cards.map((c) => (
          <StatusCard key={c.label} {...c} />
        ))}
      </div>

      <section style={{ background: "#161a23", borderRadius: 8, border: "1px solid #2a2e39", padding: 24 }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>Threat Feed</h2>
        <p style={{ color: "#6b7280", fontSize: 14 }}>
          Real-time threat hunting results and attack path alerts will stream here.
        </p>
      </section>
    </div>
  );
}
