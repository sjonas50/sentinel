import { StatusCard } from "../components/ui/StatusCard";

const cards = [
  { label: "Hosts", value: "--", status: "pending" as const },
  { label: "Services", value: "--", status: "pending" as const },
  { label: "Vulnerabilities", value: "--", status: "pending" as const },
  { label: "Subnets", value: "--", status: "pending" as const },
];

export function Discover() {
  return (
    <div>
      <p style={{ color: "#9ca3af", marginBottom: 24 }}>
        Network digital twin, asset inventory, vulnerability scanning, configuration audit.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 16, marginBottom: 32 }}>
        {cards.map((c) => (
          <StatusCard key={c.label} {...c} />
        ))}
      </div>

      <section style={{ background: "#161a23", borderRadius: 8, border: "1px solid #2a2e39", padding: 24 }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>Asset Graph</h2>
        <p style={{ color: "#6b7280", fontSize: 14 }}>
          Network topology visualization will appear here once discovery connectors are active.
        </p>
      </section>
    </div>
  );
}
