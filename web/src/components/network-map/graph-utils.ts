/**
 * Visual configuration and helpers for the network graph.
 */

export interface NodeVisual {
  color: string;
  shape: "circle" | "rect" | "diamond" | "hexagon";
  size: number;
}

export const NODE_VISUALS: Record<string, NodeVisual> = {
  Host: { color: "#3b82f6", shape: "circle", size: 10 },
  Service: { color: "#22c55e", shape: "rect", size: 9 },
  Port: { color: "#6366f1", shape: "circle", size: 6 },
  User: { color: "#f59e0b", shape: "diamond", size: 10 },
  Group: { color: "#f59e0b", shape: "rect", size: 8 },
  Role: { color: "#f59e0b", shape: "hexagon", size: 8 },
  Policy: { color: "#8b5cf6", shape: "rect", size: 8 },
  Subnet: { color: "#6366f1", shape: "hexagon", size: 12 },
  Vpc: { color: "#6366f1", shape: "hexagon", size: 14 },
  Vulnerability: { color: "#ef4444", shape: "diamond", size: 9 },
  Certificate: { color: "#14b8a6", shape: "rect", size: 7 },
  Application: { color: "#22c55e", shape: "diamond", size: 9 },
  McpServer: { color: "#ec4899", shape: "rect", size: 9 },
  Finding: { color: "#ef4444", shape: "rect", size: 8 },
  ConfigSnapshot: { color: "#9ca3af", shape: "circle", size: 6 },
};

const DEFAULT_VISUAL: NodeVisual = { color: "#6b7280", shape: "circle", size: 8 };

export function getNodeVisual(label: string): NodeVisual {
  return NODE_VISUALS[label] ?? DEFAULT_VISUAL;
}

export const EDGE_COLORS: Record<string, string> = {
  CONNECTS_TO: "#4b5563",
  HAS_ACCESS: "#f59e0b",
  MEMBER_OF: "#f59e0b",
  RUNS_ON: "#3b82f6",
  TRUSTS: "#22c55e",
  ROUTES_TO: "#6366f1",
  EXPOSES: "#ef4444",
  DEPENDS_ON: "#8b5cf6",
  CAN_REACH: "#3b82f6",
  HAS_CVE: "#ef4444",
  HAS_PORT: "#6366f1",
  HAS_CERTIFICATE: "#14b8a6",
  BELONGS_TO_SUBNET: "#6366f1",
  BELONGS_TO_VPC: "#6366f1",
  HAS_FINDING: "#ef4444",
};

const DEFAULT_EDGE_COLOR = "#374151";

export function getEdgeColor(edgeType: string): string {
  return EDGE_COLORS[edgeType] ?? DEFAULT_EDGE_COLOR;
}

/** Pick the best display name for a node given its label and properties. */
export function getNodeDisplayName(
  label: string,
  properties: Record<string, unknown>,
): string {
  switch (label) {
    case "Host":
      return (
        (properties.hostname as string) ||
        (properties.ip as string) ||
        (properties.id as string) ||
        "Host"
      );
    case "Service":
      return (
        (properties.name as string) ||
        (properties.id as string) ||
        "Service"
      );
    case "User":
      return (
        (properties.username as string) ||
        (properties.display_name as string) ||
        (properties.id as string) ||
        "User"
      );
    case "Subnet":
      return (
        (properties.cidr as string) ||
        (properties.name as string) ||
        (properties.id as string) ||
        "Subnet"
      );
    case "Vpc":
      return (
        (properties.name as string) ||
        (properties.vpc_id as string) ||
        (properties.id as string) ||
        "VPC"
      );
    case "Vulnerability":
      return (
        (properties.cve_id as string) ||
        (properties.id as string) ||
        "Vuln"
      );
    default:
      return (
        (properties.name as string) ||
        (properties.id as string) ||
        label
      );
  }
}

/** Generate SVG polygon points for a hexagon centered at (0,0). */
export function hexagonPoints(size: number): string {
  const points: string[] = [];
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i - Math.PI / 6;
    points.push(`${size * Math.cos(angle)},${size * Math.sin(angle)}`);
  }
  return points.join(" ");
}
