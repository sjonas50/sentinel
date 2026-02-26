/**
 * Discover page — network topology and vulnerability overview dashboard.
 */

import { useState, useCallback } from "react";
import { StatusCard } from "../components/ui/StatusCard";
import { GraphToolbar, type ViewMode } from "../components/network-map/GraphToolbar";
import { NetworkGraph } from "../components/network-map/NetworkGraph";
import { NodeDetail } from "../components/network-map/NodeDetail";
import { AssetTable } from "../components/network-map/AssetTable";
import { VulnSummary } from "../components/vulnerabilities/VulnSummary";
import { VulnTable } from "../components/vulnerabilities/VulnTable";
import { VulnDetail } from "../components/vulnerabilities/VulnDetail";
import { useTopology, useGraphStats, useGraphLiveUpdates } from "../hooks/useGraphData";
import { useVulnLiveUpdates } from "../hooks/useVulnerabilities";

type DiscoverTab = "network-map" | "vulnerabilities";

interface SelectedNode {
  id: string;
  label: string;
}

export function Discover() {
  const [activeTab, setActiveTab] = useState<DiscoverTab>("network-map");
  const [viewMode, setViewMode] = useState<ViewMode>("graph");
  const [activeLabels, setActiveLabels] = useState(["Host", "Service", "Subnet", "Vpc"]);
  const [selectedNode, setSelectedNode] = useState<SelectedNode | null>(null);
  const [selectedCve, setSelectedCve] = useState<string | null>(null);

  const labelsParam = activeLabels.join(",");
  const { data: topology, isLoading: topoLoading } = useTopology(labelsParam);
  const { data: stats } = useGraphStats();

  // Subscribe to live updates
  useGraphLiveUpdates();
  useVulnLiveUpdates();

  const handleSelectNode = useCallback((nodeId: string, label: string) => {
    setSelectedNode({ id: nodeId, label });
  }, []);

  const handleCloseNodeDetail = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const handleSelectVuln = useCallback((cveId: string) => {
    setSelectedCve(cveId);
  }, []);

  const handleCloseVulnDetail = useCallback(() => {
    setSelectedCve(null);
  }, []);

  const handleNavigateToAsset = useCallback(
    (assetId: string) => {
      setActiveTab("network-map");
      setSelectedCve(null);
      setSelectedNode({ id: assetId, label: "Service" });
    },
    [],
  );

  // Build status cards from graph stats
  const nodeCounts = stats?.node_counts ?? {};
  const cards = [
    {
      label: "Hosts",
      value: formatCount(nodeCounts.Host),
      status: cardStatus(nodeCounts.Host),
    },
    {
      label: "Services",
      value: formatCount(nodeCounts.Service),
      status: cardStatus(nodeCounts.Service),
    },
    {
      label: "Vulnerabilities",
      value: formatCount(nodeCounts.Vulnerability),
      status: vulnStatus(nodeCounts.Vulnerability),
    },
    {
      label: "Findings",
      value: formatCount(nodeCounts.Finding),
      status: findingStatus(nodeCounts.Finding),
    },
  ];

  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: "10px 20px",
    fontSize: 14,
    fontWeight: 500,
    background: "transparent",
    border: "none",
    borderBottom: active ? "2px solid #3b82f6" : "2px solid transparent",
    color: active ? "#e0e0e0" : "#6b7280",
    cursor: "pointer",
  });

  return (
    <div>
      <p style={{ color: "#9ca3af", marginBottom: 24 }}>
        Network digital twin, asset inventory, vulnerability scanning, configuration audit.
      </p>

      {/* KPI cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
          gap: 16,
          marginBottom: 24,
        }}
      >
        {cards.map((c) => (
          <StatusCard key={c.label} {...c} />
        ))}
      </div>

      {/* Sub-navigation tabs */}
      <div
        style={{
          display: "flex",
          borderBottom: "1px solid #2a2e39",
          marginBottom: 16,
        }}
      >
        <button
          onClick={() => setActiveTab("network-map")}
          style={tabStyle(activeTab === "network-map")}
        >
          Network Map
        </button>
        <button
          onClick={() => setActiveTab("vulnerabilities")}
          style={tabStyle(activeTab === "vulnerabilities")}
        >
          Vulnerabilities
        </button>
      </div>

      {/* ── Network Map Tab ─────────────────────────────────── */}
      {activeTab === "network-map" && (
        <>
          <GraphToolbar
            viewMode={viewMode}
            onViewModeChange={setViewMode}
            activeLabels={activeLabels}
            onActiveLabelsChange={setActiveLabels}
            onSelectNode={handleSelectNode}
          />

          <div
            style={{
              display: "flex",
              background: "#161a23",
              borderRadius: 8,
              border: "1px solid #2a2e39",
              overflow: "hidden",
              height: viewMode === "graph" ? 520 : "auto",
            }}
          >
            <div style={{ flex: 1, overflow: "hidden" }}>
              {viewMode === "graph" ? (
                topoLoading ? (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      height: "100%",
                      color: "#6b7280",
                      fontSize: 14,
                    }}
                  >
                    Loading topology...
                  </div>
                ) : topology && topology.nodes.length > 0 ? (
                  <NetworkGraph
                    nodes={topology.nodes}
                    edges={topology.edges}
                    selectedNodeId={selectedNode?.id}
                    onSelectNode={handleSelectNode}
                  />
                ) : (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      height: "100%",
                      color: "#6b7280",
                      fontSize: 14,
                    }}
                  >
                    No nodes found. Run discovery connectors to populate the graph.
                  </div>
                )
              ) : (
                <div style={{ padding: 16 }}>
                  <AssetTable onSelectNode={handleSelectNode} />
                </div>
              )}
            </div>

            {selectedNode && (
              <NodeDetail
                nodeId={selectedNode.id}
                label={selectedNode.label}
                onClose={handleCloseNodeDetail}
                onSelectNode={handleSelectNode}
              />
            )}
          </div>

          {topology?.truncated && (
            <div style={{ marginTop: 8, fontSize: 12, color: "#f59e0b" }}>
              Graph is truncated — showing {topology.nodes.length} of{" "}
              {topology.total_nodes} nodes and {topology.edges.length} of{" "}
              {topology.total_edges} edges.
            </div>
          )}
        </>
      )}

      {/* ── Vulnerabilities Tab ─────────────────────────────── */}
      {activeTab === "vulnerabilities" && (
        <>
          <VulnSummary />

          <div
            style={{
              display: "flex",
              background: "#161a23",
              borderRadius: 8,
              border: "1px solid #2a2e39",
              overflow: "hidden",
            }}
          >
            <div style={{ flex: 1, padding: 16 }}>
              <VulnTable onSelectVuln={handleSelectVuln} />
            </div>

            {selectedCve && (
              <VulnDetail
                cveId={selectedCve}
                onClose={handleCloseVulnDetail}
                onNavigateToAsset={handleNavigateToAsset}
              />
            )}
          </div>
        </>
      )}
    </div>
  );
}

function formatCount(n: number | undefined): string {
  if (n === undefined) return "--";
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

function cardStatus(n: number | undefined): "ok" | "pending" {
  return n !== undefined && n > 0 ? "ok" : "pending";
}

function vulnStatus(n: number | undefined): "ok" | "warning" | "pending" {
  if (n === undefined) return "pending";
  return n > 0 ? "warning" : "ok";
}

function findingStatus(n: number | undefined): "ok" | "warning" | "pending" {
  if (n === undefined) return "pending";
  return n > 0 ? "warning" : "ok";
}
