/**
 * Defend page — attack paths, threat hunting, adversarial simulation dashboard.
 */

import { useState, useCallback } from "react";
import { StatusCard } from "../components/ui/StatusCard";
import { AttackPathSummary } from "../components/attack-paths/AttackPathSummary";
import { AttackPathList } from "../components/attack-paths/AttackPathList";
import { AttackPathDetail } from "../components/attack-paths/AttackPathDetail";
import { AttackPathMap } from "../components/attack-paths/AttackPathMap";
import { HuntSummary } from "../components/hunt-feed/HuntSummary";
import { HuntFeed } from "../components/hunt-feed/HuntFeed";
import { HuntFindingDetail } from "../components/hunt-feed/HuntFindingDetail";
import { SimulationSummary } from "../components/simulations/SimulationSummary";
import { SimulationList } from "../components/simulations/SimulationList";
import { useAttackPathSummary, useAttackPathLiveUpdates } from "../hooks/useAttackPaths";
import { useHuntSummary, useHuntLiveUpdates } from "../hooks/useHuntFindings";
import { useSimulationSummary } from "../hooks/useSimulations";

type DefendTab = "attack-paths" | "hunt-findings" | "simulations";
type PathView = "list" | "map";

export function Defend() {
  const [activeTab, setActiveTab] = useState<DefendTab>("attack-paths");
  const [pathView, setPathView] = useState<PathView>("list");
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  // Live updates
  useAttackPathLiveUpdates();
  useHuntLiveUpdates();

  // Summary data for KPI cards
  const { data: pathSummary } = useAttackPathSummary();
  const { data: huntSummary } = useHuntSummary();
  const { data: simSummary } = useSimulationSummary();

  const handleSelectPath = useCallback((pathId: string) => {
    setSelectedPathId(pathId);
  }, []);

  const handleClosePath = useCallback(() => {
    setSelectedPathId(null);
  }, []);

  const handleShowOnMap = useCallback((pathId: string) => {
    setSelectedPathId(pathId);
    setPathView("map");
  }, []);

  const handleSelectFinding = useCallback((findingId: string) => {
    setSelectedFindingId(findingId);
  }, []);

  const handleCloseFinding = useCallback(() => {
    setSelectedFindingId(null);
  }, []);

  // Build top-level KPI cards
  const criticalPaths = pathSummary?.by_risk_tier.critical ?? 0;
  const cards = [
    {
      label: "Attack Paths",
      value: pathSummary ? String(pathSummary.total_paths) : "--",
      status: pathSummary
        ? criticalPaths > 0
          ? ("error" as const)
          : pathSummary.total_paths > 0
            ? ("warning" as const)
            : ("ok" as const)
        : ("pending" as const),
    },
    {
      label: "Active Hunts",
      value: huntSummary ? String(huntSummary.active_hunts) : "--",
      status: huntSummary
        ? huntSummary.active_hunts > 0
          ? ("ok" as const)
          : ("pending" as const)
        : ("pending" as const),
    },
    {
      label: "Simulations",
      value: simSummary ? String(simSummary.total_runs) : "--",
      status: simSummary
        ? simSummary.total_runs > 0
          ? ("ok" as const)
          : ("pending" as const)
        : ("pending" as const),
    },
    {
      label: "Findings",
      value: huntSummary ? String(huntSummary.total_findings) : "--",
      status: huntSummary
        ? huntSummary.total_findings > 0
          ? ("warning" as const)
          : ("ok" as const)
        : ("pending" as const),
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

  const viewBtnStyle = (active: boolean): React.CSSProperties => ({
    padding: "4px 12px",
    fontSize: 12,
    background: active ? "#1e2230" : "transparent",
    border: "1px solid #2a2e39",
    borderRadius: 4,
    color: active ? "#e0e0e0" : "#6b7280",
    cursor: "pointer",
  });

  return (
    <div>
      <p style={{ color: "#9ca3af", marginBottom: 24 }}>
        Attack path analysis, threat hunting, adversarial simulation, automated response.
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
        <button onClick={() => setActiveTab("attack-paths")} style={tabStyle(activeTab === "attack-paths")}>
          Attack Paths
        </button>
        <button onClick={() => setActiveTab("hunt-findings")} style={tabStyle(activeTab === "hunt-findings")}>
          Hunt Findings
        </button>
        <button onClick={() => setActiveTab("simulations")} style={tabStyle(activeTab === "simulations")}>
          Simulations
        </button>
      </div>

      {/* ── Attack Paths Tab ────────────────────────────────── */}
      {activeTab === "attack-paths" && (
        <>
          <AttackPathSummary />

          <div
            style={{
              display: "flex",
              gap: 8,
              marginBottom: 12,
            }}
          >
            <button onClick={() => setPathView("list")} style={viewBtnStyle(pathView === "list")}>
              List
            </button>
            <button onClick={() => setPathView("map")} style={viewBtnStyle(pathView === "map")}>
              Map
            </button>
          </div>

          <div
            style={{
              display: "flex",
              background: "#161a23",
              borderRadius: 8,
              border: "1px solid #2a2e39",
              overflow: "hidden",
              height: pathView === "map" ? 520 : "auto",
            }}
          >
            <div style={{ flex: 1, overflow: "hidden" }}>
              {pathView === "list" ? (
                <div style={{ padding: 16 }}>
                  <AttackPathList onSelectPath={handleSelectPath} />
                </div>
              ) : (
                <AttackPathMap pathId={selectedPathId} onSelectNode={() => {}} />
              )}
            </div>

            {selectedPathId && (
              <AttackPathDetail
                pathId={selectedPathId}
                onClose={handleClosePath}
                onShowOnMap={handleShowOnMap}
              />
            )}
          </div>
        </>
      )}

      {/* ── Hunt Findings Tab ───────────────────────────────── */}
      {activeTab === "hunt-findings" && (
        <>
          <HuntSummary />

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
              <HuntFeed onSelectFinding={handleSelectFinding} />
            </div>

            {selectedFindingId && (
              <HuntFindingDetail findingId={selectedFindingId} onClose={handleCloseFinding} />
            )}
          </div>
        </>
      )}

      {/* ── Simulations Tab ─────────────────────────────────── */}
      {activeTab === "simulations" && (
        <>
          <SimulationSummary />

          <div
            style={{
              background: "#161a23",
              borderRadius: 8,
              border: "1px solid #2a2e39",
              overflow: "hidden",
              padding: 16,
            }}
          >
            <SimulationList />
          </div>
        </>
      )}
    </div>
  );
}
