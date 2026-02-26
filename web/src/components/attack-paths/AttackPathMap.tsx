/**
 * Network graph with attack path highlighting.
 *
 * Wraps NetworkGraph and highlights nodes that appear in the selected attack path.
 */

import { useMemo } from "react";
import { NetworkGraph } from "../network-map/NetworkGraph";
import { useTopology } from "../../hooks/useGraphData";
import { useAttackPathDetail } from "../../hooks/useAttackPaths";

export interface AttackPathMapProps {
  pathId: string | null;
  onSelectNode?: (nodeId: string, label: string) => void;
}

export function AttackPathMap({ pathId, onSelectNode }: AttackPathMapProps) {
  const { data: topology, isLoading: topoLoading } = useTopology("Host,Service,Subnet,Vpc");
  const { data: pathData, isLoading: pathLoading } = useAttackPathDetail(pathId);

  const pathNodeIds = useMemo(() => {
    if (!pathData?.path) return new Set<string>();
    return new Set(pathData.path.steps.map((s) => s.node_id));
  }, [pathData]);

  const isLoading = topoLoading || (pathId !== null && pathLoading);

  if (isLoading) {
    return (
      <div
        style={{
          height: 520,
          background: "#161a23",
          borderRadius: 8,
          border: "1px solid #2a2e39",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "#6b7280",
          fontSize: 13,
        }}
      >
        Loading topology...
      </div>
    );
  }

  if (!topology || topology.nodes.length === 0) {
    return (
      <div
        style={{
          height: 520,
          background: "#161a23",
          borderRadius: 8,
          border: "1px solid #2a2e39",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "#6b7280",
          fontSize: 13,
        }}
      >
        No topology data available.
      </div>
    );
  }

  // Pick the first highlighted node to pass as the single highlightNodeId
  const firstHighlight = pathNodeIds.size > 0 ? [...pathNodeIds][0] : undefined;

  return (
    <div
      style={{
        height: 520,
        background: "#161a23",
        borderRadius: 8,
        border: "1px solid #2a2e39",
        overflow: "hidden",
      }}
    >
      <NetworkGraph
        nodes={topology.nodes}
        edges={topology.edges}
        highlightNodeId={firstHighlight}
        onSelectNode={onSelectNode}
      />
    </div>
  );
}
