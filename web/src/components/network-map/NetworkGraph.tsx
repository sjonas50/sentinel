/**
 * D3 force-directed network graph visualization.
 *
 * D3 owns the SVG subtree — React manages data and surrounding UI.
 */

import { useEffect, useRef, useCallback } from "react";
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  type Simulation,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force";
import { select } from "d3-selection";
import { zoom, zoomIdentity, type ZoomBehavior } from "d3-zoom";
import { drag } from "d3-drag";
import type { TopologyNode, TopologyEdge } from "../../services/api";
import {
  getNodeVisual,
  getNodeDisplayName,
  getEdgeColor,
  hexagonPoints,
} from "./graph-utils";

export interface NetworkGraphProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  selectedNodeId?: string;
  onSelectNode?: (nodeId: string, label: string) => void;
  highlightNodeId?: string;
  /** Set of node IDs to highlight (e.g. for attack path visualization). */
  highlightNodeIds?: Set<string>;
}

interface SimNode extends SimulationNodeDatum {
  id: string;
  label: string;
  properties: Record<string, unknown>;
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  id: string;
  edge_type: string;
}

export function NetworkGraph({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
  highlightNodeId,
  highlightNodeIds,
}: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<Simulation<SimNode, SimLink> | null>(null);
  const prevNodesRef = useRef<Map<string, { x: number; y: number }>>(new Map());
  const containerRef = useRef<HTMLDivElement>(null);

  const onSelectNodeRef = useRef(onSelectNode);
  onSelectNodeRef.current = onSelectNode;

  const selectedIdRef = useRef(selectedNodeId);
  selectedIdRef.current = selectedNodeId;

  const highlightIdRef = useRef(highlightNodeId);
  highlightIdRef.current = highlightNodeId;

  const highlightIdsRef = useRef(highlightNodeIds);
  highlightIdsRef.current = highlightNodeIds;

  // Store positions from previous simulation for continuity
  const storePositions = useCallback(() => {
    if (!simRef.current) return;
    const map = new Map<string, { x: number; y: number }>();
    simRef.current.nodes().forEach((n) => {
      if (n.x !== undefined && n.y !== undefined) {
        map.set(n.id, { x: n.x, y: n.y });
      }
    });
    prevNodesRef.current = map;
  }, []);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    const rect = svg.getBoundingClientRect();
    const width = rect.width || 800;
    const height = rect.height || 600;

    // Save positions from old simulation
    storePositions();

    // Build simulation nodes, reusing old positions
    const simNodes: SimNode[] = nodes.map((n) => {
      const prev = prevNodesRef.current.get(n.id);
      return {
        id: n.id,
        label: n.label,
        properties: n.properties,
        x: prev?.x ?? width / 2 + (Math.random() - 0.5) * 200,
        y: prev?.y ?? height / 2 + (Math.random() - 0.5) * 200,
      };
    });

    const nodeMap = new Map(simNodes.map((n) => [n.id, n]));

    const simLinks: SimLink[] = edges
      .filter((e) => nodeMap.has(e.source_id) && nodeMap.has(e.target_id))
      .map((e) => ({
        id: e.id,
        source: e.source_id,
        target: e.target_id,
        edge_type: e.edge_type,
      }));

    // Clear previous SVG content
    const svgSel = select(svg);
    svgSel.selectAll("*").remove();

    // Defs for filters
    const defs = svgSel.append("defs");
    const filter = defs
      .append("filter")
      .attr("id", "glow")
      .attr("x", "-50%")
      .attr("y", "-50%")
      .attr("width", "200%")
      .attr("height", "200%");
    filter
      .append("feGaussianBlur")
      .attr("stdDeviation", "3")
      .attr("result", "blur");
    filter
      .append("feMerge")
      .selectAll("feMergeNode")
      .data(["blur", "SourceGraphic"])
      .join("feMergeNode")
      .attr("in", (d) => d);

    // Arrow markers
    defs
      .append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 20)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#4b5563");

    const g = svgSel.append("g");

    // Zoom
    const zoomBehavior: ZoomBehavior<SVGSVGElement, unknown> = zoom<
      SVGSVGElement,
      unknown
    >()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
        // Toggle labels based on zoom level
        const k = event.transform.k;
        g.selectAll<SVGTextElement, SimNode>(".node-label").attr(
          "opacity",
          k > 0.7 ? 1 : 0,
        );
        g.selectAll<SVGTextElement, SimLink>(".edge-label").attr(
          "opacity",
          k > 1.2 ? 0.7 : 0,
        );
      });

    svgSel.call(zoomBehavior);

    // Edges
    const linkGroup = g
      .append("g")
      .attr("class", "edges")
      .selectAll<SVGLineElement, SimLink>("line")
      .data(simLinks, (d) => d.id)
      .join("line")
      .attr("stroke", (d) => getEdgeColor(d.edge_type))
      .attr("stroke-width", 1)
      .attr("stroke-opacity", 0.5)
      .attr("marker-end", "url(#arrowhead)");

    // Edge labels
    const edgeLabelGroup = g
      .append("g")
      .attr("class", "edge-labels")
      .selectAll<SVGTextElement, SimLink>("text")
      .data(simLinks, (d) => d.id)
      .join("text")
      .attr("class", "edge-label")
      .attr("text-anchor", "middle")
      .attr("fill", "#6b7280")
      .attr("font-size", 8)
      .attr("opacity", 0)
      .text((d) => d.edge_type);

    // Nodes
    const nodeGroup = g
      .append("g")
      .attr("class", "nodes")
      .selectAll<SVGGElement, SimNode>("g")
      .data(simNodes, (d) => d.id)
      .join("g")
      .attr("cursor", "pointer")
      .on("click", (_event, d) => {
        onSelectNodeRef.current?.(d.id, d.label);
      });

    // Draw node shapes
    nodeGroup.each(function (d) {
      const el = select(this);
      const visual = getNodeVisual(d.label);

      switch (visual.shape) {
        case "circle":
          el.append("circle")
            .attr("r", visual.size)
            .attr("fill", visual.color)
            .attr("fill-opacity", 0.8)
            .attr("stroke", visual.color)
            .attr("stroke-width", 1.5);
          break;
        case "rect":
          el.append("rect")
            .attr("x", -visual.size)
            .attr("y", -visual.size)
            .attr("width", visual.size * 2)
            .attr("height", visual.size * 2)
            .attr("rx", 2)
            .attr("fill", visual.color)
            .attr("fill-opacity", 0.8)
            .attr("stroke", visual.color)
            .attr("stroke-width", 1.5);
          break;
        case "diamond":
          el.append("rect")
            .attr("x", -visual.size)
            .attr("y", -visual.size)
            .attr("width", visual.size * 2)
            .attr("height", visual.size * 2)
            .attr("rx", 1)
            .attr("fill", visual.color)
            .attr("fill-opacity", 0.8)
            .attr("stroke", visual.color)
            .attr("stroke-width", 1.5)
            .attr("transform", "rotate(45)");
          break;
        case "hexagon":
          el.append("polygon")
            .attr("points", hexagonPoints(visual.size))
            .attr("fill", visual.color)
            .attr("fill-opacity", 0.8)
            .attr("stroke", visual.color)
            .attr("stroke-width", 1.5);
          break;
      }
    });

    // Node labels
    nodeGroup
      .append("text")
      .attr("class", "node-label")
      .attr("dy", (d) => getNodeVisual(d.label).size + 12)
      .attr("text-anchor", "middle")
      .attr("fill", "#d1d5db")
      .attr("font-size", 10)
      .attr("opacity", 0)
      .text((d) => getNodeDisplayName(d.label, d.properties));

    // Drag behavior
    const dragBehavior = drag<SVGGElement, SimNode>()
      .on("start", (_event, d) => {
        if (simRef.current) simRef.current.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (_event, d) => {
        if (simRef.current) simRef.current.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    nodeGroup.call(dragBehavior);

    // Highlight selected/highlighted nodes
    function updateHighlights() {
      nodeGroup.each(function (d) {
        const el = select(this);
        const isSelected = d.id === selectedIdRef.current;
        const isHighlighted =
          d.id === highlightIdRef.current ||
          (highlightIdsRef.current?.has(d.id) ?? false);
        el.select("circle, rect, polygon")
          .attr("filter", isSelected || isHighlighted ? "url(#glow)" : null)
          .attr(
            "stroke-width",
            isSelected ? 3 : isHighlighted ? 2.5 : 1.5,
          )
          .attr(
            "stroke",
            isSelected
              ? "#ffffff"
              : isHighlighted
                ? "#fbbf24"
                : getNodeVisual(d.label).color,
          );
      });
    }
    updateHighlights();

    // Force simulation
    const simulation = forceSimulation<SimNode>(simNodes)
      .force(
        "link",
        forceLink<SimNode, SimLink>(simLinks)
          .id((d) => d.id)
          .distance(80),
      )
      .force("charge", forceManyBody().strength(-200))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide<SimNode>().radius(20))
      .on("tick", () => {
        linkGroup
          .attr("x1", (d) => (d.source as SimNode).x!)
          .attr("y1", (d) => (d.source as SimNode).y!)
          .attr("x2", (d) => (d.target as SimNode).x!)
          .attr("y2", (d) => (d.target as SimNode).y!);

        edgeLabelGroup
          .attr(
            "x",
            (d) =>
              ((d.source as SimNode).x! + (d.target as SimNode).x!) / 2,
          )
          .attr(
            "y",
            (d) =>
              ((d.source as SimNode).y! + (d.target as SimNode).y!) / 2,
          );

        nodeGroup.attr("transform", (d) => `translate(${d.x},${d.y})`);

        updateHighlights();
      });

    simRef.current = simulation;

    // Fit to content after initial settle
    const fitTimer = setTimeout(() => {
      if (simNodes.length > 0) {
        svgSel.call(zoomBehavior.transform, zoomIdentity);
      }
    }, 1000);

    return () => {
      clearTimeout(fitTimer);
      simulation.stop();
      svgSel.on(".zoom", null);
    };
  }, [nodes, edges, storePositions]);

  // ResizeObserver for responsive sizing
  useEffect(() => {
    const container = containerRef.current;
    const svg = svgRef.current;
    if (!container || !svg) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        svg.setAttribute("width", String(width));
        svg.setAttribute("height", String(height));
      }
    });

    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "100%",
        minHeight: 400,
        position: "relative",
      }}
    >
      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        style={{ background: "transparent" }}
        data-testid="network-graph-svg"
      />
    </div>
  );
}
