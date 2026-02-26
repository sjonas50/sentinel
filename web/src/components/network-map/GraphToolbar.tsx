/**
 * Toolbar for the network map: search, view toggle, label filters.
 */

import { useState, useRef, useEffect } from "react";
import { useGraphSearch } from "../../hooks/useGraphSearch";
import { getNodeDisplayName, getNodeVisual } from "./graph-utils";

export type ViewMode = "graph" | "table";

const LABEL_OPTIONS = ["Host", "Service", "User", "Subnet", "Vpc"] as const;

export interface GraphToolbarProps {
  viewMode: ViewMode;
  onViewModeChange: (mode: ViewMode) => void;
  activeLabels: string[];
  onActiveLabelsChange: (labels: string[]) => void;
  onSelectNode?: (nodeId: string, label: string) => void;
}

export function GraphToolbar({
  viewMode,
  onViewModeChange,
  activeLabels,
  onActiveLabelsChange,
  onSelectNode,
}: GraphToolbarProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [showResults, setShowResults] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  const { data: searchData, isLoading } = useGraphSearch(searchQuery);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setShowResults(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  function toggleLabel(label: string) {
    if (activeLabels.includes(label)) {
      if (activeLabels.length > 1) {
        onActiveLabelsChange(activeLabels.filter((l) => l !== label));
      }
    } else {
      onActiveLabelsChange([...activeLabels, label]);
    }
  }

  const segmentStyle = (active: boolean): React.CSSProperties => ({
    padding: "6px 14px",
    fontSize: 13,
    fontWeight: 500,
    border: "none",
    cursor: "pointer",
    background: active ? "#3b82f6" : "transparent",
    color: active ? "#ffffff" : "#9ca3af",
    borderRadius: 4,
  });

  const pillStyle = (active: boolean, color: string): React.CSSProperties => ({
    padding: "4px 12px",
    fontSize: 12,
    fontWeight: 500,
    border: `1px solid ${active ? color : "#374151"}`,
    borderRadius: 12,
    cursor: "pointer",
    background: active ? `${color}22` : "transparent",
    color: active ? color : "#6b7280",
  });

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        flexWrap: "wrap",
        marginBottom: 16,
      }}
    >
      {/* Search */}
      <div ref={searchRef} style={{ position: "relative", flex: "0 0 240px" }}>
        <input
          type="text"
          placeholder="Search nodes..."
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            setShowResults(true);
          }}
          onFocus={() => setShowResults(true)}
          aria-label="Search nodes"
          style={{
            width: "100%",
            padding: "6px 12px",
            fontSize: 13,
            background: "#1e2230",
            border: "1px solid #2a2e39",
            borderRadius: 6,
            color: "#e0e0e0",
            outline: "none",
          }}
        />
        {showResults && searchQuery.length >= 2 && (
          <div
            style={{
              position: "absolute",
              top: "100%",
              left: 0,
              right: 0,
              marginTop: 4,
              background: "#1e2230",
              border: "1px solid #2a2e39",
              borderRadius: 6,
              maxHeight: 240,
              overflowY: "auto",
              zIndex: 50,
            }}
          >
            {isLoading && (
              <div style={{ padding: 8, color: "#6b7280", fontSize: 12 }}>
                Searching...
              </div>
            )}
            {searchData && searchData.results.length === 0 && (
              <div style={{ padding: 8, color: "#6b7280", fontSize: 12 }}>
                No results
              </div>
            )}
            {searchData?.results.map((r) => {
              const nodeLabel = r.labels[0] ?? "Unknown";
              const name = getNodeDisplayName(
                nodeLabel,
                r.node as Record<string, unknown>,
              );
              return (
                <button
                  key={String((r.node as Record<string, unknown>).id ?? "")}
                  onClick={() => {
                    onSelectNode?.(
                      String((r.node as Record<string, unknown>).id ?? ""),
                      nodeLabel,
                    );
                    setShowResults(false);
                    setSearchQuery("");
                  }}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    width: "100%",
                    padding: "6px 10px",
                    background: "transparent",
                    border: "none",
                    color: "#d1d5db",
                    fontSize: 12,
                    cursor: "pointer",
                    textAlign: "left",
                  }}
                >
                  <span
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: getNodeVisual(nodeLabel).color,
                      flexShrink: 0,
                    }}
                  />
                  <span style={{ flex: 1 }}>{name}</span>
                  <span style={{ color: "#6b7280", fontSize: 10 }}>
                    {nodeLabel}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* View toggle */}
      <div
        style={{
          display: "flex",
          background: "#1e2230",
          borderRadius: 6,
          border: "1px solid #2a2e39",
          overflow: "hidden",
        }}
      >
        <button
          onClick={() => onViewModeChange("graph")}
          style={segmentStyle(viewMode === "graph")}
          aria-label="Graph view"
        >
          Graph
        </button>
        <button
          onClick={() => onViewModeChange("table")}
          style={segmentStyle(viewMode === "table")}
          aria-label="Table view"
        >
          Table
        </button>
      </div>

      {/* Label filters */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {LABEL_OPTIONS.map((label) => {
          const visual = getNodeVisual(label);
          return (
            <button
              key={label}
              onClick={() => toggleLabel(label)}
              style={pillStyle(activeLabels.includes(label), visual.color)}
            >
              {label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
