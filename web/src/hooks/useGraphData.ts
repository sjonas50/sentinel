/**
 * React Query hooks for graph topology and stats data.
 */

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchTopology, fetchGraphStats } from "../services/api";
import type { TopologyResponse, GraphStatsResponse } from "../services/api";
import { onEvent } from "../services/ws";
import type { SentinelEvent } from "../types/events";

export function useTopology(labels: string, nodeLimit = 200) {
  return useQuery<TopologyResponse>({
    queryKey: ["topology", labels, nodeLimit],
    queryFn: () => fetchTopology(labels, nodeLimit),
  });
}

export function useGraphStats() {
  return useQuery<GraphStatsResponse>({
    queryKey: ["graphStats"],
    queryFn: fetchGraphStats,
  });
}

/** Subscribe to WebSocket events and invalidate topology + stats on graph changes. */
export function useGraphLiveUpdates() {
  const queryClient = useQueryClient();

  useEffect(() => {
    const unsubscribe = onEvent((event: SentinelEvent) => {
      const t = event.payload.event_type;
      if (
        t === "NodeDiscovered" ||
        t === "NodeUpdated" ||
        t === "EdgeDiscovered" ||
        t === "ScanCompleted"
      ) {
        queryClient.invalidateQueries({ queryKey: ["topology"] });
        queryClient.invalidateQueries({ queryKey: ["graphStats"] });
      }
    });
    return unsubscribe;
  }, [queryClient]);
}
