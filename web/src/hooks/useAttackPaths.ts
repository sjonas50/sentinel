/**
 * React Query hooks for attack path data.
 */

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listAttackPaths,
  getAttackPath,
  fetchAttackPathSummary,
} from "../services/api";
import type {
  AttackPathListParams,
  AttackPathListResponse,
  AttackPathDetailResponse,
  AttackPathSummaryResponse,
} from "../services/api";
import { onEvent } from "../services/ws";
import type { SentinelEvent } from "../types/events";

export function useAttackPaths(params: AttackPathListParams = {}) {
  return useQuery<AttackPathListResponse>({
    queryKey: ["attackPaths", params],
    queryFn: () => listAttackPaths(params),
  });
}

export function useAttackPathSummary() {
  return useQuery<AttackPathSummaryResponse>({
    queryKey: ["attackPathSummary"],
    queryFn: fetchAttackPathSummary,
  });
}

export function useAttackPathDetail(pathId: string | null) {
  return useQuery<AttackPathDetailResponse>({
    queryKey: ["attackPath", pathId],
    queryFn: () => getAttackPath(pathId!),
    enabled: pathId !== null,
  });
}

/** Subscribe to WebSocket events and invalidate attack path queries on changes. */
export function useAttackPathLiveUpdates() {
  const queryClient = useQueryClient();

  useEffect(() => {
    const unsubscribe = onEvent((event: SentinelEvent) => {
      if (event.payload.event_type === "AttackPathComputed") {
        queryClient.invalidateQueries({ queryKey: ["attackPaths"] });
        queryClient.invalidateQueries({ queryKey: ["attackPathSummary"] });
      }
    });
    return unsubscribe;
  }, [queryClient]);
}
