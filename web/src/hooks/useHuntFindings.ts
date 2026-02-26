/**
 * React Query hooks for hunt finding data.
 */

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listHuntFindings,
  getHuntFinding,
  fetchHuntSummary,
} from "../services/api";
import type {
  HuntFindingListParams,
  HuntFindingListResponse,
  HuntFindingDetailResponse,
  HuntSummaryResponse,
} from "../services/api";
import { onEvent } from "../services/ws";
import type { SentinelEvent } from "../types/events";

export function useHuntFindings(params: HuntFindingListParams = {}) {
  return useQuery<HuntFindingListResponse>({
    queryKey: ["huntFindings", params],
    queryFn: () => listHuntFindings(params),
  });
}

export function useHuntSummary() {
  return useQuery<HuntSummaryResponse>({
    queryKey: ["huntSummary"],
    queryFn: fetchHuntSummary,
  });
}

export function useHuntFindingDetail(findingId: string | null) {
  return useQuery<HuntFindingDetailResponse>({
    queryKey: ["huntFinding", findingId],
    queryFn: () => getHuntFinding(findingId!),
    enabled: findingId !== null,
  });
}

/** Subscribe to WebSocket events and invalidate hunt queries on changes. */
export function useHuntLiveUpdates() {
  const queryClient = useQueryClient();

  useEffect(() => {
    const unsubscribe = onEvent((event: SentinelEvent) => {
      if (event.payload.event_type === "HuntFinding") {
        queryClient.invalidateQueries({ queryKey: ["huntFindings"] });
        queryClient.invalidateQueries({ queryKey: ["huntSummary"] });
      }
    });
    return unsubscribe;
  }, [queryClient]);
}
