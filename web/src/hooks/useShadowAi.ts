/**
 * React Query hooks for Shadow AI discovery data.
 */

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listShadowAiServices,
  getShadowAiService,
  fetchShadowAiSummary,
} from "../services/api";
import type {
  ShadowAiListParams,
  ShadowAiListResponse,
  ShadowAiDetailResponse,
  ShadowAiSummaryResponse,
} from "../services/api";
import { onEvent } from "../services/ws";
import type { SentinelEvent } from "../types/events";

export function useShadowAiServices(params: ShadowAiListParams = {}) {
  return useQuery<ShadowAiListResponse>({
    queryKey: ["shadowAiServices", params],
    queryFn: () => listShadowAiServices(params),
  });
}

export function useShadowAiSummary() {
  return useQuery<ShadowAiSummaryResponse>({
    queryKey: ["shadowAiSummary"],
    queryFn: fetchShadowAiSummary,
  });
}

export function useShadowAiDetail(serviceId: string | null) {
  return useQuery<ShadowAiDetailResponse>({
    queryKey: ["shadowAiService", serviceId],
    queryFn: () => getShadowAiService(serviceId!),
    enabled: serviceId !== null,
  });
}

/** Subscribe to WebSocket events and invalidate shadow AI queries on changes. */
export function useShadowAiLiveUpdates() {
  const queryClient = useQueryClient();

  useEffect(() => {
    const unsubscribe = onEvent((event: SentinelEvent) => {
      if (event.payload.event_type === "ShadowAiDiscovered") {
        queryClient.invalidateQueries({ queryKey: ["shadowAiServices"] });
        queryClient.invalidateQueries({ queryKey: ["shadowAiSummary"] });
      }
    });
    return unsubscribe;
  }, [queryClient]);
}
