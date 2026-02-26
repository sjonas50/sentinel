/**
 * React Query hooks for vulnerability data.
 */

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listVulnerabilities,
  fetchVulnSummary,
  getVulnerability,
  getVulnAssets,
} from "../services/api";
import type {
  VulnListParams,
  VulnListResponse,
  VulnSummaryResponse,
  VulnDetailResponse,
  VulnAssetsResponse,
} from "../services/api";
import { onEvent } from "../services/ws";
import type { SentinelEvent } from "../types/events";

export function useVulnerabilities(params: VulnListParams = {}) {
  return useQuery<VulnListResponse>({
    queryKey: ["vulnerabilities", params],
    queryFn: () => listVulnerabilities(params),
  });
}

export function useVulnSummary() {
  return useQuery<VulnSummaryResponse>({
    queryKey: ["vulnSummary"],
    queryFn: fetchVulnSummary,
  });
}

export function useVulnDetail(cveId: string | null) {
  return useQuery<VulnDetailResponse>({
    queryKey: ["vulnerability", cveId],
    queryFn: () => getVulnerability(cveId!),
    enabled: cveId !== null,
  });
}

export function useVulnAssets(cveId: string | null) {
  return useQuery<VulnAssetsResponse>({
    queryKey: ["vulnAssets", cveId],
    queryFn: () => getVulnAssets(cveId!),
    enabled: cveId !== null,
  });
}

/** Subscribe to WebSocket events and invalidate vuln queries on changes. */
export function useVulnLiveUpdates() {
  const queryClient = useQueryClient();

  useEffect(() => {
    const unsubscribe = onEvent((event: SentinelEvent) => {
      if (event.payload.event_type === "VulnerabilityFound") {
        queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
        queryClient.invalidateQueries({ queryKey: ["vulnSummary"] });
        queryClient.invalidateQueries({ queryKey: ["graphStats"] });
      }
    });
    return unsubscribe;
  }, [queryClient]);
}
