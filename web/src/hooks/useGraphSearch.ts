/**
 * React Query hook for full-text search across graph nodes.
 */

import { useQuery } from "@tanstack/react-query";
import { searchNodes } from "../services/api";
import type { SearchResponse } from "../services/api";

export function useGraphSearch(query: string, enabled = true) {
  return useQuery<SearchResponse>({
    queryKey: ["graphSearch", query],
    queryFn: () => searchNodes(query),
    enabled: enabled && query.length >= 2,
  });
}
