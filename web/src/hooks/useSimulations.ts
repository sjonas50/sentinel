/**
 * React Query hooks for simulation data.
 */

import { useQuery } from "@tanstack/react-query";
import { listSimulations, fetchSimulationSummary } from "../services/api";
import type {
  SimulationListParams,
  SimulationListResponse,
  SimulationSummaryResponse,
} from "../services/api";

export function useSimulations(params: SimulationListParams = {}) {
  return useQuery<SimulationListResponse>({
    queryKey: ["simulations", params],
    queryFn: () => listSimulations(params),
  });
}

export function useSimulationSummary() {
  return useQuery<SimulationSummaryResponse>({
    queryKey: ["simulationSummary"],
    queryFn: fetchSimulationSummary,
  });
}
