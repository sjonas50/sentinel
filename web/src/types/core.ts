/**
 * Core domain types for the Sentinel platform.
 *
 * These mirror the Rust types in sentinel-core and the Pydantic models in sentinel-api.
 * Full implementation in Task 0.2.
 */

export interface Asset {
  id: string;
  type: "host" | "service" | "user" | "group" | "subnet" | "vpc";
  name: string;
  properties: Record<string, unknown>;
}
