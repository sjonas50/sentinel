/**
 * WebSocket client for real-time event streaming.
 *
 * Phase 0 stub — connects to the backend WebSocket endpoint
 * and dispatches incoming events to registered listeners.
 */

import type { SentinelEvent } from "../types/events";
import { getToken } from "./auth";

type EventListener = (event: SentinelEvent) => void;

let socket: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
const listeners = new Set<EventListener>();

const WS_BASE = `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}`;
const RECONNECT_DELAY_MS = 5000;

/** Register a listener for incoming events. Returns an unsubscribe function. */
export function onEvent(listener: EventListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Connect to the WebSocket endpoint. No-op if already connected. */
export function connect(): void {
  if (socket?.readyState === WebSocket.OPEN) return;

  const token = getToken();
  if (!token) return;

  socket = new WebSocket(`${WS_BASE}/ws/events?token=${encodeURIComponent(token)}`);

  socket.onmessage = (msg) => {
    try {
      const event = JSON.parse(msg.data) as SentinelEvent;
      for (const listener of listeners) {
        listener(event);
      }
    } catch {
      // ignore malformed messages (e.g. heartbeats)
    }
  };

  socket.onclose = () => {
    socket = null;
    scheduleReconnect();
  };

  socket.onerror = () => {
    socket?.close();
  };
}

/** Disconnect and stop reconnecting. */
export function disconnect(): void {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (socket) {
    socket.close();
    socket = null;
  }
}

function scheduleReconnect(): void {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, RECONNECT_DELAY_MS);
}
