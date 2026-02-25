/**
 * Authentication service — JWT token management and login flow.
 */

const TOKEN_KEY = "sentinel_token";
const USER_KEY = "sentinel_user";

export interface AuthUser {
  sub: string;
  tenant_id: string;
  role: string;
}

/** Store JWT token and decoded user info after login. */
export function setAuth(token: string): AuthUser {
  localStorage.setItem(TOKEN_KEY, token);
  const user = decodeToken(token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  return user;
}

/** Clear stored credentials on logout. */
export function clearAuth(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

/** Get the stored JWT token, or null if not logged in. */
export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

/** Get the current user from stored claims, or null. */
export function getUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

/** Check if the user is currently authenticated. */
export function isAuthenticated(): boolean {
  return getToken() !== null;
}

/**
 * Decode JWT payload without verification (verification happens server-side).
 * This is only for reading claims client-side.
 */
function decodeToken(token: string): AuthUser {
  const payload = token.split(".")[1];
  if (!payload) throw new Error("Invalid token format");
  const decoded = JSON.parse(atob(payload));
  return {
    sub: decoded.sub,
    tenant_id: decoded.tenant_id,
    role: decoded.role ?? "analyst",
  };
}
