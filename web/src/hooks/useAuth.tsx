/**
 * AuthProvider component — wraps app to provide auth state.
 */

import { useCallback, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { AuthUser } from "../services/auth";
import { clearAuth, getUser, setAuth } from "../services/auth";
import { AuthContext } from "./AuthContext";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(getUser);

  const login = useCallback((token: string) => {
    const u = setAuth(token);
    setUser(u);
  }, []);

  const logout = useCallback(() => {
    clearAuth();
    setUser(null);
  }, []);

  const value = useMemo(() => ({ user, login, logout }), [user, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
