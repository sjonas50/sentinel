/**
 * Auth context definition — shared between the provider and the hook.
 */

import { createContext } from "react";
import type { AuthUser } from "../services/auth";

export interface AuthContextValue {
  user: AuthUser | null;
  login: (token: string) => void;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
