/**
 * Route guard that redirects unauthenticated users to the login page.
 */

import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../../hooks/useAuthHook";

export function ProtectedRoute() {
  const { user } = useAuth();

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
