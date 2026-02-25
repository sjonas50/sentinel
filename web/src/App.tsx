import { Navigate, Route, Routes } from "react-router-dom";
import { ProtectedRoute } from "./components/auth/ProtectedRoute";
import { Layout } from "./components/layout/Layout";
import { Defend } from "./pages/Defend";
import { Discover } from "./pages/Discover";
import { Govern } from "./pages/Govern";
import { Login } from "./pages/Login";
import { Observe } from "./pages/Observe";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/" element={<Navigate to="/discover" replace />} />
          <Route path="/discover" element={<Discover />} />
          <Route path="/defend" element={<Defend />} />
          <Route path="/govern" element={<Govern />} />
          <Route path="/observe" element={<Observe />} />
        </Route>
      </Route>
    </Routes>
  );
}
