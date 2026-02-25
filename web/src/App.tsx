import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/layout/Layout";
import { Discover } from "./pages/Discover";
import { Defend } from "./pages/Defend";
import { Govern } from "./pages/Govern";
import { Observe } from "./pages/Observe";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Discover />} />
        <Route path="/discover" element={<Discover />} />
        <Route path="/defend" element={<Defend />} />
        <Route path="/govern" element={<Govern />} />
        <Route path="/observe" element={<Observe />} />
      </Route>
    </Routes>
  );
}
