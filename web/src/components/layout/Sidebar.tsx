import { NavLink } from "react-router-dom";

const navItems = [
  { to: "/discover", label: "Discover" },
  { to: "/defend", label: "Defend" },
  { to: "/govern", label: "Govern" },
  { to: "/observe", label: "Observe" },
];

export function Sidebar() {
  return (
    <nav
      style={{
        width: 220,
        background: "#161a23",
        borderRight: "1px solid #2a2e39",
        padding: "16px 0",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <div style={{ padding: "0 20px 24px", fontSize: 20, fontWeight: 700, letterSpacing: 1 }}>
        SENTINEL
      </div>
      {navItems.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          style={({ isActive }) => ({
            display: "block",
            padding: "10px 20px",
            color: isActive ? "#60a5fa" : "#9ca3af",
            textDecoration: "none",
            borderLeft: isActive ? "3px solid #60a5fa" : "3px solid transparent",
            background: isActive ? "rgba(96, 165, 250, 0.08)" : "transparent",
          })}
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}
