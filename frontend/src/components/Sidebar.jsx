import { Link, useLocation } from "react-router-dom";
import "./Sidebar.css";

export default function Sidebar() {
  const location = useLocation();

  const navItems = [
    { path: "/dashboard", label: "📊 Dashboard" },
    { path: "/inbox", label: "📥 Inbox" },
    { path: "/history", label: "⏳ Threat History" },
    { path: "/statistics", label: "📈 Statistics" },
    { path: "/settings", label: "⚙️ Settings" },
    { path: "/about", label: "ℹ️ About" },
    { path: "/documentation", label: "📚 Docs" }
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        {/* Placeholder if logo is in navbar instead */}
        <div style={{ height: "100%", width: "100%" }}></div>
      </div>
      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
          >
            {item.label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}
