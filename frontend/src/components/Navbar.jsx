import { Link, useLocation } from "react-router-dom";
import SystemStatus from "./SystemStatus";
import "./Navbar.css";

export default function Navbar() {
  const location = useLocation();

  const navItems = [
    { path: "/dashboard", label: "Dashboard" },
    { path: "/inbox", label: "Inbox" },
    { path: "/settings", label: "Settings" }
  ];

  return (
    <header className="navbar glass">
      <div className="navbar-left">
        <div className="navbar-logo">
          <h2>🐟 TunaMail</h2>
        </div>
        <nav className="navbar-links">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`navbar-link ${location.pathname.startsWith(item.path) ? "active" : ""}`}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </div>
      
      <div className="navbar-right" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <SystemStatus />
        <Link to="/" className="logout-btn">
          Logout
        </Link>
      </div>
    </header>
  );
}
