import { useState } from "react";
import ThemeToggle from "../components/ThemeToggle";
import { getSettings, saveSettings } from "../utils/settings";
import useNotification from "../hooks/useNotification";

export default function Settings() {
  const [settings, setSettings] = useState(getSettings());
  const notify = useNotification();

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setSettings(prev => ({
      ...prev,
      [name]: type === "checkbox" ? checked : type === "number" || type === "range" ? Number(value) : value
    }));
  };

  const handleSave = () => {
    saveSettings(settings);
    notify.success("✅ Settings saved successfully");
  };

  const labelStyle = { display: "block", marginBottom: "0.5rem", color: "var(--text-muted)", fontWeight: "bold" };
  const inputStyle = { width: "100%", padding: "0.5rem", borderRadius: "8px", border: "1px solid var(--border-color)", backgroundColor: "var(--bg-secondary)", color: "var(--text-main)" };
  const checkboxStyle = { marginRight: "0.5rem", transform: "scale(1.2)" };

  return (
    <div className="settings-page" style={{ display: 'flex', flexDirection: 'column', gap: '2rem', paddingBottom: '2rem' }}>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Settings</h1>
        <button className="btn-primary" onClick={handleSave} style={{ padding: '0.5rem 1.5rem', borderRadius: '8px' }}>
          Save Settings
        </button>
      </div>

      <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', maxWidth: '800px' }}>
        <h2>General Preferences</h2>
        <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          <div>
            <label style={labelStyle}>Default Email Fetch Period</label>
            <select name="defaultFetchPeriod" value={settings.defaultFetchPeriod} onChange={handleChange} style={inputStyle}>
              <option value="recent">Recent (Last 50)</option>
              <option value="today">Today</option>
              <option value="week">Past Week</option>
              <option value="month">Past Month</option>
            </select>
          </div>

          <div>
            <label style={labelStyle}>Emails Per Page</label>
            <select name="emailsPerPage" value={settings.emailsPerPage} onChange={handleChange} style={inputStyle}>
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
          </div>

          <div style={{ display: "flex", alignItems: "center" }}>
            <input type="checkbox" name="autoRefresh" checked={settings.autoRefresh} onChange={handleChange} style={checkboxStyle} id="autoRefresh" />
            <label htmlFor="autoRefresh" style={{ color: "var(--text-main)", cursor: "pointer" }}>Enable Dashboard Auto-Refresh (Every 30s)</label>
          </div>

          <div style={{ display: "flex", alignItems: "center" }}>
            <input type="checkbox" name="notifications" checked={settings.notifications} onChange={handleChange} style={checkboxStyle} id="notifications" />
            <label htmlFor="notifications" style={{ color: "var(--text-main)", cursor: "pointer" }}>Enable Toast Notifications</label>
          </div>

          <div>
            <label style={labelStyle}>High-Risk Threshold ({settings.riskThreshold}%)</label>
            <input type="range" name="riskThreshold" min="0" max="100" value={settings.riskThreshold} onChange={handleChange} style={{ width: "100%", cursor: "pointer" }} />
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginTop: "0.5rem" }}>
              Emails scoring above this threshold will automatically be flagged as high risk.
            </p>
          </div>

        </div>
      </div>

      <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', maxWidth: '800px' }}>
        <h2>Theme</h2>
        <div style={{ marginTop: '1rem', color: 'var(--text-muted)' }}>
          <ThemeToggle />
        </div>
      </div>

      <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', maxWidth: '800px' }}>
        <h2>About TunaMail</h2>
        <div style={{ marginTop: '1rem', color: 'var(--text-main)', lineHeight: '1.6' }}>
          <p>TunaMail is an AI-powered threat analysis platform designed to identify, categorize, and explain potential email threats in real-time.</p>
          <p style={{ marginTop: '1rem' }}><strong>Version:</strong> v1.0.0</p>
          <p><strong>Engine:</strong> OpenAI GPT-4o-mini + Deep Heuristics</p>
        </div>
      </div>

    </div>
  );
}
