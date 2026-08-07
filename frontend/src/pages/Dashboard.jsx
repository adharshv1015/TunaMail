import { useState, useEffect } from "react";
import axios from "axios";

export default function Dashboard() {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const fetchHealth = () => {
      axios
        .get("http://127.0.0.1:8000/system/health")
        .then((res) => {
          setHealth(res.data);
        })
        .catch(() => {
          setHealth(null);
        });
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-page" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      
      {/* Welcome Section */}
      <section className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
        <h1>Welcome to TunaMail</h1>
        <p>Your AI-powered email threat analysis dashboard.</p>
      </section>

      {/* SYSTEM HEALTH CARDS */}
      <section>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '1rem' }}>
          <h2 style={{ margin: 0, color: 'var(--text-main)' }}>System Health</h2>
          {health?.time && (
            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', backgroundColor: health?.status === 'online' ? 'var(--risk-safe)' : 'var(--risk-high)', animation: 'pulse 2s infinite' }}></span>
              Last checked: {new Date(health.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
          )}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
          
          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', borderLeft: health?.status === 'online' ? '4px solid var(--risk-safe)' : '4px solid var(--risk-high)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold', textTransform: 'uppercase' }}>Backend</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text-main)' }}>
              {health?.status === 'online' ? '🟢 Online' : '🔴 Offline'}
            </div>
          </div>

          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', borderLeft: health?.gmail === 'connected' ? '4px solid var(--risk-safe)' : '4px solid var(--risk-suspicious)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold', textTransform: 'uppercase' }}>Gmail</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text-main)' }}>
              {health?.gmail === 'connected' ? '📧 Connected' : '⚠️ Disconnected'}
            </div>
          </div>

          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', borderLeft: health?.engine === 'ready' ? '4px solid var(--risk-safe)' : '4px solid var(--risk-high)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold', textTransform: 'uppercase' }}>Detection Engine</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text-main)' }}>
              {health?.engine === 'ready' ? '🧠 Ready' : '🔴 Offline'}
            </div>
          </div>

          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', borderLeft: health?.version ? '4px solid var(--accent-primary)' : '4px solid var(--text-muted)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold', textTransform: 'uppercase' }}>Version</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text-main)' }}>
              {health?.version ? `🏷 ${health.version}` : 'Unknown'}
            </div>
          </div>

        </div>
      </section>

      {/* Grid for main layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '2rem' }}>
        
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          
          {/* Recent Threats Placeholder */}
          <section className="glass" style={{ padding: '1.5rem', borderRadius: '12px', minHeight: '300px' }}>
            <h2>Recent Threats</h2>
            <div style={{ marginTop: '1rem', color: 'var(--text-muted)' }}>
              [ Placeholder for recent threat list ]
            </div>
          </section>

        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          
          {/* Risk Overview Placeholder */}
          <section className="glass" style={{ padding: '1.5rem', borderRadius: '12px', minHeight: '200px' }}>
            <h2>Risk Overview</h2>
            <div style={{ marginTop: '1rem', color: 'var(--text-muted)' }}>
              [ Placeholder for risk meter or chart ]
            </div>
          </section>

          {/* Statistics Placeholder */}
          <section className="glass" style={{ padding: '1.5rem', borderRadius: '12px', minHeight: '200px' }}>
            <h2>Statistics</h2>
            <div style={{ marginTop: '1rem', color: 'var(--text-muted)' }}>
              [ Placeholder for stats and metrics ]
            </div>
          </section>

        </div>
      </div>
      
    </div>
  );
}
