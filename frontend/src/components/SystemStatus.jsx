import { useState, useEffect, useRef } from "react";
import axios from "axios";
import useNotification from "../hooks/useNotification";

export default function SystemStatus() {
  const [status, setStatus] = useState(null);
  const previousState = useRef("initial");
  const notify = useNotification();

  useEffect(() => {
    const fetchHealth = () => {
      axios
        .get("http://127.0.0.1:8000/system/health")
        .then((res) => {
          setStatus(res.data);
          if (previousState.current === "offline") {
            notify.success("🟢 Backend connection restored");
          }
          previousState.current = "online";
        })
        .catch(() => {
          setStatus(null);
          if (previousState.current === "online" || previousState.current === "initial") {
            notify.warning("⚠ Backend offline");
          }
          previousState.current = "offline";
        });
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  if (!status) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--risk-high)', padding: '0.4rem 0.8rem', borderRadius: '9999px', backgroundColor: 'rgba(239, 68, 68, 0.1)', fontWeight: 'bold', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
        <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--risk-high)', boxShadow: '0 0 5px var(--risk-high)' }}></div>
        SYSTEM OFFLINE
      </div>
    );
  }

  return (
    <div 
      title={`Engine: ${status.engine} | Gmail: ${status.gmail}`}
      style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--risk-safe)', padding: '0.4rem 0.8rem', borderRadius: '9999px', backgroundColor: 'rgba(16, 185, 129, 0.1)', fontWeight: 'bold', border: '1px solid rgba(16, 185, 129, 0.3)', cursor: 'default' }}
    >
      <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--risk-safe)', boxShadow: '0 0 5px var(--risk-safe)' }}></div>
      SYSTEM {status.status.toUpperCase()}
    </div>
  );
}
