import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import useNotification from "../hooks/useNotification";
import EmailCard from "../components/EmailCard";
import Loading from "../components/Loading";
import RiskChart from "../components/RiskChart";

export default function Inbox() {
  const navigate = useNavigate();
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterVerdict, setFilterVerdict] = useState("all");
  const [sortOrder, setSortOrder] = useState("newest");
  const [health, setHealth] = useState(null);
  const notify = useNotification();

  const fetchEmails = async () => {
    setLoading(true);
    try {
      const response = await api.get("/gmail/messages");

      const formattedEmails = response.data.messages.map(msg => ({
        id: msg.id,
        sender: msg.from || "Unknown",
        subject: msg.subject || "No Subject",
        snippet: msg.snippet || "No snippet available...",
        verdict: msg.analysis?.decision?.verdict || "UNKNOWN",
        detail_verdict: msg.analysis?.decision?.detail_verdict || null,
        riskScore: msg.analysis?.decision?.risk_score || 0,
        confidence: msg.analysis?.decision?.confidence || 0,
        time: msg.date || "Just now",
        categories: msg.categories || [],
        body: msg.body || "No email body provided.",
        analysis: msg.analysis || {}
      }));

      setEmails(formattedEmails);
      if (formattedEmails.length === 0) {
        notify.info("📭 No emails found");
      } else {
        notify.success("🔄 Inbox refreshed");
      }
    } catch (err) {
      console.error(err);
      notify.error("❌ Request failed");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmails();
  }, []);

  useEffect(() => {
    const fetchHealth = () => {
      api
        .get("/system/health")
        .then((res) => setHealth(res.data))
        .catch(() => setHealth(null));
    };
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const filteredEmails = emails.filter((email) => {
    const query = search.toLowerCase();
    const matchesSearch = email.subject?.toLowerCase().includes(query) ||
      email.sender?.toLowerCase().includes(query);

    if (!matchesSearch) return false;

    if (filterVerdict === "all") return true;

    const v = email.verdict.toUpperCase();
    if (filterVerdict === "safe") return v === "VERIFIED LEGITIMATE" || v === "LIKELY LEGITIMATE";
    if (filterVerdict === "unknown") return v === "UNKNOWN";
    if (filterVerdict === "suspicious") return v === "SUSPICIOUS";
    if (filterVerdict === "phishing") return v === "PHISHING" || v === "HIGH RISK";

    return true;
  });

  const sortedAndFilteredEmails = filteredEmails.sort((a, b) => {
    if (sortOrder === "newest") {
      return new Date(b.time) - new Date(a.time);
    }
    if (sortOrder === "oldest") {
      return new Date(a.time) - new Date(b.time);
    }
    if (sortOrder === "highest_risk") {
      return (b.riskScore || 0) - (a.riskScore || 0);
    }
    if (sortOrder === "lowest_risk") {
      return (a.riskScore || 0) - (b.riskScore || 0);
    }
    return 0;
  });

  const totalEmails = emails.length;
  const safeCount = emails.filter(e => e.verdict.toUpperCase() === "VERIFIED LEGITIMATE" || e.verdict.toUpperCase() === "LIKELY LEGITIMATE").length;
  const unknownCount = emails.filter(e => e.verdict.toUpperCase() === "UNKNOWN").length;
  const suspiciousCount = emails.filter(e => e.verdict.toUpperCase() === "SUSPICIOUS").length;
  const phishingCount = emails.filter(e => e.verdict.toUpperCase() === "PHISHING" || e.verdict.toUpperCase() === "HIGH RISK").length;

  const totalRisk = emails.reduce((sum, email) => sum + (email.riskScore || 0), 0);
  const averageRisk = totalEmails > 0 ? Math.round(totalRisk / totalEmails) : 0;

  const highestRiskEmail = emails.length > 0
    ? emails.reduce((max, email) => (email.riskScore || 0) > (max.riskScore || 0) ? email : max, emails[0])
    : null;

  return (
    <div className="inbox-page">

      {/* SYSTEM HEALTH STRIP */}
      <div className="glass" style={{ display: 'flex', flexWrap: 'wrap', gap: '2rem', padding: '1rem 2rem', borderRadius: '12px', marginBottom: '2rem', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.9rem', fontWeight: 'bold' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: health?.status === 'online' ? 'var(--risk-safe)' : 'var(--risk-high)' }}>
          <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: 'currentColor', boxShadow: '0 0 5px currentColor' }}></div>
          Backend {health?.status === 'online' ? 'Online' : 'Offline'}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: health?.engine === 'ready' ? 'var(--risk-safe)' : 'var(--risk-high)' }}>
          🧠 Engine {health?.engine === 'ready' ? 'Ready' : 'Offline'}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: health?.gmail === 'connected' ? 'var(--risk-safe)' : 'var(--risk-suspicious)' }}>
          📧 Gmail {health?.gmail === 'connected' ? 'Connected' : 'Disconnected'}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-muted)' }}>
          🏷️ Version {health?.version || '1.0.0'}
        </div>
      </div>

      <div className="page-header" style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1>Inbox</h1>
            <p>Review and analyze your recent incoming messages.</p>
          </div>
          <button
            onClick={fetchEmails}
            disabled={loading}
            style={{
              padding: '0.75rem 1.5rem',
              borderRadius: '8px',
              border: 'none',
              backgroundColor: 'var(--accent-primary)',
              color: 'white',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.7 : 1,
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              transition: 'all 0.2s'
            }}
          >
            {loading ? '↻ Loading...' : '↻ Refresh Inbox'}
          </button>
        </div>

        {/* STATISTICS CARDS */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem', marginTop: '1.5rem' }}>
          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', textAlign: 'center', borderLeft: '4px solid var(--accent-primary)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold' }}>Total Emails</div>
            <div style={{ fontSize: '2.5rem', fontWeight: '900', color: 'var(--text-main)' }}>{totalEmails}</div>
          </div>
          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', textAlign: 'center', borderLeft: '4px solid #a855f7' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold' }}>Avg Risk</div>
            <div style={{ fontSize: '2.5rem', fontWeight: '900', color: '#a855f7' }}>{averageRisk}%</div>
          </div>
          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', textAlign: 'center', borderLeft: '4px solid var(--risk-safe)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold' }}>Safe</div>
            <div style={{ fontSize: '2.5rem', fontWeight: '900', color: 'var(--risk-safe)' }}>{safeCount}</div>
          </div>
          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', textAlign: 'center', borderLeft: '4px solid var(--tm-text-secondary)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold' }}>Unknown</div>
            <div style={{ fontSize: '2.5rem', fontWeight: '900', color: 'var(--tm-text-secondary)' }}>{unknownCount}</div>
          </div>
          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', textAlign: 'center', borderLeft: '4px solid var(--risk-suspicious)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold' }}>Suspicious</div>
            <div style={{ fontSize: '2.5rem', fontWeight: '900', color: 'var(--risk-suspicious)' }}>{suspiciousCount}</div>
          </div>
          <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px', textAlign: 'center', borderLeft: '4px solid var(--risk-phishing)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold' }}>Phishing</div>
            <div style={{ fontSize: '2.5rem', fontWeight: '900', color: 'var(--risk-phishing)' }}>{phishingCount}</div>
          </div>
          {highestRiskEmail && (
            <div
              className="glass"
              style={{ padding: '1.5rem', borderRadius: '12px', textAlign: 'center', borderLeft: '4px solid var(--risk-high)', cursor: 'pointer' }}
              onClick={() => navigate(`/email/${highestRiskEmail.id}`)}
              onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.02)'}
              onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
            >
              <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 'bold' }}>Highest Risk</div>
              <div style={{ fontSize: '1rem', fontWeight: 'bold', color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', padding: '0 0.5rem' }}>{highestRiskEmail.subject}</div>
              <div style={{ fontSize: '1.2rem', color: 'var(--risk-phishing)', marginTop: '0.5rem', fontWeight: '900' }}>Risk: {highestRiskEmail.riskScore}</div>
            </div>
          )}
        </div>

        <div style={{ marginTop: '2rem' }}>
          <RiskChart
            safeCount={safeCount}
            suspiciousCount={suspiciousCount}
            phishingCount={phishingCount}
          />
        </div>

        <div style={{ marginTop: '2rem', display: 'flex', alignItems: 'center' }}>
          <span style={{ position: 'absolute', marginLeft: '1rem', color: 'var(--text-muted)' }}>🔍</span>
          <input
            type="text"
            placeholder="Search emails by subject or sender..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              maxWidth: '500px',
              padding: '0.75rem 1rem 0.75rem 2.5rem',
              borderRadius: '8px',
              border: '1px solid var(--border-color)',
              backgroundColor: 'rgba(0, 0, 0, 0.2)',
              color: 'var(--text-main)',
              fontSize: '1rem',
              outline: 'none'
            }}
          />
        </div>

        {/* FILTERS AND SORTING */}
        <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button
              onClick={() => setFilterVerdict('all')}
              style={{ padding: '0.5rem 1rem', borderRadius: '20px', border: 'none', cursor: 'pointer', fontWeight: 'bold', transition: 'all 0.2s', backgroundColor: filterVerdict === 'all' ? 'var(--accent-primary)' : 'rgba(255,255,255,0.1)', color: 'white' }}
            >All</button>
            <button
              onClick={() => setFilterVerdict('safe')}
              style={{ padding: '0.5rem 1rem', borderRadius: '20px', border: 'none', cursor: 'pointer', fontWeight: 'bold', transition: 'all 0.2s', backgroundColor: filterVerdict === 'safe' ? 'var(--risk-safe)' : 'rgba(255,255,255,0.1)', color: 'white' }}
            >Safe</button>
            <button
              onClick={() => setFilterVerdict('unknown')}
              style={{ padding: '0.5rem 1rem', borderRadius: '20px', border: 'none', cursor: 'pointer', fontWeight: 'bold', transition: 'all 0.2s', backgroundColor: filterVerdict === 'unknown' ? '#71717a' : 'rgba(255,255,255,0.1)', color: 'white' }}
            >Unknown</button>
            <button
              onClick={() => setFilterVerdict('suspicious')}
              style={{ padding: '0.5rem 1rem', borderRadius: '20px', border: 'none', cursor: 'pointer', fontWeight: 'bold', transition: 'all 0.2s', backgroundColor: filterVerdict === 'suspicious' ? 'var(--risk-suspicious)' : 'rgba(255,255,255,0.1)', color: 'white' }}
            >Suspicious</button>
            <button
              onClick={() => setFilterVerdict('phishing')}
              style={{ padding: '0.5rem 1rem', borderRadius: '20px', border: 'none', cursor: 'pointer', fontWeight: 'bold', transition: 'all 0.2s', backgroundColor: filterVerdict === 'phishing' ? 'var(--risk-phishing)' : 'rgba(255,255,255,0.1)', color: 'white' }}
            >Phishing</button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Sort by:</span>
            <select
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value)}
              style={{
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-main)',
                fontSize: '0.9rem',
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              <option value="newest">Newest</option>
              <option value="oldest">Oldest</option>
              <option value="highest_risk">Highest Risk</option>
              <option value="lowest_risk">Lowest Risk</option>
            </select>
          </div>

        </div>
      </div>

      {loading ? (
        <Loading />
      ) : (
        <div className="email-list">
          {sortedAndFilteredEmails.length === 0 ? (
            <div className="glass" style={{ padding: '4rem 2rem', borderRadius: '12px', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
              <div style={{ fontSize: '4rem' }}>📭</div>
              <h2 style={{ fontSize: '1.5rem', color: 'var(--text-main)', margin: 0 }}>
                {emails.length === 0 ? "No emails found" : "No matching emails"}
              </h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '1.1rem', margin: 0 }}>
                {emails.length === 0 ? "Try refreshing your inbox to fetch new messages." : "Try adjusting your search or verdict filters."}
              </p>
              {emails.length === 0 && (
                <button
                  onClick={fetchEmails}
                  style={{ marginTop: '1rem', padding: '0.75rem 1.5rem', borderRadius: '8px', border: 'none', backgroundColor: 'var(--accent-primary)', color: 'white', fontWeight: 'bold', cursor: 'pointer', transition: 'all 0.2s' }}
                  onMouseEnter={(e) => e.currentTarget.style.opacity = '0.8'}
                  onMouseLeave={(e) => e.currentTarget.style.opacity = '1'}
                >
                  ↻ Refresh Now
                </button>
              )}
            </div>
          ) : (
            sortedAndFilteredEmails.map(email => (
              <EmailCard key={email.id} email={email} />
            ))
          )}
        </div>
      )}
    </div>
  );
}
