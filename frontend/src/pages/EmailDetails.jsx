import { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";
import useNotification from "../hooks/useNotification";

export default function EmailDetails() {
  const { id } = useParams();
  const [email, setEmail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const notify = useNotification();

  useEffect(() => {
    const fetchEmail = async () => {
      try {
        setLoading(true);
        const response = await axios.get(`http://127.0.0.1:8000/gmail/message/${id}`);
        setEmail(response.data);
        notify.info("🧠 Email analysis completed");
      } catch (err) {
        console.error("Failed to fetch email details:", err);
        setError("Could not load email details.");
      } finally {
        setLoading(false);
      }
    };

    fetchEmail();
  }, [id]);

  if (loading) {
    return <div style={{ color: 'var(--text-main)', textAlign: 'center', marginTop: '3rem' }}>Loading email details...</div>;
  }

  if (error || !email) {
    return <div style={{ color: 'var(--risk-high)', textAlign: 'center', marginTop: '3rem' }}>{error || "Email not found."}</div>;
  }

  // Extract nested properties safely
  const analysis = email.analysis || {};
  const auth = analysis.authentication || {};
  const content = analysis.content || {};
  const url = analysis.url || {};
  const attachment = analysis.attachment || {};
  const decision = analysis.decision || {};
  const reasoning = analysis.reasoning || {};

  const verdict = decision.verdict || "UNKNOWN";
  const verdictColor = verdict === 'PHISHING' ? 'var(--risk-phishing)' : 
                       verdict === 'HIGH RISK' ? 'var(--risk-high)' : 
                       verdict === 'SUSPICIOUS' ? 'var(--risk-suspicious)' : 
                       verdict === 'LOW RISK' ? 'var(--risk-low)' : 'var(--risk-safe)';

  const getRiskColor = (score) => {
    if (score <= 30) return 'var(--risk-safe)';
    if (score <= 60) return 'var(--risk-suspicious)';
    return 'var(--risk-phishing)';
  };

  let bannerConfig = { bgColor: 'rgba(16, 185, 129, 0.1)', borderColor: 'var(--risk-safe)', color: 'var(--risk-safe)', icon: '🛡️', text: 'SAFE', description: 'This email appears legitimate and safe to open.' };
  
  if (verdict === 'PHISHING' || verdict === 'HIGH RISK') {
    bannerConfig = { bgColor: 'rgba(239, 68, 68, 0.1)', borderColor: 'var(--risk-phishing)', color: 'var(--risk-phishing)', icon: '🚨', text: verdict, description: 'WARNING: This email has been flagged as highly dangerous. Do not click links or download attachments.' };
  } else if (verdict === 'SUSPICIOUS' || verdict === 'LOW RISK') {
    bannerConfig = { bgColor: 'rgba(245, 158, 11, 0.1)', borderColor: 'var(--risk-suspicious)', color: 'var(--risk-suspicious)', icon: '⚠️', text: verdict, description: 'CAUTION: This email exhibits suspicious characteristics. Proceed with care.' };
  }

  return (
    <div className="email-details-page" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      
      {/* VERDICT BANNER */}
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '2rem',
        borderRadius: '12px',
        backgroundColor: bannerConfig.bgColor,
        border: `2px solid ${bannerConfig.borderColor}`,
        color: bannerConfig.color,
        textAlign: 'center',
        boxShadow: `0 4px 20px ${bannerConfig.bgColor}`
      }}>
        <div style={{ fontSize: '3.5rem', marginBottom: '0.5rem' }}>{bannerConfig.icon}</div>
        <h2 style={{ fontSize: '2.5rem', fontWeight: '900', textTransform: 'uppercase', letterSpacing: '2px', margin: 0 }}>{bannerConfig.text}</h2>
        <p style={{ marginTop: '0.5rem', fontSize: '1.2rem', fontWeight: '500', opacity: 0.9 }}>{bannerConfig.description}</p>
      </div>

      {/* EXPORT ACTION BAR */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem', marginTop: '-1rem' }}>
        <a 
          href={`http://127.0.0.1:8000/report/pdf/${id}`}
          target="_blank"
          rel="noreferrer"
          onClick={() => notify.success("📄 Report exported")}
          style={{ padding: '0.75rem 1.5rem', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.1)', color: 'var(--text-main)', textDecoration: 'none', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '0.5rem', transition: 'background 0.2s', border: '1px solid var(--border-color)' }}
          onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.2)'}
          onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.1)'}
        >
          📄 Export PDF
        </a>
        <a 
          href={`http://127.0.0.1:8000/report/json/${id}`}
          target="_blank"
          rel="noreferrer"
          onClick={() => notify.success("📄 Report exported")}
          style={{ padding: '0.75rem 1.5rem', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.1)', color: 'var(--text-main)', textDecoration: 'none', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '0.5rem', transition: 'background 0.2s', border: '1px solid var(--border-color)' }}
          onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.2)'}
          onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.1)'}
        >
          📦 Export JSON
        </a>
      </div>

      {/* HEADER CARD */}
      <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
        <h1 style={{ fontSize: '1.75rem', marginBottom: '1rem', color: 'var(--text-main)' }}>{email.subject || "No Subject"}</h1>
        <div style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '0.5rem 1rem', fontSize: '0.95rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>From:</span>
          <span style={{ fontWeight: 'bold', color: 'var(--text-main)' }}>{email.from || email.sender || "Unknown Sender"}</span>
          
          <span style={{ color: 'var(--text-muted)' }}>To:</span>
          <span style={{ color: 'var(--text-main)' }}>{email.to || "Unknown Recipient"}</span>
          
          <span style={{ color: 'var(--text-muted)' }}>Date:</span>
          <span style={{ color: 'var(--text-main)' }}>{email.date || email.time || "Unknown Date"}</span>

          {(email.categories && email.categories.length > 0) && (
            <>
              <span style={{ color: 'var(--text-muted)' }}>Categories:</span>
              <span style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {email.categories.map((cat) => (
                  <span key={cat} style={{ padding: '0.2rem 0.6rem', borderRadius: '9999px', backgroundColor: 'rgba(6, 182, 212, 0.15)', color: 'rgb(103, 232, 249)', fontSize: '0.75rem', fontWeight: 'bold', letterSpacing: '0.5px', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
                    {cat.toUpperCase()}
                  </span>
                ))}
              </span>
            </>
          )}
        </div>
      </div>

      {/* VERDICT & SCORES ROW */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '2rem' }}>
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px', textAlign: 'center' }}>
          <h2 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Verdict</h2>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: verdictColor }}>{verdict}</div>
        </div>

        <div className="glass" style={{ padding: '2rem', borderRadius: '12px', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <h2 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>Risk Score</h2>
          <div style={{ width: '100%', maxWidth: '200px', height: '12px', backgroundColor: 'rgba(255, 255, 255, 0.1)', borderRadius: '999px', overflow: 'hidden', marginBottom: '0.5rem' }}>
            <div style={{ 
              height: '100%', 
              width: `${reasoning.risk_score || 0}%`, 
              backgroundColor: getRiskColor(reasoning.risk_score || 0),
              transition: 'width 1s ease-out'
            }} />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: getRiskColor(reasoning.risk_score || 0) }}>
            {reasoning.risk_score || 0}%
          </div>
        </div>

        <div className="glass" style={{ padding: '2rem', borderRadius: '12px', textAlign: 'center' }}>
          <h2 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Confidence</h2>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--accent-secondary)' }}>{reasoning.confidence_score || email.confidence || 0}%</div>
        </div>
      </div>

      {/* RECOMMENDATIONS */}
      <div className="glass" style={{ padding: '2rem', borderRadius: '12px', borderLeft: `4px solid ${verdictColor}` }}>
        <h2 style={{ marginBottom: '1rem' }}>Recommendation</h2>
        <ul style={{ paddingLeft: '1.5rem', color: 'var(--text-main)', lineHeight: '1.6' }}>
          {(decision.recommendations || []).length > 0 ? (
            decision.recommendations.map((rec, idx) => <li key={idx}>{rec}</li>)
          ) : (
            <li>No specific recommendations provided.</li>
          )}
        </ul>
      </div>

      {/* EVIDENCE CARDS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '2rem' }}>
        
        {/* Technical */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px', borderTop: '4px solid #3b82f6' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>Technical</h2>
          <ul style={{ paddingLeft: '0', listStyle: 'none', color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {(reasoning.evidence?.technical || []).length > 0 ? (
              reasoning.evidence.technical.map((item, i) => (
                <li key={i}>
                  {item.toLowerCase().includes('pass') ? <span style={{ color: 'var(--risk-safe)', marginRight: '0.5rem' }}>✓</span> : <span style={{ color: 'var(--risk-high)', marginRight: '0.5rem' }}>⚠</span>}
                  {item}
                </li>
              ))
            ) : (
              <li style={{ color: 'var(--text-muted)' }}>No technical evidence.</li>
            )}
          </ul>
        </div>

        {/* Behavioral */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px', borderTop: '4px solid #a855f7' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>Behavioral</h2>
          <ul style={{ paddingLeft: '0', listStyle: 'none', color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {(reasoning.evidence?.behavioral || []).length > 0 ? (
              reasoning.evidence.behavioral.map((item, i) => (
                <li key={i}>
                  {item.toLowerCase().includes('clean') || item.toLowerCase().includes('pass') ? <span style={{ color: 'var(--risk-safe)', marginRight: '0.5rem' }}>✓</span> : <span style={{ color: 'var(--risk-high)', marginRight: '0.5rem' }}>⚠</span>}
                  {item}
                </li>
              ))
            ) : (
              <li style={{ color: 'var(--text-muted)' }}>No behavioral evidence.</li>
            )}
          </ul>
        </div>

        {/* Network */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px', borderTop: '4px solid #f59e0b' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>Network</h2>
          <ul style={{ paddingLeft: '0', listStyle: 'none', color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {(reasoning.evidence?.network || []).length > 0 ? (
              reasoning.evidence.network.map((item, i) => (
                <li key={i}>
                  {item.toLowerCase().includes('clean') || item.toLowerCase().includes('safe') ? <span style={{ color: 'var(--risk-safe)', marginRight: '0.5rem' }}>✓</span> : <span style={{ color: 'var(--risk-high)', marginRight: '0.5rem' }}>⚠</span>}
                  {item}
                </li>
              ))
            ) : (
              <li style={{ color: 'var(--text-muted)' }}>No network evidence.</li>
            )}
          </ul>
        </div>

        {/* WHOIS */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px', borderTop: '4px solid #10b981' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>WHOIS</h2>
          <ul style={{ paddingLeft: '0', listStyle: 'none', color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {(analysis.whois || []).length > 0 ? (
              analysis.whois.map((whois, i) => (
                <li key={i} style={{ fontSize: '0.9rem', marginBottom: i < analysis.whois.length - 1 ? '1rem' : '0' }}>
                  <div style={{ fontWeight: 'bold', color: 'var(--accent-secondary)' }}>🌐 {whois.domain}</div>
                  <div style={{ paddingLeft: '1.5rem', marginTop: '0.25rem', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                    <div><span style={{ color: 'var(--text-muted)' }}>Age:</span> {whois.age_days != null ? `${whois.age_days.toLocaleString()} days` : 'Unknown'} <span style={{ color: whois.age_category === 'new' ? 'var(--risk-high)' : 'var(--risk-safe)', fontWeight: 'bold', textTransform: 'uppercase', fontSize: '0.75rem', marginLeft: '0.5rem' }}>{whois.age_category?.replace(/_/g, ' ')}</span></div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Registrar:</span> {whois.registrar || 'Unknown'}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Country:</span> {whois.country || 'Unknown'}</div>
                    {whois.error && <div style={{ color: 'var(--risk-high)' }}>⚠ {whois.error}</div>}
                  </div>
                </li>
              ))
            ) : (
              <li style={{ color: 'var(--text-muted)' }}>No WHOIS data available.</li>
            )}
          </ul>
        </div>

      </div>

      {/* ANALYSIS GRID */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '2rem' }}>
        
        {/* AUTHENTICATION */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ marginBottom: '1rem' }}>Authentication</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '0.75rem 1rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>SPF:</span>
            <span style={{ color: (auth.spf === 'pass' || auth.spf_result === 'pass') ? 'var(--risk-safe)' : 'var(--risk-high)', fontWeight: 'bold' }}>
              {(auth.spf || auth.spf_result || "unknown").toUpperCase()}
            </span>
            
            <span style={{ color: 'var(--text-muted)' }}>DKIM:</span>
            <span style={{ color: (auth.dkim === 'pass' || auth.dkim_result === 'pass') ? 'var(--risk-safe)' : 'var(--risk-high)', fontWeight: 'bold' }}>
              {(auth.dkim || auth.dkim_result || "unknown").toUpperCase()}
            </span>
            
            <span style={{ color: 'var(--text-muted)' }}>DMARC:</span>
            <span style={{ color: (auth.dmarc === 'pass' || auth.dmarc_result === 'pass') ? 'var(--risk-safe)' : 'var(--risk-high)', fontWeight: 'bold' }}>
              {(auth.dmarc || auth.dmarc_result || "unknown").toUpperCase()}
            </span>
          </div>
          {(auth.issues || []).length > 0 && (
            <div style={{ marginTop: '1rem', fontSize: '0.85rem', color: 'var(--risk-high)' }}>
              {auth.issues.map((issue, i) => <div key={i}>• {issue}</div>)}
            </div>
          )}
        </div>

        {/* CONTENT ANALYSIS */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ marginBottom: '1rem' }}>Content Analysis</h2>
          <div style={{ marginBottom: '0.5rem', color: 'var(--text-muted)' }}>Score: {content.risk_score || 0}</div>
          <ul style={{ paddingLeft: '1.2rem', color: 'var(--text-main)', fontSize: '0.9rem' }}>
            {(content.evidence || []).length > 0 ? (
              content.evidence.map((ev, i) => <li key={i}>{ev}</li>)
            ) : (
              <li style={{ color: 'var(--risk-safe)', listStyle: 'none', marginLeft: '-1.2rem' }}>✔ Clean</li>
            )}
          </ul>
        </div>

        {/* URL ANALYSIS */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ marginBottom: '1rem' }}>URL Analysis</h2>
          <div style={{ marginBottom: '0.5rem', color: 'var(--text-muted)' }}>Score: {url.risk_score || 0}</div>
          <ul style={{ paddingLeft: '1.2rem', color: 'var(--text-main)', fontSize: '0.9rem', wordBreak: 'break-all' }}>
            {(url.evidence || []).length > 0 ? (
              url.evidence.map((ev, i) => <li key={i}>{ev}</li>)
            ) : (
              <li style={{ color: 'var(--risk-safe)', listStyle: 'none', marginLeft: '-1.2rem' }}>✔ No malicious URLs</li>
            )}
          </ul>
        </div>

        {/* ATTACHMENT ANALYSIS */}
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ marginBottom: '1rem' }}>Attachment Analysis</h2>
          <div style={{ marginBottom: '0.5rem', color: 'var(--text-muted)' }}>Score: {attachment.risk_score || 0}</div>
          <ul style={{ paddingLeft: '1.2rem', color: 'var(--text-main)', fontSize: '0.9rem' }}>
            {(attachment.evidence || []).length > 0 ? (
              attachment.evidence.map((ev, i) => <li key={i}>{ev}</li>)
            ) : (
              <li style={{ color: 'var(--risk-safe)', listStyle: 'none', marginLeft: '-1.2rem' }}>✔ No malicious attachments</li>
            )}
          </ul>
        </div>
      </div>

      {/* ORIGINAL BODY */}
      <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
        <h2 style={{ marginBottom: '1rem' }}>Body</h2>
        <div style={{ 
            color: 'var(--text-main)', 
            whiteSpace: 'pre-wrap', 
            backgroundColor: 'rgba(0,0,0,0.2)', 
            padding: '1.5rem', 
            borderRadius: '8px',
            maxHeight: '400px',
            overflowY: 'auto',
            fontFamily: 'sans-serif',
            fontSize: '0.9rem',
            lineHeight: '1.5'
          }}>
          {email.body || "No body content available."}
        </div>
      </div>

      {/* RAW HEADERS */}
      <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
        <h2 style={{ marginBottom: '1rem' }}>Headers</h2>
        <div style={{ 
            color: 'var(--text-muted)', 
            fontFamily: 'monospace', 
            whiteSpace: 'pre-wrap', 
            backgroundColor: 'rgba(0,0,0,0.3)', 
            padding: '1.5rem', 
            borderRadius: '8px',
            maxHeight: '300px',
            overflowY: 'auto',
            fontSize: '0.8rem',
            wordBreak: 'break-all'
          }}>
          {email.headers ? (typeof email.headers === 'string' ? email.headers : JSON.stringify(email.headers, null, 2)) : "No raw headers available."}
        </div>
      </div>

    </div>
  );
}
