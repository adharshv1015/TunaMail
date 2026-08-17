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
        const response = await axios.get(`http://localhost:8000/gmail/message/${id}`);
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
  const intel = analysis.intelligence || {};

  const verdict = decision.verdict || "UNKNOWN";
  const verdictColor = verdict === 'PHISHING' ? 'var(--risk-phishing)' : 
                       verdict === 'HIGH RISK' ? 'var(--risk-high)' : 
                       verdict === 'SUSPICIOUS' ? 'var(--risk-suspicious)' : 
                       verdict === 'UNKNOWN' ? 'var(--tm-text-secondary)' : 
                       'var(--risk-safe)';

  const getRiskColor = (score) => {
    if (score <= 30) return 'var(--risk-safe)';
    if (score <= 60) return 'var(--risk-suspicious)';
    return 'var(--risk-phishing)';
  };

  let bannerConfig = { bgColor: 'rgba(113, 113, 122, 0.1)', borderColor: '#71717a', color: '#71717a', icon: '❓', text: 'UNKNOWN', description: 'This email could not be fully verified.' };
  
  if (verdict === 'VERIFIED LEGITIMATE' || verdict === 'LIKELY LEGITIMATE') {
    bannerConfig = { bgColor: 'rgba(16, 185, 129, 0.1)', borderColor: 'var(--risk-safe)', color: 'var(--risk-safe)', icon: '🛡️', text: verdict, description: 'This email appears legitimate and safe to open.' };
  } else if (verdict === 'PHISHING' || verdict === 'HIGH RISK') {
    bannerConfig = { bgColor: 'rgba(239, 68, 68, 0.1)', borderColor: 'var(--risk-phishing)', color: 'var(--risk-phishing)', icon: '🚨', text: verdict, description: 'WARNING: This email has been flagged as highly dangerous. Do not click links or download attachments.' };
  } else if (verdict === 'SUSPICIOUS') {
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
        {decision.detail_verdict && (
          <div style={{ marginTop: '0.25rem', fontSize: '1rem', fontWeight: 'bold', color: 'inherit', opacity: 0.8 }}>
            Detailed State: {decision.detail_verdict.replace(/_/g, ' ')}
          </div>
        )}
        <p style={{ marginTop: '0.5rem', fontSize: '1.2rem', fontWeight: '500', opacity: 0.9 }}>{bannerConfig.description}</p>
      </div>

      {/* EXPORT ACTION BAR */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem', marginTop: '-1rem' }}>
        <a 
          href={`http://localhost:8000/report/pdf/${id}`}
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
          href={`http://localhost:8000/report/json/${id}`}
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

      {/* EVIDENCE TIMELINE */}
      <div className="glass" style={{ padding: '2rem', borderRadius: '12px', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <h2 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>Evidence Timeline</h2>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', overflowX: 'auto', paddingBottom: '1rem' }}>
          {['Authentication', 'Content Analysis', 'URL Inspection', 'WHOIS', 'Local AI', 'ARE', 'Decision Fusion'].map((stage, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{ 
                padding: '0.5rem 1rem', 
                borderRadius: '8px', 
                backgroundColor: 'rgba(255,255,255,0.05)',
                border: '1px solid var(--border-color)',
                fontSize: '0.85rem',
                fontWeight: 'bold',
                whiteSpace: 'nowrap'
              }}>
                {stage}
              </div>
              {i < 6 && <div style={{ color: 'var(--text-muted)' }}>→</div>}
            </div>
          ))}
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

        {/* AI EVIDENCE & REASONING */}
        {(analysis.ai || analysis.explanation) && (
          <div className="glass" style={{ padding: '2rem', borderRadius: '12px', borderTop: '4px solid #f43f5e', gridColumn: '1 / -1' }}>
            <h2 style={{ marginBottom: '1rem' }}>AI Evidence & Reasoning</h2>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <div style={{ backgroundColor: 'rgba(255,255,255,0.05)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>AI Assessment</div>
                <div style={{ fontWeight: 'bold', marginTop: '0.5rem', color: 'var(--accent-primary)' }}>{analysis.ai?.recommended_classification || "UNKNOWN"}</div>
              </div>
              <div style={{ backgroundColor: 'rgba(255,255,255,0.05)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Reasoning State</div>
                <div style={{ fontWeight: 'bold', marginTop: '0.5rem' }}>{analysis.conflict?.conflict_state || analysis.ai?.reasoning_state || "UNKNOWN"}</div>
              </div>
              <div style={{ backgroundColor: 'rgba(255,255,255,0.05)', padding: '1rem', borderRadius: '8px', gridColumn: 'span 2' }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Confidence: {decision.confidence || 0}%</div>
                <div style={{ width: '100%', height: '8px', backgroundColor: 'rgba(255, 255, 255, 0.1)', borderRadius: '999px', overflow: 'hidden', marginTop: '0.5rem' }}>
                  <div style={{ height: '100%', width: `${decision.confidence || 0}%`, backgroundColor: getRiskColor(100 - (decision.confidence || 0)) }} />
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', color: 'var(--risk-safe)', marginBottom: '0.5rem' }}>Positive Evidence</h3>
                <ul style={{ paddingLeft: '1.5rem', margin: 0, fontSize: '0.9rem' }}>
                  {(analysis.conflict?.structured_evidence || []).filter(e => e.classification === 'POSITIVE').map((ev, i) => (
                    <li key={i}>{ev.type.toUpperCase()}: {ev.signal} ({ev.value})</li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 style={{ fontSize: '1rem', color: 'var(--risk-high)', marginBottom: '0.5rem' }}>Negative Evidence</h3>
                <ul style={{ paddingLeft: '1.5rem', margin: 0, fontSize: '0.9rem' }}>
                  {(analysis.conflict?.structured_evidence || []).filter(e => e.classification === 'NEGATIVE').map((ev, i) => (
                    <li key={i}>{ev.type.toUpperCase()}: {ev.signal} ({ev.value})</li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Unknown/Conflicting Evidence</h3>
                <ul style={{ paddingLeft: '1.5rem', margin: 0, fontSize: '0.9rem' }}>
                  {(analysis.conflict?.structured_evidence || []).filter(e => ['UNKNOWN', 'CONFLICTING', 'NEUTRAL'].includes(e.classification)).map((ev, i) => (
                    <li key={i}>{ev.type.toUpperCase()}: {ev.signal} ({ev.value})</li>
                  ))}
                </ul>
              </div>
            </div>

            {analysis.explanation && (
              <div style={{ marginTop: '1.5rem', padding: '1rem', backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: '8px' }}>
                <h3 style={{ fontSize: '1rem', marginBottom: '0.5rem', color: 'var(--accent-secondary)' }}>Why this verdict?</h3>
                <div style={{ fontSize: '0.95rem', color: 'var(--text-main)', marginBottom: '0.5rem' }}>{analysis.explanation.summary}</div>
                {analysis.explanation.confidence_reason && (
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>{analysis.explanation.confidence_reason}</div>
                )}
              </div>
            )}
          </div>
        )}
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

      {/* ====================================================
           STAGE 5 INTELLIGENCE SECTIONS
           All sections below are additive — existing layout unchanged
         ==================================================== */}

      {/* ATTACK PATTERNS */}
      {intel.attack_patterns && intel.attack_patterns.length > 0 && (
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>⚔️ Attack Patterns Detected</h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
            {intel.attack_patterns.map((p, i) => (
              <div key={i} style={{
                padding: '0.6rem 1.2rem',
                borderRadius: '8px',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                color: 'var(--risk-phishing)',
                fontSize: '0.85rem',
                fontWeight: 'bold'
              }}>
                {p.name.replace(/_/g, ' ')} — {p.confidence}% confidence
              </div>
            ))}
          </div>
          {intel.attack_patterns[0]?.matched_signals?.length > 0 && (
            <ul style={{ marginTop: '1rem', paddingLeft: '1.5rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              {intel.attack_patterns[0].matched_signals.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          )}
        </div>
      )}

      {/* CAMPAIGN ALERT */}
      {intel.campaign?.campaign_detected && (
        <div style={{
          padding: '1.5rem 2rem',
          borderRadius: '12px',
          backgroundColor: 'rgba(245, 158, 11, 0.1)',
          border: '2px solid var(--risk-suspicious)',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem'
        }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: 'var(--risk-suspicious)' }}>
            📡 Campaign Detected: {intel.campaign.campaign_id}
          </div>
          <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
            Confidence: {intel.campaign.confidence}% · Type: {intel.campaign.campaign_type?.replace(/_/g, ' ')} · Related: {intel.campaign.related_messages} emails
          </div>
          {intel.campaign.shared_indicators?.length > 0 && (
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
              {intel.campaign.shared_indicators.map((ind, i) => (
                <span key={i} style={{
                  padding: '0.2rem 0.6rem',
                  borderRadius: '9999px',
                  backgroundColor: 'rgba(245, 158, 11, 0.2)',
                  color: 'var(--risk-suspicious)',
                  fontSize: '0.75rem',
                  fontFamily: 'monospace'
                }}>{ind}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* RELATED INTELLIGENCE */}
      {intel.related_messages && intel.related_messages.length > 0 && (
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>🔗 Related Intelligence</h2>
          <div style={{ color: 'var(--text-muted)', marginBottom: '1rem', fontSize: '0.9rem' }}>
            {intel.related_messages.length} related email(s) detected via shared infrastructure:
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {intel.related_messages.slice(0, 5).map((rel, i) => (
              <div key={i} style={{
                padding: '1rem',
                borderRadius: '8px',
                backgroundColor: 'rgba(255,255,255,0.04)',
                border: '1px solid var(--border-color)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.4rem'
              }}>
                <div style={{ fontWeight: 'bold', fontSize: '0.85rem', fontFamily: 'monospace' }}>
                  {rel.relationship_type?.replace(/_/g, ' ') || 'RELATED'} — {rel.message_id}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {rel.shared_indicators?.slice(0, 3).map((ind, j) => (
                    <span key={j} style={{
                      padding: '0.15rem 0.5rem',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(6,182,212,0.1)',
                      color: 'rgb(103,232,249)',
                      fontSize: '0.75rem',
                      fontFamily: 'monospace'
                    }}>{ind.type}: {ind.value}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IOC PANEL */}
      {intel.iocs && intel.iocs.length > 0 && (
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>🔎 Indicators of Interest</h2>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border-color)' }}>
                  {['Type', 'Value', 'Source', 'Confidence'].map(h => (
                    <th key={h} style={{ padding: '0.5rem 0.75rem', textAlign: 'left', fontWeight: '600' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {intel.iocs.slice(0, 20).map((ioc, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <span style={{
                        padding: '0.15rem 0.5rem',
                        borderRadius: '4px',
                        backgroundColor: 'rgba(6,182,212,0.1)',
                        color: 'rgb(103,232,249)',
                        fontSize: '0.7rem',
                        fontWeight: 'bold'
                      }}>{ioc.type}</span>
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem', fontFamily: 'monospace', wordBreak: 'break-all', maxWidth: '300px' }}>{ioc.normalized || ioc.value}</td>
                    <td style={{ padding: '0.5rem 0.75rem', color: 'var(--text-muted)' }}>{ioc.source}</td>
                    <td style={{ padding: '0.5rem 0.75rem' }}>{Math.round((ioc.confidence || 0) * 100)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* FIRST-SEEN FLAGS */}
      {intel.first_seen && Object.keys(intel.first_seen).length > 0 && (
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🆕 First-Seen Indicators</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
            These indicators have not been observed before. This means UNKNOWN / LOW HISTORICAL CONFIDENCE — not automatically malicious.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {Object.entries(intel.first_seen).map(([val, info], i) => (
              <span key={i} style={{
                padding: '0.3rem 0.75rem',
                borderRadius: '9999px',
                backgroundColor: 'rgba(113,113,122,0.15)',
                border: '1px solid rgba(113,113,122,0.4)',
                color: 'var(--text-muted)',
                fontSize: '0.78rem',
                fontFamily: 'monospace'
              }}>{info.type}: {val}</span>
            ))}
          </div>
        </div>
      )}

      {/* TRUST SCORES */}
      {intel.trust_scores && Object.keys(intel.trust_scores).length > 0 && (
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>📊 Evidence Trust Scores</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.82rem', marginBottom: '1rem' }}>Evidence signals only — do not directly determine verdict.</p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '1rem' }}>
            {Object.entries(intel.trust_scores).map(([key, val]) => {
              const color = val >= 70 ? 'var(--risk-safe)' : val >= 40 ? 'var(--risk-suspicious)' : 'var(--risk-phishing)';
              return (
                <div key={key} style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>
                    {key.replace(/_/g, ' ').toUpperCase()}
                  </div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color }}>{val}</div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'rgba(255,255,255,0.1)', borderRadius: '2px', marginTop: '0.3rem' }}>
                    <div style={{ width: `${val}%`, height: '100%', backgroundColor: color, borderRadius: '2px', transition: 'width 0.6s' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* THREAT TIMELINE */}
      {intel.timeline && intel.timeline.length > 0 && (
        <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>🕐 Threat Intelligence Timeline</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {intel.timeline.map((ev, i) => (
              <div key={i} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.82rem', minWidth: '70px' }}>{ev.time}</span>
                <span style={{ color: 'var(--text-main)', fontSize: '0.85rem' }}>{ev.event}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ANALYST FEEDBACK */}
      <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
        <h2 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🧑‍💻 Analyst Feedback</h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
          The automated verdict is preserved. Your feedback is stored separately for audit purposes.
        </p>
        {feedbackSubmitted ? (
          <div style={{ color: 'var(--risk-safe)', fontWeight: 'bold' }}>✅ Feedback submitted. Automated verdict unchanged.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxWidth: '600px' }}>
            <select
              value={feedbackVerdict}
              onChange={e => setFeedbackVerdict(e.target.value)}
              style={{
                padding: '0.6rem',
                borderRadius: '8px',
                backgroundColor: 'var(--tm-surface)',
                color: 'var(--tm-text)',
                border: '1px solid var(--tm-border)',
                fontSize: '0.9rem'
              }}
            >
              <option value="">Select verdict...</option>
              <option value="TRUE_POSITIVE">TRUE POSITIVE — Correctly flagged as malicious</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE — Incorrectly flagged (actually safe)</option>
              <option value="TRUE_NEGATIVE">TRUE NEGATIVE — Correctly identified as safe</option>
              <option value="FALSE_NEGATIVE">FALSE NEGATIVE — Missed a malicious email</option>
              <option value="UNKNOWN">UNKNOWN — Cannot determine</option>
            </select>
            <textarea
              value={feedbackComment}
              onChange={e => setFeedbackComment(e.target.value)}
              placeholder="Optional analyst comment..."
              rows={3}
              style={{
                padding: '0.6rem',
                borderRadius: '8px',
                backgroundColor: 'var(--tm-surface)',
                color: 'var(--tm-text)',
                border: '1px solid var(--tm-border)',
                fontSize: '0.85rem',
                resize: 'vertical'
              }}
            />
            <button
              disabled={!feedbackVerdict}
              onClick={async () => {
                try {
                  await submitFeedback(id, feedbackVerdict, decision.verdict, feedbackComment);
                  setFeedbackSubmitted(true);
                  notify.success("✅ Feedback submitted");
                } catch (err) {
                  notify.error("❌ Failed to submit feedback");
                }
              }}
              style={{
                padding: '0.65rem 1.5rem',
                borderRadius: '8px',
                backgroundColor: feedbackVerdict ? 'rgba(6,182,212,0.2)' : 'rgba(255,255,255,0.05)',
                color: feedbackVerdict ? 'rgb(103,232,249)' : 'var(--text-muted)',
                border: `1px solid ${feedbackVerdict ? 'rgba(6,182,212,0.4)' : 'var(--border-color)'}`,
                cursor: feedbackVerdict ? 'pointer' : 'not-allowed',
                fontWeight: 'bold',
                fontSize: '0.9rem',
                alignSelf: 'flex-start',
                transition: 'all 0.2s'
              }}
            >
              Submit Feedback
            </button>
          </div>
        )}
      </div>

      {/* RAW EVIDENCE */}
      <details className="glass" style={{ padding: '2rem', borderRadius: '12px', cursor: 'pointer' }}>
        <summary style={{ fontSize: '1.25rem', fontWeight: 'bold' }}>View Raw Evidence</summary>
        <div style={{ 
            marginTop: '1rem',
            color: 'var(--text-muted)', 
            fontFamily: 'monospace', 
            whiteSpace: 'pre-wrap', 
            backgroundColor: 'rgba(0,0,0,0.3)', 
            padding: '1.5rem', 
            borderRadius: '8px',
            maxHeight: '500px',
            overflowY: 'auto',
            fontSize: '0.8rem',
            cursor: 'text'
          }}>
          {JSON.stringify(analysis, null, 2)}
        </div>
      </details>

    </div>
  );
}
