import { useState } from "react";
import { Link } from "react-router-dom";
import VerdictBadge from "./VerdictBadge";
import "./EmailCard.css";
export default function EmailCard({ email }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const analysis = email.analysis || {};

  return (
    <Link to={`/email/${email.id}`} style={{ textDecoration: 'none', color: 'inherit', display: 'block' }}>
      <div className={`email-card glass ${isExpanded ? 'expanded' : ''}`} onClick={() => setIsExpanded(!isExpanded)}>

        {/* CARD HEADER (Always Visible) */}
        <div className="email-card-header">
          <div className="sender-info">
            <div className="sender-avatar">{email.sender.charAt(0)}</div>
            <span className="sender-name">{email.sender}</span>
            <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem', minWidth: '150px' }}>
            <VerdictBadge verdict={email.verdict} />
            <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                <span>Risk: {email.riskScore}/100</span>
                <span>Conf: {email.confidence}%</span>
              </div>
              <div style={{ width: '100%', height: '6px', backgroundColor: 'rgba(255, 255, 255, 0.1)', borderRadius: '9999px', overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${Math.min(100, Math.max(0, email.riskScore || 0))}%`,
                    height: '100%',
                    backgroundColor:
                      email.riskScore >= 80 ? 'var(--risk-phishing)' :
                        email.riskScore >= 60 ? 'var(--risk-high)' :
                          email.riskScore >= 40 ? 'var(--risk-suspicious)' :
                            email.riskScore >= 20 ? 'var(--risk-low)' : 'var(--risk-safe)',
                    transition: 'width 1s ease-out'
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        <div className="email-card-body">
          <h3 className="email-subject">{email.subject}</h3>
          {!isExpanded && <p className="email-snippet">{email.snippet}</p>}

          {email.categories && email.categories.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.75rem' }}>
              {email.categories.map((category) => (
                <span
                  key={category}
                  style={{
                    padding: '0.2rem 0.6rem',
                    borderRadius: '9999px',
                    backgroundColor: 'rgba(6, 182, 212, 0.15)', // similar to bg-cyan-600/20
                    color: 'rgb(103, 232, 249)', // text-cyan-300
                    fontSize: '0.7rem',
                    fontWeight: 'bold',
                    letterSpacing: '0.5px',
                    border: '1px solid rgba(6, 182, 212, 0.3)' // border-cyan-500/30
                  }}
                >
                  {category.toUpperCase()}
                </span>
              ))}
            </div>
          )}
        </div>

        {!isExpanded && (
          <div className="email-card-footer">
            <span className="email-time">{email.time}</span>
          </div>
        )}

        {/* EXPANDED DETAILS (VirusTotal Style) */}
        {isExpanded && (
          <div className="email-expanded-details" onClick={(e) => e.stopPropagation()}>
            <hr className="details-divider" />

            {/* Section: Email Header */}
            <div className="detail-section" style={{ borderLeft: 'none', backgroundColor: 'transparent', padding: '0 0 1rem 0', marginBottom: '2rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1.5rem' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                  <span className="label" style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>Subject</span>
                  <span style={{ fontWeight: '600', color: 'var(--text-main)', fontSize: '1.1rem' }}>{email.subject}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                  <span className="label" style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>From</span>
                  <span style={{ fontWeight: '600', color: 'var(--text-main)' }}>{email.sender}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                  <span className="label" style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>Received</span>
                  <span style={{ fontWeight: '600', color: 'var(--text-main)' }}>{email.time}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                  <span className="label" style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>Verdict</span>
                  <div><VerdictBadge verdict={email.verdict} /></div>
                </div>
              </div>
            </div>

            {/* Section: Original Message */}
            <div className="detail-section" style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderLeft: '3px solid var(--text-muted)' }}>
              <h4>Original Message</h4>
              <div style={{
                whiteSpace: 'pre-wrap',
                fontSize: '0.85rem',
                color: 'var(--text-main)',
                lineHeight: '1.5',
                maxHeight: '300px',
                overflowY: 'auto',
                padding: '1rem',
                backgroundColor: 'rgba(0,0,0,0.3)',
                borderRadius: '4px'
              }}>
                {email.body}
              </div>
            </div>

            {/* Section: Authentication */}
            <div className="detail-section">
              <h4>Authentication</h4>
              <div className="detail-grid" style={{ gridTemplateColumns: 'max-content 1fr', rowGap: '0.75rem' }}>
                <span className="label">SPF:</span>
                <span className={analysis.authentication?.spf_result === 'pass' ? 'text-safe' : 'text-danger'}>
                  {analysis.authentication?.spf_result === 'pass' ? '✔ pass' : '✖ fail'}
                </span>
                <span className="label">DKIM:</span>
                <span className={analysis.authentication?.dkim_result === 'pass' ? 'text-safe' : 'text-danger'}>
                  {analysis.authentication?.dkim_result === 'pass' ? '✔ pass' : '✖ fail'}
                </span>
                <span className="label">DMARC:</span>
                <span className={analysis.authentication?.dmarc_result === 'pass' ? 'text-safe' : 'text-danger'}>
                  {analysis.authentication?.dmarc_result === 'pass' ? '✔ pass' : '✖ fail'}
                </span>
              </div>
            </div>

            {/* Section: Trust Engine */}
            <div className="detail-section">
              <h4>Trust Engine (Score: {analysis.trust?.trust_score || 0}/100)</h4>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
                {analysis.trust?.evidence?.map((evidence, i) => (
                  <span key={i} style={{
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    color: 'var(--risk-safe)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: '600'
                  }}>
                    ✔ {evidence}
                  </span>
                ))}
                {(!analysis.trust?.evidence || analysis.trust.evidence.length === 0) && (
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No trust evidence found.</span>
                )}
              </div>
            </div>

            {/* Section: URLs */}
            {analysis.url?.analysis?.length > 0 && (
              <div className="detail-section">
                <h4>URLs Detected</h4>
                <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))' }}>
                  {analysis.url.analysis.map((u, i) => {
                    const isHttps = u.url?.startsWith('https');
                    const riskLevel = (u.shortener || u.ip_based || u.keywords?.length > 0) ? 'High' : 'Low';
                    const riskColor = riskLevel === 'High' ? 'var(--risk-phishing)' : 'var(--risk-safe)';

                    return (
                      <div key={i} style={{ backgroundColor: 'rgba(255, 255, 255, 0.05)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                        <div style={{ wordBreak: 'break-all', marginBottom: '0.75rem', color: 'var(--accent-secondary)', fontWeight: '600' }}>
                          {u.domain}
                        </div>
                        <div className="detail-grid" style={{ gridTemplateColumns: 'max-content 1fr', rowGap: '0.5rem', fontSize: '0.8rem' }}>
                          <span className="label">Risk:</span>
                          <span style={{ color: riskColor, fontWeight: 'bold' }}>{riskLevel}</span>

                          <span className="label">HTTPS:</span>
                          <span style={{ color: isHttps ? 'var(--risk-safe)' : 'var(--risk-phishing)' }}>{isHttps ? 'Yes' : 'No'}</span>

                          <span className="label">Shortener:</span>
                          <span style={{ color: u.shortener ? 'var(--risk-phishing)' : 'var(--text-main)' }}>{u.shortener ? 'Yes' : 'No'}</span>

                          <span className="label">IP Address:</span>
                          <span style={{ color: u.ip_based ? 'var(--risk-phishing)' : 'var(--text-main)' }}>{u.ip_based ? 'Yes' : 'No'}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Section: WHOIS Domain Intelligence */}
            {analysis.whois?.length > 0 && (
              <div className="whois-section">
                <h4>WHOIS Domain Intelligence</h4>

                {analysis.whois.map((whois, i) => {
                  const ageCategory = whois.age_category || "unknown";
                  const formatDate = (date) => {
                    if (!date) return 'Unknown';
                    try {
                      return new Date(date).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
                    } catch {
                      return date;
                    }
                  };

                  return (
                    <div
                      key={`${whois.domain}-${i}`}
                      className="whois-card"
                    >
                      <div>
                        <strong>🌐 {whois.domain}</strong>
                      </div>

                      <div>
                        <strong>Domain Age:</strong>{" "}
                        {whois.age_days != null
                          ? `${whois.age_days.toLocaleString()} days`
                          : "Unknown"}
                      </div>

                      <div>
                        <strong>Age Category:</strong>{" "}
                        {ageCategory}
                      </div>

                      <div>
                        <strong>Created:</strong>{" "}
                        {formatDate(whois.created)}
                      </div>

                      <div>
                        <strong>Expires:</strong>{" "}
                        {formatDate(whois.expires)}
                      </div>

                      <div>
                        <strong>Registrar:</strong>{" "}
                        {whois.registrar || "Unknown"}
                      </div>

                      <div>
                        <strong>Country:</strong>{" "}
                        {whois.country || "Unknown"}
                      </div>

                      <div>
                        <strong>Status:</strong>{" "}
                        <span
                          style={{
                            color: whois.error ? "red" : "green",
                            fontWeight: "bold",
                          }}
                        >
                          {whois.error ? "Failed" : "Successful"}
                        </span>
                      </div>

                      {whois.error && (
                        <div style={{ color: "red" }}>
                          WHOIS lookup error: {whois.error}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Section: Content Analysis */}
            <div className="detail-section">
              <h4>Content Analysis (Risk: {analysis.content?.risk_score || 0}/100)</h4>
              <div className="detail-grid" style={{ gridTemplateColumns: 'max-content 1fr', rowGap: '0.5rem' }}>

                <span className="label">Credential Request:</span>
                <span className={analysis.content?.credential_request ? 'text-danger' : 'text-safe'}>
                  {analysis.content?.credential_request ? '✖ Yes' : '✔ No'}
                </span>

                <span className="label">Urgency:</span>
                <span className={analysis.content?.urgency ? 'text-danger' : 'text-safe'}>
                  {analysis.content?.urgency ? '✖ Yes' : '✔ No'}
                </span>

                <span className="label">Financial:</span>
                <span className={analysis.content?.financial_request ? 'text-danger' : 'text-safe'}>
                  {analysis.content?.financial_request ? '✖ Yes' : '✔ No'}
                </span>

                <span className="label">Impersonation:</span>
                <span className={analysis.content?.impersonation ? 'text-danger' : 'text-safe'}>
                  {analysis.content?.impersonation ? '✖ Yes' : '✔ No'}
                </span>

                <span className="label">Threat Language:</span>
                <span className={analysis.content?.threat_language ? 'text-danger' : 'text-safe'}>
                  {analysis.content?.threat_language ? '✖ Yes' : '✔ No'}
                </span>

              </div>
            </div>

            {/* Section: Decision Path (Evidence Timeline) */}
            <div className="detail-section decision-section">
              <h4>Decision Path</h4>
              <div className="decision-path">
                {/* Authentication Path */}
                {analysis.authentication?.spf_result && (
                  <div className="path-item">
                    <span className={analysis.authentication.spf_result === 'pass' ? 'text-safe' : 'text-danger'}>
                      {analysis.authentication.spf_result === 'pass' ? '✔' : '✖'}
                    </span>
                    <span> SPF {analysis.authentication.spf_result === 'pass' ? 'Passed' : 'Failed'}</span>
                  </div>
                )}
                {analysis.authentication?.dkim_result && (
                  <div className="path-item">
                    <span className={analysis.authentication.dkim_result === 'pass' ? 'text-safe' : 'text-danger'}>
                      {analysis.authentication.dkim_result === 'pass' ? '✔' : '✖'}
                    </span>
                    <span> DKIM {analysis.authentication.dkim_result === 'pass' ? 'Passed' : 'Failed'}</span>
                  </div>
                )}
                {analysis.authentication?.dmarc_result && (
                  <div className="path-item">
                    <span className={analysis.authentication.dmarc_result === 'pass' ? 'text-safe' : 'text-danger'}>
                      {analysis.authentication.dmarc_result === 'pass' ? '✔' : '✖'}
                    </span>
                    <span> DMARC {analysis.authentication.dmarc_result === 'pass' ? 'Passed' : 'Failed'}</span>
                  </div>
                )}

                {/* Trust Path */}
                {analysis.trust?.evidence?.map((ev, i) => (
                  <div className="path-item" key={`trust-${i}`}>
                    <span className="text-safe">✔</span>
                    <span> {ev}</span>
                  </div>
                ))}

                {/* Content / URL Path (Negative Flags) */}
                {analysis.content?.credential_request && (
                  <div className="path-item">
                    <span className="text-danger">✖</span>
                    <span> Credential Request Detected</span>
                  </div>
                )}
                {analysis.content?.financial_request && (
                  <div className="path-item">
                    <span className="text-danger">✖</span>
                    <span> Financial Request Detected</span>
                  </div>
                )}
                {analysis.content?.impersonation && (
                  <div className="path-item">
                    <span className="text-danger">✖</span>
                    <span> Brand Impersonation Detected</span>
                  </div>
                )}
                {analysis.url?.analysis?.some(u => u.shortener || u.ip_based) && (
                  <div className="path-item">
                    <span className="text-danger">✖</span>
                    <span> Suspicious URLs Detected</span>
                  </div>
                )}

                {/* Arrow */}
                <div className="path-arrow">↓</div>

                {/* Final Verdict */}
                <div className="path-verdict-block">
                  <VerdictBadge verdict={email.verdict} />
                  <div className="path-confidence">Confidence {email.confidence}%</div>
                </div>
              </div>
            </div>

          </div>
        )}
      </div>
    </Link>
  );
}
