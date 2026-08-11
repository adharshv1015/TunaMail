import React, { useState } from "react";
import SectionHeader from "../common/SectionHeader";
import EmptyState from "../common/EmptyState";

function StatusIcon({ type }) {
  if (type === "success") return <span className="text-emerald-500 mr-2 text-sm">✓</span>;
  if (type === "warning") return <span className="text-amber-500 mr-2 text-sm">⚠</span>;
  if (type === "error") return <span className="text-red-500 mr-2 text-sm">✗</span>;
  return <span className="text-gray-400 mr-2 text-sm">•</span>;
}

function EvidenceRow({ type, text }) {
  return (
    <div className="flex items-start text-sm py-1 border-b border-[var(--tm-border)]/50 last:border-0">
      <StatusIcon type={type} />
      <span className="text-[var(--tm-text-secondary)]">{text}</span>
    </div>
  );
}

function IndicatorBadge({ label, isSuspicious, type="warning" }) {
  if (!isSuspicious) return null;
  
  const colors = {
    warning: "bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20",
    error: "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20",
    neutral: "bg-gray-500/10 text-gray-600 dark:text-gray-400 border-gray-500/20"
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${colors[type]}`}>
      {label}
    </span>
  );
}

function UrlCard({ item }) {
  const [expanded, setExpanded] = useState(false);
  
  const hasRisk = item.ip_based || item.shortener || item.obfuscated || item.punycode || item.suspicious_port || (item.keywords && item.keywords.length > 0) || item.brand_impersonation || (item.threat_intelligence && item.threat_intelligence.detections > 0);

  return (
    <div className={`flex flex-col gap-3 rounded-[12px] border bg-[var(--tm-surface-secondary)] p-4 ${hasRisk ? "border-orange-500/30" : "border-[var(--tm-border)]"}`}>
      <div className="flex flex-col">
        <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider">URL</div>
        <div className="mt-1 break-all font-mono text-[13px] text-[var(--tm-text)]" style={{ wordBreak: "break-word" }}>{item.url}</div>
      </div>
      
      <div className="flex flex-col md:flex-row gap-4 mt-2">
        <div className="flex-1">
          <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider">Domain Information</div>
          <div className="mt-1 font-mono text-[13px] text-[var(--tm-accent)]">{item.domain || "Unknown"}</div>
          {item.registered_domain && item.registered_domain !== item.domain && (
            <div className="mt-1 text-[11px] text-[var(--tm-text-muted)] font-mono opacity-80">Root: {item.registered_domain}</div>
          )}
        </div>
        
        <div className="flex-1">
          <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-1.5">Contextual Indicators</div>
          <div className="flex flex-wrap gap-2">
            {!hasRisk && <span className="inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20">NO FLAGS</span>}
            
            <IndicatorBadge label="IP-Based" isSuspicious={item.ip_based} type="warning" />
            <IndicatorBadge label="Shortener" isSuspicious={item.shortener} type="warning" />
            <IndicatorBadge label="Obfuscated" isSuspicious={item.obfuscated} type="error" />
            <IndicatorBadge label="Punycode" isSuspicious={item.punycode} type="error" />
            <IndicatorBadge label="Brand Impersonation" isSuspicious={item.brand_impersonation} type="error" />
            <IndicatorBadge label="Suspicious Port" isSuspicious={item.suspicious_port} type="warning" />
            
            {item.keywords && item.keywords.length > 0 && (
              <IndicatorBadge label={`KEYWORDS: ${item.keywords.join(", ")}`} isSuspicious={true} type="warning" />
            )}
            
            {item.email_alignment === "misaligned" && (
              <IndicatorBadge label="Sender Misalignment" isSuspicious={true} type="warning" />
            )}
          </div>
        </div>
      </div>
      
      <div className="mt-2 pt-3 border-t border-[var(--tm-border)]/50">
        <button 
          onClick={() => setExpanded(!expanded)}
          className="text-[12px] font-medium text-[var(--tm-accent)] hover:underline flex items-center gap-1 focus:outline-none"
        >
          {expanded ? "Hide URL Evidence" : "View URL Evidence"}
          <span className="text-[10px]">{expanded ? "▲" : "▼"}</span>
        </button>
        
        {expanded && (
          <div className="mt-4 flex flex-col gap-1 bg-[var(--tm-surface)] p-3 rounded-lg border border-[var(--tm-border)]/50">
            {/* DNS Evidence */}
            {item.dns && item.dns.resolved ? (
               <EvidenceRow type="success" text={`DNS resolved successfully (${[...(item.dns.a || []), ...(item.dns.aaaa || [])].length} records)`} />
            ) : item.dns && item.dns.private_ip_detected ? (
               <EvidenceRow type="error" text="DNS resolved to an internal/private IP (SSRF Blocked)" />
            ) : (
               <EvidenceRow type="warning" text="DNS resolution unavailable or failed" />
            )}
            
            {/* TLS Evidence */}
            {item.tls && item.tls.https ? (
              item.tls.certificate_valid ? (
                 <EvidenceRow type="success" text={`TLS certificate valid (Issuer: ${item.tls.issuer || "Unknown"})`} />
              ) : (
                 <EvidenceRow type="error" text="TLS certificate invalid or expired" />
              )
            ) : (
               <EvidenceRow type="warning" text="Connection does not use HTTPS" />
            )}
            
            {/* Redirects */}
            {item.redirects && item.redirects.detected ? (
               <EvidenceRow type={item.redirects.external_domain_change ? "error" : "warning"} text={`Redirect chain detected (${item.redirects.chain.length} hops)${item.redirects.external_domain_change ? " - External domain change!" : ""}`} />
            ) : (
               <EvidenceRow type="success" text="No redirects detected" />
            )}
            
            {/* Threat Intel */}
            {item.threat_intelligence && item.threat_intelligence.status === "available" ? (
               item.threat_intelligence.detections > 0 ? (
                 <EvidenceRow type="error" text={`Threat intelligence detected malicious activity (${item.threat_intelligence.detections} flags)`} />
               ) : (
                 <EvidenceRow type="success" text="No malicious reputation detected" />
               )
            ) : (
               <EvidenceRow type="neutral" text="Threat intelligence unavailable" />
            )}
            
            {/* Email Alignment */}
            {item.email_alignment === "aligned" ? (
               <EvidenceRow type="success" text="Sender domain matches URL registered domain" />
            ) : item.email_alignment === "partially_aligned" ? (
               <EvidenceRow type="warning" text="Partial alignment (e.g., matching return-path or unauthenticated sender)" />
            ) : item.email_alignment === "misaligned" ? (
               <EvidenceRow type="error" text="Sender domain is completely unrelated to URL domain" />
            ) : (
               <EvidenceRow type="neutral" text="Email alignment could not be verified" />
            )}

            {/* Brand Match */}
            {item.brand_impersonation && (
               <EvidenceRow type="error" text="URL attempts to impersonate a trusted brand" />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function URLIntelligence({ urlAnalysis }) {
  const data = urlAnalysis || {};
  const analyzedUrls = data.analysis || [];
  const isLimitedContext = data.limited_context === true;

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
      <SectionHeader icon="🔗" title="URL Intelligence" subtitle={`${analyzedUrls.length} URL(s) analyzed via Active Evidence Engine`} />
      
      {isLimitedContext && (
        <div className="mt-4 mb-2 p-3 rounded-lg border border-orange-500/30 bg-orange-500/10 flex items-start gap-3">
          <span className="text-orange-500 mt-0.5">⚠</span>
          <div className="flex flex-col">
            <span className="text-[13px] font-bold text-orange-600 dark:text-orange-400">Limited Context</span>
            <span className="text-[12px] text-orange-600/80 dark:text-orange-400/80 mt-0.5">
              Only a URL was detected in this email. There is insufficient message context to confidently establish legitimacy. 
            </span>
          </div>
        </div>
      )}

      {analyzedUrls.length === 0 ? (
        <EmptyState icon="✓" message="No URLs detected in this email." />
      ) : (
        <div className="mt-5 space-y-4">
          {analyzedUrls.map((item, index) => (
            <UrlCard key={`${item.url}-${index}`} item={item} />
          ))}
        </div>
      )}
    </section>
  );
}

export default URLIntelligence;
