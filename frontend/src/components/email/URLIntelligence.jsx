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
      <span className="text-[var(--tm-text-secondary)] break-words [overflow-wrap:anywhere] min-w-0">{text}</span>
    </div>
  );
}

function IndicatorBadge({ label, isSuspicious, type = "warning" }) {
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

const SEVERITY_STYLES = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  LOW: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  INFO: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const SEVERITY_ICONS = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🔵",
  INFO: "⚪",
};

const INDICATOR_LABELS = {
  FAKE_ERROR_PAGE: "Fake Error Page",
  SPARSE_CREDENTIAL_FORM: "Credential Harvesting Form",
  CREDENTIAL_FORM: "Credential Form Detected",
  SPARSE_EMAIL_FORM: "Sparse Email Form",
  SPARSE_FORM_PAGE: "Sparse Form Page",
  URGENCY_LANGUAGE: "Urgency Language",
  CREDENTIAL_SOLICITATION: "Sensitive Data Requested",
  SUSPICIOUS_TITLE: "Suspicious Page Title",
  MULTI_DOMAIN_REDIRECT: "Multi-Domain Redirect",
};

function PageRiskMeter({ score }) {
  const pct = Math.min(score, 100);
  const color = pct >= 60 ? "#ef4444" : pct >= 30 ? "#f97316" : pct >= 10 ? "#eab308" : "#22c55e";
  return (
    <div className="flex items-center gap-2 mt-1">
      <div className="flex-1 h-1.5 rounded-full bg-[var(--tm-border)] overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-[11px] font-bold tabular-nums" style={{ color }}>{pct}/100</span>
    </div>
  );
}

function PageAnalysisPanel({ pageAnalysis }) {
  if (!pageAnalysis) return null;

  if (!pageAnalysis.available) {
    const errMsg = pageAnalysis.error || "Page inspection skipped or not available.";
    return (
      <div className="mt-3 pt-3 border-t border-[var(--tm-border)]/40">
        <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <span>🌐</span> Live Page Inspection
        </div>
        <div className="text-[12px] text-[var(--tm-text-muted)] italic">{errMsg}</div>
      </div>
    );
  }

  const indicators = pageAnalysis.indicators || [];
  const score = pageAnalysis.page_risk_score || 0;

  return (
    <div className="mt-3 pt-3 border-t border-[var(--tm-border)]/40">
      {/* Header row */}
      <div className="flex items-center justify-between mb-2">
        <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
          <span>🌐</span> Live Page Inspection
        </div>
        <div className="text-[11px] text-[var(--tm-text-muted)]">
          {pageAnalysis.word_count != null ? `${pageAnalysis.word_count} words` : ""}
          {pageAnalysis.title ? ` · "${pageAnalysis.title.slice(0, 30)}${pageAnalysis.title.length > 30 ? "…" : ""}"` : ""}
        </div>
      </div>

      {/* Risk score */}
      <div className="mb-3">
        <div className="text-[10px] text-[var(--tm-text-muted)] mb-0.5">Page Phishing Risk</div>
        <PageRiskMeter score={score} />
      </div>

      {/* Quick signals row */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        {pageAnalysis.has_credential_form && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-red-500/10 text-red-400 border-red-500/20">
            🔑 Credential Form
          </span>
        )}
        {pageAnalysis.has_fake_error && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-orange-500/10 text-orange-400 border-orange-500/20">
            ⚠ Fake Error Page
          </span>
        )}
        {pageAnalysis.has_urgency && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-400 border-amber-500/20">
            ⏱ Urgency Tactics
          </span>
        )}
        {indicators.length === 0 && (
          <span className="inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
            ✓ No Page Threats Detected
          </span>
        )}
      </div>

      {/* Indicator list */}
      {indicators.length > 0 && (
        <div className="flex flex-col gap-2">
          {indicators.map((ind, i) => (
            <div
              key={i}
              className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[12px] ${SEVERITY_STYLES[ind.severity] || SEVERITY_STYLES.INFO}`}
            >
              <span className="mt-0.5 shrink-0 text-[13px]">{SEVERITY_ICONS[ind.severity] || "⚪"}</span>
              <div className="flex flex-col gap-0.5">
                <span className="font-bold uppercase tracking-wide text-[10px]">
                  {INDICATOR_LABELS[ind.type] || ind.type}
                </span>
                <span className="leading-relaxed opacity-90 break-words [overflow-wrap:anywhere]">{ind.detail}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Form details */}
      {pageAnalysis.forms && (pageAnalysis.forms.count > 0) && (
        <div className="mt-2 text-[11px] text-[var(--tm-text-muted)]">
          Forms: {pageAnalysis.forms.count} found
          {pageAnalysis.forms.password_fields > 0 && ` · ${pageAnalysis.forms.password_fields} password field(s)`}
          {pageAnalysis.forms.email_fields > 0 && ` · ${pageAnalysis.forms.email_fields} email/login field(s)`}
        </div>
      )}
    </div>
  );
}

function UrlCard({ item }) {
  const [expanded, setExpanded] = useState(false);
  const pageAnalysis = item.page_analysis;

  const pageHasRisk =
    pageAnalysis?.available &&
    (pageAnalysis.page_risk_score > 0 ||
      (pageAnalysis.indicators || []).length > 0);

  const hasRisk =
    item.ip_based ||
    item.shortener ||
    item.obfuscated ||
    item.punycode ||
    item.suspicious_port ||
    (item.keywords && item.keywords.length > 0) ||
    item.brand_impersonation ||
    (item.threat_intelligence && item.threat_intelligence.detections > 0) ||
    pageHasRisk ||
    item.tls_policy_violation;

  const getRiskFlags = () => {
    const flags = [];

    if (item.ip_based) flags.push("IP-Based");
    if (item.shortener) flags.push("Shortener");
    if (item.obfuscated) flags.push("Obfuscated");
    if (item.punycode) flags.push("Punycode");
    if (item.brand_impersonation) flags.push("Impersonation");
    if (item.tls_policy_violation) flags.push("TLS Violation");
    if (pageHasRisk) flags.push("Page Risk");

    return flags;
  };

  const flags = getRiskFlags();

  return (
    <>
      {/* Compact URL Card */}
      <div
        className={`flex min-w-0 rounded-[8px] border bg-[var(--tm-surface-secondary)] overflow-hidden transition-all duration-200 ${hasRisk
          ? "border-orange-500/30"
          : "border-[var(--tm-border)]"
          }`}
      >
        <button
          type="button"
          onClick={() => setExpanded(true)}
          aria-label={`View URL intelligence for ${item.domain || "Unknown"}`}
          className="flex items-center justify-between w-full min-w-0 p-3 text-left hover:bg-[var(--tm-surface)] transition-colors focus:outline-none focus:ring-1 focus:ring-[var(--tm-accent)]"
        >
          <div className="flex items-center gap-2 min-w-0 flex-1">
            <div
              className={`shrink-0 w-2 h-2 rounded-full ${hasRisk ? "bg-orange-500" : "bg-emerald-500"
                }`}
            />

            <div className="font-mono text-[11px] text-[var(--tm-accent)] font-semibold truncate min-w-0">
              {item.domain || "Unknown"}
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 ml-2">
            {flags.length > 0 ? (
              <span className="text-[9px] font-bold uppercase tracking-wider text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded border border-orange-500/20 whitespace-nowrap">
                {flags.length} FLAG{flags.length !== 1 ? "S" : ""}
              </span>
            ) : (
              <span className="text-[9px] font-bold uppercase tracking-wider text-emerald-500 opacity-80 whitespace-nowrap">
                CLEAN
              </span>
            )}

            <span className="text-[10px] text-[var(--tm-text-muted)]">
              ▼
            </span>
          </div>
        </button>
      </div>

      {/* Floating URL Details Popup */}
      {expanded && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 bg-black/50 backdrop-blur-[2px]"
          onClick={() => setExpanded(false)}
          role="dialog"
          aria-modal="true"
          aria-label={`URL intelligence details for ${item.domain || "Unknown"}`}
        >
          <div
            className="relative w-full max-w-2xl max-h-[85vh] overflow-hidden rounded-2xl border border-[var(--tm-border)] bg-[var(--tm-surface)] shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            {/* Popup Header */}
            <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
              <div className="flex items-center gap-2 min-w-0">
                <div
                  className={`shrink-0 w-2.5 h-2.5 rounded-full ${hasRisk ? "bg-orange-500" : "bg-emerald-500"
                    }`}
                />

                <div className="min-w-0">
                  <div className="font-mono text-[13px] font-bold text-[var(--tm-accent)] truncate">
                    {item.domain || "Unknown"}
                  </div>

                  <div className="text-[10px] text-[var(--tm-text-muted)] truncate">
                    {item.url}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {flags.length > 0 ? (
                  <span className="text-[9px] font-bold uppercase tracking-wider text-orange-400 bg-orange-500/10 px-2 py-1 rounded border border-orange-500/20 whitespace-nowrap">
                    {flags.length} FLAG{flags.length !== 1 ? "S" : ""}
                  </span>
                ) : (
                  <span className="text-[9px] font-bold uppercase tracking-wider text-emerald-500 bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20 whitespace-nowrap">
                    CLEAN
                  </span>
                )}

                <button
                  type="button"
                  onClick={() => setExpanded(false)}
                  aria-label="Close URL details"
                  className="flex h-7 w-7 items-center justify-center rounded-lg text-[var(--tm-text-muted)] hover:bg-[var(--tm-border)] hover:text-[var(--tm-text)] transition-colors"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Popup Scrollable Content */}
            <div className="max-h-[calc(85vh-61px)] overflow-y-auto p-4 sm:p-5">
              <div className="flex flex-col gap-4">
                {/* Full URL */}
                <div className="flex flex-col">
                  <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-1">
                    Full URL
                  </div>

                  <div
                    className="break-all font-mono text-[12px] text-[var(--tm-text)] opacity-90 leading-relaxed bg-[var(--tm-surface-secondary)] p-3 rounded-lg border border-[var(--tm-border)]/50"
                    style={{ wordBreak: "break-word" }}
                  >
                    {item.url}
                  </div>
                </div>

                {/* Domain Context */}
                <div className="flex flex-col">
                  <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-1.5">
                    Domain Context
                  </div>

                  {item.registered_domain &&
                    item.registered_domain !== item.domain && (
                      <div className="text-[11px] text-[var(--tm-text-muted)] font-mono opacity-80">
                        Root: {item.registered_domain}
                      </div>
                    )}

                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {!hasRisk && (
                      <span className="inline-flex items-center px-2 py-0.5 rounded border text-[9px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20">
                        NO FLAGS
                      </span>
                    )}

                    <IndicatorBadge
                      label="IP-Based"
                      isSuspicious={item.ip_based}
                      type="warning"
                    />

                    <IndicatorBadge
                      label="Shortener"
                      isSuspicious={item.shortener}
                      type="warning"
                    />

                    <IndicatorBadge
                      label="Obfuscated"
                      isSuspicious={item.obfuscated}
                      type="error"
                    />

                    <IndicatorBadge
                      label="Punycode"
                      isSuspicious={item.punycode}
                      type="error"
                    />

                    <IndicatorBadge
                      label="Brand Impersonation"
                      isSuspicious={item.brand_impersonation}
                      type="error"
                    />

                    <IndicatorBadge
                      label="Suspicious Port"
                      isSuspicious={item.suspicious_port}
                      type="warning"
                    />

                    <IndicatorBadge
                      label="TLS Violation"
                      isSuspicious={item.tls_policy_violation}
                      type="error"
                    />

                    <IndicatorBadge
                      label="Insecure Transport"
                      isSuspicious={item.http_policy_warning}
                      type="warning"
                    />

                    <IndicatorBadge
                      label="TLS Inspection Failed"
                      isSuspicious={item.tls_inspection_unavailable}
                      type="warning"
                    />

                    {item.keywords && item.keywords.length > 0 && (
                      <IndicatorBadge
                        label={`KEYWORDS: ${item.keywords.join(", ")}`}
                        isSuspicious={true}
                        type="warning"
                      />
                    )}

                    {item.email_alignment === "misaligned" && (
                      <IndicatorBadge
                        label="Sender Misalignment"
                        isSuspicious={true}
                        type="warning"
                      />
                    )}
                  </div>
                </div>

                {/* Page Analysis */}
                {pageAnalysis && (
                  <PageAnalysisPanel pageAnalysis={pageAnalysis} />
                )}

                {/* Technical Evidence */}
                <div className="mt-1 flex flex-col gap-1 bg-[var(--tm-surface-secondary)] p-3 rounded-lg border border-[var(--tm-border)]/50">
                  {/* DNS Evidence */}
                  {item.dns && item.dns.resolved ? (
                    <EvidenceRow
                      type="success"
                      text={`DNS resolved successfully (${[
                        ...(item.dns.a || []),
                        ...(item.dns.aaaa || []),
                      ].length} records)`}
                    />
                  ) : item.dns && item.dns.private_ip_detected ? (
                    <EvidenceRow
                      type="error"
                      text="DNS resolved to an internal/private IP (SSRF Blocked)"
                    />
                  ) : (
                    <EvidenceRow
                      type="warning"
                      text="DNS resolution unavailable or failed"
                    />
                  )}

                  {/* TLS Evidence */}
                  {item.tls && item.tls.https ? (
                    item.tls.certificate_valid ? (
                      <EvidenceRow
                        type="success"
                        text={`TLS certificate valid (Issuer: ${item.tls.issuer || "Unknown"
                          })`}
                      />
                    ) : (
                      <EvidenceRow
                        type="error"
                        text={
                          item.tls.error_detail
                            ? `TLS policy violation: ${item.tls.error_detail} (${item.tls.violation})`
                            : "TLS certificate invalid or expired"
                        }
                      />
                    )
                  ) : item.tls &&
                    item.tls.certificate_present === false &&
                    item.tls.violation ? (
                    <EvidenceRow
                      type="warning"
                      text={`TLS inspection issue: ${item.tls.error_detail} (${item.tls.violation})`}
                    />
                  ) : (
                    <EvidenceRow
                      type="warning"
                      text="Connection does not use HTTPS"
                    />
                  )}

                  {/* Redirects */}
                  {item.redirects && item.redirects.detected ? (
                    <EvidenceRow
                      type={
                        item.redirects.external_domain_change
                          ? "error"
                          : "warning"
                      }
                      text={`Redirect chain detected (${item.redirects.chain.length} hops)${item.redirects.external_domain_change
                        ? " - External domain change!"
                        : ""
                        }`}
                    />
                  ) : (
                    <EvidenceRow
                      type="success"
                      text="No redirects detected"
                    />
                  )}

                  {/* Email Alignment */}
                  {item.email_alignment === "aligned" ? (
                    <EvidenceRow
                      type="success"
                      text="Sender domain matches URL registered domain"
                    />
                  ) : item.email_alignment === "partially_aligned" ? (
                    <EvidenceRow
                      type="warning"
                      text="Partial alignment (e.g., matching return-path or unauthenticated sender)"
                    />
                  ) : item.email_alignment === "misaligned" ? (
                    <EvidenceRow
                      type="error"
                      text="Sender domain is completely unrelated to URL domain"
                    />
                  ) : (
                    <EvidenceRow
                      type="neutral"
                      text="Email alignment was not evaluated for this URL"
                    />
                  )}

                  {/* Brand Match */}
                  {item.brand_impersonation && (
                    <EvidenceRow
                      type="error"
                      text="URL attempts to impersonate a trusted brand"
                    />
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function URLIntelligence({ urlAnalysis, urlPageIntelligence }) {
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
        <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
          {analyzedUrls.map((item, index) => (
            <UrlCard key={`${item.url}-${index}`} item={item} />
          ))}
        </div>
      )}

      {/* Deep Page Inspection */}
      {urlPageIntelligence && Object.keys(urlPageIntelligence).length > 0 && (
        <div className="mt-6 border-t border-[var(--tm-border)]/50 pt-4">
          <div className="text-[13px] font-bold text-[var(--tm-text)] uppercase tracking-wider mb-4 flex items-center gap-2">
            <span className="text-[var(--tm-accent)]">👁</span>
            Deep Page Inspection (Worker Results)
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(urlPageIntelligence).map(([url, pageData], i) => (
              <div
                key={i}
                className="flex flex-col gap-3 rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-4"
              >
                {/* URL */}
                <div className="text-[12px] font-mono text-[var(--tm-accent)] break-all border-b border-[var(--tm-border)]/50 pb-2">
                  {url}
                </div>

                {/* Security */}
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase">
                    Security
                  </span>

                  {pageData.security?.blocked ? (
                    <span className="text-[10px] font-bold text-red-500">
                      BLOCKED
                    </span>
                  ) : pageData.security?.error ? (
                    <span className="text-[10px] font-bold text-orange-500">
                      ERROR
                    </span>
                  ) : (
                    <span className="text-[10px] font-bold text-emerald-500">
                      ALLOWED
                    </span>
                  )}
                </div>

                {pageData.security?.error && (
                  <div className="text-[11px] text-red-500 bg-red-500/10 border border-red-500/20 rounded-lg p-2">
                    {pageData.security.error}
                  </div>
                )}

                {/* DNS */}
                <div className="rounded-lg border border-[var(--tm-border)]/50 p-3">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)] mb-2">
                    DNS
                  </div>

                  {pageData.dns ? (
                    <>
                      <div className="text-[11px] mb-1">
                        Status:{" "}
                        <span
                          className={
                            pageData.dns.resolved
                              ? "text-emerald-500 font-bold"
                              : "text-red-500 font-bold"
                          }
                        >
                          {pageData.dns.resolved ? "RESOLVED" : "FAILED"}
                        </span>
                      </div>

                      {pageData.dns.validated_ips?.length > 0 && (
                        <div className="text-[10px] font-mono text-[var(--tm-text-muted)] break-all">
                          IPs: {pageData.dns.validated_ips.join(", ")}
                        </div>
                      )}
                    </>
                  ) : (
                    <span className="text-[11px] text-[var(--tm-text-muted)]">
                      Not available
                    </span>
                  )}
                </div>

                {/* TLS */}
                <div className="rounded-lg border border-[var(--tm-border)]/50 p-3">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)] mb-2">
                    TLS
                  </div>

                  {pageData.tls ? (
                    <>
                      <div className="text-[11px]">
                        Status:{" "}
                        <span
                          className={
                            pageData.tls.certificate_valid
                              ? "text-emerald-500 font-bold"
                              : "text-red-500 font-bold"
                          }
                        >
                          {pageData.tls.certificate_valid
                            ? "VALID"
                            : "INVALID"}
                        </span>
                      </div>

                      {pageData.tls.issuer && (
                        <div className="text-[10px] text-[var(--tm-text-muted)] mt-1">
                          Issuer: {pageData.tls.issuer}
                        </div>
                      )}

                      {pageData.tls.tls_version && (
                        <div className="text-[10px] text-[var(--tm-text-muted)]">
                          Version: {pageData.tls.tls_version}
                        </div>
                      )}
                    </>
                  ) : (
                    <span className="text-[11px] text-[var(--tm-text-muted)]">
                      Not available
                    </span>
                  )}
                </div>

                {/* HTTP */}
                <div className="rounded-lg border border-[var(--tm-border)]/50 p-3">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)] mb-2">
                    HTTP
                  </div>

                  {pageData.http ? (
                    <>
                      <div className="text-[11px]">
                        Status Code:{" "}
                        <span className="font-bold text-[var(--tm-text)]">
                          {pageData.http.status_code ?? "N/A"}
                        </span>
                      </div>

                      {pageData.http.final_url && (
                        <div className="text-[10px] text-[var(--tm-text-muted)] break-all mt-1">
                          Final URL: {pageData.http.final_url}
                        </div>
                      )}
                    </>
                  ) : (
                    <span className="text-[11px] text-[var(--tm-text-muted)]">
                      Not available
                    </span>
                  )}
                </div>

                {/* Domain */}
                {pageData.registered_domain && (
                  <div className="text-[11px]">
                    <span className="font-bold text-[var(--tm-text-secondary)]">
                      Registered Domain:
                    </span>{" "}
                    <span className="font-mono text-[var(--tm-text)]">
                      {pageData.registered_domain}
                    </span>
                  </div>
                )}

                {/* Page Content */}
                {!pageData.security?.error && (
                  <>
                    <div className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-[12px]">
                      <span className="text-[var(--tm-text-secondary)] font-bold">
                        Title:
                      </span>
                      <span className="text-[var(--tm-text)]">
                        {pageData.title || (
                          <span className="italic text-gray-500">None</span>
                        )}
                      </span>

                      <span className="text-[var(--tm-text-secondary)] font-bold">
                        Word Count:
                      </span>
                      <span className="text-[var(--tm-text)]">
                        {pageData.word_count || 0}
                      </span>

                      <span className="text-[var(--tm-text-secondary)] font-bold">
                        Forms:
                      </span>
                      <span
                        className={`font-bold ${pageData.forms?.password_fields > 0 ||
                          pageData.forms?.email_fields > 0
                          ? "text-orange-500"
                          : "text-[var(--tm-text)]"
                          }`}
                      >
                        {pageData.forms?.password_fields > 0 &&
                          `Password (${pageData.forms.password_fields}) `}

                        {pageData.forms?.email_fields > 0 &&
                          `Email/Login (${pageData.forms.email_fields}) `}

                        {pageData.forms?.password_fields === 0 &&
                          pageData.forms?.email_fields === 0 &&
                          "None"}
                      </span>
                    </div>

                    {/* Structured Evidence */}
                    {pageData.structured_evidence?.length > 0 && (
                      <div className="rounded-lg border border-[var(--tm-border)]/50 p-3">
                        <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)] mb-2">
                          Evidence
                        </div>

                        <div className="flex flex-col gap-2">
                          {pageData.structured_evidence.map((evidence, index) => (
                            <div
                              key={index}
                              className="text-[11px] rounded-md bg-[var(--tm-surface)] p-2"
                            >
                              <div className="font-bold text-[var(--tm-text)]">
                                {evidence.type || "UNKNOWN"}
                              </div>

                              {evidence.explanation && (
                                <div className="text-[var(--tm-text-muted)] mt-0.5">
                                  {evidence.explanation}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Visible Text */}
                    {pageData.visible_text && (
                      <div className="text-[11px] text-[var(--tm-text-muted)] italic line-clamp-3 bg-[var(--tm-surface)] p-2 rounded">
                        "{pageData.visible_text}"
                      </div>
                    )}
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

export default URLIntelligence;
