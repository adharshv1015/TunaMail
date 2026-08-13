import React, { useState } from "react";
import SectionHeader from "../common/SectionHeader";
import { submitFeedback } from "../../api/intelligence";

/* ─────────── helpers ─────────── */
const VERDICT_COLORS = {
  "PHISHING":           "text-red-500 dark:text-red-400",
  "HIGH RISK":          "text-orange-500 dark:text-orange-400",
  "SUSPICIOUS":         "text-amber-500 dark:text-amber-400",
  "UNKNOWN":            "text-yellow-500 dark:text-yellow-400",
  "LIKELY LEGITIMATE":  "text-teal-500 dark:text-teal-400",
  "VERIFIED LEGITIMATE":"text-emerald-500 dark:text-emerald-400",
};

const IOC_TYPE_COLORS = {
  "URL":          "bg-indigo-500/10 text-indigo-500 dark:text-indigo-400",
  "DOMAIN":       "bg-blue-500/10 text-blue-500 dark:text-blue-400",
  "IP_ADDRESS":   "bg-violet-500/10 text-violet-500 dark:text-violet-400",
  "HASH_SHA256":  "bg-orange-500/10 text-orange-500 dark:text-orange-400",
  "HASH_SHA1":    "bg-orange-500/10 text-orange-500 dark:text-orange-400",
  "HASH_MD5":     "bg-amber-500/10 text-amber-500 dark:text-amber-400",
  "EMAIL_ADDRESS":"bg-cyan-500/10 text-cyan-500 dark:text-cyan-400",
  "ATTACHMENT_NAME":"bg-slate-500/10 text-slate-500 dark:text-slate-400",
};

const Tag = ({ label, colorClass = "bg-indigo-500/10 text-indigo-400" }) => (
  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wide ${colorClass}`}>
    {label}
  </span>
);

/* ─────────── Attack Pattern Badge ─────────── */
function AttackPatternBadge({ pattern }) {
  return (
    <div className="flex flex-col gap-1.5 p-3 rounded-xl border border-red-500/20 bg-red-500/5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-bold text-red-500 dark:text-red-400">
          ⚔️ {pattern.name.replace(/_/g, " ")}
        </span>
        <Tag label={`${pattern.confidence}%`} colorClass="bg-red-500/10 text-red-500 dark:text-red-400" />
      </div>
      {pattern.matched_signals?.length > 0 && (
        <ul className="text-[11px] text-[var(--tm-text-secondary)] list-disc list-inside space-y-0.5">
          {pattern.matched_signals.map((s, i) => <li key={i}>{s}</li>)}
        </ul>
      )}
    </div>
  );
}

/* ─────────── Campaign Alert ─────────── */
function CampaignAlert({ campaign }) {
  if (!campaign?.campaign_detected) return null;
  return (
    <div className="flex flex-col gap-2 p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-bold text-amber-500 dark:text-amber-400">
          📡 Campaign: {campaign.campaign_id}
        </span>
        <Tag label={`${campaign.confidence}% confidence`} colorClass="bg-amber-500/10 text-amber-500 dark:text-amber-400" />
      </div>
      <p className="text-[12px] text-[var(--tm-text-secondary)]">
        {campaign.related_messages} related emails · {campaign.campaign_type?.replace(/_/g, " ")}
        {campaign.infrastructure_evolution && " · ⚡ Infrastructure Evolution Detected"}
      </p>
      {campaign.shared_indicators?.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-1">
          {campaign.shared_indicators.map((ind, i) => (
            <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-500 dark:text-amber-400">
              {ind}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

/* ─────────── IOC Table ─────────── */
function IOCTable({ iocs }) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? iocs : iocs.slice(0, 6);

  if (!iocs?.length) return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-[12px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)]">
          Indicators of Interest ({iocs.length})
        </h3>
        {iocs.length > 6 && (
          <button
            onClick={() => setExpanded(e => !e)}
            className="text-[11px] text-indigo-400 hover:text-indigo-300 transition-colors"
          >
            {expanded ? "Show less" : `+${iocs.length - 6} more`}
          </button>
        )}
      </div>
      <div className="rounded-xl border border-[var(--tm-border)] overflow-hidden">
        <table className="w-full text-[12px]">
          <thead className="bg-[var(--tm-surface-secondary)]">
            <tr>
              {["Type", "Value", "Source", "Conf."].map(h => (
                <th key={h} className="px-3 py-2 text-left font-semibold text-[var(--tm-text-secondary)] text-[11px] uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--tm-border)]">
            {shown.map((ioc, i) => (
              <tr key={i} className="hover:bg-[var(--tm-surface-secondary)] transition-colors">
                <td className="px-3 py-2">
                  <Tag
                    label={ioc.type}
                    colorClass={IOC_TYPE_COLORS[ioc.type] || "bg-slate-500/10 text-slate-400"}
                  />
                </td>
                <td className="px-3 py-2 font-mono text-[11px] text-[var(--tm-text)] break-all min-w-0" title={ioc.normalized || ioc.value}>
                  {ioc.normalized || ioc.value}
                </td>
                <td className="px-3 py-2 text-[var(--tm-text-secondary)]">{ioc.source}</td>
                <td className="px-3 py-2 text-[var(--tm-text-secondary)]">
                  {Math.round((ioc.confidence || 0) * 100)}%
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ─────────── Related Messages ─────────── */
function RelatedMessages({ related }) {
  if (!related?.length) return null;
  return (
    <div className="space-y-2">
      <h3 className="text-[12px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)]">
        🔗 Related Emails ({related.length})
      </h3>
      <div className="space-y-2">
        {related.slice(0, 4).map((rel, i) => (
          <div key={i} className="flex flex-col gap-1.5 p-3 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
            <div className="flex items-center gap-2">
              <Tag
                label={rel.relationship_type?.replace(/_/g, " ") || "RELATED"}
                colorClass="bg-indigo-500/10 text-indigo-400"
              />
              <span className="font-mono text-[10px] text-[var(--tm-text-secondary)] break-all">{rel.message_id}</span>
            </div>
            {rel.shared_indicators?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {rel.shared_indicators.slice(0, 3).map((ind, j) => (
                  <span key={j} className="font-mono text-[10px] px-2 py-0.5 rounded bg-[var(--tm-border)] text-[var(--tm-text-secondary)] break-all">
                    {ind.type}: {ind.value}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─────────── Trust Scores ─────────── */
function TrustScores({ scores }) {
  if (!scores || !Object.keys(scores).length) return null;

  const getColor = (v) => {
    if (v >= 70) return "bg-emerald-500";
    if (v >= 40) return "bg-amber-500";
    return "bg-red-500";
  };

  return (
    <div className="space-y-2">
      <h3 className="text-[12px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)]">
        📊 Evidence Trust Scores
      </h3>
      <p className="text-[11px] text-[var(--tm-text-secondary)] italic">Evidence signals — do not directly determine verdict.</p>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {Object.entries(scores).map(([key, val]) => (
          <div key={key} className="flex flex-col gap-1 p-3 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)]">
              {key.replace(/_/g, " ")}
            </span>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1.5 bg-[var(--tm-border)] rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${getColor(val)}`}
                  style={{ width: `${val}%` }}
                />
              </div>
              <span className="text-sm font-bold text-[var(--tm-text)] w-7 text-right">{val}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─────────── First-Seen Flags ─────────── */
function FirstSeenFlags({ flags }) {
  if (!flags || !Object.keys(flags).length) return null;
  return (
    <div className="flex flex-col gap-2 p-4 rounded-xl border border-slate-500/20 bg-slate-500/5">
      <div className="flex items-center gap-2">
        <span className="text-sm font-bold text-[var(--tm-text-secondary)]">🆕 First-Seen Indicators</span>
        <Tag label="UNKNOWN / LOW CONFIDENCE" colorClass="bg-slate-500/10 text-slate-400" />
      </div>
      <p className="text-[11px] text-[var(--tm-text-secondary)]">
        Not observed before. Does NOT automatically mean malicious.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {Object.entries(flags).map(([val, info], i) => (
          <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-500/10 text-slate-400">
            {info.type}: {val.length > 40 ? val.slice(0, 40) + "…" : val}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ─────────── Intelligence Timeline ─────────── */
function IntelTimeline({ timeline }) {
  if (!timeline?.length) return null;
  return (
    <div className="space-y-2">
      <h3 className="text-[12px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)]">🕐 Intelligence Timeline</h3>
      <div className="space-y-1.5">
        {timeline.map((ev, i) => (
          <div key={i} className="flex items-start gap-3">
            <span className="font-mono text-[10px] text-[var(--tm-text-secondary)] min-w-[60px] mt-0.5">{ev.time}</span>
            <div className="flex items-start gap-2">
              <div className="mt-1.5 h-1.5 w-1.5 rounded-full bg-indigo-500 shrink-0" />
              <span className="text-[12px] text-[var(--tm-text)]">{ev.event}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─────────── Analyst Feedback ─────────── */
function AnalystFeedback({ messageId, automatedVerdict }) {
  const [verdict, setVerdict] = useState("");
  const [comment, setComment] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async () => {
    if (!verdict) return;
    setLoading(true);
    setError("");
    try {
      await submitFeedback(messageId, verdict, automatedVerdict, comment);
      setSubmitted(true);
    } catch (e) {
      setError("Failed to submit feedback. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const VERDICTS = [
    { value: "TRUE_POSITIVE",  label: "✅ True Positive — correctly flagged malicious" },
    { value: "FALSE_POSITIVE", label: "❌ False Positive — incorrectly flagged (actually safe)" },
    { value: "TRUE_NEGATIVE",  label: "✅ True Negative — correctly identified as safe" },
    { value: "FALSE_NEGATIVE", label: "⚠️ False Negative — missed malicious email" },
    { value: "UNKNOWN",        label: "❓ Unknown — cannot determine" },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-start gap-2">
        <div className="text-xs text-[var(--tm-text-secondary)] mt-0.5">
          Automated verdict is always preserved. Your feedback is stored separately for audit purposes.
        </div>
      </div>

      {submitted ? (
        <div className="flex items-center gap-2 p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/5 text-emerald-500 dark:text-emerald-400 text-sm font-medium">
          ✅ Feedback submitted. Automated verdict unchanged.
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <select
            value={verdict}
            onChange={e => setVerdict(e.target.value)}
            className="w-full rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface)] text-[var(--tm-text)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/30 transition-colors"
          >
            <option value="">Select your verdict…</option>
            {VERDICTS.map(v => (
              <option key={v.value} value={v.value}>{v.label}</option>
            ))}
          </select>

          <textarea
            value={comment}
            onChange={e => setComment(e.target.value)}
            placeholder="Optional analyst comment (e.g. 'Legitimate Microsoft security notification')…"
            rows={2}
            className="w-full rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface)] text-[var(--tm-text)] px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-indigo-500/30 placeholder:text-[var(--tm-text-secondary)] transition-colors"
          />

          {error && <p className="text-xs text-red-400">{error}</p>}

          <button
            onClick={handleSubmit}
            disabled={!verdict || loading}
            className="self-start flex items-center gap-2 px-4 py-2 rounded-xl border border-indigo-500/30 bg-indigo-500/10 text-indigo-500 dark:text-indigo-400 text-sm font-semibold hover:bg-indigo-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <span className="h-3 w-3 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin" />
            ) : "🧑‍💻"}
            {loading ? "Submitting…" : "Submit Feedback"}
          </button>
        </div>
      )}
    </div>
  );
}

/* ─────────── MAIN INTELLIGENCE CARD ─────────── */
function IntelligenceCard({ intelligence, messageId, automatedVerdict }) {
  const intel = intelligence || {};
  const [activeTab, setActiveTab] = useState("overview");

  const hasPatterns = intel.attack_patterns?.length > 0;
  const hasCampaign = intel.campaign?.campaign_detected;
  const hasRelated  = intel.related_messages?.length > 0;
  const hasIOCs     = intel.iocs?.length > 0;

  const tabs = [
    { key: "overview",  label: "Overview",   badge: (hasCampaign || hasPatterns) ? "!" : null },
    { key: "iocs",      label: "IOCs",        badge: intel.iocs?.length || null },
    { key: "related",   label: "Related",     badge: intel.related_messages?.length || null },
    { key: "trust",     label: "Trust",       badge: null },
    { key: "timeline",  label: "Timeline",    badge: null },
    { key: "feedback",  label: "Feedback",    badge: null },
  ];

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm">
      <SectionHeader
        icon="🛰️"
        title="Stage 5 Intelligence"
        subtitle="IOC correlation, campaign detection, attack patterns & analyst feedback"
      />

      {/* Tab bar */}
      <div className="mt-5 flex gap-1 overflow-x-auto pb-1 border-b border-[var(--tm-border)]">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`relative shrink-0 px-3 py-2 text-[12px] font-semibold rounded-t-lg transition-colors
              ${activeTab === tab.key
                ? "text-indigo-500 dark:text-indigo-400 border-b-2 border-indigo-500 dark:border-indigo-400 -mb-px bg-indigo-500/5"
                : "text-[var(--tm-text-secondary)] hover:text-[var(--tm-text)]"
              }`}
          >
            {tab.label}
            {tab.badge && (
              <span className="ml-1.5 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-indigo-500 text-white text-[9px] font-bold px-1">
                {tab.badge === "!" ? "!" : tab.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="mt-5 space-y-5">
        {/* ── OVERVIEW ── */}
        {activeTab === "overview" && (
          <div className="space-y-4">
            {!hasPatterns && !hasCampaign && !hasRelated && (
              <div className="text-center py-6 text-[var(--tm-text-secondary)] text-sm">
                No campaign or attack patterns detected for this email.
              </div>
            )}
            {hasPatterns && intel.attack_patterns.map((p, i) => (
              <AttackPatternBadge key={i} pattern={p} />
            ))}
            <CampaignAlert campaign={intel.campaign} />
            <FirstSeenFlags flags={intel.first_seen} />
          </div>
        )}

        {/* ── IOCs ── */}
        {activeTab === "iocs" && (
          <div className="space-y-4">
            {hasIOCs
              ? <IOCTable iocs={intel.iocs} />
              : <p className="text-[var(--tm-text-secondary)] text-sm text-center py-6">No indicators extracted from this email.</p>
            }
          </div>
        )}

        {/* ── RELATED ── */}
        {activeTab === "related" && (
          <div className="space-y-4">
            {hasRelated
              ? <RelatedMessages related={intel.related_messages} />
              : <p className="text-[var(--tm-text-secondary)] text-sm text-center py-6">No related emails detected.</p>
            }
          </div>
        )}

        {/* ── TRUST ── */}
        {activeTab === "trust" && (
          <TrustScores scores={intel.trust_scores} />
        )}

        {/* ── TIMELINE ── */}
        {activeTab === "timeline" && (
          <IntelTimeline timeline={intel.timeline} />
        )}

        {/* ── FEEDBACK ── */}
        {activeTab === "feedback" && (
          <AnalystFeedback messageId={messageId} automatedVerdict={automatedVerdict} />
        )}
      </div>
    </section>
  );
}

export default IntelligenceCard;
