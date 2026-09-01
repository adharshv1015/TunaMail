import React, { useState } from 'react';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-500/10 text-red-600 border-red-500/20 dark:text-red-400',
  HIGH: 'bg-orange-500/10 text-orange-600 border-orange-500/20 dark:text-orange-400',
  MEDIUM: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20 dark:text-yellow-400',
  LOW: 'bg-blue-500/10 text-blue-600 border-blue-500/20 dark:text-blue-400',
  INFO: 'bg-slate-500/10 text-slate-600 border-slate-500/20 dark:text-slate-400'
};

const EvidenceCard = ({ item }) => {
  const colorClass = SEVERITY_COLORS[item.severity] || SEVERITY_COLORS.INFO;

  return (
    <div className={`p-3 rounded-lg border text-sm mb-2 ${colorClass}`}>
      <div className="flex justify-between items-center mb-1">
        <span className="font-bold">[{item?.severity || 'INFO'}] {item?.type ? String(item.type).replace(/_/g, ' ').toUpperCase() : 'EVIDENCE'}</span>
        <span className="text-xs opacity-75">
          Confidence: {Math.round(
            Number(item?.confidence || 0) <= 1
              ? Number(item?.confidence || 0) * 100
              : Number(item?.confidence || 0)
          )}%
        </span>
      </div>
      <div className="mb-1"><span className="font-semibold">Source:</span> {item?.source || 'Unknown'}</div>
      {item?.observation && item.observation !== item.explanation && <div className="mb-1"><span className="font-semibold">Observation:</span> {String(item.observation)}</div>}
      {item?.explanation && <div><span className="font-semibold">Explanation:</span> {String(item.explanation)}</div>}
    </div>
  );
};

const AnalystExplanation = ({ messageId, decision, explanation, sender }) => {
  const [expanded, setExpanded] = useState(false);

  const exp = explanation || decision?.explanation || {};
  const negEv = exp.groups?.NEGATIVE_EVIDENCE || exp.negative_evidence || [];
  const posEv = exp.groups?.POSITIVE_EVIDENCE || exp.positive_evidence || [];
  const limitations = exp.groups?.CONTEXT_LIMITATIONS || exp.limitations || [];
  const confidenceFactors = exp.confidence_explanation ? [exp.confidence_explanation] : (exp.confidence_factors || []);

  const renderListItem = (item) => {
    if (typeof item === 'string') return item;
    if (!item) return '';
    return (
      <span>
        {item.title && <strong className="mr-1">{item.title}:</strong>}
        {item.explanation || item.observation || item.type || JSON.stringify(item)}
      </span>
    );
  };

  if (!decision) return null;

  return (
    <div className="mt-6 border border-slate-200 dark:border-slate-700 rounded-xl bg-slate-50 dark:bg-slate-900 overflow-hidden">
      <div
        className="p-4 bg-slate-100 dark:bg-slate-800 flex justify-between items-center cursor-pointer select-none"
        onClick={() => setExpanded(!expanded)}
      >
        <div>
          <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
            🛡️ ANALYST EXPLANATION
          </h3>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Verdict: <span className="font-bold">{decision.verdict}</span> |
            Detail: <span className="font-bold">{decision.detail_verdict || 'N/A'}</span> |
            Risk: {decision.risk_score}/100 |
            Confidence: {decision.confidence}%
          </p>
        </div>
        <div className="text-slate-500">
          {expanded ? '▼' : '▶'}
        </div>
      </div>

      {expanded && (
        <div className="p-4">
          <div className="mb-4">
            <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-2">Primary Reason</h4>
            <p className="text-sm text-slate-700 dark:text-slate-300">{exp.primary_reason}</p>
          </div>

          {limitations.length > 0 && (
            <div className="mb-4">
              <h4 className="font-semibold text-amber-600 uppercase text-xs tracking-wider mb-2">Limitations & Contradictions</h4>
              <ul className="list-disc pl-4 text-sm text-slate-700 dark:text-slate-300">
                {limitations.map((lim, i) => <li key={i}>{renderListItem(lim)}</li>)}
              </ul>
            </div>
          )}

          {confidenceFactors.length > 0 && (
            <div className="mb-4">
              <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-2">Confidence Factors</h4>
              <ul className="list-disc pl-4 text-sm text-slate-700 dark:text-slate-300">
                {confidenceFactors.map((cf, i) => <li key={i}>{renderListItem(cf)}</li>)}
              </ul>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
            <div>
              <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-2">
                Negative Security Evidence ({negEv.length})
              </h4>
              {negEv.map((item, i) => (
                <EvidenceCard key={i} item={item} />
              ))}
              {negEv.length === 0 && (
                <div className="text-sm text-slate-500 italic p-2">No negative evidence.</div>
              )}
            </div>

            <div>
              <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-2">
                Positive Security Evidence ({posEv.length})
              </h4>
              {posEv.map((item, i) => (
                <EvidenceCard key={i} item={item} />
              ))}
              {posEv.length === 0 && (
                <div className="text-sm text-slate-500 italic p-2">No positive evidence.</div>
              )}
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
export default AnalystExplanation;
