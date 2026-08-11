import React, { useState, useEffect } from 'react';

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
        <span className="font-bold">[{item.severity}] {item.type.replace(/_/g, ' ').toUpperCase()}</span>
        <span className="text-xs opacity-75">Confidence: {item.confidence}%</span>
      </div>
      <div className="mb-1"><span className="font-semibold">Source:</span> {item.source}</div>
      {item.observation && <div className="mb-1"><span className="font-semibold">Observation:</span> {item.observation}</div>}
      {item.explanation && <div><span className="font-semibold">Explanation:</span> {item.explanation}</div>}
    </div>
  );
};

const AnalystExplanation = ({ messageId, decision, sender }) => {
  const [expanded, setExpanded] = useState(false);
  const [feedbackState, setFeedbackState] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [pendingLabel, setPendingLabel] = useState("");
  const [reason, setReason] = useState("");

  const explanation = decision?.explanation || {};

  useEffect(() => {
    // Fetch previous feedback if any
    fetch(`/api/gmail/message/${messageId}/feedback`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.analyst_label) {
          setFeedbackState(data);
        }
      })
      .catch(e => console.error(e));
  }, [messageId]);

  const handleFeedbackClick = (label) => {
    setPendingLabel(label);
    setModalOpen(true);
  };

  const submitFeedback = async () => {
    try {
      const res = await fetch(`/api/gmail/message/${messageId}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: pendingLabel,
          reason,
          sender,
          previous_verdict: decision.verdict,
          previous_risk_score: decision.risk_score
        })
      });
      if (res.ok) {
        setFeedbackState({ analyst_label: pendingLabel });
        setModalOpen(false);
      }
    } catch (e) {
      console.error(e);
    }
  };

  if (!decision || !explanation.summary) return null;

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
            <p className="text-sm text-slate-700 dark:text-slate-300">{explanation.primary_reason}</p>
          </div>

          {explanation.limitations?.length > 0 && (
            <div className="mb-4">
              <h4 className="font-semibold text-amber-600 uppercase text-xs tracking-wider mb-2">Limitations & Contradictions</h4>
              <ul className="list-disc pl-4 text-sm text-slate-700 dark:text-slate-300">
                {explanation.limitations.map((lim, i) => <li key={i}>{lim}</li>)}
              </ul>
            </div>
          )}

          {explanation.confidence_factors?.length > 0 && (
            <div className="mb-4">
              <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-2">Confidence Factors</h4>
              <ul className="list-disc pl-4 text-sm text-slate-700 dark:text-slate-300">
                {explanation.confidence_factors.map((cf, i) => <li key={i}>{cf}</li>)}
              </ul>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
            <div>
              <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-2">
                Negative Security Evidence ({explanation.negative_evidence?.length || 0})
              </h4>
              {explanation.negative_evidence?.map((item, i) => (
                <EvidenceCard key={i} item={item} />
              ))}
              {(!explanation.negative_evidence || explanation.negative_evidence.length === 0) && (
                <div className="text-sm text-slate-500 italic p-2">No negative evidence.</div>
              )}
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-2">
                Positive Security Evidence ({explanation.positive_evidence?.length || 0})
              </h4>
              {explanation.positive_evidence?.map((item, i) => (
                <EvidenceCard key={i} item={item} />
              ))}
              {(!explanation.positive_evidence || explanation.positive_evidence.length === 0) && (
                <div className="text-sm text-slate-500 italic p-2">No positive evidence.</div>
              )}
            </div>
          </div>

          {/* Analyst Feedback Section */}
          <div className="mt-8 border-t border-slate-200 dark:border-slate-700 pt-4">
            <h4 className="font-semibold text-slate-800 dark:text-slate-200 uppercase text-xs tracking-wider mb-3">Analyst Feedback</h4>
            {feedbackState ? (
              <div className="flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400 font-semibold bg-emerald-500/10 p-2 rounded border border-emerald-500/20">
                ✓ Feedback recorded: {feedbackState.analyst_label.replace(/_/g, ' ')}
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                <button onClick={() => handleFeedbackClick('CONFIRMED_SAFE')} className="px-3 py-1.5 text-xs font-semibold rounded bg-emerald-100 text-emerald-700 hover:bg-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-400 dark:hover:bg-emerald-800/40">✓ Confirm Safe</button>
                <button onClick={() => handleFeedbackClick('CONFIRMED_PHISHING')} className="px-3 py-1.5 text-xs font-semibold rounded bg-red-100 text-red-700 hover:bg-red-200 dark:bg-red-900/30 dark:text-red-400 dark:hover:bg-red-800/40">⚠ Confirm Phishing</button>
                <button onClick={() => handleFeedbackClick('FALSE_POSITIVE')} className="px-3 py-1.5 text-xs font-semibold rounded bg-amber-100 text-amber-700 hover:bg-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:hover:bg-amber-800/40">↩ False Positive</button>
                <button onClick={() => handleFeedbackClick('FALSE_NEGATIVE')} className="px-3 py-1.5 text-xs font-semibold rounded bg-amber-100 text-amber-700 hover:bg-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:hover:bg-amber-800/40">↩ False Negative</button>
                <button onClick={() => handleFeedbackClick('UNKNOWN')} className="px-3 py-1.5 text-xs font-semibold rounded bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700">? Mark Unknown</button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Feedback Modal */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-slate-900 p-6 rounded-xl shadow-xl max-w-md w-full m-4">
            <h3 className="text-lg font-bold mb-4 text-slate-900 dark:text-white">Provide Reason (Optional)</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">You are marking this email as <strong>{pendingLabel.replace(/_/g, ' ')}</strong>.</p>
            <textarea 
              className="w-full border rounded p-2 text-sm bg-transparent dark:border-slate-700 text-slate-900 dark:text-white mb-4 h-24"
              placeholder="e.g. This was a legitimate Microsoft password reset."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <div className="flex justify-end gap-2">
              <button 
                className="px-4 py-2 text-sm font-semibold rounded text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                onClick={() => setModalOpen(false)}
              >
                Cancel
              </button>
              <button 
                className="px-4 py-2 text-sm font-semibold rounded bg-blue-600 text-white hover:bg-blue-700"
                onClick={submitFeedback}
              >
                Submit Feedback
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
