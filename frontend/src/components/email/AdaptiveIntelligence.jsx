import React, { useState } from 'react';
import SectionHeader from '../common/SectionHeader';

export default function AdaptiveIntelligence({ adaptive }) {
  const [expanded, setExpanded] = useState(false);

  if (!adaptive) return null;

  const senderBaseline = adaptive.sender_baseline || {};
  const riskTrend = adaptive.risk_trend || {};
  const anomalies = adaptive.behavioral_anomalies || [];
  const historyConfidence = adaptive.history_confidence || {};
  
  const hasShift = anomalies.length > 0;

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm mt-6">
      <SectionHeader icon="🧠" title="Adaptive Intelligence" subtitle="Local historical correlation & behavioral learning" />
      
      <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
          <div className="text-xs uppercase text-slate-500 font-bold mb-1">History Confidence</div>
          <div className={`text-lg font-bold ${historyConfidence.level === 'HIGH' || historyConfidence.level === 'VERY_HIGH' ? 'text-blue-500' : 'text-slate-500'}`}>
            {historyConfidence.level?.replace('_', ' ') || "UNKNOWN"}
          </div>
        </div>
        
        <div className="p-4 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
          <div className="text-xs uppercase text-slate-500 font-bold mb-1">Behavior</div>
          <div className={`text-lg font-bold ${hasShift ? 'text-orange-500' : 'text-emerald-500'}`}>
            {hasShift ? 'SHIFT DETECTED' : 'NORMAL'}
          </div>
        </div>
        
        <div className="p-4 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
          <div className="text-xs uppercase text-slate-500 font-bold mb-1">Risk Trend</div>
          <div className={`text-lg font-bold ${riskTrend.trend === 'DEGRADING' ? 'text-red-500' : riskTrend.trend === 'IMPROVING' ? 'text-emerald-500' : 'text-slate-500'}`}>
            {riskTrend.trend || "STABLE"}
          </div>
        </div>
        
        <div className="p-4 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
          <div className="text-xs uppercase text-slate-500 font-bold mb-1">Campaign</div>
          <div className="text-lg font-bold text-slate-500">
            {/* If campaign matched, it would be passed, for now rely on anomaly list or general state */}
            {anomalies.some(a => a.type === 'SHARED_INFRASTRUCTURE') ? 'EVOLVING' : 'NONE'}
          </div>
        </div>
      </div>
      
      {hasShift && (
        <div className="mt-4 p-4 rounded-xl border border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-400">
          <div className="font-bold flex items-center gap-2 mb-2">
            <span>⚠️</span> Behavioral Shift Detected
          </div>
          <ul className="list-disc pl-5 text-sm space-y-1">
            {anomalies.map((anom, i) => (
              <li key={i} className="break-words [overflow-wrap:anywhere]">{anom.explanation}</li>
            ))}
          </ul>
        </div>
      )}
      
      {historyConfidence.level === 'LOW' || historyConfidence.level === 'VERY_LOW' ? (
        <div className="mt-4 p-4 rounded-xl border border-slate-500/30 bg-slate-500/10 text-slate-700 dark:text-slate-300">
          <div className="font-bold flex items-center gap-2 mb-2">
            <span>ℹ️</span> Limited Historical Context
          </div>
          <p className="text-sm">
            Only {senderBaseline.messages_analyzed || 0} messages have been analyzed for this sender. Reputation confidence is low.
          </p>
        </div>
      ) : null}

      <div className="mt-6">
        <button 
          onClick={() => setExpanded(!expanded)}
          className="text-sm font-bold text-blue-600 hover:text-blue-800 dark:text-blue-400 flex items-center gap-1"
        >
          {expanded ? 'Hide Details ▲' : 'View Baseline Details ▼'}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] text-sm">
            <h4 className="font-bold mb-3 border-b border-[var(--tm-border)] pb-2 text-slate-700 dark:text-slate-300">Sender Baseline</h4>
            <div className="grid grid-cols-2 gap-2 text-slate-600 dark:text-slate-400">
              <span className="font-semibold">Messages Analyzed:</span>
              <span>{senderBaseline.messages_analyzed || 0}</span>
              
              <span className="font-semibold">First Seen:</span>
              <span>{senderBaseline.first_seen ? new Date(senderBaseline.first_seen).toLocaleDateString() : 'N/A'}</span>
              
              <span className="font-semibold">Last Seen:</span>
              <span>{senderBaseline.last_seen ? new Date(senderBaseline.last_seen).toLocaleDateString() : 'N/A'}</span>
              
              <span className="font-semibold">Normal Domains:</span>
              <span className="break-all">{senderBaseline.normal_domains?.join(', ') || 'N/A'}</span>
            </div>
          </div>
          
          <div className="p-4 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] text-sm">
            <h4 className="font-bold mb-3 border-b border-[var(--tm-border)] pb-2 text-slate-700 dark:text-slate-300">Risk Trend</h4>
            <div className="text-slate-600 dark:text-slate-400">
              <p>{riskTrend.explanation || 'No trend established.'}</p>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
