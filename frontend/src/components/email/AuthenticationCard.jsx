import React from "react";
import SectionHeader from "../common/SectionHeader";

function AuthItem({ name, value }) {
  const passed = value === "pass";
  const unknown = !value || value === "unknown";

  const getStatusColor = () => {
    if (unknown) return "text-slate-500 bg-slate-500/10 border-slate-500/20";
    if (passed) return "text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
    return "text-red-600 dark:text-red-400 bg-red-500/10 border-red-500/20";
  };

  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-5 min-w-0">
      <span className="text-[12px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-widest">{name}</span>
      <div className={`flex items-center justify-center rounded-full border px-3 py-1 text-[11px] font-bold uppercase tracking-wider ${getStatusColor()}`}>
        {unknown ? "— UNKNOWN" : passed ? "✓ PASS" : "✕ FAIL"}
      </div>
    </div>
  );
}

function AuthenticationCard({ authentication }) {
  const auth = authentication || {};

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm">
      <SectionHeader icon="🛡️" title="Authentication" subtitle="Email sender authentication results" />
      <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-3">
        <AuthItem name="SPF" value={auth.spf} />
        <AuthItem name="DKIM" value={auth.dkim} />
        <AuthItem name="DMARC" value={auth.dmarc} />
      </div>
    </section>
  );
}

export default AuthenticationCard;
