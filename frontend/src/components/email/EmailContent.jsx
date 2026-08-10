import React, { useState } from "react";
import SectionHeader from "../common/SectionHeader";

function EmailContent({ body, htmlBody }) {
  const [viewMode, setViewMode] = useState("raw"); // "raw" or "rendered"

  const hasHtml = !!htmlBody;
  
  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <SectionHeader icon="✉️" title="Email Content" subtitle="Message body and structure" />
        
        {hasHtml && (
          <div className="flex bg-[var(--tm-surface-secondary)] p-1 rounded-lg border border-[var(--tm-border)] shrink-0">
            <button
              onClick={() => setViewMode("raw")}
              className={`px-4 py-1.5 text-[12px] font-bold uppercase tracking-wider rounded-md transition-colors ${
                viewMode === "raw" 
                  ? "bg-[var(--tm-surface)] text-[var(--tm-text)] shadow-sm border border-[var(--tm-border)]" 
                  : "text-[var(--tm-text-secondary)] hover:text-[var(--tm-text)]"
              }`}
            >
              Plain Text
            </button>
            <button
              onClick={() => setViewMode("rendered")}
              className={`px-4 py-1.5 text-[12px] font-bold uppercase tracking-wider rounded-md transition-colors ${
                viewMode === "rendered" 
                  ? "bg-[var(--tm-surface)] text-[var(--tm-text)] shadow-sm border border-[var(--tm-border)]" 
                  : "text-[var(--tm-text-secondary)] hover:text-[var(--tm-text)]"
              }`}
            >
              Rendered HTML
            </button>
          </div>
        )}
      </div>
      
      <div className="mt-5 rounded-[12px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] max-h-[600px] overflow-hidden flex flex-col">
        {viewMode === "raw" || !hasHtml ? (
          <div className="p-5 overflow-y-auto custom-scrollbar h-full">
            <pre className="text-[13px] leading-relaxed text-[var(--tm-text-secondary)] font-mono whitespace-pre-wrap break-words">
              {body || "No text content available."}
            </pre>
          </div>
        ) : (
          <div className="p-0 h-[600px] w-full bg-white dark:bg-white rounded-[12px]">
            <iframe 
              srcDoc={htmlBody}
              title="Rendered Email Content"
              className="w-full h-full border-none rounded-[12px]"
              sandbox="allow-popups allow-popups-to-escape-sandbox allow-same-origin"
            />
          </div>
        )}
      </div>
    </section>
  );
}

export default EmailContent;
