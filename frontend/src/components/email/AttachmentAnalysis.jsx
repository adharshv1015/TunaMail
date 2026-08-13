import React from "react";
import SectionHeader from "../common/SectionHeader";
import EmptyState from "../common/EmptyState";

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
}

function AttachmentCard({ file }) {
  const filename = file.filename || "Unknown file";
  const size = file.size ? formatBytes(file.size) : "Unknown size";
  const extension = filename.includes(".")
    ? filename.substring(filename.lastIndexOf(".")).toUpperCase()
    : "FILE";

  return (
    <div className="rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-5 min-w-0">
      <div className="flex items-center gap-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--tm-accent)]/10 text-[var(--tm-accent)] text-xl border border-[var(--tm-accent)]/20">
          📄
        </div>
        <div className="min-w-0">
          <div className="break-words [overflow-wrap:anywhere] text-[13px] font-bold text-[var(--tm-text)]">{filename}</div>
          <div className="mt-0.5 text-[11px] font-semibold text-[var(--tm-text-secondary)]">{extension} • {size}</div>
        </div>
      </div>
    </div>
  );
}

function AttachmentAnalysis({ attachmentData, rawAttachments }) {
  const data = attachmentData || {};
  const files = rawAttachments || [];

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm">
      <SectionHeader icon="📎" title="Attachment Analysis" subtitle={`${data.attachment_count || 0} attachment(s) detected`} />
      
      {files.length === 0 ? (
        <EmptyState icon="✓" message="No attachments detected." />
      ) : (
        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
          {files.map((file, index) => (
            <AttachmentCard key={`${file.filename}-${index}`} file={file} />
          ))}
        </div>
      )}

      {data.evidence?.length > 0 && (
        <div className="mt-5 rounded-[12px] border border-orange-500/30 bg-orange-500/10 p-5">
          <h3 className="text-[12px] font-bold uppercase tracking-wider text-orange-600 dark:text-orange-400">Attachment Evidence</h3>
          <div className="mt-3 space-y-2">
            {data.evidence.map((item, index) => (
              <div key={index} className="flex gap-2 text-[13px] font-medium text-[var(--tm-text)]">
                <span className="shrink-0 text-orange-500">⚠️</span>
                <span className="break-words [overflow-wrap:anywhere]">{item}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

export default AttachmentAnalysis;
