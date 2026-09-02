import React, { useState } from "react";
import SectionHeader from "../common/SectionHeader";
import EmptyState from "../common/EmptyState";
import UnlockDialog from "../common/UnlockDialog";

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
}

function AttachmentCard({ file, isEncrypted, onUnlockClick }) {
  const filename = file.filename || "Unknown file";
  const size = file.size ? formatBytes(file.size) : "Unknown size";
  const extension = filename.includes(".")
    ? filename.substring(filename.lastIndexOf(".")).toUpperCase()
    : "FILE";

  return (
    <div className="rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-5 min-w-0 flex flex-col justify-between">
      <div className="flex items-center gap-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--tm-accent)]/10 text-[var(--tm-accent)] text-xl border border-[var(--tm-accent)]/20">
          📄
        </div>
        <div className="min-w-0">
          <div className="break-words [overflow-wrap:anywhere] text-[13px] font-bold text-[var(--tm-text)]">{filename}</div>
          <div className="mt-0.5 text-[11px] font-semibold text-[var(--tm-text-secondary)]">{extension} • {size}</div>
        </div>
      </div>
      {isEncrypted && (
        <div className="mt-4 flex justify-end">
          <button
            onClick={() => onUnlockClick(file)}
            className="flex items-center gap-2 rounded-[8px] border border-blue-500/30 bg-blue-500/10 px-3 py-1.5 text-xs font-bold text-blue-600 hover:bg-blue-500/20"
          >
            🔒 Unlock PDF
          </button>
        </div>
      )}
    </div>
  );
}

function AttachmentAnalysis({ attachmentData, rawAttachments, messageId, onAnalysisUpdated }) {
  const [localData, setLocalData] = useState(attachmentData || {});
  const files = rawAttachments || [];

  const [unlockTarget, setUnlockTarget] = useState(null);
  const [unlockError, setUnlockError] = useState(null);

  const isFileEncrypted = (filename) => {
    if (!filename?.toLowerCase().endsWith(".pdf")) return false;
    const structured = localData.structured_evidence || [];
    return structured.some(
      (ev) => ev.type === "PDF_ENCRYPTED" && ev.explanation.includes(filename)
    );
  };

  const handleUnlock = async (password) => {
    setUnlockError(null);
    try {
      const response = await fetch(`http://localhost:8000/gmail/message/${messageId}/unlock-pdf`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          attachment_id: unlockTarget.attachmentId || unlockTarget.id || unlockTarget.attachment_id,
          password: password,
        }),
      });

      const result = await response.json();

      if (!response.ok) {
        setUnlockError(result.detail || "Failed to unlock PDF.");
        return;
      }

      if (result.status === "INVALID_PASSWORD") {
        setUnlockError("Invalid password provided.");
        return;
      }

      if (result.status === "ERROR") {
        setUnlockError(result.message || "An error occurred during analysis.");
        return;
      }

      const newEvidence = result.evidence || [];
      const newStructured = result.structured_evidence || [];
      const newDecision = result.new_decision;

      setLocalData((prev) => {
        // Filter out old PDF_ENCRYPTED for this file
        const filteredStructured = (prev.structured_evidence || []).filter(
          ev => !(ev.type === "PDF_ENCRYPTED" && ev.explanation.includes(unlockTarget.filename))
        );
        const filteredPlain = (prev.evidence || []).filter(
          ev => !(ev.includes("PDF is encrypted") && ev.includes(unlockTarget.filename))
        );

        return {
          ...prev,
          evidence: [...filteredPlain, ...newEvidence],
          structured_evidence: [...filteredStructured, ...newStructured]
        };
      });

      if (newDecision && onAnalysisUpdated) {
        onAnalysisUpdated(newDecision);
      }

      setUnlockTarget(null);
    } catch (err) {
      setUnlockError(err.message || "Network error.");
    }
  };

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm">
      <SectionHeader icon="📎" title="Attachment Analysis" subtitle={`${localData.attachment_count || 0} attachment(s) detected`} />

      {files.length === 0 ? (
        <EmptyState icon="✓" message="No attachments detected." />
      ) : (
        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
          {files.map((file, index) => (
            <AttachmentCard
              key={`${file.filename}-${index}`}
              file={file}
              isEncrypted={isFileEncrypted(file.filename)}
              onUnlockClick={setUnlockTarget}
            />
          ))}
        </div>
      )}

      {localData.evidence?.length > 0 ? (
        <div className="mt-5 rounded-[12px] border border-orange-500/30 bg-orange-500/10 p-5">
          <h3 className="text-[12px] font-bold uppercase tracking-wider text-orange-600 dark:text-orange-400">Attachment Evidence</h3>
          <div className="mt-3 space-y-2">
            {localData.evidence.map((item, index) => (
              <div key={index} className="flex gap-2 text-[13px] font-medium text-[var(--tm-text)]">
                <span className="shrink-0 text-orange-500">⚠️</span>
                <span className="break-words [overflow-wrap:anywhere]">{item}</span>
              </div>
            ))}
          </div>
        </div>
      ) : files.length > 0 ? (
        <div className="mt-5 rounded-[12px] border border-green-500/30 bg-green-500/10 p-5">
          <h3 className="text-[12px] font-bold uppercase tracking-wider text-green-600 dark:text-green-400">Analysis Result</h3>
          <div className="mt-3 flex gap-2 text-[13px] font-medium text-[var(--tm-text)]">
            <span className="shrink-0 text-green-500">✓</span>
            <span>Attachments were analyzed successfully. No suspicious file extensions, executable behaviors, or high-risk indicators were detected.</span>
          </div>
        </div>
      ) : null}

      <UnlockDialog
        isOpen={!!unlockTarget}
        onClose={() => { setUnlockTarget(null); setUnlockError(null); }}
        onUnlock={handleUnlock}
        filename={unlockTarget?.filename}
        error={unlockError}
      />
    </section>
  );
}

export default AttachmentAnalysis;
