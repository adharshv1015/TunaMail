import React from "react";

function AnalysisProgressScreen({
    progress = 0,
    step = "Preparing analysis",
    detail = "",
}) {
    const safeProgress = Math.max(
        0,
        Math.min(100, Number(progress) || 0)
    );

    const stages = [
        ["URLs", 32],
        ["Content", 58],
        ["AI", 74],
        ["Decision", 90],
    ];

    return (
        <div className="flex min-h-full w-full items-center justify-center p-6 md:p-8">
            <div className="w-full max-w-2xl">
                <div className="rounded-2xl border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-xl md:p-8">

                    {/* Header */}
                    <div className="mb-8 flex items-start justify-between gap-4">
                        <div>
                            <div className="mb-2 flex items-center gap-2">
                                <span className="relative flex h-3 w-3">
                                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[var(--tm-accent)] opacity-60" />
                                    <span className="relative inline-flex h-3 w-3 rounded-full bg-[var(--tm-accent)]" />
                                </span>

                                <span className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--tm-accent)]">
                                    Live Analysis
                                </span>
                            </div>

                            <h2 className="text-xl font-semibold text-[var(--tm-text)] md:text-2xl">
                                Analyzing Email
                            </h2>

                            <p className="mt-1 text-sm text-[var(--tm-text-secondary)]">
                                Security intelligence is being evaluated in real time.
                            </p>
                        </div>

                        {/* Percentage */}
                        <div className="shrink-0 text-right">
                            <div className="text-3xl font-bold tabular-nums text-[var(--tm-text)] md:text-4xl">
                                {safeProgress}%
                            </div>
                        </div>
                    </div>

                    {/* Progress bar */}
                    <div className="mb-6">
                        <div className="mb-2 flex items-center justify-between">
                            <span className="text-xs font-medium text-[var(--tm-text-secondary)]">
                                Analysis progress
                            </span>

                            <span className="text-xs tabular-nums text-[var(--tm-text-muted)]">
                                {safeProgress} / 100
                            </span>
                        </div>

                        <div className="h-3 overflow-hidden rounded-full bg-[var(--tm-surface-secondary)]">
                            <div
                                className="h-full rounded-full bg-[var(--tm-accent)] transition-all duration-500 ease-out"
                                style={{ width: `${safeProgress}%` }}
                            />
                        </div>
                    </div>

                    {/* Current step */}
                    <div className="rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-4 md:p-5">
                        <div className="flex items-start gap-3">

                            <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--tm-accent)]/10">
                                <span className="animate-pulse text-sm">
                                    ✦
                                </span>
                            </div>

                            <div className="min-w-0">
                                <p className="text-sm font-semibold text-[var(--tm-text)]">
                                    {step}
                                </p>

                                {detail && (
                                    <p className="mt-1 text-xs leading-5 text-[var(--tm-text-secondary)]">
                                        {detail}
                                    </p>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Pipeline stages */}
                    <div className="mt-6 grid grid-cols-2 gap-2 sm:grid-cols-4">
                        {stages.map(([label, threshold]) => {
                            const completed = safeProgress >= threshold;

                            return (
                                <div
                                    key={label}
                                    className={`rounded-lg border px-3 py-2 text-center transition-all ${completed
                                        ? "border-[var(--tm-accent)]/40 bg-[var(--tm-accent)]/5"
                                        : "border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]"
                                        }`}
                                >
                                    <div
                                        className={`text-[10px] font-semibold uppercase tracking-wider ${completed
                                            ? "text-[var(--tm-accent)]"
                                            : "text-[var(--tm-text-muted)]"
                                            }`}
                                    >
                                        {completed ? "✓" : "○"} {label}
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Footer */}
                    <p className="mt-6 text-center text-[11px] text-[var(--tm-text-muted)]">
                        Please keep this window open while the security analysis completes.
                    </p>
                </div>
            </div>
        </div>
    );
}

export default AnalysisProgressScreen;