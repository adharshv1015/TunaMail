import React from "react";

function SkeletonCard({ className }) {
  return (
    <div className={`rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 ${className}`}>
      <div className="flex animate-[pulse_0.8s_ease-in-out_infinite] space-x-4">
        <div className="h-10 w-10 rounded-full bg-slate-800"></div>
        <div className="flex-1 space-y-3 py-1">
          <div className="h-3 w-3/4 rounded bg-slate-800"></div>
          <div className="space-y-2">
            <div className="h-2 w-full rounded bg-slate-800/50"></div>
            <div className="h-2 w-5/6 rounded bg-slate-800/50"></div>
          </div>
        </div>
      </div>
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="min-h-full space-y-6 p-6 lg:p-8">
      {/* Header Skeleton */}
      <div className="flex items-center justify-between">
        <div className="space-y-3 w-1/2">
          <div className="h-6 w-3/4 animate-[pulse_0.8s_ease-in-out_infinite] rounded bg-slate-800"></div>
          <div className="h-4 w-1/2 animate-[pulse_0.8s_ease-in-out_infinite] rounded bg-slate-800/50"></div>
        </div>
        <div className="h-10 w-24 animate-[pulse_0.8s_ease-in-out_infinite] rounded-lg bg-slate-800"></div>
      </div>
      
      {/* Cards Grid Skeleton */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        <SkeletonCard className="col-span-1 lg:col-span-3" />
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>

      <SkeletonCard className="h-40" />
    </div>
  );
}

export default LoadingSkeleton;
