import React, { useState } from "react";

function UnlockDialog({ isOpen, onClose, onUnlock, filename, error }) {
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await onUnlock(password);
    setLoading(false);
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-sm rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-xl">
        <h3 className="text-lg font-bold text-[var(--tm-text)]">Unlock PDF</h3>
        <p className="mt-2 text-[13px] text-[var(--tm-text-secondary)]">
          Provide the password to temporarily unlock and scan <strong>{filename}</strong>.
        </p>

        {error && (
          <div className="mt-4 rounded-[8px] bg-red-500/10 p-3 text-sm text-red-500 border border-red-500/20">
            ⚠️ {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="mt-4">
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="PDF Password"
              className="w-full rounded-[8px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-2.5 pr-10 text-sm text-[var(--tm-text)] focus:border-blue-500 focus:outline-none"
              required
              autoFocus
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute inset-y-0 right-0 flex items-center pr-3 text-[var(--tm-text-secondary)] hover:text-[var(--tm-text)]"
              tabIndex="-1"
            >
              {showPassword ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path>
                  <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path>
                  <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path>
                  <line x1="2" y1="2" x2="22" y2="22"></line>
                </svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
              )}
            </button>
          </div>
          <div className="mt-6 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="rounded-[8px] px-4 py-2 text-sm font-medium text-[var(--tm-text-secondary)] hover:bg-[var(--tm-surface-secondary)]"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !password}
              className="rounded-[8px] bg-blue-600 px-4 py-2 text-sm font-bold text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? "Unlocking..." : "Unlock & Scan"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default UnlockDialog;
