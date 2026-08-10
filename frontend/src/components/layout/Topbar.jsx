import React, { useState } from "react";

function Topbar({ isConnected = true, theme = "dark", toggleTheme, handleLogout }) {
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const handleConnect = () => {
    window.location.href = "http://127.0.0.1:8000/auth/login";
  };

  const onLogout = async () => {
    if (!handleLogout) return;
    setIsLoggingOut(true);
    await handleLogout();
    setIsLoggingOut(false);
  };

  return (
    <header className="h-[60px] md:h-[70px] shrink-0 border-b border-[var(--tm-border)] bg-[var(--tm-bg)] px-4 lg:px-6 flex items-center justify-between z-20 relative transition-colors duration-200">
      <div className="flex items-center gap-3">
        {/* Logo Icon */}
        <div className="flex h-9 w-9 md:h-10 md:w-10 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-indigo-700 shadow-lg shadow-indigo-500/20 text-white font-bold text-lg md:text-xl tracking-tight">
          T
        </div>

        {/* Brand Name */}
        <div className="flex flex-col">
          <span className="text-base md:text-lg font-bold text-[var(--tm-text)] leading-tight tracking-tight">
            TunaMail
          </span>
          <span className="text-[10px] md:text-xs font-medium text-[var(--tm-text-secondary)] leading-tight">
            Email Security Intelligence
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3 md:gap-4">
        {/* Connection Status */}
        {isConnected ? (
          <div className="hidden sm:flex items-center gap-2 rounded-full border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] px-3 py-1.5 shadow-sm transition-colors duration-200">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            <span className="text-xs font-medium text-[var(--tm-text-secondary)]">
              Gmail Connected
            </span>
          </div>
        ) : (
          <button
            onClick={handleConnect}
            className="flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1.5 shadow-sm hover:bg-red-500/20 transition-colors cursor-pointer"
          >
            <span className="relative flex h-2 w-2">
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
            </span>
            <span className="text-xs font-medium text-red-500 dark:text-red-400">
              Connect to Gmail
            </span>
          </button>
        )}

        <div className="h-6 w-px bg-[var(--tm-border)] mx-1"></div>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          aria-label="Toggle Light/Dark Mode"
          title="Toggle Theme"
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] text-[var(--tm-text-secondary)] hover:bg-[var(--tm-border)] hover:text-[var(--tm-text)] transition-colors cursor-pointer"
        >
          {theme === "dark" ? (
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-2.25l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0z" />
            </svg>
          ) : (
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />
            </svg>
          )}
        </button>

        {/* Logout Button */}
        {isConnected && (
          <button
            onClick={onLogout}
            disabled={isLoggingOut}
            aria-label="Logout"
            title="Logout"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] text-[var(--tm-text-secondary)] hover:bg-red-500/10 hover:text-red-500 hover:border-red-500/30 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoggingOut ? (
              <span className="block h-4 w-4 animate-spin rounded-full border-2 border-slate-400 border-t-transparent"></span>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" />
              </svg>
            )}
          </button>
        )}
      </div>
    </header>
  );
}

export default Topbar;
