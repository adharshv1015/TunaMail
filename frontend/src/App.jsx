import { useState, useEffect } from "react";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { logout, checkSessionStatus } from "./api/api";
import Topbar from "./components/layout/Topbar";
import Inbox from "./components/Inbox";
import EmailDetail from "./components/EmailDetail";

function App() {
  const [selectedMessageId, setSelectedMessageId] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isInitializing, setIsInitializing] = useState(true);
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem("tunamail-theme");
    if (saved) return saved;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });

  useEffect(() => {
    const initAuth = async () => {
      try {
        const { authenticated } = await checkSessionStatus();
        setIsConnected(authenticated);
      } catch (err) {
        setIsConnected(false);
      } finally {
        setIsInitializing(false);
      }
    };
    initAuth();
  }, []);

  useEffect(() => {
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
    localStorage.setItem("tunamail-theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === "dark" ? "light" : "dark");
  };

  const handleSelectMessage = (messageId) => {
    setSelectedMessageId(messageId);
  };

  const handleAuthError = () => {
    if (isConnected) {
      toast.error("Gmail connection lost. Please reconnect.");
      setIsConnected(false);
      setSelectedMessageId(null);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      setIsConnected(false);
      setSelectedMessageId(null);
      toast.success("Logged out successfully");
    } catch (err) {
      console.error(err);
      toast.error("Unable to log out. Please try again.");
    }
  };

  if (isInitializing) {
    return (
      <div className="flex h-screen w-full flex-col bg-[var(--tm-bg)] text-[var(--tm-text)] items-center justify-center">
        <div className="text-xl font-medium animate-pulse">Initializing Security Session...</div>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-full flex-col bg-[var(--tm-bg)] text-[var(--tm-text)] overflow-hidden font-sans transition-colors duration-200">
      <Topbar
          isConnected={isConnected}
          theme={theme}
          toggleTheme={toggleTheme}
          handleLogout={handleLogout}
        />
        <ToastContainer theme={theme === "dark" ? "dark" : "light"} position="bottom-right" />

      <main className="flex flex-1 overflow-hidden relative">
        {/* LEFT SIDEBAR (Inbox) */}
        <div className={`w-full lg:w-[350px] xl:w-[390px] shrink-0 border-r border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] flex flex-col z-10 absolute lg:relative h-full transition-all duration-300 ${selectedMessageId ? "hidden lg:flex" : "flex"}`}>
          <Inbox
            selectedMessageId={selectedMessageId}
            onSelectMessage={handleSelectMessage}
            onAuthError={handleAuthError}
          />
        </div>

        {/* RIGHT ANALYSIS AREA (EmailDetail) */}
        <div className="flex-1 overflow-y-auto custom-scrollbar relative bg-[var(--tm-bg)] transition-colors duration-200">
          <EmailDetail messageId={selectedMessageId} />
        </div>
      </main>
    </div>
  );
}

export default App;
