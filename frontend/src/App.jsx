import { useState, useEffect, useCallback, useRef } from "react";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { logout, checkSessionStatus } from "./api/api";
import Topbar from "./components/layout/Topbar";
import Inbox from "./components/Inbox";
import EmailDetail from "./components/EmailDetail";

function App() {
  const [selectedMessageId, setSelectedMessageId] = useState(null);
  const [inboxResultSet, setInboxResultSet] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isInitializing, setIsInitializing] = useState(true);
  // Callback ref: Inbox registers its badge-update fn here so EmailDetail can call it
  const inboxAnalyzedRef = useRef(null);

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

  const handleSelectMessage = (messageId, resultSet = []) => {
    setSelectedMessageId(messageId);
    if (resultSet.length > 0) setInboxResultSet(resultSet);
  };

  // EmailDetail notifies App when analysis is done;
  // App forwards it to Inbox's badge-update function
  const handleMessageAnalyzed = useCallback((messageId, data) => {
    inboxAnalyzedRef.current?.(messageId, data);
  }, []);

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
      <div className="flex h-screen w-full flex-col bg-[var(--tm-bg)] bg-[image:var(--tm-bg-gradient)] text-[var(--tm-text)] items-center justify-center">
        <div className="text-xl font-medium animate-[pulse_0.8s_ease-in-out_infinite]">Initializing Security Session...</div>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-full flex-col bg-[var(--tm-bg)] bg-[image:var(--tm-bg-gradient)] text-[var(--tm-text)] overflow-hidden font-sans transition-colors duration-200">
      <Topbar
        isConnected={isConnected}
        theme={theme}
        toggleTheme={toggleTheme}
        handleLogout={handleLogout}
      />
      <ToastContainer theme={theme === "dark" ? "dark" : "light"} position="bottom-right" />

      <main className="flex flex-1 overflow-hidden relative">
        {/* LEFT SIDEBAR (Inbox) */}
        <div className={`w-full lg:w-[350px] xl:w-[390px] shrink-0 border-r border-[var(--tm-border)] bg-gradient-to-b from-[#f8fafc] to-[#e0e7ff] dark:bg-none dark:bg-[var(--tm-surface-secondary)] flex flex-col z-10 absolute lg:relative h-full transition-all duration-300 ${selectedMessageId ? "hidden lg:flex" : "flex"}`}>
          <Inbox
            selectedMessageId={selectedMessageId}
            onSelectMessage={handleSelectMessage}
            onAuthError={handleAuthError}
            isConnected={isConnected}
            // Inbox registers its own badge-update fn here
            onRegisterAnalyzedCallback={(fn) => { inboxAnalyzedRef.current = fn; }}
          />
        </div>

        {/* RIGHT ANALYSIS AREA (EmailDetail) */}
        <div className="flex-1 overflow-y-auto custom-scrollbar relative bg-transparent transition-colors duration-200">
          <EmailDetail
            messageId={selectedMessageId}
            messageMeta={inboxResultSet.find(m => m.id === selectedMessageId)}
            onBack={() => setSelectedMessageId(null)}
            resultSet={inboxResultSet}
            currentIndex={inboxResultSet.findIndex(m => m.id === selectedMessageId)}
            onNavigate={(idx) => {
              const msg = inboxResultSet[idx];
              if (msg) setSelectedMessageId(msg.id);
            }}
            onMessageAnalyzed={handleMessageAnalyzed}
          />
        </div>
      </main>
    </div>
  );
}

export default App;
