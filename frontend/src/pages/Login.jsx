import { useNavigate } from "react-router-dom";
import useNotification from "../hooks/useNotification";
import "./Login.css";

export default function Login() {
  const navigate = useNavigate();
  const notify = useNotification();

  const handleLogin = (e) => {
    e.preventDefault();
    try {
      // Simulate successful OAuth connection
      notify.success("✅ Gmail connected successfully");
      navigate("/dashboard");
    } catch (err) {
      notify.error("❌ Request failed");
    }
  };

  return (
    <div className="login-container">
      <div className="login-card glass">
        <div className="login-header">
          <h1>🐟 TunaMail</h1>
          <p>AI-Powered Threat Analysis</p>
        </div>
        
        <form onSubmit={handleLogin} className="login-form">
          <button type="submit" className="login-button">
            <span className="google-icon">G</span>
            Connect with Google
          </button>
        </form>
        
        <p className="login-footer">
          Secure OAuth2 connection. TunaMail only requests read access to analyze incoming threats.
        </p>
      </div>
      
      {/* Background decoration elements */}
      <div className="blob blob-1"></div>
      <div className="blob blob-2"></div>
    </div>
  );
}
