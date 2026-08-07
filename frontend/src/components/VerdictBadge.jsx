import "./VerdictBadge.css";

export default function VerdictBadge({ verdict }) {
  const getVerdictClass = (v) => {
    switch(v?.toUpperCase()) {
      case "SAFE": return "badge-safe";
      case "LOW RISK": return "badge-low";
      case "SUSPICIOUS": return "badge-suspicious";
      case "HIGH RISK": return "badge-high";
      case "PHISHING": return "badge-phishing";
      default: return "badge-unknown";
    }
  };

  const getVerdictIcon = (v) => {
    switch(v?.toUpperCase()) {
      case "SAFE": return "🟢 ";
      case "LOW RISK": return "🟢 ";
      case "SUSPICIOUS": return "🟡 ";
      case "HIGH RISK": return "🔴 ";
      case "PHISHING": return "🔴 ";
      default: return "⚪ ";
    }
  };

  return (
    <span className={`verdict-badge ${getVerdictClass(verdict)}`}>
      {getVerdictIcon(verdict)}{verdict || "UNKNOWN"}
    </span>
  );
}
