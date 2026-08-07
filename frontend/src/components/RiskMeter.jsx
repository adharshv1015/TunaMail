import "./RiskMeter.css";

export default function RiskMeter({ score }) {
  const normalizedScore = Math.min(100, Math.max(0, score || 0));
  
  let colorVar = "--risk-safe";
  if (normalizedScore >= 20) colorVar = "--risk-low";
  if (normalizedScore >= 40) colorVar = "--risk-suspicious";
  if (normalizedScore >= 60) colorVar = "--risk-high";
  if (normalizedScore >= 80) colorVar = "--risk-phishing";

  return (
    <div className="risk-meter-container">
      <div className="risk-meter-header">
        <span>Risk Score</span>
        <span style={{ color: `var(${colorVar})`, fontWeight: 'bold' }}>
          {normalizedScore}/100
        </span>
      </div>
      <div className="risk-meter-bar">
        <div 
          className="risk-meter-fill" 
          style={{ 
            width: `${normalizedScore}%`,
            backgroundColor: `var(${colorVar})`
          }}
        ></div>
      </div>
    </div>
  );
}
