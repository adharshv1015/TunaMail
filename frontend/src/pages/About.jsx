import { useEffect, useState } from "react";
import axios from "axios";
import FeatureCard from "../components/FeatureCard";

export default function About() {
    const [versionData, setVersionData] = useState(null);

    useEffect(() => {
        axios.get("http://localhost:8000/system/version")
            .then(res => setVersionData(res.data))
            .catch(err => console.error("Failed to fetch version info", err));
    }, []);
    return (
        <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '2rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
                <h1 style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'var(--text-main)', margin: 0 }}>
                    About TunaMail
                </h1>

                {versionData && (
                    <div className="glass" style={{ padding: '1rem 1.5rem', borderRadius: '12px', fontSize: '0.9rem', color: 'var(--text-muted)', minWidth: '200px' }}>
                        <div style={{ fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '0.5rem', fontSize: '1.1rem' }}>
                            {versionData.name} v{versionData.version}
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                            <div><strong>Build:</strong> {versionData.build}</div>
                            <div><strong>Engine:</strong> {versionData.engine}</div>
                        </div>
                    </div>
                )}
            </div>
            <div className="glass" style={{ padding: '2rem', borderRadius: '12px' }}>
                <p style={{ color: 'var(--text-main)', lineHeight: '1.8', fontSize: '1.1rem' }}>
                    TunaMail is an AI-powered phishing detection platform
                    that analyzes emails using authentication validation,
                    URL inspection, behavioral analysis, content analysis,
                    attachment inspection and multiple trust signals.
                </p>
            </div>

            <div className="glass" style={{ padding: '2rem', borderRadius: '12px', marginTop: '2rem' }}>
                <h2 style={{ fontSize: '2rem', fontWeight: 'bold', marginBottom: '1rem', color: 'var(--text-main)' }}>
                    Mission
                </h2>
                <p style={{ color: 'var(--text-main)', lineHeight: '1.8', fontSize: '1.1rem' }}>
                    Protect every email user from phishing, BEC attacks, credential theft, and malicious attachments using explainable AI.
                </p>
            </div>

            <div style={{ marginTop: '3rem' }}>
                <h2 style={{ fontSize: '2rem', fontWeight: 'bold', marginBottom: '1.5rem', color: 'var(--text-main)' }}>
                    Features
                </h2>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem' }}>
                    <FeatureCard 
                        title="Authentication Analysis" 
                        icon="🔐" 
                        items={["SPF", "DKIM", "DMARC"]} 
                    />
                    <FeatureCard 
                        title="URL Intelligence" 
                        icon="🔗" 
                        items={["IP detection", "Shortener detection", "HTTPS inspection", "Domain reputation"]} 
                    />
                    <FeatureCard 
                        title="Content Analysis" 
                        icon="📝" 
                        items={["Urgency detection", "Credential harvesting", "Financial scam", "Threat language"]} 
                    />
                    <FeatureCard 
                        title="Trust Engine" 
                        icon="🤝" 
                        items={["Organization verification", "Sender alignment", "Trusted infrastructure"]} 
                    />
                    <FeatureCard 
                        title="Attachment Scanner" 
                        icon="📎" 
                        items={["File extension", "Macro detection", "Double extensions", "Future sandbox"]} 
                    />
                    <FeatureCard 
                        title="AI Decision Engine" 
                        icon="🧠" 
                        items={["Risk Score", "Confidence", "Evidence", "Explainability"]} 
                    />
                </div>
            </div>

            <div style={{ marginTop: '3rem', paddingBottom: '3rem' }}>
                <h2 style={{ fontSize: '2rem', fontWeight: 'bold', marginBottom: '1.5rem', color: 'var(--text-main)' }}>
                    Architecture
                </h2>
                <div className="glass" style={{ padding: '2rem', borderRadius: '12px', overflowX: 'auto', textAlign: 'center' }}>
                    <pre style={{ 
                        fontFamily: 'monospace', 
                        color: 'var(--accent-primary)', 
                        fontSize: '1.2rem', 
                        lineHeight: '2.5',
                        margin: 0
                    }}>
{`Inbox
  ↓
Parser
  ↓
Authentication
  ↓
URL Analyzer
  ↓
Content Analyzer
  ↓
Attachment Analyzer
  ↓
Trust Engine
  ↓
Decision Engine
  ↓
Risk Score
  ↓
Frontend Dashboard`}
                    </pre>
                </div>
            </div>

            <div style={{ marginTop: '3rem', paddingBottom: '3rem' }}>
                <h2 style={{ fontSize: '2rem', fontWeight: 'bold', marginBottom: '1.5rem', color: 'var(--text-main)' }}>
                    Technology Stack
                </h2>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem' }}>
                    <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px' }}>
                        <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '1rem', color: 'var(--text-main)', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>Frontend</h3>
                        <ul style={{ paddingLeft: '1.5rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.5rem', listStyleType: 'disc' }}>
                            <li>React</li>
                            <li>Vite</li>
                            <li>Vanilla CSS (Glassmorphism)</li>
                            <li>Axios</li>
                            <li>React Router</li>
                        </ul>
                    </div>
                    <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px' }}>
                        <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '1rem', color: 'var(--text-main)', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>Backend</h3>
                        <ul style={{ paddingLeft: '1.5rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.5rem', listStyleType: 'disc' }}>
                            <li>FastAPI</li>
                            <li>Python</li>
                            <li>Google Gmail API</li>
                            <li>OAuth2</li>
                        </ul>
                    </div>
                    <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px' }}>
                        <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '1rem', color: 'var(--text-main)', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>Detection Engine</h3>
                        <ul style={{ paddingLeft: '1.5rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.5rem', listStyleType: 'disc' }}>
                            <li>SPF / DKIM / DMARC</li>
                            <li>WHOIS (Version 1)</li>
                            <li>Trust Engine</li>
                            <li>Decision Engine</li>
                        </ul>
                    </div>
                </div>
            </div>

        </div>
    );
}
