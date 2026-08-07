import FAQItem from "../components/FAQItem";

export default function Documentation() {
    const sectionStyle = "glass";
    const sectionPadding = { padding: '2rem', borderRadius: '12px', marginBottom: '2rem' };
    const h2Style = { fontSize: '1.75rem', fontWeight: 'bold', marginBottom: '1rem', color: 'var(--text-main)', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' };
    const pStyle = { color: 'var(--text-main)', lineHeight: '1.8', fontSize: '1.05rem' };
    const codeStyle = { backgroundColor: 'rgba(0,0,0,0.3)', padding: '0.2rem 0.5rem', borderRadius: '4px', fontFamily: 'monospace', color: 'var(--accent-primary)' };

    return (
        <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '2rem' }}>
            <h1 style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '2rem', color: 'var(--text-main)' }}>
                Documentation
            </h1>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>Getting Started</h2>
                <p style={pStyle}>
                    Welcome to TunaMail! To begin, connect your Gmail account securely using OAuth2. 
                    Once connected, the system automatically begins ingesting and analyzing your most recent emails.
                </p>
            </div>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>How Email Analysis Works</h2>
                <p style={pStyle}>
                    TunaMail processes every email through a multi-stage pipeline: starting with header authentication (SPF/DKIM/DMARC), 
                    moving through URL reputation checks, attachment macros, and finally behavioral heuristics via our AI Decision Engine.
                </p>
            </div>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>Understanding Risk Scores</h2>
                <p style={pStyle}>
                    Risk scores range from <span style={codeStyle}>0</span> to <span style={codeStyle}>100</span>.
                    A score below 30 is generally safe, 30-60 is suspicious, and anything above 60 is flagged as highly dangerous.
                </p>
            </div>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>Understanding Confidence</h2>
                <p style={pStyle}>
                    The Confidence metric indicates how certain the AI engine is of its verdict. A 99% confidence score on a PHISHING 
                    verdict means the model found undeniable cryptographic or structural proof of malicious intent.
                </p>
            </div>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>Reading Technical Evidence</h2>
                <p style={pStyle}>
                    Technical evidence breaks down exactly which security checks passed or failed. Look for green checkmarks for 
                    verified domains and red warnings for anomalies like spoofed sender headers or failing DMARC policies.
                </p>
            </div>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>Exporting Reports</h2>
                <p style={pStyle}>
                    Click the <b>Export PDF</b> or <b>Export JSON</b> buttons on any Email Details page to download a full forensic 
                    report of the threat, perfectly formatted for your security operations center (SOC) or IT team.
                </p>
            </div>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>API Endpoints</h2>
                <p style={pStyle} style={{ marginBottom: '1rem' }}>
                    TunaMail is built on a headless architecture. You can interact with the backend directly using these endpoints:
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <div style={{ backgroundColor: 'rgba(0,0,0,0.1)', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #3b82f6' }}>
                        <div style={{ fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '0.25rem' }}>GET /gmail/messages</div>
                        <div style={{ color: 'var(--text-muted)' }}>Returns analyzed inbox.</div>
                    </div>
                    <div style={{ backgroundColor: 'rgba(0,0,0,0.1)', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #3b82f6' }}>
                        <div style={{ fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '0.25rem' }}>GET /gmail/message/{'{id}'}</div>
                        <div style={{ color: 'var(--text-muted)' }}>Returns a single email.</div>
                    </div>
                    <div style={{ backgroundColor: 'rgba(0,0,0,0.1)', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #10b981' }}>
                        <div style={{ fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '0.25rem' }}>GET /system/health</div>
                        <div style={{ color: 'var(--text-muted)' }}>Backend health status.</div>
                    </div>
                    <div style={{ backgroundColor: 'rgba(0,0,0,0.1)', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #8b5cf6' }}>
                        <div style={{ fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '0.25rem' }}>GET /system/version</div>
                        <div style={{ color: 'var(--text-muted)' }}>Application version.</div>
                    </div>
                </div>
            </div>

            <div className={sectionStyle} style={sectionPadding}>
                <h2 style={h2Style}>Frequently Asked Questions</h2>
                
                <FAQItem 
                    question="Why is a legitimate email marked suspicious?" 
                    answer="TunaMail uses strict security policies. If an email fails DMARC authentication, uses tracking pixels, or includes urgency-inducing language, it may be flagged out of an abundance of caution." 
                />
                <FAQItem 
                    question="Does TunaMail delete emails?" 
                    answer="No. TunaMail operates in a strict read-only mode. It only analyzes metadata and content to provide a risk assessment; it never deletes, moves, or alters your inbox." 
                />
                <FAQItem 
                    question="Does TunaMail store Gmail passwords?" 
                    answer="No. We use secure OAuth2 tokens provided directly by Google. Your password is never seen, transmitted, or stored by TunaMail." 
                />
                <FAQItem 
                    question="How accurate is TunaMail?" 
                    answer="Our engine achieves over 99% accuracy by combining deterministic cryptographic checks (like DKIM) with probabilistic AI behavioral analysis to eliminate false positives." 
                />
                <FAQItem 
                    question="Can it detect Business Email Compromise?" 
                    answer="Yes. The Trust Engine specifically looks for sender alignment, organizational verification, and reply-to mismatches to detect sophisticated BEC and spoofing attacks." 
                />
                <FAQItem 
                    question="Can I analyze attachments?" 
                    answer="TunaMail currently inspects attachment metadata (like file extensions, double extensions, and macro indicators). Full sandbox detonation is coming in a future update." 
                />
            </div>

        </div>
    );
}
