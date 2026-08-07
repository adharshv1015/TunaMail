import { useState } from "react";

export default function FAQItem({ question, answer }) {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <div 
            className="glass" 
            style={{ 
                padding: '1.5rem', 
                borderRadius: '12px', 
                marginBottom: '1rem', 
                cursor: 'pointer',
                transition: 'all 0.2s ease-in-out'
            }}
            onClick={() => setIsOpen(!isOpen)}
        >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ margin: 0, fontSize: '1.15rem', color: 'var(--text-main)', fontWeight: 'bold' }}>{question}</h3>
                <span style={{ fontSize: '1.5rem', color: 'var(--text-muted)', fontWeight: 'bold' }}>{isOpen ? '−' : '+'}</span>
            </div>
            {isOpen && (
                <div style={{ marginTop: '1rem', color: 'var(--text-muted)', lineHeight: '1.6', fontSize: '1rem' }}>
                    {answer}
                </div>
            )}
        </div>
    );
}
