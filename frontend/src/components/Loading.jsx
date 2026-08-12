export default function Loading() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
      <style>
        {`
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
          }
          .skeleton-pulse {
            animation: pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite;
            background-color: rgba(255, 255, 255, 0.1);
            border-radius: 6px;
          }
        `}
      </style>
      
      {[1, 2, 3].map((i) => (
        <div key={i} className="glass" style={{ padding: '1.5rem', borderRadius: '12px', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Header Row */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div className="skeleton-pulse" style={{ height: '24px', width: '60%' }}></div>
            <div className="skeleton-pulse" style={{ height: '28px', width: '90px', borderRadius: '16px' }}></div>
          </div>
          {/* Subheader */}
          <div className="skeleton-pulse" style={{ height: '16px', width: '30%' }}></div>
          {/* Body Lines */}
          <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div className="skeleton-pulse" style={{ height: '14px', width: '100%' }}></div>
            <div className="skeleton-pulse" style={{ height: '14px', width: '92%' }}></div>
            <div className="skeleton-pulse" style={{ height: '14px', width: '60%' }}></div>
          </div>
        </div>
      ))}
    </div>
  );
}
