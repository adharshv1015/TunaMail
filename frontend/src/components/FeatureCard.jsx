export default function FeatureCard({ title, icon, items }) {
  return (
    <div className="glass" style={{ padding: '1.5rem', borderRadius: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
        <span style={{ fontSize: '1.5rem' }}>{icon}</span>
        <h3 style={{ margin: 0, fontSize: '1.25rem', color: 'var(--text-main)' }}>{title}</h3>
      </div>
      <ul style={{ paddingLeft: '1.5rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {items.map((item, index) => (
          <li key={index} style={{ listStyleType: 'disc' }}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
