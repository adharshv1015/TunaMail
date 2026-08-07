import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function RiskChart({ safeCount, suspiciousCount, phishingCount }) {
  const data = [
    { name: 'Safe', count: safeCount, color: '#10b981' }, // Hardcoding colors fallback if css vars aren't parsed by recharts SVG
    { name: 'Suspicious', count: suspiciousCount, color: '#f59e0b' },
    { name: 'Phishing', count: phishingCount, color: '#ef4444' },
  ];

  return (
    <div className="glass" style={{ padding: '2rem', borderRadius: '12px', height: '300px', width: '100%' }}>
      <h2 style={{ marginBottom: '1.5rem', color: 'var(--text-main)', fontSize: '1.25rem' }}>Risk Distribution</h2>
      <ResponsiveContainer width="100%" height="80%">
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 30, left: 0, bottom: 0 }}>
          <XAxis type="number" hide />
          <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: 'var(--text-main)' }} width={80} />
          <Tooltip 
            cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }} 
            contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: 'white' }} 
            itemStyle={{ color: 'white' }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={32}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
