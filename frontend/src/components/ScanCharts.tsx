import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { ScanReport, Severity } from '../types'

const colors: Record<Severity, string> = {
  critical: '#ff647c',
  high: '#ff9368',
  medium: '#f8c76a',
  low: '#54c7bc',
  informational: '#8192a9',
}

const labels: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}

export function ScanCharts({ report }: { report: ScanReport }) {
  const severities = (Object.keys(labels) as Severity[]).map((key) => ({ name: labels[key], key, value: report.summary[key] }))
  const checks = report.headers.map((header) => ({ name: header.name.replace('X-', '').replace('Strict-Transport-Security', 'HSTS'), value: header.present ? 1 : 0 }))
  return <div className="charts-grid">
    <div className="chart-card">
      <div className="chart-heading"><span className="eyebrow">FINDING MIX</span><span className="chart-note">{report.findings.length} observations</span></div>
      <div className="chart-area"><ResponsiveContainer width="100%" height="100%"><PieChart>
        <Pie data={severities.filter((item) => item.value > 0)} dataKey="value" nameKey="name" innerRadius={58} outerRadius={86} paddingAngle={4} stroke="none">
          {severities.map((item) => <Cell key={item.key} fill={colors[item.key]} />)}
        </Pie>
        <Tooltip contentStyle={{ background: '#101d2c', border: '1px solid #274058', borderRadius: 10 }} itemStyle={{ color: '#e8f1f7' }} />
      </PieChart></ResponsiveContainer></div>
      <div className="legend-row">{severities.map((item) => <span key={item.key} className="legend-item"><i style={{ background: colors[item.key] }} />{item.name} <b>{item.value}</b></span>)}</div>
    </div>
    <div className="chart-card">
      <div className="chart-heading"><span className="eyebrow">CONTROL COVERAGE</span><span className="chart-note">observed response headers</span></div>
      <div className="chart-area"><ResponsiveContainer width="100%" height="100%"><BarChart data={checks} layout="vertical" margin={{ top: 4, right: 14, left: 4, bottom: 4 }}>
        <XAxis type="number" domain={[0, 1]} hide />
        <YAxis type="category" dataKey="name" width={92} tick={{ fill: '#8192a9', fontSize: 10 }} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: '#15263a' }} contentStyle={{ background: '#101d2c', border: '1px solid #274058', borderRadius: 10 }} formatter={(value: number) => [value ? 'Present' : 'Missing', 'Status']} />
        <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={12} fill="#1ed6c4" />
      </BarChart></ResponsiveContainer></div>
      <div className="chart-footnote"><span className="dot dot-teal" /> observed <span className="dot dot-muted" /> not visible in final response</div>
    </div>
  </div>
}
