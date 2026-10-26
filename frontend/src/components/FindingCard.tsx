import { ChevronDown, ChevronUp, CircleAlert, Info } from 'lucide-react'
import { useState } from 'react'
import type { Finding, Severity } from '../types'

const severityLabel: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity}`}>{severityLabel[severity]}</span>
}

export function FindingCard({ item }: { item: Finding }) {
  const [open, setOpen] = useState(false)
  return (
    <article className={`finding-card finding-${item.severity}`}>
      <div className="finding-accent" />
      <div className="finding-summary" onClick={() => setOpen((value) => !value)} role="button" tabIndex={0} onKeyDown={(event) => event.key === 'Enter' && setOpen((value) => !value)}>
        <div className="finding-icon">{item.severity === 'informational' ? <Info size={16} /> : <CircleAlert size={16} />}</div>
        <div className="finding-title-wrap">
          <div className="finding-meta"><SeverityBadge severity={item.severity} /><span>{item.category}</span></div>
          <h3>{item.title}</h3>
          <p>{item.description}</p>
        </div>
        <button className="icon-button" aria-label={open ? 'Collapse finding' : 'Expand finding'} onClick={(event) => { event.stopPropagation(); setOpen((value) => !value) }}>
          {open ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </button>
      </div>
      {open && <div className="finding-detail">
        <div className="detail-block"><span className="detail-label">Evidence</span><code>{item.evidence}</code></div>
        <div className="detail-grid">
          <div><span className="detail-label">Why it matters</span><p>{item.why_it_matters}</p></div>
          <div><span className="detail-label">Potential risk</span><p>{item.risk}</p></div>
        </div>
        <div className="recommendation"><span className="detail-label">Recommended fix</span><p>{item.recommendation}</p></div>
      </div>}
    </article>
  )
}
