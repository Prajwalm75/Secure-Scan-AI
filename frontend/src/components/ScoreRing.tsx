import type { CSSProperties } from 'react'

type Props = { score: number | null | undefined; label: string }

export function ScoreRing({ score, label }: Props) {
  const numeric = score ?? 0
  const tone = score === null || score === undefined ? 'neutral' : score >= 75 ? 'good' : score >= 50 ? 'watch' : 'risk'
  return (
    <div className={`score-ring score-ring-${tone}`} style={{ '--score': `${numeric * 3.6}deg` } as CSSProperties}>
      <div className="score-ring-core">
        <span className="score-number">{score ?? '—'}</span>
        <span className="score-label">{score === null || score === undefined ? 'No score' : 'out of 100'}</span>
      </div>
      <div className="score-ring-caption">{label}</div>
    </div>
  )
}
