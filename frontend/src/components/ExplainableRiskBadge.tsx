interface Attribution {
  signal: string
  points: number
  detail: string
}

interface ExplainableRiskBadgeProps {
  score: number
  level: string
  attributions?: Attribution[]
  primaryFinding?: string
}

export default function ExplainableRiskBadge({
  score,
  level,
  attributions = [],
  primaryFinding
}: ExplainableRiskBadgeProps) {
  const getLevelColor = (lvl: string) => {
    switch (lvl.toUpperCase()) {
      case 'CRITICAL':
        return '#ef4444'
      case 'HIGH':
        return '#f97316'
      case 'MEDIUM':
        return '#eab308'
      case 'LOW':
        return '#10b981'
      default:
        return '#3b82f6'
    }
  }

  const color = getLevelColor(level)

  return (
    <div className="explainable-risk-card card p-4 mb-4" style={{ borderLeft: `4px solid ${color}` }}>
      <div className="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
        <div>
          <h5 className="fw-bold mb-1 d-flex align-items-center gap-2">
            <span>Threat Risk Score:</span>
            <span className="font-monospace px-2 py-1 rounded" style={{ background: `${color}20`, color, fontSize: '1.2rem' }}>
              {score} / 100
            </span>
          </h5>
          <small className="text-muted">
            Explainable AI Signal Attribution Breakdown
          </small>
        </div>
        <div>
          <span className="badge px-3 py-2 uppercase fw-bold" style={{ background: `${color}20`, color, border: `1px solid ${color}40`, fontSize: '0.88rem' }}>
            <i className="fas fa-shield-cat me-1"></i> {level.toUpperCase()} THREAT
          </span>
        </div>
      </div>

      {primaryFinding && (
        <div className="p-3 mb-3 rounded" style={{ background: 'var(--bg-input)', border: '1px solid var(--border-color)', fontSize: '0.88rem' }}>
          <strong className="text-cyan me-2"><i className="fas fa-search-minus me-1"></i> Primary Forensic Finding:</strong>
          <span className="text-main">{primaryFinding}</span>
        </div>
      )}

      <div className="attributions-list mt-3">
        <h6 className="fw-semibold text-muted mb-2 font-monospace" style={{ fontSize: '0.78rem', letterSpacing: '0.05em' }}>
          SIGNAL POINT ATTRIBUTIONS:
        </h6>
        <div className="row g-2">
          {attributions.map((attr, i) => (
            <div key={i} className="col-md-6">
              <div className="p-2 rounded d-flex align-items-center justify-content-between" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-color)' }}>
                <div className="text-truncate me-2">
                  <div className="fw-semibold text-main" style={{ fontSize: '0.82rem' }}>{attr.signal}</div>
                  <small className="text-muted text-truncate d-block" style={{ fontSize: '0.72rem' }}>{attr.detail}</small>
                </div>
                <span className="badge bg-secondary font-monospace" style={{ fontSize: '0.78rem' }}>
                  +{attr.points} pts
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
