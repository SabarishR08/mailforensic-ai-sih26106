interface HopData {
  hop_number: number
  ip?: string
  from_host?: string
  by_host?: string
  timestamp?: string
  delay_seconds?: number
  suspicious?: boolean
  suspicious_reasons?: string[]
  geo?: {
    city?: string
    country?: string
    country_code?: string
    org?: string
  }
}

interface InvestigationTimelineProps {
  hops: HopData[]
  originIp?: string
}

export default function InvestigationTimeline({ hops, originIp }: InvestigationTimelineProps) {
  if (!hops || hops.length === 0) {
    return (
      <div className="alert alert-secondary py-2 small">
        <i className="fas fa-info-circle me-2"></i>
        No Received routing headers found in email metadata.
      </div>
    )
  }

  return (
    <div className="investigation-timeline-wrapper">
      <div className="d-flex align-items-center justify-content-between mb-3">
        <h6 className="fw-bold mb-0 text-main">
          <i className="fas fa-clock text-cyan me-2"></i>
          Forensic Received Routing Timeline ({hops.length} Hops)
        </h6>
        {originIp && (
          <span className="badge bg-danger-subtle text-danger border border-danger-subtle px-2 py-1 font-monospace small">
            <i className="fas fa-crosshairs me-1"></i> Origin: {originIp}
          </span>
        )}
      </div>

      <div className="timeline-container ps-3 style-minimal" style={{ borderLeft: '2px solid var(--border-glow)' }}>
        {hops.map((hop, idx) => {
          const isOrigin = hop.ip === originIp || idx === hops.length - 1
          const isSuspicious = hop.suspicious

          return (
            <div
              key={idx}
              className={`timeline-item position-relative mb-4 ps-4 ${isSuspicious ? 'suspicious-hop' : ''}`}
            >
              {/* Timeline Dot Marker */}
              <div
                className={`position-absolute top-0 start-0 translate-middle-x rounded-circle d-flex align-items-center justify-content-center ${
                  isSuspicious
                    ? 'bg-danger text-white'
                    : isOrigin
                    ? 'bg-warning text-dark'
                    : 'bg-primary text-white'
                }`}
                style={{ width: 24, height: 24, fontSize: '0.7rem', left: -1, fontWeight: 700 }}
              >
                {hops.length - idx}
              </div>

              <div
                className="card p-3"
                style={{
                  background: isSuspicious ? 'rgba(239, 68, 68, 0.06)' : 'var(--bg-card)',
                  borderColor: isSuspicious ? 'rgba(239, 68, 68, 0.3)' : 'var(--border-color)',
                }}
              >
                <div className="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-2">
                  <div className="d-flex align-items-center gap-2">
                    <span className="fw-bold font-monospace text-main" style={{ fontSize: '0.9rem' }}>
                      {hop.from_host || 'Unknown Host'}
                    </span>
                    <i className="fas fa-arrow-right text-muted mx-1" style={{ fontSize: '0.75rem' }}></i>
                    <span className="text-muted font-monospace" style={{ fontSize: '0.85rem' }}>
                      {hop.by_host || 'Relay Server'}
                    </span>
                  </div>

                  <div className="d-flex align-items-center gap-2">
                    {hop.delay_seconds !== undefined && hop.delay_seconds > 0 && (
                      <span className="badge bg-secondary-subtle text-secondary border border-secondary px-2 py-1 font-monospace small">
                        <i className="fas fa-hourglass-half me-1 text-warning"></i> +{hop.delay_seconds}s delay
                      </span>
                    )}
                    <small className="text-muted font-monospace" style={{ fontSize: '0.75rem' }}>
                      {hop.timestamp || 'No timestamp'}
                    </small>
                  </div>
                </div>

                <div className="d-flex align-items-center justify-content-between flex-wrap gap-2 text-muted small">
                  <div>
                    <i className="fas fa-network-wired me-1 text-cyan"></i>
                    <span className="font-monospace fw-semibold text-main me-3">{hop.ip || 'N/A'}</span>
                    {hop.geo?.country && (
                      <span className="me-3">
                        <i className="fas fa-globe-americas me-1"></i>
                        {hop.geo.country} ({hop.geo.city || 'Unknown City'})
                      </span>
                    )}
                    {hop.geo?.org && <span className="text-dim"><i className="fas fa-building me-1"></i>{hop.geo.org}</span>}
                  </div>

                  {isOrigin && (
                    <span className="badge bg-danger text-white px-2 py-1">
                      <i className="fas fa-shield-virus me-1"></i> Attacker Origin Hop
                    </span>
                  )}
                </div>

                {hop.suspicious_reasons && hop.suspicious_reasons.length > 0 && (
                  <div className="mt-2 text-danger small">
                    <i className="fas fa-exclamation-triangle me-1"></i>
                    {hop.suspicious_reasons.join(', ')}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
