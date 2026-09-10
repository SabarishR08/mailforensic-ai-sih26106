interface Hop {
  hop_number: number;
  from_host?: string;
  by_host?: string;
  ip?: string;
  geo?: {
    city?: string;
    country_code?: string;
    country?: string;
  };
  delay_seconds?: number;
  suspicious?: boolean;
  suspicious_reasons?: string[];
}

export default function RouteTimeline({ hops }: { hops: Hop[] }) {
  if (!hops || hops.length === 0) return null;

  return (
    <div className="route-timeline">
      {hops.map((hop) => (
        <div
          key={hop.hop_number}
          className={`hop-node ${hop.suspicious ? 'suspicious' : ''}`}
        >
          <div className="hop-header">
            <span className="hop-num">#Hop {hop.hop_number}</span>
            {hop.delay_seconds !== undefined && hop.delay_seconds > 0 && (
              <span className="badge bg-secondary text-light">
                <i className="fas fa-clock me-1"></i> +{hop.delay_seconds.toFixed(1)}s delay
              </span>
            )}
          </div>
          <div className="row g-2 align-items-center">
            <div className="col-md-5">
              <small className="text-muted d-block">From Host</small>
              <div className="fw-semibold text-truncate" title={hop.from_host || 'Unknown'}>
                {hop.from_host || 'Origin Server'}
              </div>
            </div>
            <div className="col-md-2 text-center text-muted">
              <i className="fas fa-arrow-right d-none d-md-inline"></i>
            </div>
            <div className="col-md-5">
              <small className="text-muted d-block">Receiving Host</small>
              <div className="fw-semibold text-truncate" title={hop.by_host || 'Unknown'}>
                {hop.by_host || 'Destination Mail Gateway'}
              </div>
            </div>
          </div>

          <div className="d-flex justify-content-between align-items-center mt-2 pt-2 border-top border-secondary border-opacity-25 flex-wrap gap-2">
            <div>
              <span className="badge bg-dark text-info border border-info border-opacity-25 me-2">
                <i className="fas fa-network-wired me-1"></i> {hop.ip || 'Local / Hidden IP'}
              </span>
              {hop.geo && (hop.geo.city || hop.geo.country) && (
                <span className="badge bg-dark text-light border border-secondary border-opacity-25">
                  <i className="fas fa-map-marker-alt text-danger me-1"></i>
                  {hop.geo.city ? `${hop.geo.city}, ` : ''}{hop.geo.country || hop.geo.country_code}
                </span>
              )}
            </div>

            {hop.suspicious ? (
              <div className="text-danger small fw-bold">
                <i className="fas fa-exclamation-triangle me-1"></i>
                {(hop.suspicious_reasons || ['Suspicious routing anomaly']).join(', ')}
              </div>
            ) : (
              <div className="text-success small">
                <i className="fas fa-check-circle me-1"></i> Verified Route Node
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
