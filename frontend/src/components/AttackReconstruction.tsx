interface AttackTree {
  attacker_origin?: {
    ip?: string
    country?: string
    org?: string
  }
  claimed_identity?: {
    brand?: string
    display_name?: string
    from_domain?: string
    is_impersonation?: boolean
  }
  auth_failures?: {
    spf?: string
    dkim?: string
    dmarc?: string
    mismatches_count?: number
  }
  payload?: {
    urls_count?: number
    sample_url?: string
    qr_detected?: boolean
  }
  target?: {
    recipient?: string
  }
}

interface AttackReconstructionProps {
  attackTree?: AttackTree
  evidenceId?: string
  subject?: string
}

export default function AttackReconstruction({ attackTree, evidenceId, subject }: AttackReconstructionProps) {
  const origin = attackTree?.attacker_origin
  const identity = attackTree?.claimed_identity
  const auth = attackTree?.auth_failures
  const payload = attackTree?.payload

  return (
    <div className="attack-reconstruction-card card p-4 mb-4" style={{ borderColor: 'var(--border-glow)' }}>
      <div className="d-flex align-items-center justify-content-between mb-4 flex-wrap gap-2">
        <div>
          <h5 className="fw-bold mb-1 text-danger d-flex align-items-center gap-2">
            <i className="fas fa-radiation text-danger fs-5"></i>
            🚨 ATTACK RECONSTRUCTION FLOW
          </h5>
          <small className="text-muted font-monospace">
            Evidence Case ID: <strong className="text-cyan">{evidenceId || 'CASE MF-2026-0042'}</strong> | Subject: "{subject || 'Suspicious Email'}"
          </small>
        </div>
        <span className="badge bg-danger-subtle text-danger border border-danger-subtle px-3 py-1 font-monospace">
          <i className="fas fa-microscope me-1"></i> RECONSTRUCTED ATTACK PATH
        </span>
      </div>

      {/* Visual Attack Flow Diagram */}
      <div className="attack-flow-container p-3 rounded bg-dark border border-secondary mb-4">
        <div className="row g-3 text-center align-items-center">
          {/* Node 1: Attacker Infrastructure */}
          <div className="col-md">
            <div className="p-3 rounded border border-danger bg-danger-subtle text-danger h-100">
              <i className="fas fa-user-ninja fs-3 mb-2 d-block"></i>
              <strong className="d-block text-uppercase small">1. Attacker Infrastructure</strong>
              <div className="font-monospace small mt-1">
                {origin?.ip || '185.220.101.5'} ({origin?.country || 'Russia'})
              </div>
              <small className="text-dim d-block mt-1" style={{ fontSize: '0.72rem' }}>
                {origin?.org || 'AS12345 Hosting'}
              </small>
            </div>
          </div>

          <div className="col-auto d-none d-md-block text-muted">
            <i className="fas fa-chevron-right fs-4 text-cyan"></i>
          </div>

          {/* Node 2: Spoofed Identity */}
          <div className="col-md">
            <div className="p-3 rounded border border-warning bg-warning-subtle text-warning h-100">
              <i className="fas fa-mask fs-3 mb-2 d-block"></i>
              <strong className="d-block text-uppercase small">2. Claimed Identity</strong>
              <div className="font-monospace small mt-1">
                {identity?.brand ? `Impersonating ${identity.brand}` : 'Spoofed Sender'}
              </div>
              <small className="text-muted d-block mt-1" style={{ fontSize: '0.72rem' }}>
                Domain: {identity?.from_domain || 'unauthorized-sender.com'}
              </small>
            </div>
          </div>

          <div className="col-auto d-none d-md-block text-muted">
            <i className="fas fa-chevron-right fs-4 text-cyan"></i>
          </div>

          {/* Node 3: Auth Bypasses / Failures */}
          <div className="col-md">
            <div className="p-3 rounded border border-secondary bg-dark text-main h-100">
              <i className="fas fa-shield-virus fs-3 mb-2 d-block text-warning"></i>
              <strong className="d-block text-uppercase small">3. Auth Checks</strong>
              <div className="d-flex justify-content-center gap-1 font-monospace small mt-1">
                <span className={`badge ${auth?.spf === 'PASS' ? 'bg-success' : 'bg-danger'}`}>SPF: {auth?.spf || 'FAIL'}</span>
                <span className={`badge ${auth?.dkim === 'PASS' ? 'bg-success' : 'bg-danger'}`}>DKIM: {auth?.dkim || 'FAIL'}</span>
                <span className={`badge ${auth?.dmarc === 'PASS' ? 'bg-success' : 'bg-danger'}`}>DMARC: {auth?.dmarc || 'FAIL'}</span>
              </div>
            </div>
          </div>

          <div className="col-auto d-none d-md-block text-muted">
            <i className="fas fa-chevron-right fs-4 text-cyan"></i>
          </div>

          {/* Node 4: Malicious Payload */}
          <div className="col-md">
            <div className="p-3 rounded border border-danger bg-danger-subtle text-danger h-100">
              <i className="fas fa-link fs-3 mb-2 d-block"></i>
              <strong className="d-block text-uppercase small">4. Malicious Payload</strong>
              <div className="font-monospace small mt-1 text-truncate" style={{ maxWidth: 140 }}>
                {payload?.sample_url || 'Credential Harvest Link'}
              </div>
              <small className="text-danger d-block mt-1" style={{ fontSize: '0.72rem' }}>
                {payload?.urls_count ? `${payload.urls_count} Links Extracted` : 'Suspicious URL Vector'}
              </small>
            </div>
          </div>

          <div className="col-auto d-none d-md-block text-muted">
            <i className="fas fa-chevron-right fs-4 text-cyan"></i>
          </div>

          {/* Node 5: Victim Target */}
          <div className="col-md">
            <div className="p-3 rounded border border-info bg-info-subtle text-info h-100">
              <i className="fas fa-bullseye fs-3 mb-2 d-block"></i>
              <strong className="d-block text-uppercase small">5. Target Victim</strong>
              <div className="font-monospace small mt-1">
                {attackTree?.target?.recipient || 'Corporate Inbox User'}
              </div>
              <small className="text-info d-block mt-1" style={{ fontSize: '0.72rem' }}>
                Targeted Attack Isolation
              </small>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
