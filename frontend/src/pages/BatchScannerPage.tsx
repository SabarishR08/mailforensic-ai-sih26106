import { useState } from 'react'

interface BatchItemResult {
  email_id: string
  subject?: string
  from?: string
  ml?: {
    prediction: string
    confidence: number
  }
  risk_assessment?: {
    risk_level: string
    risk_score: number
  }
  geo?: {
    country?: string
    city?: string
    ip?: string
  }
  forensic?: {
    routing?: {
      origin_ip?: string
    }
  }
  urls_found?: string[]
}

interface BatchScanResponse {
  total: number
  phishing_count: number
  legitimate_count: number
  avg_risk_score: number
  results: BatchItemResult[]
}

const SAMPLE_BATCH = [
  {
    id: 'sample-1',
    subject: 'URGENT: Password Reset Required for Corporate Account',
    body: 'Dear Employee, Your account access will expire in 2 hours. Please reset your password immediately at http://secure-corporate-verify-auth.com/login to maintain access. Received: from 185.220.101.5 by mail.company.com'
  },
  {
    id: 'sample-2',
    subject: 'Weekly Security Update & Patch Release',
    body: 'Team, Here is the weekly summary of security patches applied to internal servers. No action is required. Regards, IT Operations.'
  },
  {
    id: 'sample-3',
    subject: 'Action Required: Verify Wire Transfer Invoice #8849',
    body: 'Please review the attached invoice #8849 for wire transfer processing. Update banking details to beneficiary account in Overseas Bank: http://194.26.29.11/payment.pdf'
  }
]

export default function BatchScannerPage() {
  const [inputText, setInputText] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)
  const [data, setData] = useState<BatchScanResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectedPlaybook, setSelectedPlaybook] = useState<any | null>(null)

  const handleLoadSamples = () => {
    const formatted = SAMPLE_BATCH.map(
      (s) => `Subject: ${s.subject}\n\n${s.body}`
    ).join('\n\n---EMAIL_SEPARATOR---\n\n')
    setInputText(formatted)
  }

  const handleScanBatch = async () => {
    if (!inputText.trim()) {
      setError('Please paste email text or click "Load Sample Emails".')
      return
    }

    setError(null)
    setLoading(true)

    try {
      const rawBlocks = inputText
        .split(/---EMAIL_SEPARATOR---|===EMAIL===/gi)
        .map((b) => b.trim())
        .filter(Boolean)

      const emailsPayload = rawBlocks.map((block, idx) => {
        let subject = `Batch Email #${idx + 1}`
        const subjMatch = block.match(/^Subject:\s*(.+)$/im)
        if (subjMatch) {
          subject = subjMatch[1].trim()
        }
        return {
          id: `batch-item-${idx + 1}`,
          subject,
          body: block,
          headers: block.includes('Received:') ? block : ''
        }
      })

      const res = await fetch('/api/batch-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emails: emailsPayload })
      })

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`)
      }

      const json: BatchScanResponse = await res.json()
      setData(json)
    } catch (err: any) {
      setError(err.message || 'Failed to execute batch email scan.')
    } finally {
      setLoading(false)
    }
  }

  const fetchPlaybook = async (item: BatchItemResult) => {
    try {
      const res = await fetch('/api/remediation-playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: item.from || 'unknown@domain.com',
          subject: item.subject || 'Threat Email',
          origin_ip: item.geo?.ip || item.forensic?.routing?.origin_ip || '',
          risk_level: item.risk_assessment?.risk_level || 'HIGH',
          urls: item.urls_found || []
        })
      })
      const pb = await res.json()
      setSelectedPlaybook(pb)
    } catch (e) {
      alert('Failed to generate remediation playbook')
    }
  }

  const downloadCSV = () => {
    if (!data || !data.results.length) return
    const headers = ['Email ID', 'Subject', 'ML Prediction', 'Risk Level', 'Risk Score', 'Origin Country']
    const rows = data.results.map((r) => [
      `"${r.email_id || ''}"`,
      `"${(r.subject || '').replace(/"/g, '""')}"`,
      `"${r.ml?.prediction || 'unknown'}"`,
      `"${r.risk_assessment?.risk_level || 'UNKNOWN'}"`,
      r.risk_assessment?.risk_score || 0,
      `"${r.geo?.country || 'Unknown'}"`
    ])

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n')
    const encodedUri = encodeURI(csvContent)
    const link = document.createElement('a')
    link.setAttribute('href', encodedUri)
    link.setAttribute('download', `batch_threat_report_${Date.now()}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  return (
    <div className="container-fluid px-0">
      <div className="d-flex align-items-center justify-content-between mb-4">
        <div>
          <h2 className="fw-bold mb-1" style={{ letterSpacing: '-0.02em' }}>
            <i className="fas fa-layer-group text-primary me-2"></i>
            Batch Threat Scanner
          </h2>
          <p className="text-muted small mb-0">
            Analyze multiple raw email headers or bodies simultaneously with AI threat scoring and bulk playbook generation.
          </p>
        </div>
        <div className="d-flex gap-2">
          <button className="btn btn-outline-secondary btn-sm" onClick={handleLoadSamples}>
            <i className="fas fa-magic me-1"></i> Load Sample Emails
          </button>
        </div>
      </div>

      <div className="card p-4 mb-4">
        <label className="form-label fw-semibold text-main mb-2">
          Paste Raw Emails (Separate multiple emails with <code className="text-info">---EMAIL_SEPARATOR---</code>):
        </label>
        <textarea
          className="form-control font-monospace mb-3"
          rows={7}
          placeholder="Subject: Urgent Notice&#10;&#10;Please reset your password...&#10;&#10;---EMAIL_SEPARATOR---&#10;&#10;Subject: Invoice #991&#10;&#10;Attached payment link..."
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          style={{ fontSize: '0.88rem' }}
        />

        {error && (
          <div className="alert alert-danger py-2 small mb-3">
            <i className="fas fa-exclamation-triangle me-2"></i> {error}
          </div>
        )}

        <div className="d-flex justify-content-end gap-2">
          <button
            className="btn btn-primary px-4"
            onClick={handleScanBatch}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                Scanning Batch...
              </>
            ) : (
              <>
                <i className="fas fa-search me-2"></i>
                Scan Batch Now
              </>
            )}
          </button>
        </div>
      </div>

      {data && (
        <>
          {/* Stat Summary Cards */}
          <div className="row g-3 mb-4">
            <div className="col-md-3">
              <div className="stat-card">
                <div className="number">{data.total}</div>
                <div className="label">Total Emails Processed</div>
              </div>
            </div>
            <div className="col-md-3">
              <div className="stat-card" style={{ borderColor: 'rgba(239, 68, 68, 0.4)' }}>
                <div className="number text-danger">{data.phishing_count}</div>
                <div className="label">Phishing Threats</div>
              </div>
            </div>
            <div className="col-md-3">
              <div className="stat-card" style={{ borderColor: 'rgba(16, 185, 129, 0.4)' }}>
                <div className="number text-success">{data.legitimate_count}</div>
                <div className="label">Legitimate Mail</div>
              </div>
            </div>
            <div className="col-md-3">
              <div className="stat-card">
                <div className="number text-warning">{data.avg_risk_score}</div>
                <div className="label">Avg Risk Score</div>
              </div>
            </div>
          </div>

          {/* Results Table */}
          <div className="card p-4">
            <div className="d-flex align-items-center justify-content-between mb-3">
              <h5 className="fw-bold mb-0">
                <i className="fas fa-list-check me-2 text-cyan"></i>
                Batch Threat Analysis Results
              </h5>
              <div className="d-flex gap-2">
                <button className="btn btn-outline-primary btn-sm" onClick={downloadCSV}>
                  <i className="fas fa-file-csv me-1"></i> Export CSV
                </button>
              </div>
            </div>

            <div className="table-responsive">
              <table className="table table-hover align-middle mb-0">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Subject / Identifier</th>
                    <th>ML Prediction</th>
                    <th>Risk Level</th>
                    <th>Risk Score</th>
                    <th>Origin Country</th>
                    <th className="text-end">Remediation</th>
                  </tr>
                </thead>
                <tbody>
                  {data.results.map((item, idx) => {
                    const isPhish = item.ml?.prediction === 'phishing'
                    const riskLvl = item.risk_assessment?.risk_level || 'UNKNOWN'
                    const score = item.risk_assessment?.risk_score || 0

                    return (
                      <tr key={idx}>
                        <td className="font-monospace text-muted small">{idx + 1}</td>
                        <td>
                          <div className="fw-semibold text-main">{item.subject || item.email_id}</div>
                          <small className="text-muted font-monospace" style={{ fontSize: '0.75rem' }}>
                            {item.email_id}
                          </small>
                        </td>
                        <td>
                          <span className={`badge ${isPhish ? 'bg-danger-subtle text-danger border border-danger-subtle' : 'bg-success-subtle text-success border border-success-subtle'}`}>
                            <i className={`fas ${isPhish ? 'fa-skull me-1' : 'fa-check-circle me-1'}`}></i>
                            {item.ml?.prediction?.toUpperCase() || 'UNKNOWN'}
                          </span>
                        </td>
                        <td>
                          <span className={`badge-risk risk-${riskLvl.toLowerCase()}`}>
                            {riskLvl}
                          </span>
                        </td>
                        <td>
                          <span className="fw-bold font-monospace">{score}/100</span>
                        </td>
                        <td>
                          <i className="fas fa-globe-americas me-1 text-muted"></i>
                          {item.geo?.country || 'Unknown'}
                        </td>
                        <td className="text-end">
                          <button
                            className="btn btn-outline-secondary btn-sm"
                            onClick={() => fetchPlaybook(item)}
                          >
                            <i className="fas fa-shield-alt me-1 text-primary"></i> SOC Playbook
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* SOC Remediation Playbook Modal */}
      {selectedPlaybook && (
        <div className="modal show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1050 }}>
          <div className="modal-dialog modal-lg modal-dialog-centered">
            <div className="modal-content card border-glow" style={{ background: 'var(--bg-dark)' }}>
              <div className="modal-header border-bottom border-secondary">
                <h5 className="modal-title fw-bold text-main">
                  <i className="fas fa-shield-cat text-primary me-2"></i>
                  SOC Remediation Playbook
                </h5>
                <button
                  type="button"
                  className="btn-close btn-close-white"
                  onClick={() => setSelectedPlaybook(null)}
                ></button>
              </div>
              <div className="modal-body">
                <div className="alert alert-danger d-flex align-items-center mb-3">
                  <i className="fas fa-shield-virus fs-3 me-3"></i>
                  <div>
                    <strong className="d-block">{selectedPlaybook.summary}</strong>
                    <small>Level: {selectedPlaybook.threat_level} | Domain: {selectedPlaybook.sender_domain}</small>
                  </div>
                </div>

                <h6 className="fw-bold text-cyan mt-3"><i className="fas fa-fire-flame-curved me-2"></i>Automated Firewall Block Rules:</h6>
                <div className="bg-dark p-3 rounded border border-secondary font-monospace small mb-3">
                  <div><strong>iptables:</strong> {selectedPlaybook.firewall_rules?.iptables}</div>
                  <div><strong>ufw:</strong> {selectedPlaybook.firewall_rules?.ufw}</div>
                  <div><strong>DNS static block:</strong> {selectedPlaybook.firewall_rules?.unbound_dns}</div>
                </div>

                <h6 className="fw-bold text-cyan mt-3"><i className="fas fa-tasks me-2"></i>Incident Gateway Action Items:</h6>
                <ul className="small text-muted mb-3">
                  {selectedPlaybook.email_gateway_actions?.map((act: string, i: number) => (
                    <li key={i}>{act}</li>
                  ))}
                </ul>

                <h6 className="fw-bold text-cyan mt-3"><i className="fas fa-code me-2"></i>Generated YARA Rule:</h6>
                <pre className="bg-dark p-3 rounded border border-secondary text-success small">
                  {selectedPlaybook.yara_rule}
                </pre>
              </div>
              <div className="modal-footer border-top border-secondary">
                <button className="btn btn-secondary btn-sm" onClick={() => setSelectedPlaybook(null)}>
                  Close Playbook
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
