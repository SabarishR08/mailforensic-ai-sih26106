import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { escapeHtml, riskClass, riskColor, riskGradient } from '../lib/format'

type Phase = 'upload' | 'loading' | 'error' | 'results'

export default function ForensicEmlPage() {
  const [phase, setPhase] = useState<Phase>('upload')
  const [fileName, setFileName] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [report, setReport] = useState<any | null>(null)
  const [dragover, setDragover] = useState(false)
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const analyzeFile = (file: File) => {
    const name = file.name.toLowerCase()
    if (!name.endsWith('.eml') && !name.endsWith('.txt')) {
      alert('Please upload a .eml file')
      return
    }
    setFileName(file.name)
    setPhase('loading')
    api
      .analyzeEml(file)
      .then((data) => {
        if (data.error) {
          setErrorMsg(data.error)
          setPhase('error')
        } else {
          setReport(data)
          setPhase('results')
        }
      })
      .catch((e: any) => {
        setErrorMsg('Network error: ' + String(e.message || e))
        setPhase('error')
      })
  }

  const resetPage = () => {
    setPhase('upload')
    setReport(null)
    setErrorMsg('')
    setFileName('')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  return (
    <div className="container-fluid" style={{ maxWidth: 1200 }}>
      <h4 className="mb-4">
        <i className="fas fa-microscope"></i> Forensic Analysis — .eml Upload
      </h4>

      {phase === 'upload' && (
        <div
          className={'upload-zone' + (dragover ? ' dragover' : '')}
          onDragOver={(e) => {
            e.preventDefault()
            setDragover(true)
          }}
          onDragLeave={() => setDragover(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragover(false)
            if (e.dataTransfer.files.length > 0) analyzeFile(e.dataTransfer.files[0])
          }}
          onClick={() => fileInputRef.current?.click()}
        >
          <div className="icon">
            <i className="fas fa-file-import"></i>
          </div>
          <h5>Drop an .eml file here</h5>
          <p>or click to browse — no Gmail credentials needed</p>
          <p style={{ marginTop: 8, fontSize: '0.8rem', color: '#666' }}>
            Accepts raw .eml files exported from any email client
          </p>
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,.txt"
            style={{ display: 'none' }}
            onChange={(e) => {
              if (e.target.files?.[0]) analyzeFile(e.target.files[0])
            }}
          />
        </div>
      )}

      {phase === 'loading' && (
        <div className="text-center py-5">
          <i className="fas fa-spinner fa-spin" style={{ fontSize: '3rem', color: 'var(--glow)' }} />
          <div className="spinner-text">Analyzing {fileName}…</div>
        </div>
      )}

      {phase === 'error' && (
        <div className="error-state">
          <i className="fas fa-exclamation-triangle"></i>
          <h5>Analysis Failed</h5>
          <p style={{ color: '#ef5350' }}>{errorMsg}</p>
          <button className="btn-forensic mt-3" onClick={resetPage}>
            <i className="fas fa-redo"></i> Try Another File
          </button>
        </div>
      )}

      {phase === 'results' && report && <Results report={report} onReset={resetPage} />}
    </div>
  )
}

/* ------------------------------------------------------------------ */

function Results({ report, onReset }: { report: any; onReset: () => void }) {
  const risk = report.risk_assessment || {}
  const forensic = report.forensic || {}
  const auth = forensic.authentication || {}
  const routing = forensic.routing || {}
  const geo = report.geo || {}
  const ml = report.ml || {}
  const riskLevel = String(risk.risk_level || 'unknown').toLowerCase()
  const mlPred = ml.prediction || 'unknown'
  const mlConf = (ml.confidence || 0) * 100
  const urlResults = report.url_results || {}

  const mlClass =
    mlPred === 'phishing'
      ? 'ml-phishing'
      : mlPred === 'legitimate'
        ? 'ml-legitimate'
        : mlPred === 'suspicious'
          ? 'ml-suspicious'
          : 'ml-unknown'
  const mlIcon =
    mlPred === 'phishing'
      ? 'fa-skull-crossbones'
      : mlPred === 'legitimate'
        ? 'fa-check-circle'
        : mlPred === 'suspicious'
          ? 'fa-exclamation-circle'
          : 'fa-question-circle'

  const breakdown = risk.breakdown || {}
  const breakdownLabels: Record<string, string> = {
    ml_prediction: 'ML Prediction',
    threat_intel: 'Threat Intel',
    authentication: 'Authentication',
    geolocation: 'Geolocation',
    forensic: 'Forensic Trust',
    content: 'Content Analysis',
  }
  const BREAKDOWN_ORDER = [
    'ml_prediction',
    'threat_intel',
    'authentication',
    'geolocation',
    'forensic',
    'content',
  ]

  const authBadge = (label: string, value?: string) => {
    if (!value) return null
    const cls =
      value === 'PASS'
        ? 'auth-pass'
        : value === 'FAIL'
          ? 'auth-fail'
          : value === 'SOFTFAIL'
            ? 'auth-softfail'
            : 'auth-missing'
    const icon =
      value === 'PASS' ? 'check-circle' : value === 'FAIL' ? 'times-circle' : 'question-circle'
    return (
      <span key={label} className={'auth-badge-lg ' + cls}>
        <i className={'fas fa-' + icon}></i> {label}: {value}
      </span>
    )
  }

  return (
    <div className="results-view">
      <div className="card-grid">
        {/* Risk */}
        <div className="fcard" style={{ borderTop: '3px solid ' + riskColor(riskLevel) }}>
          <div className="fcard-header">
            <i className="fas fa-shield-halved"></i>
            <h6>Risk Assessment</h6>
          </div>
          <div className="text-center">
            <div className="risk-gauge" style={{ background: riskGradient(riskLevel) }}>
              {risk.risk_score ?? 0}
            </div>
            <div className="risk-verdict" style={{ color: riskColor(riskLevel) }}>
              {risk.risk_level || 'Unknown'}
            </div>
            <div style={{ color: '#8892a4', fontSize: '0.8rem', marginTop: 2 }}>out of 100</div>
          </div>
        </div>

        {/* ML */}
        <div
          className="fcard"
          style={{
            borderTop: '3px solid ' + (mlPred === 'phishing' ? '#ef5350' : mlPred === 'legitimate' ? '#66bb6a' : '#8892a4'),
          }}
        >
          <div className="fcard-header">
            <i className="fas fa-brain"></i>
            <h6>ML Classification</h6>
          </div>
          <div className="text-center" style={{ padding: '16px 0' }}>
            <span className={'ml-badge ' + mlClass}>
              <i className={'fas ' + mlIcon}></i> {String(mlPred).toUpperCase()}
            </span>
            <div style={{ marginTop: 12, color: '#8892a4', fontSize: '0.85rem' }}>
              Confidence:{' '}
              <span style={{ fontWeight: 700, color: '#e0e0e0' }}>{mlConf.toFixed(1)}%</span>
            </div>
            <div className="conf-bar" style={{ maxWidth: 250, margin: '10px auto 0' }}>
              <div
                className="conf-fill"
                style={{
                  width: mlConf + '%',
                  background: mlPred === 'phishing' ? '#ef5350' : mlPred === 'legitimate' ? '#66bb6a' : '#ffa726',
                }}
              />
            </div>
            <div style={{ marginTop: 12, color: '#8892a4', fontSize: '0.8rem' }}>
              Model: <span style={{ color: '#e0e0e0' }}>{ml.model_loaded ? 'Ensemble (XGB + LGB)' : 'Not loaded'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Auth + Metadata */}
      <div className="card-grid">
        <div className="fcard">
          <div className="fcard-header">
            <i className="fas fa-key"></i>
            <h6>Email Authentication</h6>
          </div>
          <div>
            {authBadge('SPF', auth.spf)}
            {authBadge('DKIM', auth.dkim)}
            {authBadge('DMARC', auth.dmarc)}
          </div>
          {auth.all_pass && (
            <div className="mt-2">
              <span className="auth-badge-lg auth-pass">
                <i className="fas fa-check-circle"></i> All checks passed
              </span>
            </div>
          )}
        </div>

        <div className="fcard">
          <div className="fcard-header">
            <i className="fas fa-envelope"></i>
            <h6>Email Metadata</h6>
          </div>
          <table className="meta-table">
            <tbody>
              <tr><td>Subject</td><td>{report.subject || '—'}</td></tr>
              <tr><td>From</td><td>{report.from || '—'}</td></tr>
              <tr><td>To</td><td>{report.to || '—'}</td></tr>
              <tr><td>Date</td><td>{report.date || '—'}</td></tr>
              <tr>
                <td>Message-ID</td>
                <td className="mono" style={{ fontSize: '0.78rem' }}>{report.email_id || '—'}</td>
              </tr>
              <tr><td>Body Size</td><td>{(report.body_length || 0).toLocaleString()} chars</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Geo + Routing */}
      <div className="card-grid">
        <div className="fcard">
          <div className="fcard-header">
            <i className="fas fa-globe"></i>
            <h6>Sender IP Geolocation</h6>
          </div>
          {geo.ip && geo.source !== 'unknown' ? (
            <div className="geo-grid">
              <div className="geo-item">
                <div className="geo-label">IP Address</div>
                <div className="geo-value mono">{geo.ip || '—'}</div>
              </div>
              <div className="geo-item">
                <div className="geo-label">Country</div>
                <div className="geo-value">
                  {(geo.country || '—') + (geo.country_code ? ` (${geo.country_code})` : '')}
                </div>
              </div>
              <div className="geo-item">
                <div className="geo-label">City</div>
                <div className="geo-value">{geo.city || '—'}</div>
              </div>
              <div className="geo-item">
                <div className="geo-label">ASN / Org</div>
                <div className="geo-value" style={{ fontSize: '0.8rem' }}>{geo.org || '—'}</div>
              </div>
              <div className="geo-item">
                <div className="geo-label">Hosting</div>
                <div className="geo-value">
                  {geo.is_hosting ? (
                    <span style={{ color: '#ffa726' }}>Yes (cloud/VPS)</span>
                  ) : (
                    <span style={{ color: '#66bb6a' }}>No</span>
                  )}
                </div>
              </div>
              <div className="geo-item">
                <div className="geo-label">Risk Score</div>
                <div className="geo-value">{(geo.risk_score || 0) + '/100 (tier ' + (geo.risk_tier || 0) + ')'}</div>
              </div>
            </div>
          ) : (
            <div className="text-muted" style={{ fontSize: '0.85rem' }}>
              No geolocation available for this email.
            </div>
          )}
        </div>

        <div className="fcard">
          <div className="fcard-header">
            <i className="fas fa-route"></i>
            <h6>Routing Chain</h6>
          </div>
          <div>
            {(routing.hops || []).map((hop: any) => {
              const geoStr = hop.geo
                ? ` — ${hop.geo.city || ''}, ${hop.geo.country || ''}`
                : ''
              return (
                <div key={hop.hop_number} className={'hop-item' + (hop.suspicious ? ' suspicious' : '')}>
                  <div className="hop-number">{hop.hop_number}</div>
                  <div className="hop-detail">
                    <div className="hop-host">
                      {hop.from_host || '?'} &rarr; {hop.by_host || '?'}
                    </div>
                    {hop.ip && <div className="hop-ip">{hop.ip}</div>}
                    {geoStr && (
                      <div className="hop-geo">
                        <i className="fas fa-map-pin"></i> {geoStr}
                      </div>
                    )}
                    {hop.suspicious_reasons?.length > 0 && (
                      <div style={{ color: '#ef5350', fontSize: '0.75rem', marginTop: 2 }}>
                        <i className="fas fa-exclamation-triangle"></i>{' '}
                        {hop.suspicious_reasons.join(', ')}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
            {(routing.hops || []).length === 0 && (
              <div style={{ color: '#8892a4', fontSize: '0.85rem' }}>
                No routing headers found
              </div>
            )}
          </div>
          {routing.origin_ip && (
            <div className="mt-2" style={{ fontSize: '0.8rem', color: '#8892a4' }}>
              Origin: {routing.origin_ip}
            </div>
          )}
        </div>
      </div>

      {/* Mismatches + Breakdown */}
      <div className="card-grid">
        <div className="fcard">
          <div className="fcard-header">
            <i className="fas fa-exclamation-triangle" style={{ color: '#ffa726' }}></i>
            <h6>Address Mismatches</h6>
          </div>
          {(forensic.mismatches || []).length === 0 ? (
            <div style={{ color: '#66bb6a', fontSize: '0.85rem' }}>
              <i className="fas fa-check-circle"></i> No mismatches detected
            </div>
          ) : (
            (forensic.mismatches || []).map((mm: any, i: number) => (
              <div key={i} className={'mismatch-item' + (mm.severity === 'HIGH' ? ' high' : '')}>
                <strong style={{ color: '#ffa726' }}>{String(mm.type).replace(/_/g, ' ')}</strong>{' '}
                <span style={{ color: '#8892a4', fontSize: '0.75rem' }}>({mm.severity})</span>
                <br />
                <span style={{ fontSize: '0.8rem', color: '#8892a4' }}>{mm.detail}</span>
              </div>
            ))
          )}
        </div>

        <div className="fcard">
          <div className="fcard-header">
            <i className="fas fa-chart-bar"></i>
            <h6>Risk Score Breakdown</h6>
          </div>
          {BREAKDOWN_ORDER.map((key) => {
            const val = breakdown[key] || 0
            const barColor = val > 70 ? '#ef5350' : val > 40 ? '#ffa726' : val > 20 ? '#ffeb3b' : '#66bb6a'
            return (
              <div className="risk-bar-row" key={key}>
                <div className="risk-bar-label">{breakdownLabels[key] || key}</div>
                <div className="risk-bar-track">
                  <div className="risk-bar-fill" style={{ width: val + '%', background: barColor }} />
                </div>
                <div className="risk-bar-value">{val}</div>
              </div>
            )
          })}
          {Object.keys(breakdown).length === 0 && (
            <div style={{ color: '#8892a4', fontSize: '0.85rem' }}>No breakdown available.</div>
          )}
        </div>
      </div>

      {/* URLs */}
      {(report.urls_found || []).length > 0 && (
        <div className="full-card">
          <div className="fcard-header">
            <i className="fas fa-link"></i>
            <h6>URL Threat Intelligence</h6>
          </div>
          {(report.urls_found || []).map((url: string) => {
            const r = urlResults[url] || {}
            const score = r.threat_score || 0
            const color = score > 50 ? '#ef5350' : score > 20 ? '#ffa726' : '#66bb6a'
            const level = r.threat_level
            return (
              <div className="url-item" key={url}>
                <span className="url-score" style={{ color }}>
                  Score: {score}
                </span>
                <div className="url-text">{escapeHtml(url)}</div>
                <div style={{ fontSize: '0.75rem', color: '#8892a4', marginTop: 4 }}>
                  {level && <span className={'badge-risk ' + riskClass(level)} style={{ marginRight: 6 }}>{level}</span>}
                  {r.sources?.virustotal?.status && <>VT: {r.sources.virustotal.status} · </>}
                  {r.sources?.safebrowsing?.status && <>SafeBrowsing: {r.sources.safebrowsing.status} · </>}
                  {r.sources?.phishtank?.status && <>PhishTank: {r.sources.phishtank.status}</>}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Body */}
      <div className="full-card">
        <div className="fcard-header">
          <i className="fas fa-file-alt"></i>
          <h6>Email Body Content</h6>
        </div>
        <div className="body-preview">{report.body_preview || '(empty)'}</div>
      </div>

      {/* Actions */}
      <div className="text-center mt-4 mb-5">
        <button className="btn-forensic" onClick={onReset}>
          <i className="fas fa-redo"></i> Analyze Another File
        </button>
        {report.scan_id && (
          <a
            href={api.forensicPdfUrl(report.scan_id)}
            target="_blank"
            rel="noreferrer"
            className="btn-forensic ms-2"
            style={{ textDecoration: 'none' }}
          >
            <i className="fas fa-file-pdf"></i> Download PDF Report
          </a>
        )}
      </div>
    </div>
  )
}
