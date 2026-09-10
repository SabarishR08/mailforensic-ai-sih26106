import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import L from 'leaflet'
import { api } from '../lib/api'
import { fmtTime, riskClass, escapeHtml } from '../lib/format'

export default function ForensicReportPage() {
  const { scanId } = useParams()
  const [data, setData] = useState<any | null>(null)
  const [error, setError] = useState('')
  const mapRef = useRef<L.Map | null>(null)

  useEffect(() => {
    setData(null)
    setError('')
    api
      .forensicReport(scanId || '')
      .then((d) => setData(d))
      .catch((e) => setError(String(e.message || e)))
  }, [scanId])

  // Sender geo map
  useEffect(() => {
    const result = data?.result || {}
    const geo = result.geo || {}
    if (!data || !geo.latitude) return
    if (mapRef.current) return
    const el = document.getElementById('forensic-map')
    if (!el) return
    const map = L.map(el, { zoomControl: false, attributionControl: false }).setView([geo.latitude, geo.longitude], 8)
    L.tileLayer('https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; CartoDB',
    }).addTo(map)
    L.marker([geo.latitude, geo.longitude])
      .addTo(map)
      .bindPopup(`<b>${geo.city || 'Unknown'}, ${geo.country || ''}</b><br><span style="color:#94a3b8">Risk: ${geo.risk_score}/100</span>`)
      .openPopup()
    mapRef.current = map
    return () => {
      map.remove()
      mapRef.current = null
    }
  }, [data])

  if (error) {
    return (
      <div className="container-fluid p-0">
        <h4 className="mb-4 fw-bold">
          <i className="fas fa-microscope text-info me-2"></i> Forensic Inspection Report
        </h4>
        <div className="alert alert-danger" style={{ background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.3)', color: '#F87171' }}>
          <i className="fas fa-exclamation-triangle me-2"></i> {error}
        </div>
        <Link to="/forensic/scan" className="btn btn-outline-secondary">
          <i className="fas fa-arrow-left me-1"></i> Return to Scanner
        </Link>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="text-center py-5">
        <div className="spinner-border text-info mb-3" style={{ width: '2.5rem', height: '2.5rem' }} role="status"></div>
        <p className="text-muted">Extracting header telemetry and reconstructing routing chain...</p>
      </div>
    )
  }

  const { scan, result } = data
  const risk = result.risk_assessment || {}
  const breakdown = risk.breakdown || {}
  const ml = result.ml || {}
  const auth = (result.forensic || {}).authentication || {}
  const mismatches = (result.forensic || {}).mismatches || []
  const routing = (result.forensic || {}).routing || {}
  const hops = routing.hops || []
  const geo = result.geo || {}
  const urlResults = result.url_results || {}

  return (
    <div className="container-fluid p-0">
      {/* Header bar */}
      <div className="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
          <h4 className="fw-bold mb-1">
            <i className="fas fa-microscope text-info me-2"></i> Forensic Inspection Report
          </h4>
          <span className="text-muted font-monospace" style={{ fontSize: '0.84rem' }}>
            Message Target: <span className="text-white">{scan.email_id}</span>
          </span>
        </div>
        <div className="d-flex gap-2">
          <a
            href={api.forensicPdfUrl(scan.id)}
            className="btn btn-primary btn-sm"
            target="_blank"
            rel="noreferrer"
          >
            <i className="fas fa-file-pdf"></i> Export Forensic PDF
          </a>
          <Link to="/dashboard" className="btn btn-outline-secondary btn-sm">
            <i className="fas fa-arrow-left"></i> Dashboard
          </Link>
        </div>
      </div>

      <div className="row g-3">
        {/* Left Column: Risk & ML Classification */}
        <div className="col-lg-4 col-md-5">
          {/* Numerical Risk Assessment */}
          <div className="card p-4 mb-3">
            <div className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style={{ borderColor: 'var(--border)' }}>
              <h6 className="fw-bold mb-0 text-uppercase" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
                Composite Risk Assessment
              </h6>
              <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                Scale 0-100
              </span>
            </div>

            <div className="text-center my-3">
              <div
                style={{ fontSize: '3.6rem', fontWeight: 800, lineHeight: 1, letterSpacing: '-2px' }}
                className={riskClass(risk.risk_level)}
              >
                {risk.risk_score || 0}
              </div>
              <div className="mt-2">
                <span className={`badge-risk ${riskClass(risk.risk_level)}`} style={{ fontSize: '0.92rem', padding: '5px 14px' }}>
                  {risk.risk_level || 'Unknown'} Risk
                </span>
              </div>
            </div>

            {Object.keys(breakdown).length > 0 && (
              <div className="mt-4 pt-3 border-top" style={{ borderColor: 'var(--border)' }}>
                <small className="text-muted fw-bold d-block mb-2 text-uppercase" style={{ fontSize: '0.72rem', letterSpacing: '0.6px' }}>
                  Threat Component Breakdown:
                </small>
                <table className="table table-sm mb-0">
                  <tbody>
                    {Object.entries(breakdown).map(([k, v]) => (
                      <tr key={k}>
                        <td className="text-muted ps-0" style={{ textTransform: 'capitalize', fontSize: '0.82rem' }}>
                          {String(k).replace(/_/g, ' ')}
                        </td>
                        <td className="text-end pe-0 fw-bold font-monospace" style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                          {Number(v).toFixed(1)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* ML Classifier Verdict */}
          <div className="card p-4">
            <div className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style={{ borderColor: 'var(--border)' }}>
              <h6 className="fw-bold mb-0 text-uppercase" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
                ML Classifier Inference
              </h6>
              <span className="badge" style={{ background: 'rgba(79, 70, 229, 0.12)', color: '#A5B4FC', border: '1px solid rgba(79, 70, 229, 0.3)' }}>
                DistilBERT NLP
              </span>
            </div>

            <div className="d-flex align-items-center justify-content-between mb-3">
              <span
                className={`badge-risk ${ml.prediction === 'phishing' ? 'risk-critical' : ml.prediction === 'suspicious' ? 'risk-medium' : 'risk-safe'}`}
                style={{ fontSize: '1rem', padding: '6px 16px', fontWeight: 800 }}
              >
                {String(ml.prediction || 'unknown').toUpperCase()}
              </span>
              <span className="font-monospace fw-bold" style={{ fontSize: '1.2rem', color: 'var(--text-primary)' }}>
                {(((ml.confidence || 0)) * 100).toFixed(1)}%
              </span>
            </div>

            <div style={{ height: '6px', background: 'var(--bg-input)', borderRadius: '3px', overflow: 'hidden', border: '1px solid var(--border)' }}>
              <div style={{
                height: '100%',
                width: `${(((ml.confidence || 0)) * 100).toFixed(1)}%`,
                background: ml.prediction === 'phishing' ? 'var(--status-critical)' : ml.prediction === 'suspicious' ? 'var(--status-warning)' : 'var(--status-safe)',
              }}></div>
            </div>

            {scan.timestamp && (
              <p className="text-muted mt-3 mb-0 font-monospace" style={{ fontSize: '0.78rem' }}>
                <i className="fas fa-clock me-1"></i> Recorded: {fmtTime(scan.timestamp)}
              </p>
            )}
          </div>
        </div>

        {/* Right Column: Protocols, Hops, Geolocation, URL Intel */}
        <div className="col-lg-8 col-md-7">
          {/* Email Authentication Matrix */}
          <div className="card p-4 mb-3">
            <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
              <i className="fas fa-lock text-success me-2"></i> Cryptographic Authentication Protocols
            </h6>
            <div className="row text-center g-3">
              {[
                { name: 'SPF', value: auth.spf },
                { name: 'DKIM', value: auth.dkim },
                { name: 'DMARC', value: auth.dmarc },
              ].map((a) => {
                const isPass = a.value === 'PASS'
                return (
                  <div className="col-4" key={a.name}>
                    <div className="p-3 rounded" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)' }}>
                      <div style={{ fontSize: '1.3rem', fontWeight: 800, color: isPass ? 'var(--status-safe)' : 'var(--status-critical)' }}>
                        {a.name}
                      </div>
                      <div className="font-monospace fw-semibold mt-1" style={{ fontSize: '0.84rem', color: isPass ? '#34D399' : '#F87171' }}>
                        <i className={`fas ${isPass ? 'fa-circle-check' : 'fa-circle-xmark'} me-1`}></i>
                        {a.value || 'MISSING'}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Header Mismatches */}
          {mismatches.length > 0 && (
            <div className="card p-4 mb-3" style={{ borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.03)' }}>
              <h6 className="text-danger fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px' }}>
                <i className="fas fa-triangle-exclamation me-2"></i> Header Inconsistencies & Spoofing Flags ({mismatches.length})
              </h6>
              {mismatches.map((mm: any, i: number) => (
                <div
                  key={i}
                  className="py-2 px-3 mb-2 rounded"
                  style={{
                    fontSize: '0.84rem',
                    background: mm.severity === 'HIGH' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                    border: `1px solid ${mm.severity === 'HIGH' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
                    color: mm.severity === 'HIGH' ? '#FCA5A5' : '#FDE68A',
                  }}
                >
                  <b className="me-1">[{mm.severity}]</b> {mm.type}: {mm.detail}
                </div>
              ))}
            </div>
          )}

          {/* Routing Chain */}
          {hops.length > 0 && (
            <div className="card p-4 mb-3">
              <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
                <i className="fas fa-route text-warning me-2"></i> Received Relay Hop Trace ({routing.hop_count} hops)
              </h6>
              <div className="table-responsive">
                <table className="table table-hover align-middle mb-0">
                  <thead>
                    <tr>
                      <th style={{ width: '36px' }}>#</th>
                      <th>Originating Relay</th>
                      <th>Receiving MTA</th>
                      <th>Relay IP</th>
                      <th>Geo Node</th>
                      <th>Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hops.map((hop: any) => (
                      <tr key={hop.hop_number}>
                        <td className="font-monospace text-muted fw-bold">{hop.hop_number}</td>
                        <td className="mono" style={{ fontSize: '0.78rem', maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={hop.from_host}>
                          {hop.from_host || '-'}
                        </td>
                        <td className="mono" style={{ fontSize: '0.78rem', maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={hop.by_host}>
                          {hop.by_host || '-'}
                        </td>
                        <td className="mono" style={{ fontSize: '0.82rem', color: 'var(--accent-cyan)' }}>
                          {hop.ip || '-'}
                        </td>
                        <td style={{ fontSize: '0.82rem' }}>
                          {hop.geo ? `${hop.geo.city || ''}, ${hop.geo.country_code || ''}` : '-'}
                        </td>
                        <td>
                          {hop.suspicious ? (
                            <span className="badge-risk risk-critical" style={{ fontSize: '0.72rem' }}>
                              ⚠ Anomaly
                            </span>
                          ) : (
                            <span className="text-success" style={{ fontSize: '0.82rem', fontWeight: 600 }}>
                              ✓ Clean
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Sender Geolocation Map */}
          {geo && geo.latitude ? (
            <div className="card p-4 mb-3">
              <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
                <i className="fas fa-earth-americas text-info me-2"></i> Origin Server Geolocation
              </h6>
              <div id="forensic-map" style={{ height: 210, borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-canvas)', overflow: 'hidden' }} />
              <p className="mt-3 mb-0 text-muted font-monospace" style={{ fontSize: '0.82rem' }}>
                <i className="fas fa-location-dot text-info me-1"></i> {geo.city}, {geo.country} | ASN: {geo.asn} | {geo.org} | Geo Risk: <span className="fw-bold text-warning">{geo.risk_score}/100</span>
              </p>
            </div>
          ) : null}

          {/* URL Threat Intelligence */}
          {Object.keys(urlResults).length > 0 && (
            <div className="card p-4">
              <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
                <i className="fas fa-link text-info me-2"></i> Embedded URL Threat Intelligence ({Object.keys(urlResults).length})
              </h6>
              <div className="table-responsive">
                <table className="table table-hover align-middle mb-0">
                  <thead>
                    <tr>
                      <th>Extracted URL</th>
                      <th>VirusTotal</th>
                      <th>Google SafeBrowsing</th>
                      <th>Risk Level</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(urlResults).map(([url, ti]: any[]) => (
                      <tr key={url}>
                        <td className="mono" style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.8rem' }} title={url}>
                          {escapeHtml(url)}
                        </td>
                        <td className="font-monospace fw-bold">{ti.threat_score ?? 0}</td>
                        <td>
                          <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-secondary)', fontSize: '0.72rem' }}>
                            {ti.sources?.safebrowsing?.status ?? '-'}
                          </span>
                        </td>
                        <td>
                          <span className={`badge-risk ${riskClass(ti.threat_level)}`}>
                            {ti.threat_level || '-'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
