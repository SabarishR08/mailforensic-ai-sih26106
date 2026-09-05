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
    const map = L.map(el).setView([geo.latitude, geo.longitude], 8)
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap',
    }).addTo(map)
    L.marker([geo.latitude, geo.longitude])
      .addTo(map)
      .bindPopup(`<b>${geo.city}, ${geo.country}</b><br>Risk: ${geo.risk_score}/100`)
      .openPopup()
    mapRef.current = map
    return () => {
      map.remove()
      mapRef.current = null
    }
  }, [data])

  if (error) {
    return (
      <div className="container-fluid">
        <h4 className="mb-4">
          <i className="fas fa-microscope"></i> Forensic Report
        </h4>
        <div className="alert alert-danger">
          <i className="fas fa-exclamation-triangle"></i> {error}
        </div>
        <Link to="/forensic/scan" className="btn btn-outline-secondary">
          <i className="fas fa-arrow-left"></i> Back
        </Link>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="text-center py-5">
        <i className="fas fa-spinner fa-spin fa-2x" style={{ color: 'var(--glow)' }}></i>
        <p className="text-muted mt-3">Loading forensic report…</p>
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
    <div className="container-fluid">
      <div className="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <h4 className="mb-0">
          <i className="fas fa-microscope"></i> Forensic Report: {scan.email_id}
        </h4>
        <div>
          <a
            href={api.forensicPdfUrl(scan.id)}
            className="btn btn-outline-danger"
            target="_blank"
            rel="noreferrer"
          >
            <i className="fas fa-file-pdf"></i> Export PDF
          </a>{' '}
          <Link to="/forensic/scan" className="btn btn-outline-secondary">
            <i className="fas fa-arrow-left"></i> Back
          </Link>
        </div>
      </div>

      <div className="row g-3">
        {/* Risk summary */}
        <div className="col-md-4">
          <div className="card p-4 mb-3">
            <h6>Risk Assessment</h6>
            <div className="text-center my-3">
              <div
                style={{ fontSize: '3rem', fontWeight: 700 }}
                className={riskClass(risk.risk_level)}
              >
                {risk.risk_score || 0}
              </div>
              <div className={'badge-risk ' + riskClass(risk.risk_level)} style={{ fontSize: '1.1rem' }}>
                {risk.risk_level || 'Unknown'}
              </div>
            </div>
            {Object.keys(breakdown).length > 0 && (
              <table className="table table-sm">
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(breakdown).map(([k, v]) => (
                    <tr key={k}>
                      <td style={{ textTransform: 'capitalize' }}>{String(k).replace(/_/g, ' ')}</td>
                      <td>{Number(v).toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="card p-4">
            <h6>ML Classification</h6>
            <p>
              <span
                className={'badge ' + (ml.prediction === 'phishing' ? 'bg-danger' : 'bg-success')}
                style={{ fontSize: '1rem' }}
              >
                {ml.prediction || 'unknown'}
              </span>
            </p>
            <p>
              Confidence: <b>{(((ml.confidence || 0)) * 100).toFixed(1)}%</b>
            </p>
            {scan.timestamp && <p className="text-muted" style={{ fontSize: '0.85rem' }}>Scanned: {fmtTime(scan.timestamp)}</p>}
          </div>
        </div>

        <div className="col-md-8">
          {/* Authentication */}
          <div className="card p-4 mb-3">
            <h6>Email Authentication</h6>
            <div className="row text-center g-2">
              {[
                { name: 'SPF', value: auth.spf },
                { name: 'DKIM', value: auth.dkim },
                { name: 'DMARC', value: auth.dmarc },
              ].map((a) => (
                <div className="col-4" key={a.name}>
                  <div
                    className={'p-3 rounded text-white ' + (a.value === 'PASS' ? 'bg-success' : 'bg-danger')}
                  >
                    <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>{a.name}</div>
                    <div>{a.value || 'MISSING'}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Mismatches */}
          {mismatches.length > 0 && (
            <div className="card p-4 mb-3 border-danger">
              <h6 className="text-danger">
                <i className="fas fa-exclamation-triangle"></i> Header Mismatches
              </h6>
              {mismatches.map((mm: any, i: number) => (
                <div
                  key={i}
                  className={
                    'alert ' + (mm.severity === 'HIGH' ? 'alert-danger' : 'alert-warning') + ' py-2 mb-2'
                  }
                >
                  <b>[{mm.severity}]</b> {mm.type}: {mm.detail}
                </div>
              ))}
            </div>
          )}

          {/* Routing chain */}
          {hops.length > 0 && (
            <div className="card p-4 mb-3">
              <h6>
                <i className="fas fa-route"></i> Routing Chain ({routing.hop_count} hops)
              </h6>
              <div className="table-responsive">
                <table className="table table-sm">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>From</th>
                      <th>By</th>
                      <th>IP</th>
                      <th>Geo</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hops.map((hop: any) => (
                      <tr key={hop.hop_number} className={hop.suspicious ? 'table-danger' : ''}>
                        <td>{hop.hop_number}</td>
                        <td style={{ fontSize: '0.8rem' }}>{hop.from_host || '-'}</td>
                        <td style={{ fontSize: '0.8rem' }}>{hop.by_host || '-'}</td>
                        <td>{hop.ip || '-'}</td>
                        <td>
                          {hop.geo
                            ? `${hop.geo.city || ''}, ${hop.geo.country_code || ''}`
                            : '-'}
                        </td>
                        <td>
                          {hop.suspicious ? (
                            <span className="text-danger">
                              ⚠ {(hop.suspicious_reasons || []).join(', ')}
                            </span>
                          ) : (
                            '✓'
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Geo */}
          {geo && geo.latitude ? (
            <div className="card p-4 mb-3">
              <h6>
                <i className="fas fa-globe"></i> Sender Geolocation
              </h6>
              <div id="forensic-map" style={{ height: 200, borderRadius: 8, background: '#12141c' }} />
              <p className="mt-2 text-muted" style={{ fontSize: '0.85rem' }}>
                {geo.city}, {geo.country} | ASN: {geo.asn} | {geo.org} | Risk: {geo.risk_score}/100
              </p>
            </div>
          ) : null}

          {/* URL results */}
          {Object.keys(urlResults).length > 0 && (
            <div className="card p-4">
              <h6>
                <i className="fas fa-link"></i> URL Threat Intelligence
              </h6>
              <div className="table-responsive">
                <table className="table table-sm">
                  <thead>
                    <tr>
                      <th>URL</th>
                      <th>VT Score</th>
                      <th>SafeBrowsing</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(urlResults).map(([url, ti]: any[]) => (
                      <tr key={url}>
                        <td
                          style={{
                            maxWidth: 250,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={url}
                        >
                          {escapeHtml(url)}
                        </td>
                        <td>{ti.threat_score ?? 0}</td>
                        <td>{ti.sources?.safebrowsing?.status ?? '-'}</td>
                        <td>
                          <span className={'badge-risk ' + riskClass(ti.threat_level)}>
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
