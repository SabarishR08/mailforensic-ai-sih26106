import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import L from 'leaflet'
import { api, ScanRow } from '../lib/api'
import { fmtClock, riskClass } from '../lib/format'

type Stats = { total_scans: number; phishing_detected: number; total_threats: number }

const GEO_COLOR: Record<string, string> = {
  Critical: '#EF4444',
  High: '#F97316',
  Medium: '#F59E0B',
  Low: '#10B981',
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [scans, setScans] = useState<ScanRow[]>([])
  const [mlOnline, setMlOnline] = useState<boolean | null>(null)
  const [geoPoints, setGeoPoints] = useState<any[]>([])
  const [error, setError] = useState('')
  const mapRef = useRef<L.Map | null>(null)
  const markersRef = useRef<L.CircleMarker[]>([])

  useEffect(() => {
    api
      .stats()
      .then(setStats)
      .catch((e) => setError(String(e.message || e)))
    api
      .recentScans(20)
      .then((d) => setScans(d.scans || []))
      .catch(() => setScans([]))
    api.health().then(
      () => setMlOnline(true),
      () => setMlOnline(false),
    )
    api
      .geoThreats()
      .then((d) => setGeoPoints(d.points || []))
      .catch(() => setGeoPoints([]))
  }, [])

  // Mini geo map
  useEffect(() => {
    if (mapRef.current) return
    const el = document.getElementById('geo-map')
    if (!el) return
    const map = L.map(el, { zoomControl: false, attributionControl: false }).setView([20, 0], 2)
    L.tileLayer('https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; CartoDB',
    }).addTo(map)
    mapRef.current = map
    return () => {
      map.remove()
      mapRef.current = null
      markersRef.current = []
    }
  }, [])

  useEffect(() => {
    const map = mapRef.current
    if (!map || geoPoints.length === 0) return
    markersRef.current.forEach((m) => map.removeLayer(m))
    markersRef.current = []
    geoPoints.forEach((p) => {
      const color = GEO_COLOR[p.risk_level] || '#06B6D4'
      const marker = L.circleMarker([p.lat, p.lon], {
        radius: 5,
        color: color,
        fillColor: color,
        fillOpacity: 0.8,
        weight: 1,
      })
        .bindPopup(
          `<b>${p.city || 'Unknown'}, ${p.country || ''}</b><br><span style="color:#94a3b8">Risk: ${p.risk_level} (${p.risk_score})</span>`,
        )
        .addTo(map)
      markersRef.current.push(marker)
    })
  }, [geoPoints])

  return (
    <div className="container-fluid p-0">
      {/* Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 className="fw-bold mb-1">
            <i className="fas fa-chart-line text-info me-2"></i> Executive Threat Dashboard
          </h4>
          <p className="text-muted mb-0" style={{ fontSize: '0.88rem' }}>
            Real-time telemetry, machine learning verification rates, and geolocated attack origins.
          </p>
        </div>
        <div className="d-flex gap-2">
          <Link to="/email/scan" className="btn btn-primary btn-sm">
            <i className="fas fa-satellite-dish"></i> Run Scan
          </Link>
          <Link to="/threat-map" className="btn btn-outline-secondary btn-sm">
            <i className="fas fa-globe"></i> Threat Map
          </Link>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger py-2 mb-3" style={{ background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.3)', color: '#F87171' }}>
          <i className="fas fa-exclamation-triangle me-2"></i> {error}
        </div>
      )}

      {/* 4 Stat Cards */}
      <div className="row g-3 mb-4">
        <div className="col-md-3">
          <div className="stat-card">
            <div className="d-flex justify-content-between align-items-center mb-1">
              <span className="label">Total Scanned</span>
              <i className="fas fa-inbox text-muted"></i>
            </div>
            <div className="number">{stats?.total_scans ?? '—'}</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="stat-card danger">
            <div className="d-flex justify-content-between align-items-center mb-1">
              <span className="label">Phishing Intercepted</span>
              <i className="fas fa-shield-virus text-danger"></i>
            </div>
            <div className="number text-danger">{stats?.phishing_detected ?? '—'}</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="stat-card warning">
            <div className="d-flex justify-content-between align-items-center mb-1">
              <span className="label">High / Critical Threats</span>
              <i className="fas fa-triangle-exclamation text-warning"></i>
            </div>
            <div className="number text-warning">{stats?.total_threats ?? '—'}</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="stat-card safe">
            <div className="d-flex justify-content-between align-items-center mb-1">
              <span className="label">ML Model Status</span>
              <i className="fas fa-microchip text-success"></i>
            </div>
            <div className="number text-success" style={{ fontSize: '1.4rem', paddingTop: '10px' }}>
              {mlOnline === true ? (
                <span><i className="fas fa-circle-check me-2"></i>Online</span>
              ) : mlOnline === false ? (
                <span className="text-danger"><i className="fas fa-circle-xmark me-2"></i>Offline</span>
              ) : (
                <span className="text-muted">—</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main Table + Threat Map */}
      <div className="row g-3">
        {/* Recent Scans Table */}
        <div className="col-lg-8 col-md-12">
          <div className="card p-4 h-100">
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h6 className="fw-bold mb-0">
                <i className="fas fa-list text-info me-2"></i> Recent Email Scans
              </h6>
              <Link to="/email/scan" className="text-muted text-decoration-none" style={{ fontSize: '0.8rem' }}>
                View All <i className="fas fa-chevron-right ms-1"></i>
              </Link>
            </div>
            <div className="table-responsive">
              <table className="table table-hover align-middle">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Email Target</th>
                    <th>ML Verdict</th>
                    <th>Risk Score</th>
                    <th>Trust</th>
                    <th>Origin</th>
                    <th className="text-end">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => {
                    const isPhishing = s.ml_prediction === 'phishing'
                    const isSuspicious = s.ml_prediction === 'suspicious'
                    return (
                      <tr key={s.id}>
                        <td className="text-muted font-monospace" style={{ fontSize: '0.8rem' }}>
                          {fmtClock(s.timestamp) || '-'}
                        </td>
                        <td className="fw-medium font-monospace" style={{ fontSize: '0.82rem', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.email_id}>
                          {s.email_id || '-'}
                        </td>
                        <td>
                          <span className={`badge-risk ${isPhishing ? 'risk-critical' : isSuspicious ? 'risk-medium' : 'risk-safe'}`}>
                            <i className={`fas ${isPhishing ? 'fa-triangle-exclamation' : 'fa-check'} me-1`}></i>
                            {s.ml_prediction}
                          </span>
                        </td>
                        <td>
                          <span className={`badge-risk ${riskClass(s.risk_level)}`}>
                            {s.risk_level} ({s.risk_score})
                          </span>
                        </td>
                        <td className="font-monospace fw-semibold" style={{ color: 'var(--accent-cyan)' }}>
                          {s.forensic_trust_score ?? 0}/100
                        </td>
                        <td>
                          <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'JetBrains Mono' }}>
                            {s.geo_country || '-'}
                          </span>
                        </td>
                        <td className="text-end">
                          <Link to={`/forensic/report/${s.id}`} className="btn btn-sm btn-outline-secondary py-1 px-2" title="Inspect Forensic Details">
                            <i className="fas fa-magnifying-glass"></i>
                          </Link>
                        </td>
                      </tr>
                    )
                  })}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan={7} className="text-center text-muted py-5">
                        <i className="fas fa-inbox d-block mb-2" style={{ fontSize: '1.8rem', color: 'var(--text-muted)' }}></i>
                        No scans available yet. Go to <Link to="/email/scan">Email Scanner</Link> to run tests.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Sidebar Mini-Map & Quick Launch */}
        <div className="col-lg-4 col-md-12">
          <div className="card p-4 mb-3">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <h6 className="fw-bold mb-0">
                <i className="fas fa-globe text-info me-2"></i> Threat Origin Map
              </h6>
              <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                CartoDB Dark
              </span>
            </div>
            <div
              id="geo-map"
              style={{ height: 240, borderRadius: 8, marginTop: 8, border: '1px solid var(--border)', background: 'var(--bg-canvas)', overflow: 'hidden' }}
            />
            {geoPoints.length === 0 && (
              <div className="text-muted text-center mt-2" style={{ fontSize: '0.78rem' }}>
                Awaiting geo-tagged telemetry
              </div>
            )}
          </div>

          <div className="card p-4">
            <h6 className="fw-bold mb-3">
              <i className="fas fa-bolt text-warning me-2"></i> Rapid Triage Actions
            </h6>
            <div className="d-flex flex-column gap-2">
              <Link to="/email/scan" className="btn btn-primary w-100 justify-content-start">
                <i className="fas fa-envelope-open-text me-2"></i> Open Email Scanner
              </Link>
              <Link to="/forensic/scan" className="btn btn-outline-secondary w-100 justify-content-start">
                <i className="fas fa-microscope me-2"></i> Upload Raw .EML File
              </Link>
              <Link to="/threat-map" className="btn btn-outline-secondary w-100 justify-content-start">
                <i className="fas fa-map-location-dot me-2"></i> Launch Full Screen Threat Map
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
