import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import ChartCanvas from '../components/Chart'
import { escapeHtml, fmtTime } from '../lib/format'

const COLORS = {
  phishing: '#c62828',
  phishingBg: 'rgba(198,40,40,0.15)',
  legitimate: '#2e7d32',
  legitimateBg: 'rgba(46,125,50,0.15)',
  unknown: '#f9a825',
  unknownBg: 'rgba(249,168,37,0.15)',
  spf: '#1565c0',
  dkim: '#6a1b9a',
  dmarc: '#e65100',
  riskColors: { Critical: '#c62828', High: '#e65100', Medium: '#f9a825', Low: '#2e7d32', Safe: '#1565c0', Unknown: '#9e9e9e' } as Record<string, string>,
}

export default function ThreatIntelPage() {
  const [days, setDays] = useState(30)
  const [summary, setSummary] = useState<any>(null)
  const [trends, setTrends] = useState<any>(null)
  const [distribution, setDistribution] = useState<any>(null)
  const [sources, setSources] = useState<any>(null)
  const [auth, setAuth] = useState<any>(null)
  const [recent, setRecent] = useState<any[]>([])
  const [updated, setUpdated] = useState('')

  const loadAll = useCallback(async () => {
    try {
      const [s, t, d, so, a, r] = await Promise.all([
        api.summary(),
        api.trends(days),
        api.distribution(),
        api.topSources(),
        api.authTrends(days),
        api.threatIntelRecent(25),
      ])
      setSummary(s)
      setTrends(t)
      setDistribution(d)
      setSources(so)
      setAuth(a)
      setRecent(r.scans || [])
      setUpdated(new Date().toLocaleTimeString())
    } catch {
      /* backend unreachable — keep previous data */
    }
  }, [days])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  // ---------- Chart configs ----------
  const trendConfig = useMemo(() => {
    if (!trends) return null
    const skip = Math.max(1, Math.floor(trends.labels.length / 15))
    return {
      type: 'line',
      data: {
        labels: trends.labels.map((l: string, i: number) => (i % skip === 0 ? l.slice(5) : '')),
        datasets: [
          {
            label: 'Phishing',
            data: trends.phishing,
            borderColor: COLORS.phishing,
            backgroundColor: COLORS.phishingBg,
            fill: true,
            tension: 0.3,
            pointRadius: 2,
          },
          {
            label: 'Legitimate',
            data: trends.legitimate,
            borderColor: COLORS.legitimate,
            backgroundColor: COLORS.legitimateBg,
            fill: true,
            tension: 0.3,
            pointRadius: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'top', labels: { color: '#e0e0e0' } } },
        scales: {
          x: { grid: { display: false }, ticks: { maxRotation: 45, color: '#8892a4', font: { size: 10 } } },
          y: { beginAtZero: true, ticks: { stepSize: 1, color: '#8892a4' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        },
      },
    }
  }, [trends])

  const riskPieConfig = useMemo(() => {
    if (!distribution) return null
    const rl = distribution.risk_levels || {}
    const labels = Object.keys(rl)
    return {
      type: 'doughnut',
      data: {
        labels,
        datasets: [
          {
            data: Object.values(rl),
            backgroundColor: labels.map((k) => COLORS.riskColors[k] || '#9e9e9e'),
            borderWidth: 2,
            borderColor: '#1a1d27',
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: '#e0e0e0', font: { size: 12 } } } },
        cutout: '55%',
      },
    }
  }, [distribution])

  const mlPieConfig = useMemo(() => {
    if (!distribution) return null
    const ml = distribution.ml_predictions || {}
    const labels = Object.keys(ml)
    return {
      type: 'doughnut',
      data: {
        labels: labels.map((l) => l.charAt(0).toUpperCase() + l.slice(1)),
        datasets: [
          {
            data: Object.values(ml),
            backgroundColor: labels.map((k) =>
              k === 'phishing' ? COLORS.phishing : k === 'legitimate' ? COLORS.legitimate : COLORS.unknown,
            ),
            borderWidth: 2,
            borderColor: '#1a1d27',
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: '#e0e0e0', font: { size: 12 } } } },
        cutout: '55%',
      },
    }
  }, [distribution])

  const histConfig = useMemo(() => {
    if (!distribution) return null
    const rh = distribution.risk_histogram || {}
    const histBg = (rh.labels || []).map((_: string, i: number) => {
      const intensity = Math.round(50 + (i / 9) * 205)
      return `rgb(${intensity}, ${Math.max(50, 200 - i * 20)}, ${Math.max(50, 200 - i * 25)})`
    })
    return {
      type: 'bar',
      data: {
        labels: rh.labels || [],
        datasets: [{ label: 'Scans', data: rh.values || [], backgroundColor: histBg, borderRadius: 4 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#8892a4' }, title: { display: true, text: 'Risk Score Range', color: '#8892a4', font: { size: 11 } } },
          y: { beginAtZero: true, ticks: { color: '#8892a4' }, grid: { color: 'rgba(255,255,255,0.05)' }, title: { display: true, text: 'Count', color: '#8892a4', font: { size: 11 } } },
        },
      },
    }
  }, [distribution])

  const geoConfig = useMemo(() => {
    if (!sources) return null
    const bv = sources.by_volume || []
    return {
      type: 'bar',
      data: {
        labels: bv.map((x: any) => x.country),
        datasets: [
          {
            label: 'Scans',
            data: bv.map((x: any) => x.count),
            backgroundColor: bv.map((_: any, i: number) => `rgba(26,35,126,${0.9 - i * 0.05})`),
            borderRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { color: '#8892a4' }, grid: { color: 'rgba(255,255,255,0.05)' }, title: { display: true, text: 'Number of Scans', color: '#8892a4', font: { size: 11 } } },
          y: { grid: { display: false }, ticks: { color: '#8892a4' } },
        },
      },
    }
  }, [sources])

  const phishingRateConfig = useMemo(() => {
    if (!sources) return null
    const pr = sources.phishing_rate || []
    return {
      type: 'bar',
      data: {
        labels: pr.map((x: any) => x.country),
        datasets: [
          { label: 'Phishing', data: pr.map((x: any) => x.phishing), backgroundColor: COLORS.phishing, borderRadius: 4 },
          { label: 'Legitimate', data: pr.map((x: any) => x.total - x.phishing), backgroundColor: COLORS.legitimate, borderRadius: 4 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'top', labels: { color: '#e0e0e0' } } },
        scales: {
          x: { stacked: true, grid: { display: false }, ticks: { color: '#8892a4' } },
          y: { stacked: true, beginAtZero: true, ticks: { color: '#8892a4' }, grid: { color: 'rgba(255,255,255,0.05)' }, title: { display: true, text: 'Count', color: '#8892a4', font: { size: 11 } } },
        },
      },
    }
  }, [sources])

  const authConfig = useMemo(() => {
    if (!auth) return null
    const skip = Math.max(1, Math.floor(auth.labels.length / 15))
    return {
      type: 'line',
      data: {
        labels: auth.labels.map((l: string, i: number) => (i % skip === 0 ? l.slice(5) : '')),
        datasets: [
          {
            label: 'SPF Failure %',
            data: auth.spf_failure_rate,
            borderColor: COLORS.spf,
            backgroundColor: 'rgba(21,101,192,0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 1,
          },
          {
            label: 'DKIM Failure %',
            data: auth.dkim_failure_rate,
            borderColor: COLORS.dkim,
            backgroundColor: 'rgba(106,27,154,0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 1,
          },
          {
            label: 'DMARC Failure %',
            data: auth.dmarc_failure_rate,
            borderColor: COLORS.dmarc,
            backgroundColor: 'rgba(230,81,0,0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'top', labels: { color: '#e0e0e0' } } },
        scales: {
          x: { grid: { display: false }, ticks: { maxRotation: 45, color: '#8892a4', font: { size: 10 } } },
          y: { beginAtZero: true, max: 100, ticks: { color: '#8892a4' }, grid: { color: 'rgba(255,255,255,0.05)' }, title: { display: true, text: 'Failure Rate %', color: '#8892a4', font: { size: 11 } } },
        },
      },
    }
  }, [auth])

  const isEmpty = summary && summary.total_scans === 0

  return (
    <div className="container-fluid">
      <h4 className="mb-4">
        <i className="fas fa-chart-area"></i> Threat Intelligence
      </h4>

      <div className="d-flex align-items-center gap-2 mb-4 flex-wrap">
        <label style={{ fontSize: '0.85rem', color: '#8892a4' }}>Time Range:</label>
        <select
          className="form-select form-select-sm w-auto"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
        >
          <option value={7}>Last 7 days</option>
          <option value={14}>Last 14 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
        <button className="btn-refresh" onClick={() => loadAll()}>
          <i className="fas fa-sync-alt"></i> Refresh
        </button>
        <div style={{ flex: 1 }} />
        {updated && (
          <span style={{ fontSize: '0.8rem', color: '#999' }}>Updated: {updated}</span>
        )}
      </div>

      {isEmpty ? (
        <div className="empty-state">
          <i className="fas fa-inbox"></i>
          <h5>No scan data yet</h5>
          <p>Scan some emails or upload .eml files to populate the threat intelligence dashboard.</p>
          <Link to="/email/scan" className="btn-refresh mt-2">
            Go to Email Scanner
          </Link>
        </div>
      ) : (
        <>
          {/* Stat cards */}
          <div className="ti-stat-row">
            <div className="ti-stat-card">
              <div className="number">{summary ? summary.total_scans.toLocaleString() : '—'}</div>
              <div className="label">Total Scans</div>
            </div>
            <div className="ti-stat-card phishing">
              <div className="number">{summary ? summary.phishing_count.toLocaleString() : '—'}</div>
              <div className="label">Phishing Detected</div>
            </div>
            <div className="ti-stat-card safe">
              <div className="number">{summary ? summary.legitimate_count.toLocaleString() : '—'}</div>
              <div className="label">Legitimate</div>
            </div>
            <div className="ti-stat-card warn">
              <div className="number">{summary ? summary.phishing_rate + '%' : '—'}</div>
              <div className="label">Phishing Rate</div>
            </div>
            <div className="ti-stat-card">
              <div className="number">{summary ? summary.avg_risk_score : '—'}</div>
              <div className="label">Avg Risk Score</div>
            </div>
            <div className="ti-stat-card">
              <div className="number">{summary ? summary.avg_trust_score : '—'}</div>
              <div className="label">Avg Trust Score</div>
            </div>
            <div className="ti-stat-card">
              <div className="number">{summary ? summary.unique_countries || 0 : '—'}</div>
              <div className="label">Countries Seen</div>
            </div>
          </div>

          {/* Row 1 */}
          <div className="row g-3">
            <div className="col-lg-8">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-chart-line"></i> Phishing vs Legitimate Over Time
                </h6>
                {trendConfig && <ChartCanvas config={trendConfig} height={350} />}
              </div>
            </div>
            <div className="col-lg-4">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-chart-pie"></i> Risk Level Distribution
                </h6>
                {riskPieConfig && <ChartCanvas config={riskPieConfig} height={350} />}
              </div>
            </div>
          </div>

          {/* Row 2 */}
          <div className="row g-3">
            <div className="col-lg-6">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-chart-bar"></i> Risk Score Distribution
                </h6>
                {histConfig && <ChartCanvas config={histConfig} height={280} />}
              </div>
            </div>
            <div className="col-lg-6">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-brain"></i> ML Prediction Breakdown
                </h6>
                {mlPieConfig && <ChartCanvas config={mlPieConfig} height={280} />}
              </div>
            </div>
          </div>

          {/* Row 3 */}
          <div className="row g-3">
            <div className="col-lg-6">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-globe"></i> Top Threat Source Countries
                </h6>
                {geoConfig && <ChartCanvas config={geoConfig} height={350} />}
              </div>
            </div>
            <div className="col-lg-6">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-key"></i> Authentication Failure Rates
                </h6>
                {authConfig && <ChartCanvas config={authConfig} height={350} />}
              </div>
            </div>
          </div>

          {/* Row 4 */}
          <div className="row g-3">
            <div className="col-lg-6">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-percentage"></i> Phishing Rate by Country
                </h6>
                {phishingRateConfig && <ChartCanvas config={phishingRateConfig} height={350} />}
              </div>
            </div>
            <div className="col-lg-6">
              <div className="chart-card">
                <h6>
                  <i className="fas fa-stream"></i> Recent Activity
                </h6>
                <div style={{ maxHeight: 400, overflowY: 'auto' }}>
                  {recent.length === 0 && (
                    <div style={{ textAlign: 'center', color: '#999', padding: 20 }}>
                      No recent scans
                    </div>
                  )}
                  {recent.map((s) => {
                    const pred = s.ml_prediction || 'unknown'
                    return (
                      <div key={s.id} className={'activity-item ' + pred}>
                        <div className={'activity-dot ' + pred} />
                        <div className="activity-info">
                          <div className="activity-subject">
                            {escapeHtml(s.subject || s.email_id || 'Unknown')}
                          </div>
                          <div className="activity-meta">
                            {escapeHtml(s.from || '')} · {fmtTime(s.timestamp)}
                          </div>
                          <div className="activity-badges">
                            <span className={'mini-badge ' + pred}>{String(pred).toUpperCase()}</span>
                            <span className="mini-badge risk">Risk: {s.risk_score || 0}</span>
                            {s.geo_city && (
                              <span className="mini-badge country">
                                <i className="fas fa-map-pin"></i> {escapeHtml(s.geo_city)}
                              </span>
                            )}
                            {s.geo_country && <span className="mini-badge country">{s.geo_country}</span>}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
