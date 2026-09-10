import { useEffect, useRef, useState } from 'react'
import L from 'leaflet'
import { api } from '../lib/api'
import { fmtTime } from '../lib/format'

const PRED_COLORS: Record<string, string> = {
  phishing: '#e74c3c',
  legitimate: '#2ecc71',
  suspicious: '#f39c12',
  unknown: '#f39c12',
}
const RISK_BAR_COLORS: Record<string, string> = {
  Critical: '#e74c3c',
  High: '#e67e22',
  Medium: '#f1c40f',
  Low: '#3498db',
  Safe: '#2ecc71',
  Unknown: '#95a5a6',
}

const TIME_BUTTONS = [
  { days: 1, label: '24h' },
  { days: 7, label: '7d' },
  { days: 30, label: '30d' },
  { days: 365, label: 'All' },
]
const RISK_BUTTONS = [
  { value: '', label: 'All' },
  { value: 'Critical', label: 'Critical' },
  { value: 'High', label: 'High' },
  { value: 'Medium', label: 'Medium' },
]

export default function ThreatMapPage() {
  const mapDivRef = useRef<HTMLDivElement | null>(null)
  const mapRef = useRef<L.Map | null>(null)
  const originLayerRef = useRef<L.LayerGroup | null>(null)
  const routeLayerRef = useRef<L.LayerGroup | null>(null)
  const heatLayerRef = useRef<L.LayerGroup | null>(null)
  const heatPointsRef = useRef<[number, number, number][]>([])

  const [days, setDays] = useState(1)
  const [riskFilter, setRiskFilter] = useState('')
  const [layers, setLayers] = useState({ origin: true, route: true, heat: false })
  const [stats, setStats] = useState<any>(null)
  const [countries, setCountries] = useState<any[]>([])
  const [feed, setFeed] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  // --- Init map once ---
  useEffect(() => {
    const el = mapDivRef.current
    if (!el || mapRef.current) return
    const map = L.map(el, {
      center: [20, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: false,
    })
    L.tileLayer('https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap &copy; CartoDB',
    }).addTo(map)
    mapRef.current = map
    originLayerRef.current = L.layerGroup().addTo(map)
    routeLayerRef.current = L.layerGroup().addTo(map)
    heatLayerRef.current = L.layerGroup()
    return () => {
      map.remove()
      mapRef.current = null
    }
  }, [])

  // --- Load data whenever days/risk change ---
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [pointsData, statsData, recentData] = await Promise.all([
          api.mapPoints(days, riskFilter),
          api.mapStats(days),
          api.mapRecent(10),
        ])
        if (cancelled) return
        setStats(statsData)
        setCountries(statsData.top_countries || [])
        setFeed(recentData.recent || [])
        setLoading(false)

        const map = mapRef.current
        if (!map || !originLayerRef.current || !routeLayerRef.current) return
        const originLayer = originLayerRef.current
        const routeLayer = routeLayerRef.current
        originLayer.clearLayers()
        routeLayer.clearLayers()
        heatPointsRef.current = []

        for (const p of pointsData.points || []) {
          if (p.type === 'origin' && p.lat && p.lon) {
            createMarker(p).addTo(originLayer)
            heatPointsRef.current.push([p.lat, p.lon, (p.risk_score || 0) / 100])
          } else if (p.type === 'route' && p.hops && p.hops.length > 1) {
            const line = createRouteLine(p.hops)
            if (line) line.addTo(routeLayer)
          }
        }
      } catch (e) {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    const timer = setInterval(load, 30000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [days, riskFilter])

  // --- Heat layer visibility ---
  useEffect(() => {
    const map = mapRef.current
    const heat = heatLayerRef.current
    if (!map || !heat) return
    if (layers.heat) {
      heat.clearLayers()
      for (const [lat, lon, intensity] of heatPointsRef.current) {
        L.circle([lat, lon], {
          radius: 50000 + intensity * 100000,
          color: '#e67e22',
          fillColor: '#e67e22',
          fillOpacity: 0.15 + intensity * 0.2,
          weight: 0,
        }).addTo(heat)
      }
      map.addLayer(heat)
    } else if (map.hasLayer(heat)) {
      map.removeLayer(heat)
    }
  }, [layers.heat])

  const toggleLayer = (key: 'origin' | 'route' | 'heat') => {
    const map = mapRef.current
    if (key === 'origin' && originLayerRef.current && map) {
      map.hasLayer(originLayerRef.current)
        ? map.removeLayer(originLayerRef.current)
        : map.addLayer(originLayerRef.current)
    } else if (key === 'route' && routeLayerRef.current && map) {
      map.hasLayer(routeLayerRef.current)
        ? map.removeLayer(routeLayerRef.current)
        : map.addLayer(routeLayerRef.current)
    }
    setLayers((l) => ({ ...l, [key]: !l[key] }))
  }

  const maxCount = countries[0]?.count || 1
  const maxZoom = 19

  return (
    <div className="map-wrapper">
      <div ref={mapDivRef} id="map" />
      <div className="map-sidebar">
        <h5>
          <i className="fas fa-globe-americas"></i> THREAT MAP
        </h5>

        <div className="stat-row">
          <span className="stat-label">Total Scans</span>
          <span className="stat-value">{stats?.total_scans ?? '…'}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Geo-Tagged</span>
          <span className="stat-value">{stats?.geo_tagged ?? '…'}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Countries</span>
          <span className="stat-value">{stats?.countries ?? '…'}</span>
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-circle" style={{ fontSize: 8 }}></i> Legend
        </h5>
        <div className="pred-legend">
          <div className="pred-legend-item">
            <div className="pred-dot" style={{ background: '#e74c3c' }}></div> Phishing
          </div>
          <div className="pred-legend-item">
            <div className="pred-dot" style={{ background: '#2ecc71' }}></div> Legitimate
          </div>
          <div className="pred-legend-item">
            <div className="pred-dot" style={{ background: '#f39c12' }}></div> Unknown
          </div>
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-layer-group"></i> Layers
        </h5>
        {(
          [
            ['origin', 'Threat Origins'],
            ['route', 'Routing Hops'],
            ['heat', 'Heat Density'],
          ] as const
        ).map(([key, label]) => (
          <div className="layer-toggle" key={key}>
            <input
              type="checkbox"
              id={'layer-' + key}
              checked={layers[key]}
              onChange={() => toggleLayer(key)}
            />
            <label htmlFor={'layer-' + key}>{label}</label>
          </div>
        ))}

        <div className="section-divider" />
        <h5>
          <i className="fas fa-clock"></i> Time Range
        </h5>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {TIME_BUTTONS.map((b) => (
            <button
              key={b.days}
              className={'btn btn-sm btn-outline-light time-btn' + (days === b.days ? ' active' : '')}
              onClick={() => setDays(b.days)}
            >
              {b.label}
            </button>
          ))}
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-filter"></i> Risk Filter
        </h5>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {RISK_BUTTONS.map((b) => (
            <button
              key={b.label}
              className={
                'btn btn-sm btn-outline-danger risk-btn' +
                (riskFilter === b.value ? ' active' : '')
              }
              onClick={() => setRiskFilter(b.value)}
            >
              {b.label}
            </button>
          ))}
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-flag"></i> Top Threat Sources
        </h5>
        <div id="country-list">
          {countries.slice(0, 10).map((c) => (
            <div className="country-bar" key={c.country}>
              <span className="bar-name">{c.country}</span>
              <div className="bar">
                <div
                  className="bar-fill"
                  style={{
                    width: (c.count / maxCount) * 100 + '%',
                    background: RISK_BAR_COLORS[c.avg_risk > 50 ? 'High' : 'Medium'],
                  }}
                />
              </div>
              <span className="bar-label">{c.count}</span>
            </div>
          ))}
          {countries.length === 0 && !loading && (
            <div style={{ color: '#888', fontSize: 12 }}>No geo data in this range</div>
          )}
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-exclamation-triangle"></i> Recent Phishing
        </h5>
        <div className="live-feed" id="live-feed">
          {feed.map((r, i) => (
            <div key={i} className={'feed-item ' + String(r.risk_level || '').toLowerCase()}>
              <div className="feed-from">{r.from || 'Unknown'}</div>
              <div className="feed-subject">{r.subject || 'No subject'}</div>
              <div className="feed-meta">
                {r.country || '?'} ·{' '}
                <span className={'risk-badge risk-' + String(r.risk_level || '').toLowerCase()}>
                  {r.risk_level}
                </span>{' '}
                · {r.timestamp ? fmtTime(r.timestamp) : ''}
              </div>
            </div>
          ))}
          {feed.length === 0 && !loading && (
            <div style={{ color: '#888', fontSize: 12 }}>No recent phishing</div>
          )}
        </div>
      </div>
    </div>
  )

  // --- helpers (closure-safe; leaflet objects built imperatively) ---
  function createMarker(p: any) {
    const color = PRED_COLORS[p.prediction] || RISK_BAR_COLORS[p.risk_level] || '#95a5a6'
    const size = p.risk_score > 70 ? 14 : p.risk_score > 40 ? 10 : 7
    const icon = L.divIcon({
      className: '',
      html:
        `<div style="width:${size}px;height:${size}px;background:${color};` +
        `border:2px solid ${color}44;border-radius:50%;box-shadow:0 0 ${size}px ${color}66;"></div>`,
      iconSize: [size, size],
      iconAnchor: [size / 2, size / 2],
    })
    const predLabel = p.prediction || 'unknown'
    const popup =
      `<div class="popup-title">${p.from || p.email_id || 'Unknown'}</div>` +
      `<div class="popup-row"><strong>Subject:</strong> ${p.subject || 'N/A'}</div>` +
      `<div class="popup-row"><strong>Prediction:</strong> <span style="color:${
        PRED_COLORS[predLabel] || '#95a5a6'
      };font-weight:700;text-transform:uppercase">${predLabel}</span></div>` +
      `<div class="popup-row"><strong>Location:</strong> ${p.city || '?'}, ${p.country || '?'}</div>` +
      `<div class="popup-row"><strong>Risk:</strong> ${p.risk_level} (${p.risk_score}/100)</div>` +
      `<div class="popup-row"><strong>Auth:</strong> SPF ${p.auth?.spf || '?'} / DKIM ${p.auth?.dkim || '?'} / DMARC ${p.auth?.dmarc || '?'}</div>` +
      `<div class="popup-row"><strong>Trust:</strong> ${p.trust_score || 0}/100</div>` +
      `<div class="popup-row"><strong>Time:</strong> ${p.timestamp ? fmtTime(p.timestamp) : 'N/A'}</div>`
    return L.marker([p.lat, p.lon], { icon }).bindPopup(popup, { maxWidth: 320 })
  }

  function createRouteLine(hops: any[]) {
    if (hops.length < 2) return null
    const coords = hops.map((h) => [h.lat, h.lon] as [number, number])
    const hasSuspicious = hops.some((h) => h.suspicious)
    return L.polyline(coords, {
      color: hasSuspicious ? '#e74c3c' : '#3498db',
      weight: hasSuspicious ? 3 : 2,
      opacity: 0.6,
      dashArray: hasSuspicious ? '8, 4' : undefined,
    })
  }
}
