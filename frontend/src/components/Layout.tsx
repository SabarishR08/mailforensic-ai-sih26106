import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'

const NAV = [
  { to: '/dashboard', icon: 'fa-chart-line', label: 'Dashboard' },
  { to: '/email/scan', icon: 'fa-envelope-open-text', label: 'Email Scanner' },
  { to: '/email/batch', icon: 'fa-layer-group', label: 'Batch Scanner' },
  { to: '/dashboard/campaigns', icon: 'fa-sitemap', label: 'Threat Campaigns' },
  { to: '/forensic/scan', icon: 'fa-microscope', label: 'Forensic Analysis' },
  { to: '/threat-map', icon: 'fa-globe', label: 'Threat Map' },
  { to: '/dashboard/threat-intel', icon: 'fa-chart-area', label: 'Threat Intel' },
]

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const { pathname } = useLocation()
  const flush = pathname === '/threat-map'

  return (
    <div>
      {/* Sidebar Navigation */}
      <div className={`sidebar ${sidebarOpen ? '' : 'collapsed'}`}>
        <div className="brand d-flex justify-content-between align-items-center px-3 pb-3 border-bottom border-secondary">
          <div className="d-flex align-items-center gap-2 overflow-hidden brand-text">
            <i className="fas fa-shield-halved text-light fs-5"></i>
            <div className="d-flex flex-column">
              <span className="fw-bold text-light lh-1" style={{ fontSize: '0.95rem' }}>
                MailForensic AI
              </span>
              <small className="text-muted font-monospace mt-1 badge-sih" style={{ fontSize: '0.65rem' }}>
                THREAT OPERATIONS
              </small>
            </div>
          </div>
          <button
            className="sidebar-toggle-btn px-2 py-1 text-light border-secondary flex-shrink-0"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            title={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            style={{ fontSize: '0.85rem' }}
          >
            <i className="fas fa-bars"></i>
          </button>
        </div>
        <div className="sidebar-section-label nav-text">WORKSPACE</div>
        <nav className="nav flex-column mt-2">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/dashboard'}
              title={!sidebarOpen ? item.label : undefined}
              className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}
            >
              <i className={'fas ' + item.icon}></i>
              <span className="nav-text ms-2">{item.label}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      <main className={`${flush ? 'main-content--flush' : 'main-content'} ${sidebarOpen ? '' : 'collapsed'}`}>
        {!flush && (
          <div className="top-header">
            <div className="d-flex align-items-center gap-3">
              <span className="system-status font-monospace">
                <span className="status-pulse"></span><i className="fas fa-satellite-dish"></i> SYSTEM ONLINE
              </span>
            </div>
            <div className="d-flex align-items-center gap-2">
              <span className="header-vault font-monospace">
                <i className="fas fa-lock"></i> Evidence vault protected
              </span>
            </div>
          </div>
        )}
        <Outlet />
      </main>
    </div>
  )
}
