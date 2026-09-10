import { NavLink, Outlet, useLocation } from 'react-router-dom'

const NAV = [
  { to: '/dashboard', icon: 'fa-chart-line', label: 'Dashboard' },
  { to: '/email/scan', icon: 'fa-envelope-open-text', label: 'Email Scanner' },
  { to: '/forensic/scan', icon: 'fa-microscope', label: 'Forensic Analysis' },
  { to: '/threat-map', icon: 'fa-globe', label: 'Threat Map' },
  { to: '/dashboard/threat-intel', icon: 'fa-chart-area', label: 'Threat Intel' },
  { to: '/email/demo', icon: 'fa-bolt', label: 'Live Simulation' },
]

export default function Layout() {
  const { pathname } = useLocation()
  const flush = pathname === '/threat-map'

  return (
    <div>
      <aside className="sidebar">
        <div>
          <div className="brand">
            <div className="brand-icon">
              <i className="fas fa-shield-halved"></i>
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: '0.96rem', letterSpacing: '-0.3px', lineHeight: 1.2 }}>
                EmailForensic AI
              </div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 500 }}>
                AICTE • SIH 26106
              </div>
            </div>
            <span className="brand-tag">v2.0</span>
          </div>
          <nav className="nav flex-column mt-3">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/dashboard'}
                className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}
              >
                <i className={'fas ' + item.icon}></i>
                <span>{item.label}</span>
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="sidebar-footer">
          <div className="d-flex align-items-center justify-content-between mb-1">
            <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
              <i className="fas fa-circle text-success me-1" style={{ fontSize: '0.45rem' }}></i> ML Engine Ready
            </span>
            <span className="badge" style={{ background: 'var(--bg-panel)', color: 'var(--text-muted)', border: '1px solid var(--border)', fontSize: '0.68rem' }}>
              DISTILBERT
            </span>
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
            Obsidian Intelligence Platform
          </div>
        </div>
      </aside>
      <main className={flush ? 'main-content--flush' : 'main-content'}>
        <Outlet />
      </main>
    </div>
  )
}
