import { NavLink, Outlet, useLocation } from 'react-router-dom'

const NAV = [
  { to: '/dashboard', icon: 'fa-chart-line', label: 'Dashboard' },
  { to: '/email/scan', icon: 'fa-envelope-open-text', label: 'Email Scanner' },
  { to: '/forensic/scan', icon: 'fa-microscope', label: 'Forensic Analysis' },
  { to: '/threat-map', icon: 'fa-globe', label: 'Threat Map' },
  { to: '/dashboard/threat-intel', icon: 'fa-chart-area', label: 'Threat Intel' },
  { to: '/email/demo', icon: 'fa-play-circle', label: 'Live Demo' },
]

export default function Layout() {
  const { pathname } = useLocation()
  // The threat map is a full-bleed page (like the original template).
  const flush = pathname === '/threat-map'

  return (
    <div>
      <div className="sidebar">
        <div className="brand">
          <i className="fas fa-shield-halved"></i> AI Email Forensics
        </div>
        <nav className="nav flex-column mt-3">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/dashboard'}
              className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}
            >
              <i className={'fas ' + item.icon}></i> {item.label}
            </NavLink>
          ))}
        </nav>
      </div>
      <main className={flush ? 'main-content--flush' : 'main-content'}>
        <Outlet />
      </main>
    </div>
  )
}
