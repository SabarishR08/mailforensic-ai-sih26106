import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import DashboardPage from './pages/DashboardPage'
import EmailScannerPage from './pages/EmailScannerPage'
import DemoPage from './pages/DemoPage'
import ForensicEmlPage from './pages/ForensicEmlPage'
import ForensicReportPage from './pages/ForensicReportPage'
import ThreatMapPage from './pages/ThreatMapPage'
import ThreatIntelPage from './pages/ThreatIntelPage'

// Routes mirror the original Jinja URLs 1:1 so nothing breaks and the
// backend keeps serving the same /api + /email/api + /forensic/api surface.
export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/email/scan" element={<EmailScannerPage />} />
        <Route path="/email/demo" element={<DemoPage />} />
        <Route path="/forensic/scan" element={<ForensicEmlPage />} />
        <Route path="/forensic/report/:scanId" element={<ForensicReportPage />} />
        <Route path="/threat-map" element={<ThreatMapPage />} />
        <Route path="/dashboard/threat-intel" element={<ThreatIntelPage />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  )
}
