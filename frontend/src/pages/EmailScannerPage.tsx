import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { predBadgeBg, riskBadgeBg } from '../lib/format'

// --- Pre-built sample emails ---
const SAMPLE_EMAILS: Record<string, string> = {
  legit_statement: `From: statements@bankofamerica.com
Subject: Monthly Account Statement Available
Date: Mon, 25 Aug 2026 09:00:00 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass; dmarc=pass

Hello,

Your monthly account statement for August 2026 is now available in your account.

You can sign in to your account through the official website or mobile application to review your recent activity, transactions, and account information.

No action is required if you have already reviewed your statement.

Thank you,
Customer Support Team
Bank of America
https://www.bankofamerica.com`,

  legit_application: `From: applicant@gmail.com
Subject: Application for Cybersecurity Analyst Internship
Date: Mon, 25 Aug 2026 14:30:00 +0530
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Reply-To: applicant@gmail.com

Dear Hiring Team,

I am writing to express my strong interest in the Cybersecurity Analyst Internship. 
I have built automated forensic tools and machine learning classifiers for detecting malicious email vectors.

I would welcome the opportunity to discuss how my skill set matches your team's needs.
Thank you for your time and consideration.

Best regards,
Sanjai R.
Panimalar Engineering College`,

  legit_welcome: `From: noreply@github.com
Subject: Welcome to GitHub Security Lab
Date: Mon, 25 Aug 2026 11:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass

Welcome! Your repository access has been authorized for secure forensic triage.
You can view code auditing workflows and automated vulnerability scanning at:
https://github.com/security-lab`,

  phish_paypal: `From: security@paypa1-alerts.com
Subject: URGENT: Your PayPal Account Has Been Limited!
Date: Mon, 25 Aug 2026 10:30:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 185.220.101.34
Received: from mail.evil-server.ru (185.220.101.34) by mx.gmail.com

Dear Valued Customer,

We have detected suspicious unauthorized sign-in attempts to your PayPal account from Moscow, Russia.
To restore full access to your account, you must verify your identity within 24 hours:

http://185.220.101.34/paypal-secure/verify?id=93821

Failure to verify will result in permanent account suspension and asset lock.

PayPal Security Team`,

  phish_bank: `From: alerts@secure-banking-verify.com
Subject: [ACTION REQUIRED] Unauthorized Wire Transfer - Verify Immediately!
Date: Mon, 25 Aug 2026 08:15:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 45.77.65.211
Received: from smtp-relay.cn (45.77.65.211) by mx.gmail.com

Dear Customer,

We detected an unauthorized international wire transfer of $4,850.00 on your checking account.
If you did not authorize this transaction, click the link below immediately to cancel the transfer:

http://45.77.65.211/bank-security/cancel?txid=982412

Security Department`,

  suspicious_bec: `From: ceo@company-work-mail.com
Subject: Urgent - Confidential Acquisition Wire Transfer
Date: Mon, 25 Aug 2026 15:45:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Reply-To: johnsmith.private@gmail.com
X-Originating-IP: 103.25.48.12

Hi,

I need you to process an urgent confidential wire transfer of $47,500 for our ongoing acquisition.
I am currently in an executive briefing and cannot take calls. Send confirmation once the funds clear:

Account: 3847291056
Routing: 021000021
Beneficiary: Apex Holdings LLC

Thanks,
John Smith
Chief Executive Officer`,
}

const QUICK_INSERTS = [
  { key: 'legit_statement', label: 'Legit: Bank Statement', kind: 'safe', icon: 'fa-check-circle' },
  { key: 'legit_application', label: 'Legit: Job Application', kind: 'safe', icon: 'fa-check-circle' },
  { key: 'legit_welcome', label: 'Legit: Platform Welcome', kind: 'safe', icon: 'fa-check-circle' },
  { key: 'phish_paypal', label: 'Phishing: Fake PayPal Alert', kind: 'danger', icon: 'fa-exclamation-triangle' },
  { key: 'phish_bank', label: 'Phishing: Wire Transfer Scam', kind: 'danger', icon: 'fa-exclamation-triangle' },
  { key: 'suspicious_bec', label: 'Suspicious: CEO BEC Wire', kind: 'warning', icon: 'fa-user-shield' },
]

type Status = { text: string; kind: 'info' | 'success' | 'danger' | 'warning' } | null

export default function EmailScannerPage() {
  const [gmailCount, setGmailCount] = useState(5)
  const [sampleCount, setSampleCount] = useState(5)
  const [gmailStatus, setGmailStatus] = useState<Status>(null)
  const [sampleStatus, setSampleStatus] = useState<Status>(null)
  const [busy, setBusy] = useState<string | null>(null)
  
  // Manual modality tab: 'text' or 'file'
  const [manualMode, setManualMode] = useState<'text' | 'file'>('text')
  const [text, setText] = useState('')
  const [results, setResults] = useState<React.ReactNode | null>(null)
  const [emlPreview, setEmlPreview] = useState('')
  const [emlName, setEmlName] = useState('')
  const [emlStatus, setEmlStatus] = useState<Status>(null)
  const fileRef = useRef<HTMLInputElement | null>(null)

  const insertSample = (key: string) => {
    setText(SAMPLE_EMAILS[key] || '')
    setManualMode('text')
  }

  // ---------- Scan 1: Gmail Live Scan ----------
  const scanGmail = async () => {
    setBusy('gmail')
    setGmailStatus({ text: 'Connecting to Gmail API and fetching recent messages...', kind: 'info' })
    try {
      const data = await api.scanGmail(gmailCount)
      if (data.error) {
        setGmailStatus({ text: 'Failed: ' + data.error, kind: 'danger' })
      } else {
        setGmailStatus({ text: `Successfully scanned ${data.count} live messages from Gmail`, kind: 'success' })
        renderResults(data.results || [], 'Gmail Live Scan')
      }
    } catch (e: any) {
      setGmailStatus({ text: 'Error: ' + String(e.message || e), kind: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  // ---------- Scan 2: Pre-Loaded Sample Data ----------
  const scanSample = async (count = sampleCount) => {
    setBusy('sample')
    setSampleStatus({ text: `Scanning ${count} realistic threat samples...`, kind: 'info' })
    try {
      const data = await api.scanSample(count)
      if (data.error) {
        setSampleStatus({ text: 'Failed: ' + data.error, kind: 'danger' })
      } else {
        setSampleStatus({ text: `Processed ${data.count} threat dataset samples`, kind: 'success' })
        renderResults(data.results || [], 'Pre-Loaded Sample Dataset')
      }
    } catch (e: any) {
      setSampleStatus({ text: 'Error: ' + String(e.message || e), kind: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  // ---------- Scan 3A: Custom Raw Text ----------
  const scanText = async () => {
    if (!text.trim()) {
      alert('Please enter or insert email text first.')
      return
    }
    setBusy('text')
    try {
      const data = await api.scanText(text)
      const pred = (data.prediction || 'unknown').toLowerCase()
      const conf = ((data.confidence || 0) * 100).toFixed(1)
      const riskClass = pred === 'phishing' ? 'risk-critical' : pred === 'suspicious' ? 'risk-medium' : 'risk-safe'

      setResults(
        <div className="card p-4">
          <div className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style={{ borderColor: 'var(--border)' }}>
            <h6 className="mb-0 fw-bold">
              <i className="fas fa-brain text-info me-2"></i> ML Threat Classification Result
            </h6>
            <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
              Target: Raw Input Text
            </span>
          </div>
          <div className="row g-3 align-items-center">
            <div className="col-md-4 text-center">
              <div className="text-muted mb-1" style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Verdict
              </div>
              <span className={`badge-risk ${riskClass}`} style={{ fontSize: '1.05rem', padding: '6px 18px', fontWeight: 800 }}>
                {pred.toUpperCase()}
              </span>
            </div>
            <div className="col-md-4">
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="text-muted" style={{ fontSize: '0.82rem' }}>Confidence Level:</span>
                <span className="fw-bold font-monospace">{conf}%</span>
              </div>
              <div style={{ height: '8px', background: 'var(--bg-input)', borderRadius: '4px', overflow: 'hidden', border: '1px solid var(--border)' }}>
                <div style={{
                  height: '100%',
                  width: `${conf}%`,
                  background: pred === 'phishing' ? 'var(--status-critical)' : pred === 'suspicious' ? 'var(--status-warning)' : 'var(--status-safe)',
                }}></div>
              </div>
            </div>
            <div className="col-md-4">
              <span className="text-muted d-block mb-1" style={{ fontSize: '0.82rem' }}>Engine Status:</span>
              <div style={{ fontSize: '0.88rem', color: data.model_loaded ? 'var(--status-safe)' : 'var(--status-warning)', fontWeight: 600 }}>
                <i className={`fas ${data.model_loaded ? 'fa-check-circle' : 'fa-info-circle'} me-1`}></i>
                {data.model_loaded ? 'Trained Classifier Active' : 'Fallback Heuristic Active'}
              </div>
            </div>
          </div>
        </div>
      )
    } catch (e: any) {
      alert('Error: ' + String(e.message || e))
    } finally {
      setBusy(null)
    }
  }

  // ---------- Scan 3B: Upload .eml File ----------
  const onEmlFile = (file: File) => {
    if (!file) return
    setEmlName(file.name)
    setEmlStatus(null)
    const reader = new FileReader()
    reader.onload = (e) => setEmlPreview(String(e.target?.result || '').substring(0, 3000))
    reader.readAsText(file)
  }

  const analyzeEml = async () => {
    const file = fileRef.current?.files?.[0]
    if (!file) {
      alert('Please select a valid .eml file.')
      return
    }
    setBusy('eml')
    setEmlStatus({ text: 'Parsing MIME structure and inspecting routing hops...', kind: 'info' })
    try {
      const textContent = await file.text()
      const data = await api.scanText(textContent)
      const pred = (data.prediction || 'unknown').toLowerCase()
      const conf = ((data.confidence || 0) * 100).toFixed(1)
      const riskClass = pred === 'phishing' ? 'risk-critical' : pred === 'suspicious' ? 'risk-medium' : 'risk-safe'
      setEmlStatus({ text: 'File analysis complete', kind: 'success' })

      setResults(
        <div className="card p-4">
          <div className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style={{ borderColor: 'var(--border)' }}>
            <h6 className="mb-0 fw-bold">
              <i className="fas fa-file-lines text-info me-2"></i> .EML File Forensic Result: {file.name}
            </h6>
            <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
              {(file.size / 1024).toFixed(1)} KB
            </span>
          </div>
          <div className="row g-3 align-items-center">
            <div className="col-md-4 text-center">
              <div className="text-muted mb-1" style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Classification
              </div>
              <span className={`badge-risk ${riskClass}`} style={{ fontSize: '1.05rem', padding: '6px 18px', fontWeight: 800 }}>
                {pred.toUpperCase()}
              </span>
            </div>
            <div className="col-md-4">
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="text-muted" style={{ fontSize: '0.82rem' }}>Confidence:</span>
                <span className="fw-bold font-monospace">{conf}%</span>
              </div>
              <div style={{ height: '8px', background: 'var(--bg-input)', borderRadius: '4px', overflow: 'hidden', border: '1px solid var(--border)' }}>
                <div style={{
                  height: '100%',
                  width: `${conf}%`,
                  background: pred === 'phishing' ? 'var(--status-critical)' : pred === 'suspicious' ? 'var(--status-warning)' : 'var(--status-safe)',
                }}></div>
              </div>
            </div>
            <div className="col-md-4">
              <span className="text-muted d-block mb-1" style={{ fontSize: '0.82rem' }}>MIME Inspection:</span>
              <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.12)', color: 'var(--accent-cyan)', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
                Headers & Body Extracted
              </span>
            </div>
          </div>
        </div>
      )
    } catch (e: any) {
      setEmlStatus({ text: 'Error: ' + String(e.message || e), kind: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  // ---------- Render Results Table ----------
  const renderResults = (rows: any[], title: string) => {
    if (!rows.length) {
      setResults(
        <div className="card p-4 text-center">
          <p className="text-muted mb-0">No emails returned from scan.</p>
        </div>
      )
      return
    }
    const phishing = rows.filter((r) => r.ml?.prediction === 'phishing').length
    const legit = rows.filter((r) => r.ml?.prediction === 'legitimate').length
    const susp = rows.filter((r) => r.ml?.prediction === 'suspicious').length

    setResults(
      <div className="card p-4">
        <div className="d-flex justify-content-between align-items-center mb-3">
          <h6 className="mb-0 fw-bold">
            <i className="fas fa-table-list text-info me-2"></i> {title} — Inspection Results
          </h6>
          <div className="d-flex gap-2">
            <span className="badge-risk risk-critical">{phishing} Phishing</span>
            <span className="badge-risk risk-safe">{legit} Legitimate</span>
            {susp > 0 && <span className="badge-risk risk-medium">{susp} Suspicious</span>}
            <span className="badge-risk" style={{ color: 'var(--text-secondary)' }}>{rows.length} Total</span>
          </div>
        </div>
        <div className="table-responsive">
          <table className="table table-hover align-middle">
            <thead>
              <tr>
                <th style={{ width: '40px' }}>#</th>
                <th>Subject / Content Snippet</th>
                <th>ML Verdict</th>
                <th>Risk Score</th>
                <th>Trust</th>
                <th>Origin Country</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, idx) => {
                const risk = r.risk_assessment || {}
                const ml = r.ml || {}
                const geo = r.geo || {}
                const pred = (ml.prediction || 'unknown').toLowerCase()
                const riskLevel = String(risk.risk_level || 'Unknown').toLowerCase()
                const rawSnippet = String(r.snippet || r.body || '').trim()
                const displaySnippet = rawSnippet.length > 80 ? rawSnippet.substring(0, 80) + '...' : (rawSnippet || 'No content preview')

                return (
                  <tr key={idx}>
                    <td className="text-muted font-monospace">{idx + 1}</td>
                    <td style={{ maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={rawSnippet}>
                      {displaySnippet}
                    </td>
                    <td>
                      <span className={`badge-risk ${pred === 'phishing' ? 'risk-critical' : pred === 'suspicious' ? 'risk-medium' : 'risk-safe'}`}>
                        <i className={`fas ${pred === 'phishing' ? 'fa-triangle-exclamation' : 'fa-check'} me-1`} style={{ fontSize: '0.7rem' }}></i>
                        {pred.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span className={`badge-risk risk-${riskLevel}`}>
                        {risk.risk_level || 'Unknown'} ({risk.risk_score || 0})
                      </span>
                    </td>
                    <td className="font-monospace" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                      {r.forensic?.trust_score !== undefined ? `${r.forensic.trust_score}%` : '-'}
                    </td>
                    <td>
                      <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'JetBrains Mono' }}>
                        {geo.country_code || 'XX'}
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  return (
    <div className="container-fluid p-0">
      {/* Page Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 className="fw-bold mb-1">
            <i className="fas fa-envelope-open-text text-info me-2"></i> Email Threat Scanner
          </h4>
          <p className="text-muted mb-0" style={{ fontSize: '0.88rem' }}>
            Choose from three distinct scan modalities: live inbox sync, curated test payloads, or custom email ingestion.
          </p>
        </div>
      </div>

      {/* 3 Core Scanner Modalities */}
      <div className="row g-3">
        {/* MODALITY 1: Real-Time Gmail Scanner */}
        <div className="col-lg-4 col-md-6">
          <div className="card p-4 h-100 d-flex flex-column" style={{ borderTop: '3px solid #EA4335' }}>
            <div className="d-flex align-items-center gap-2 mb-2">
              <i className="fab fa-google text-danger" style={{ fontSize: '1.2rem' }}></i>
              <h6 className="fw-bold mb-0">1. Real Inbox (Gmail API)</h6>
            </div>
            <p className="text-muted mb-3" style={{ fontSize: '0.83rem', minHeight: '38px' }}>
              Connect via OAuth refresh token to inspect live inbox headers, DKIM records, and relay hops in real time.
            </p>

            <div className="d-flex gap-2 mb-3">
              <input
                type="number"
                className="form-control"
                style={{ width: '80px', textAlign: 'center' }}
                value={gmailCount}
                min={1}
                max={25}
                onChange={(e) => setGmailCount(Math.max(1, parseInt(e.target.value) || 1))}
              />
              <button
                className="btn btn-danger flex-grow-1"
                onClick={scanGmail}
                disabled={busy !== null}
              >
                <i className={`fas ${busy === 'gmail' ? 'fa-spinner fa-spin' : 'fa-satellite-dish'}`}></i>
                {busy === 'gmail' ? 'Connecting...' : 'Scan Inbox'}
              </button>
            </div>

            {gmailStatus && (
              <div className={`text-${gmailStatus.kind} mb-2`} style={{ fontSize: '0.8rem' }}>
                {gmailStatus.text}
              </div>
            )}

            <div className="mt-auto pt-2 border-top" style={{ borderColor: 'var(--border)', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              <i className="fas fa-key me-1 text-warning"></i> Requires server OAuth token
            </div>
          </div>
        </div>

        {/* MODALITY 2: Pre-Loaded Sample Threat Dataset */}
        <div className="col-lg-4 col-md-6">
          <div className="card p-4 h-100 d-flex flex-column" style={{ borderTop: '3px solid var(--accent-cyan)' }}>
            <div className="d-flex align-items-center gap-2 mb-2">
              <i className="fas fa-vial text-info" style={{ fontSize: '1.2rem' }}></i>
              <h6 className="fw-bold mb-0">2. Pre-Loaded Samples</h6>
            </div>
            <p className="text-muted mb-3" style={{ fontSize: '0.83rem', minHeight: '38px' }}>
              Instant offline evaluation using realistic phishing, banking OTP fraud, CEO BEC scams, and legitimate emails.
            </p>

            <div className="d-flex gap-2 mb-3">
              <input
                type="number"
                className="form-control"
                style={{ width: '80px', textAlign: 'center' }}
                value={sampleCount}
                min={1}
                max={8}
                onChange={(e) => setSampleCount(Math.max(1, parseInt(e.target.value) || 1))}
              />
              <button
                className="btn btn-primary flex-grow-1"
                onClick={() => scanSample(sampleCount)}
                disabled={busy !== null}
              >
                <i className={`fas ${busy === 'sample' ? 'fa-spinner fa-spin' : 'fa-play'}`}></i>
                {busy === 'sample' ? 'Scanning...' : 'Run Samples'}
              </button>
            </div>

            {sampleStatus && (
              <div className={`text-${sampleStatus.kind} mb-2`} style={{ fontSize: '0.8rem' }}>
                {sampleStatus.text}
              </div>
            )}

            <div className="mt-auto pt-2 border-top d-flex justify-content-between align-items-center" style={{ borderColor: 'var(--border)', fontSize: '0.76rem' }}>
              <span className="text-success"><i className="fas fa-check-circle me-1"></i> Ready instantly</span>
              <button
                className="btn btn-sm btn-outline-secondary py-0"
                style={{ fontSize: '0.72rem' }}
                onClick={() => scanSample(8)}
                disabled={busy !== null}
              >
                Run All 8
              </button>
            </div>
          </div>
        </div>

        {/* MODALITY 3: Manual Direct Input (.EML / Custom Text) */}
        <div className="col-lg-4 col-md-12">
          <div className="card p-4 h-100 d-flex flex-column" style={{ borderTop: '3px solid var(--primary)' }}>
            <div className="d-flex align-items-center gap-2 mb-2">
              <i className="fas fa-keyboard text-primary" style={{ fontSize: '1.2rem' }}></i>
              <h6 className="fw-bold mb-0">3. Custom Input & File Upload</h6>
            </div>
            <p className="text-muted mb-3" style={{ fontSize: '0.83rem', minHeight: '38px' }}>
              Paste raw headers and message bodies for custom inspection, or upload an exported .eml file.
            </p>

            {/* Sub-selector pills */}
            <div className="d-flex gap-2 mb-3">
              <button
                className={`btn btn-sm flex-grow-1 ${manualMode === 'text' ? 'btn-primary' : 'btn-outline-secondary'}`}
                onClick={() => setManualMode('text')}
              >
                <i className="fas fa-paste me-1"></i> Paste Text
              </button>
              <button
                className={`btn btn-sm flex-grow-1 ${manualMode === 'file' ? 'btn-primary' : 'btn-outline-secondary'}`}
                onClick={() => setManualMode('file')}
              >
                <i className="fas fa-file-arrow-up me-1"></i> Upload .EML
              </button>
            </div>

            <div className="mt-auto pt-2 border-top" style={{ borderColor: 'var(--border)', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              <i className="fas fa-microchip me-1 text-info"></i> Direct ML inference pipeline
            </div>
          </div>
        </div>
      </div>

      {/* Manual Modality Working Area */}
      <div className="row mt-3">
        <div className="col-12">
          {manualMode === 'text' ? (
            <div className="card p-4">
              <div className="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
                <h6 className="fw-bold mb-0">
                  <i className="fas fa-paste text-info me-2"></i> Custom Email Text Analysis
                </h6>
                <div className="d-flex align-items-center gap-1 flex-wrap">
                  <span className="text-muted me-1" style={{ fontSize: '0.78rem' }}>Insert Template:</span>
                  {QUICK_INSERTS.map((q) => (
                    <button
                      key={q.key}
                      className="btn btn-sm btn-outline-secondary py-1 px-2"
                      style={{ fontSize: '0.74rem' }}
                      onClick={() => insertSample(q.key)}
                    >
                      <i className={`fas ${q.icon} me-1 text-${q.kind}`}></i> {q.label}
                    </button>
                  ))}
                </div>
              </div>
              <textarea
                className="form-control mb-3 mono"
                rows={10}
                style={{ fontSize: '0.84rem', lineHeight: 1.45 }}
                placeholder="Paste raw email headers and body here (e.g. From:, Subject:, Received: headers)..."
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <div className="d-flex gap-2">
                <button
                  className="btn btn-primary"
                  onClick={scanText}
                  disabled={busy !== null || !text.trim()}
                >
                  <i className={`fas ${busy === 'text' ? 'fa-spinner fa-spin' : 'fa-brain'}`}></i>
                  {busy === 'text' ? 'Evaluating Model...' : 'Analyze with ML'}
                </button>
                <button className="btn btn-outline-secondary" onClick={() => setText('')} disabled={!text}>
                  <i className="fas fa-eraser"></i> Clear
                </button>
              </div>
            </div>
          ) : (
            <div className="card p-4">
              <h6 className="fw-bold mb-3">
                <i className="fas fa-file-arrow-up text-info me-2"></i> Upload Raw .EML Message File
              </h6>
              <div
                className="upload-zone mb-3"
                onClick={() => fileRef.current?.click()}
              >
                <div className="icon">
                  <i className="fas fa-file-code"></i>
                </div>
                <h5>Select or Drop an .EML File</h5>
                <p>RFC 822 / MIME compliant email file exported from Gmail, Outlook, or Thunderbird</p>
                <input
                  ref={fileRef}
                  type="file"
                  className="d-none"
                  accept=".eml,.txt"
                  onChange={(e) => e.target.files?.[0] && onEmlFile(e.target.files[0])}
                />
              </div>

              {emlName && (
                <div className="d-flex justify-content-between align-items-center p-2 rounded mb-3" style={{ background: 'var(--bg-input)', border: '1px solid var(--border)' }}>
                  <span className="font-monospace" style={{ fontSize: '0.85rem' }}>
                    <i className="fas fa-file me-2 text-info"></i> {emlName}
                  </span>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={analyzeEml}
                    disabled={busy !== null}
                  >
                    <i className={`fas ${busy === 'eml' ? 'fa-spinner fa-spin' : 'fa-search'}`}></i>
                    {busy === 'eml' ? 'Parsing...' : 'Analyze File'}
                  </button>
                </div>
              )}

              {emlStatus && (
                <div className={`text-${emlStatus.kind} mb-2`} style={{ fontSize: '0.85rem' }}>
                  {emlStatus.text}
                </div>
              )}

              {emlPreview && (
                <div>
                  <small className="text-muted font-monospace d-block mb-1">Preview (first 3,000 characters):</small>
                  <pre
                    className="mono"
                    style={{
                      maxHeight: '160px',
                      overflow: 'auto',
                      fontSize: '0.78rem',
                      background: 'var(--bg-input)',
                      padding: '12px',
                      borderRadius: '8px',
                      border: '1px solid var(--border)',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {emlPreview}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Results Container */}
      {results && <div className="mt-4">{results}</div>}
    </div>
  )
}
