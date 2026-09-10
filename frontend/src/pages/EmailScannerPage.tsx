import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { predBadgeBg, riskBadgeBg } from '../lib/format'

// --- Pre-built sample emails (same content as the Jinja template) ---
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

If you have any questions or notice an activity you do not recognize, please contact our customer support team through the contact information provided on our official website.

Thank you,
Customer Support Team
Bank of America
https://www.bankofamerica.com`,

  legit_application: `From: sabarish@gmail.com
Subject: Application for Software Developer Internship
Date: Mon, 25 Aug 2026 14:30:00 +0530
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Reply-To: sabarish@gmail.com

Dear Sir/Madam,

I hope you are doing well.

I am writing to introduce myself and express my interest in discussing the relevant opportunity/project with you. I would appreciate the opportunity to present my ideas, demonstrate the work completed so far, and receive your valuable feedback.

Please let me know a convenient date and time for a brief discussion or demonstration. I would be happy to provide any additional information required beforehand.

Thank you for your time and consideration. I look forward to hearing from you.

Best regards,
Sanjai R.
B.Tech - Computer Science and Engineering
Panimalar Engineering College`,

  legit_welcome: `From: noreply@freebuff.io
Subject: Welcome to Freebuff - Your Account is Ready
Date: Mon, 25 Aug 2026 11:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass

Hi Sabarish,

Welcome to Freebuff! My name is James, and I'll be your point of contact.

We're excited to have you on board. Your account has been set up and you can start using all features right away.

Here's what you can do next:
1. Complete your profile setup
2. Explore the dashboard
3. Connect your email accounts

If you need any help, feel free to reach out.

Best,
James
Freebuff Team`,

  phish_paypal: `From: security@paypa1-alerts.com
Subject: URGENT: Your PayPal Account Has Been Limited!
Date: Mon, 25 Aug 2026 10:30:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 185.220.101.34
Received: from mail.evil-server.ru (185.220.101.34) by mx.gmail.com

Dear Valued Customer,

We have detected unusual activity on your PayPal account. Your account has been temporarily limited due to multiple sign-in attempts from an unrecognized device in Moscow, Russia.

To restore full access to your account, please verify your identity within 24 hours or your account will be permanently suspended.

Click the link below to verify your account:
http://192.168.1.100/paypal-secure/verify?id=38291

You will need to confirm:
- Your full name
- Credit card number
- PayPal password
- Social Security Number

This is a mandatory security measure. Failure to verify will result in permanent account closure.

Thank you for your immediate attention.

PayPal Security Team`,

  phish_bank: `From: alerts@secure-banking-verify.com
Subject: [ACTION REQUIRED] Unusual Transaction Detected - Verify Now!
Date: Mon, 25 Aug 2026 08:15:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 45.77.65.211
Received: from smtp-relay.cn (45.77.65.211) by mx.gmail.com

Dear Customer,

We have detected an unauthorized transaction of $2,847.50 on your account ending in ****4521.

Transaction Details:
- Amount: $2,847.50
- Merchant: UNKNOWN INTERNATIONAL TRANSFER
- Location: Lagos, Nigeria
- Date: August 25, 2026 03:42 UTC

If this was NOT you, immediately secure your account by clicking below:
http://45.77.65.211/bank-security/verify?acct=4521&ref=TX9281

You must verify within 1 hour or the transaction will be processed and funds deducted permanently.

DO NOT reply to this email. Call us at 1-800-555-0199 (SCAM NUMBER).

Your Bank Security Team`,

  phish_prize: `From: winner@lottery-intl-2026.com
Subject: CONGRATULATIONS! You Have Won $5,000,000!!!
Date: Mon, 25 Aug 2026 06:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 91.219.236.88
Received: from lotto-server.net (91.219.236.88) by mx.gmail.com

DEAR WINNER,

CONGRATULATIONS!!! You have been selected as the winner of the INTERNATIONAL LOTTERY PROGRAM 2026.

Your email was randomly selected from over 50 million email addresses worldwide.

YOU HAVE WON: $5,000,000.00 USD (FIVE MILLION DOLLARS)

To claim your prize, you must respond within 48 HOURS and provide:
1. Full legal name
2. Home address
3. Phone number
4. Bank account details (for wire transfer)
5. Copy of your passport or ID

A processing fee of $150 is required to release your winnings. Send via Western Union to our agent.

Send your details to: claim@lottery-intl-2026.com

Dr. James Morrison
International Lottery Commission`,

  suspicious_bec: `From: ceo@company-work-mail.com
Subject: Urgent - Confidential Wire Transfer Required
Date: Mon, 25 Aug 2026 15:45:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Reply-To: johnsmith.private@gmail.com
X-Originating-IP: 103.25.48.12

Hi,

I need you to process a wire transfer urgently. I'm in a meeting and can't talk.

Please transfer $47,500 to the following account immediately:

Account Name: Global Tech Solutions LLC
Bank: Chase Bank
Routing: 021000021
Account: 3847291056

This is for a confidential acquisition. Do NOT discuss with anyone else. I'll explain when I'm out of the meeting.

Thanks,
John Smith
CEO

Sent from my iPhone`,
}

const QUICK_INSERTS: { key: string; label: string; kind: string; icon: string }[] = [
  { key: 'legit_statement', label: 'Legit: Monthly Statement', kind: 'green', icon: 'fa-check-circle' },
  { key: 'legit_application', label: 'Legit: Job Application', kind: 'green', icon: 'fa-check-circle' },
  { key: 'legit_welcome', label: 'Legit: Welcome Email', kind: 'green', icon: 'fa-check-circle' },
  { key: 'phish_paypal', label: 'Phishing: PayPal Alert', kind: 'red', icon: 'fa-exclamation-triangle' },
  { key: 'phish_bank', label: 'Phishing: Bank OTP', kind: 'red', icon: 'fa-exclamation-triangle' },
  { key: 'phish_prize', label: 'Phishing: Prize Won', kind: 'red', icon: 'fa-exclamation-triangle' },
  { key: 'suspicious_bec', label: 'Suspicious: CEO Wire', kind: 'orange', icon: 'fa-exclamation-circle' },
]

const INSERT_BG: Record<string, string> = {
  green: 'background:#1b5e20;color:#fff;border:1px solid #2e7d32',
  red: 'background:#b71c1c;color:#fff;border:1px solid #c62828',
  orange: 'background:#e65100;color:#fff;border:1px solid #ef6c00',
}

type Status = { text: string; kind: string } | null

// Subcomponent for individual email scan result card with inline URL & QR details
function ScanResultCard({ result, index }: { result: any; index: number }) {
  const [expanded, setExpanded] = useState(false)

  const risk = result.risk_assessment || {}
  const ml = result.ml || {}
  const geo = result.geo || {}
  const pred = ml.prediction || result.prediction || 'unknown'
  const urlIntel = result.url_intelligence || {}
  const qrAnalysis = result.qr_analysis || {}
  const forensic = result.forensic || {}
  const urlsFound: string[] = result.urls_found || (urlIntel.details ? Object.keys(urlIntel.details) : [])

  const hasQr = qrAnalysis.qr_detected || (qrAnalysis.payloads && qrAnalysis.payloads.length > 0)
  const isQrishing = qrAnalysis.qrishing_threat
  const urlCount = urlIntel.total_urls !== undefined ? urlIntel.total_urls : urlsFound.length
  const maxUrlRisk = urlIntel.max_risk_score || 0
  const urlThreats: string[] = urlIntel.url_threats || []

  return (
    <div className="card mb-3 shadow-sm border-0" style={{ background: '#121625', border: '1px solid #1e293b', borderRadius: '12px' }}>
      {/* Summary Header */}
      <div className="card-header bg-transparent border-bottom p-3 d-flex flex-wrap align-items-center justify-content-between gap-2" style={{ borderColor: '#1e293b' }}>
        <div className="d-flex align-items-center gap-3">
          <span className="badge bg-secondary rounded-pill px-3 py-2" style={{ fontSize: '0.85rem' }}>#{index + 1}</span>
          <div>
            <strong className="text-white d-block" style={{ fontSize: '0.95rem' }}>{result.email_id || `Email #${index + 1}`}</strong>
            <div className="text-muted small" style={{ maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {result.snippet || result.body || 'No text preview'}
            </div>
          </div>
        </div>

        <div className="d-flex align-items-center flex-wrap gap-2">
          {/* ML Verdict */}
          <span className={'badge bg-' + predBadgeBg(pred)} style={{ padding: '6px 12px' }}>
            <i className="fas fa-brain me-1"></i> {String(pred).toUpperCase()} ({((ml.confidence || result.confidence || 0) * 100).toFixed(0)}%)
          </span>

          {/* Risk Score */}
          <span className={'badge bg-' + riskBadgeBg(risk.risk_level)} style={{ padding: '6px 12px' }}>
            <i className="fas fa-shield-alt me-1"></i> Risk: {risk.risk_level || '?'} ({risk.risk_score || 0}/100)
          </span>

          {/* URL Threat Pill */}
          <span className={`badge ${urlCount > 0 ? (maxUrlRisk >= 60 ? 'bg-danger' : 'bg-info text-dark') : 'bg-dark text-muted'}`} style={{ padding: '6px 12px' }}>
            <i className="fas fa-link me-1"></i> {urlCount} URL{urlCount !== 1 ? 's' : ''} {maxUrlRisk > 0 ? `(Risk: ${maxUrlRisk})` : ''}
          </span>

          {/* QR Code Pill */}
          {hasQr ? (
            <span className={`badge ${isQrishing ? 'bg-danger' : 'bg-warning text-dark'}`} style={{ padding: '6px 12px' }}>
              <i className="fas fa-qrcode me-1"></i> {isQrishing ? '🚨 QRishing Threat' : 'QR Found'}
            </span>
          ) : (
            <span className="badge bg-dark text-muted" style={{ padding: '6px 12px' }}>
              <i className="fas fa-qrcode me-1"></i> No QR
            </span>
          )}

          {/* Expand Details button */}
          <button
            className="btn btn-sm btn-outline-info ms-2"
            onClick={() => setExpanded(!expanded)}
          >
            <i className={`fas fa-chevron-${expanded ? 'up' : 'down'} me-1`}></i>
            {expanded ? 'Hide Details' : 'View Threat Details'}
          </button>
        </div>
      </div>

      {/* Expanded Details Body */}
      {expanded && (
        <div className="card-body p-4" style={{ background: '#0b0f19', borderBottomLeftRadius: '12px', borderBottomRightRadius: '12px' }}>
          <div className="row g-4">
            
            {/* 1. URL Phishing Detection Section */}
            <div className="col-md-6">
              <div className="p-3 rounded" style={{ background: '#131b2e', border: '1px solid #1e293b' }}>
                <h6 className="text-cyan fw-bold mb-3 d-flex align-items-center justify-content-between">
                  <span><i className="fas fa-globe text-info me-2"></i> URL Phishing Analysis</span>
                  <span className={`badge ${maxUrlRisk >= 70 ? 'bg-danger' : maxUrlRisk >= 40 ? 'bg-warning text-dark' : 'bg-success'}`}>
                    Max URL Risk: {maxUrlRisk}/100
                  </span>
                </h6>

                {urlCount === 0 ? (
                  <p className="text-muted small mb-0"><i className="fas fa-check-circle text-success me-1"></i> No URLs extracted from email body or headers.</p>
                ) : (
                  <>
                    {urlThreats.length > 0 && (
                      <div className="alert alert-danger p-2 mb-3 small">
                        <strong><i className="fas fa-exclamation-triangle me-1"></i> Threat Flags Detected:</strong>
                        <ul className="mb-0 ps-3 mt-1">
                          {urlThreats.map((t: string, i: number) => (
                            <li key={i}>{t}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="url-list overflow-auto pe-1" style={{ maxHeight: '220px' }}>
                      {urlsFound.map((u: string, i: number) => {
                        const detail = (urlIntel.details && urlIntel.details[u]) || {}
                        const uRisk = detail.risk_score || 0
                        const threats: string[] = detail.threats || []
                        const isIp = detail.is_ip
                        const isShortened = detail.is_shortened
                        const isTyposquat = detail.typosquatting_detected

                        return (
                          <div key={i} className="p-2 mb-2 rounded" style={{ background: '#1a233a', border: '1px solid #273554' }}>
                            <div className="d-flex justify-content-between align-items-start gap-2">
                              <span className="text-break font-monospace small text-info" style={{ fontSize: '0.82rem' }}>{u}</span>
                              <span className={`badge ${uRisk >= 70 ? 'bg-danger' : uRisk >= 40 ? 'bg-warning text-dark' : 'bg-success'}`}>
                                {uRisk}
                              </span>
                            </div>
                            <div className="mt-1 d-flex flex-wrap gap-1">
                              {isIp && <span className="badge bg-danger" style={{ fontSize: '0.7rem' }}>IP-Host</span>}
                              {isShortened && <span className="badge bg-warning text-dark" style={{ fontSize: '0.7rem' }}>URL Shortener</span>}
                              {isTyposquat && <span className="badge bg-danger" style={{ fontSize: '0.7rem' }}>Typosquat Domain</span>}
                              {threats.map((th: string, ti: number) => (
                                <span key={ti} className="badge bg-danger" style={{ fontSize: '0.7rem' }}>{th}</span>
                              ))}
                              {!isIp && !isShortened && !isTyposquat && threats.length === 0 && (
                                <span className="badge bg-secondary" style={{ fontSize: '0.7rem' }}>No direct threat flag</span>
                              )}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* 2. QR Code & QRishing Detection Section */}
            <div className="col-md-6">
              <div className="p-3 rounded" style={{ background: '#131b2e', border: '1px solid #1e293b' }}>
                <h6 className="text-warning fw-bold mb-3 d-flex align-items-center justify-content-between">
                  <span><i className="fas fa-qrcode me-2"></i> QR Code & QRishing Detection</span>
                  <span className={`badge ${isQrishing ? 'bg-danger' : hasQr ? 'bg-warning text-dark' : 'bg-secondary'}`}>
                    {isQrishing ? '🚨 QRishing Threat' : hasQr ? 'QR Code Found' : 'No QR'}
                  </span>
                </h6>

                {!hasQr ? (
                  <p className="text-muted small mb-0"><i className="fas fa-check-circle text-success me-1"></i> No embedded or attached QR code images found in this email.</p>
                ) : (
                  <>
                    <div className="alert alert-warning p-2 mb-3 small d-flex align-items-center justify-content-between">
                      <div>
                        <i className="fas fa-qrcode me-2 text-warning fs-5"></i>
                        <strong>QR Images Analyzed:</strong> {qrAnalysis.qr_count || 1}
                      </div>
                      <span className={`badge ${isQrishing ? 'bg-danger' : 'bg-success'}`}>
                        {isQrishing ? 'Malicious QR' : 'Clean Payload'}
                      </span>
                    </div>

                    {isQrishing && (
                      <div className="alert alert-danger p-2 mb-3 small">
                        <i className="fas fa-exclamation-triangle me-1"></i> <strong>QRishing Payload Warning:</strong> This QR code decodes to an external login or phishing URL attempting to bypass email body scanners!
                      </div>
                    )}

                    {/* Decoded QR Payloads */}
                    <div className="mb-2">
                      <label className="small text-muted fw-bold d-block mb-1">Decoded QR Payloads:</label>
                      {(qrAnalysis.payloads || []).map((p: string, pi: number) => (
                        <div key={pi} className="p-2 mb-2 rounded font-monospace small" style={{ background: '#1a233a', border: '1px solid #eab308', color: '#fef08a' }}>
                          <div className="d-flex align-items-center gap-2">
                            <i className="fas fa-terminal text-warning"></i>
                            <span className="text-break">{p}</span>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Details sources */}
                    {qrAnalysis.details && qrAnalysis.details.length > 0 && (
                      <div className="mt-2">
                        <span className="small text-muted">Image Sources:</span>
                        <div className="d-flex flex-wrap gap-1 mt-1">
                          {qrAnalysis.details.map((d: any, di: number) => (
                            <span key={di} className="badge bg-dark border border-secondary text-light" style={{ fontSize: '0.75rem' }}>
                              <i className="fas fa-image me-1 text-info"></i> {d.source}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>

            {/* 3. Composite Risk Breakdown & Forensic Headers */}
            <div className="col-12">
              <div className="p-3 rounded" style={{ background: '#131b2e', border: '1px solid #1e293b' }}>
                <h6 className="text-white fw-bold mb-3 d-flex align-items-center gap-2">
                  <i className="fas fa-layer-group text-primary"></i> Risk Score & Signal Breakdown
                </h6>
                <div className="row g-3 text-center">
                  <div className="col-md-2 col-4">
                    <div className="p-2 rounded" style={{ background: '#1a233a' }}>
                      <div className="text-muted small">ML Text</div>
                      <div className="fw-bold text-white">{risk.breakdown?.ml_prediction || 0}/100</div>
                    </div>
                  </div>
                  <div className="col-md-2 col-4">
                    <div className="p-2 rounded" style={{ background: '#1a233a' }}>
                      <div className="text-muted small">URL Risk</div>
                      <div className="fw-bold text-info">{risk.breakdown?.url_intelligence || 0}/100</div>
                    </div>
                  </div>
                  <div className="col-md-2 col-4">
                    <div className="p-2 rounded" style={{ background: '#1a233a' }}>
                      <div className="text-muted small">Threat Intel</div>
                      <div className="fw-bold text-warning">{risk.breakdown?.threat_intel || 0}/100</div>
                    </div>
                  </div>
                  <div className="col-md-2 col-4">
                    <div className="p-2 rounded" style={{ background: '#1a233a' }}>
                      <div className="text-muted small">Auth Check</div>
                      <div className="fw-bold text-danger">{risk.breakdown?.authentication || 0}/100</div>
                    </div>
                  </div>
                  <div className="col-md-2 col-4">
                    <div className="p-2 rounded" style={{ background: '#1a233a' }}>
                      <div className="text-muted small">Geo Risk</div>
                      <div className="fw-bold text-light">{risk.breakdown?.geolocation || 0}/100</div>
                    </div>
                  </div>
                  <div className="col-md-2 col-4">
                    <div className="p-2 rounded" style={{ background: '#1a233a' }}>
                      <div className="text-muted small">Trust Score</div>
                      <div className="fw-bold text-success">{forensic.trust_score || 50}%</div>
                    </div>
                  </div>
                </div>

                {geo.country_code && (
                  <div className="mt-3 small text-muted d-flex align-items-center gap-3 flex-wrap">
                    <span><i className="fas fa-map-marker-alt me-1 text-danger"></i> Origin IP: <b>{forensic.routing?.origin_ip || result.origin_ip || 'N/A'}</b></span>
                    <span><i className="fas fa-globe me-1 text-info"></i> Country: <b>{geo.country_code} ({geo.city || 'Unknown'})</b></span>
                    <span><i className="fas fa-building me-1 text-warning"></i> Org: <b>{geo.org || 'Unknown'}</b></span>
                  </div>
                )}
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  )
}

export default function EmailScannerPage() {
  const [gmailStatus, setGmailStatus] = useState<Status>(null)
  const [sampleStatus, setSampleStatus] = useState<Status>(null)
  const [busy, setBusy] = useState<string | null>(null) // which action is running
  const [showManual, setShowManual] = useState(false)
  const [showUpload, setShowUpload] = useState(false)
  const [text, setText] = useState('')
  const [results, setResults] = useState<React.ReactNode | null>(null)
  const [emlPreview, setEmlPreview] = useState('')
  const [emlName, setEmlName] = useState('')
  const fileRef = useRef<HTMLInputElement | null>(null)
  const textAreaRef = useRef<HTMLTextAreaElement | null>(null)

  const toggleManual = () => {
    setShowUpload(false)
    setShowManual((v) => !v)
  }
  const toggleUpload = () => {
    setShowManual(false)
    setShowUpload((v) => !v)
  }

  const insertSample = (key: string) => {
    setText(SAMPLE_EMAILS[key] || '')
    setShowUpload(false)
    setShowManual(true)
  }

  // ---------- Results rendering ----------
  const renderResults = (rows: any[], title: string) => {
    if (!rows || !rows.length) {
      setResults(
        <div className="card p-4">
          <p className="text-muted mb-0">No results to display</p>
        </div>,
      )
      return
    }
    const phishing = rows.filter((r) => (r.ml?.prediction || r.prediction) === 'phishing').length
    const legit = rows.filter((r) => (r.ml?.prediction || r.prediction) === 'legitimate').length
    const susp = rows.filter((r) => (r.ml?.prediction || r.prediction) === 'suspicious').length

    setResults(
      <div className="card p-4 shadow-sm" style={{ background: '#0b0f19', border: '1px solid #1e293b' }}>
        <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
          <h5 className="mb-0 text-white fw-bold">
            <i className="fas fa-shield-virus text-cyan me-2"></i> {title} Findings
          </h5>
          <div className="d-flex gap-2">
            <span className="badge bg-danger px-3 py-2 fs-6">{phishing} Phishing</span>
            <span className="badge bg-success px-3 py-2 fs-6">{legit} Legitimate</span>
            {susp > 0 && <span className="badge bg-warning px-3 py-2 fs-6 text-dark">{susp} Suspicious</span>}
            <span className="badge bg-secondary px-3 py-2 fs-6">{rows.length} Total</span>
          </div>
        </div>

        <div className="scan-list mt-3">
          {rows.map((r, idx) => (
            <ScanResultCard key={idx} result={r} index={idx} />
          ))}
        </div>
      </div>,
    )
  }

  // ---------- Scan flows ----------
  const scanGmail = async () => {
    setBusy('gmail')
    setGmailStatus({ text: 'Connecting to Gmail and fetching emails...', kind: 'info' })
    try {
      const data = await api.scanGmail(5)
      if (data.error) setGmailStatus({ text: '❌ ' + data.error, kind: 'danger' })
      else {
        setGmailStatus({ text: `✅ Scanned ${data.count} real emails from Gmail`, kind: 'success' })
        renderResults(data.results || [], 'Gmail Live Scan')
      }
    } catch (e: any) {
      setGmailStatus({ text: '❌ Error: ' + String(e.message || e), kind: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  const scanSample = async (count = 5) => {
    setBusy('sample')
    setSampleStatus({ text: 'Analyzing sample emails...', kind: 'info' })
    try {
      const data = await api.scanSample(count)
      if (data.error) setSampleStatus({ text: '❌ ' + data.error, kind: 'danger' })
      else {
        setSampleStatus({ text: `✅ Analyzed ${data.count} sample threat emails`, kind: 'success' })
        renderResults(data.results || [], 'Sample Data Test')
      }
    } catch (e: any) {
      setSampleStatus({ text: '❌ Error: ' + String(e.message || e), kind: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  const scanText = async () => {
    if (!text.trim()) {
      alert('Please paste some email text first.')
      return
    }
    setBusy('text')
    try {
      const data = await api.scanText(text)
      renderResults([data], 'Manual Text Scan')
    } catch (e: any) {
      alert('Error: ' + String(e.message || e))
    } finally {
      setBusy(null)
    }
  }

  const onEmlFile = (file: File) => {
    if (!file) return
    setEmlName(file.name)
    const reader = new FileReader()
    reader.onload = (e) => setEmlPreview(String(e.target?.result || '').substring(0, 3000))
    reader.readAsText(file)
  }

  const analyzeEml = async () => {
    const file = fileRef.current?.files?.[0]
    if (!file) {
      alert('Please select an .eml file first.')
      return
    }
    setBusy('eml')
    try {
      const textContent = await file.text()
      const data = await api.scanText(textContent)
      renderResults([data], `.eml File Scan: ${file.name}`)
    } catch (e: any) {
      alert('❌ Error: ' + String(e.message || e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="container-fluid">
      <h4 className="mb-4">
        <i className="fas fa-envelope-open-text me-2"></i> Email Scanner & Threat Intelligence
      </h4>

      <div className="row g-3">
        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6>
              <i className="fab fa-google text-danger me-2"></i> Scan Real Inbox
            </h6>
            <p className="text-muted">Connect to your Gmail and analyze recent emails in real-time.</p>
            <button
              className="btn btn-danger mb-3"
              onClick={scanGmail}
              disabled={busy !== null}
            >
              <i className={'fas ' + (busy === 'gmail' ? 'fa-spinner fa-spin me-2' : 'fa-satellite-dish me-2')}></i>{' '}
              {busy === 'gmail' ? 'Scanning...' : 'Scan Real Inbox'}
            </button>
            <div className={'text-muted' + (gmailStatus ? ' ' + gmailStatus.kind : '')} style={{ fontSize: '0.9rem' }}>
              {gmailStatus?.text}
            </div>
            <small className="text-warning mt-2">
              <i className="fas fa-exclamation-triangle me-1"></i> Requires Gmail API credentials
            </small>
          </div>
        </div>

        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6>
              <i className="fas fa-flask text-primary me-2"></i> Test with Sample Data
            </h6>
            <p className="text-muted">
              Scan realistic sample emails including phishing, URL threats, QRishing, and legitimate messages.
            </p>
            <button
              className="btn btn-primary mb-3"
              onClick={() => scanSample(5)}
              disabled={busy !== null}
            >
              <i className={'fas ' + (busy === 'sample' ? 'fa-spinner fa-spin me-2' : 'fa-vial me-2')}></i>{' '}
              {busy === 'sample' ? 'Scanning...' : 'Test with Sample Data'}
            </button>
            <div
              className={'text-muted' + (sampleStatus ? ' ' + sampleStatus.kind : '')}
              style={{ fontSize: '0.9rem' }}
            >
              {sampleStatus?.text}
            </div>
            <small className="text-success mt-2">
              <i className="fas fa-check-circle me-1"></i> No credentials required — works instantly
            </small>
          </div>
        </div>
      </div>

      {/* Quick actions */}
      <div className="row mt-3">
        <div className="col-12">
          <div className="card p-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
            <div>
              <span className="badge bg-info me-2">Quick Demo</span>
              <button
                className="btn btn-sm btn-outline-secondary"
                onClick={() => scanSample(9)}
                disabled={busy !== null}
              >
                <i className="fas fa-play me-1"></i> Run All Samples (9)
              </button>
            </div>
            <div>
              <span className="badge bg-secondary me-2">Manual</span>
              <button className="btn btn-sm btn-outline-secondary me-2" onClick={toggleManual}>
                <i className="fas fa-keyboard me-1"></i> Paste Custom Email
              </button>
              <button className="btn btn-sm btn-outline-secondary" onClick={toggleUpload}>
                <i className="fas fa-upload me-1"></i> Upload .eml File
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Manual text scan */}
      {showManual && (
        <div className="row mt-3">
          <div className="col-12">
            <div className="card p-4">
              <h6>
                <i className="fas fa-paste me-2"></i> Manual Email Scan
              </h6>
              <p className="text-muted">
                Paste full email text (headers + body) to run ML classification, URL threat detection, and QR code analysis.
              </p>
              <div className="mb-3">
                <small className="text-muted d-block mb-2">
                  <i className="fas fa-magic me-1"></i> Quick Insert — Pre-built Sample Emails:
                </small>
                <div className="d-flex flex-wrap gap-2">
                  {QUICK_INSERTS.map((q) => (
                    <button
                      key={q.key}
                      className="btn btn-sm"
                      style={{ ...parseCss(INSERT_BG[q.kind]) }}
                      onClick={() => insertSample(q.key)}
                    >
                      <i className={'fas ' + q.icon + ' me-1'}></i> {q.label}
                    </button>
                  ))}
                </div>
              </div>
              <textarea
                ref={textAreaRef}
                className="form-control mb-3 mono"
                rows={14}
                style={{ minHeight: 260, fontSize: '0.88rem' }}
                placeholder={
                  'Paste full email here (headers + body)...\n\nExample:\nFrom: security@paypa1-alerts.com\nSubject: URGENT: Your Account Has Been Limited!\n...\nLink: http://192.168.1.100/verify'
                }
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <div className="d-flex gap-2">
                <button
                  className="btn btn-success"
                  onClick={scanText}
                  disabled={busy !== null}
                >
                  <i className={'fas ' + (busy === 'text' ? 'fa-spinner fa-spin me-2' : 'fa-brain me-2')}></i>{' '}
                  Analyze Email (ML + URLs + QR)
                </button>
                <button className="btn btn-outline-secondary" onClick={() => setText('')}>
                  <i className="fas fa-eraser me-1"></i> Clear
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Upload .eml */}
      {showUpload && (
        <div className="row mt-3">
          <div className="col-12">
            <div className="card p-4">
              <h6>
                <i className="fas fa-file-upload me-2"></i> Upload .eml File
              </h6>
              <p className="text-muted">Upload an email file (.eml) for deep URL and QR code forensic analysis.</p>
              <div className="input-group mb-3">
                <input
                  ref={fileRef}
                  type="file"
                  className="form-control"
                  accept=".eml,.txt"
                  onChange={(e) => e.target.files?.[0] && onEmlFile(e.target.files[0])}
                />
                <button className="btn btn-info" onClick={analyzeEml} disabled={busy !== null}>
                  <i className={'fas ' + (busy === 'eml' ? 'fa-spinner fa-spin me-2' : 'fa-search me-2')}></i>{' '}
                  Analyze File
                </button>
              </div>
              {emlPreview && (
                <div className="mt-2">
                  <small className="text-muted">Preview ({emlName}):</small>
                  <pre
                    style={{
                      maxHeight: 200,
                      overflow: 'auto',
                      fontSize: '0.8rem',
                      background: '#1a1a2e',
                      padding: 10,
                      borderRadius: 5,
                      color: '#e0e0e0',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {emlPreview}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && <div className="mt-4">{results}</div>}
    </div>
  )
}

function parseCss(css: string): React.CSSProperties {
  const out: Record<string, string> = {}
  css.split(';').forEach((part) => {
    const idx = part.indexOf(':')
    if (idx > -1) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim()
  })
  return out as React.CSSProperties
}
