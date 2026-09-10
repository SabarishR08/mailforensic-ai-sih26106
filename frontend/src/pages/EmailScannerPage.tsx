import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { predBadgeBg, riskBadgeBg, riskClass } from '../lib/format'

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

  const status = (set: (s: Status) => void, text: string, kind: string) => set({ text, kind })

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
      const pred = data.prediction
      const label =
        pred === 'phishing' ? '🚨 PHISHING DETECTED' : pred === 'suspicious' ? '⚠️ SUSPICIOUS' : '✅ LEGITIMATE'
      const conf = (data.confidence || 0) * 100
      setResults(
        <div className="card p-4">
          <h6>
            <i className="fas fa-brain"></i> ML Classification Result
          </h6>
          <div className="row mt-3 g-3">
            <div className="col-md-4 text-center">
              <div style={{ fontSize: '1.4rem', marginBottom: 10 }}>{label}</div>
              <span
                className={'badge bg-' + predBadgeBg(pred)}
                style={{ fontSize: '1.2rem', padding: '10px 20px' }}
              >
                {String(pred).toUpperCase()}
              </span>
            </div>
            <div className="col-md-4">
              <h6>Confidence</h6>
              <div className="progress" style={{ height: 25 }}>
                <div
                  className={'progress-bar bg-' + predBadgeBg(pred)}
                  style={{ width: conf + '%' }}
                >
                  {conf.toFixed(1)}%
                </div>
              </div>
            </div>
            <div className="col-md-4">
              <h6>Model Status</h6>
              <p>{data.model_loaded ? '✅ ML Model loaded' : '⚠️ Model not loaded — train models first'}</p>
            </div>
          </div>
        </div>,
      )
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
      const pred = data.prediction
      setResults(
        <div className="card p-4">
          <h6>
            <i className="fas fa-file-alt"></i> .eml Analysis: {file.name}
          </h6>
          <div className="row mt-2 g-3">
            <div className="col-md-4">
              <b>ML Prediction:</b>{' '}
              <span className={'badge bg-' + predBadgeBg(pred)}>{pred}</span>
            </div>
            <div className="col-md-4">
              <b>Confidence:</b> {((data.confidence || 0) * 100).toFixed(1)}%
            </div>
            <div className="col-md-4">
              <b>File Size:</b> {(file.size / 1024).toFixed(1)} KB
            </div>
          </div>
        </div>,
      )
    } catch (e: any) {
      alert('❌ Error: ' + String(e.message || e))
    } finally {
      setBusy(null)
    }
  }

  // ---------- Results rendering ----------
  const renderResults = (rows: any[], title: string) => {
    if (!rows.length) {
      setResults(
        <div className="card p-4">
          <p className="text-muted mb-0">No results to display</p>
        </div>,
      )
      return
    }
    const phishing = rows.filter((r) => r.ml?.prediction === 'phishing').length
    const legit = rows.filter((r) => r.ml?.prediction === 'legitimate').length
    const susp = rows.filter((r) => r.ml?.prediction === 'suspicious').length
    setResults(
      <div className="card p-4">
        <h6>
          <i className="fas fa-chart-bar"></i> {title} Results
        </h6>
        <div className="table-responsive">
          <table className="table table-sm table-hover">
            <thead>
              <tr>
                <th>#</th>
                <th>Preview</th>
                <th>ML Prediction</th>
                <th>Risk Level</th>
                <th>Trust Score</th>
                <th>Geo</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, idx) => {
                const risk = r.risk_assessment || {}
                const ml = r.ml || {}
                const geo = r.geo || {}
                const pred = ml.prediction || '?'
                return (
                  <tr key={idx}>
                    <td>{idx + 1}</td>
                    <td
                      style={{
                        maxWidth: 250,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {String(r.snippet || '').substring(0, 80)}...
                    </td>
                    <td>
                      <span className={'badge bg-' + predBadgeBg(pred)}>{pred}</span>
                    </td>
                    <td>
                      <span className={'badge bg-' + riskBadgeBg(risk.risk_level)}>
                        {risk.risk_level || '?'} ({risk.risk_score || 0})
                      </span>
                    </td>
                    <td>{r.forensic?.trust_score || '-'}%</td>
                    <td>{geo.country_code || '-'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <div className="mt-3">
          <span className="badge bg-danger me-2">{phishing} Phishing</span>
          <span className="badge bg-success me-2">{legit} Legitimate</span>
          {susp > 0 && <span className="badge bg-warning me-2">{susp} Suspicious</span>}
          <span className="badge bg-secondary">{rows.length} Total</span>
        </div>
      </div>,
    )
  }

  return (
    <div className="container-fluid">
      <h4 className="mb-4">
        <i className="fas fa-envelope-open-text"></i> Email Scanner
      </h4>

      <div className="row g-3">
        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6>
              <i className="fab fa-google text-danger"></i> Scan Real Inbox
            </h6>
            <p className="text-muted">Connect to your Gmail and analyze recent emails in real-time.</p>
            <button
              className="btn btn-danger mb-3"
              onClick={scanGmail}
              disabled={busy !== null}
            >
              <i className={'fas ' + (busy === 'gmail' ? 'fa-spinner fa-spin' : 'fa-satellite-dish')}></i>{' '}
              {busy === 'gmail' ? 'Scanning...' : 'Scan Real Inbox'}
            </button>
            <div className={'text-muted' + (gmailStatus ? ' ' + gmailStatus.kind : '')} style={{ fontSize: '0.9rem' }}>
              {gmailStatus?.text}
            </div>
            <small className="text-warning mt-2">
              <i className="fas fa-exclamation-triangle"></i> Requires Gmail API credentials
            </small>
          </div>
        </div>

        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6>
              <i className="fas fa-flask text-primary"></i> Test with Sample Data
            </h6>
            <p className="text-muted">
              Scan realistic sample emails including phishing, malware, and legitimate messages.
            </p>
            <button
              className="btn btn-primary mb-3"
              onClick={() => scanSample(5)}
              disabled={busy !== null}
            >
              <i className={'fas ' + (busy === 'sample' ? 'fa-spinner fa-spin' : 'fa-vial')}></i>{' '}
              {busy === 'sample' ? 'Scanning...' : 'Test with Sample'}
            </button>
            <div
              className={'text-muted' + (sampleStatus ? ' ' + sampleStatus.kind : '')}
              style={{ fontSize: '0.9rem' }}
            >
              {sampleStatus?.text}
            </div>
            <small className="text-success mt-2">
              <i className="fas fa-check-circle"></i> No credentials required — works instantly
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
                onClick={() => scanSample(8)}
                disabled={busy !== null}
              >
                <i className="fas fa-play"></i> Run All Samples (8)
              </button>
            </div>
            <div>
              <span className="badge bg-secondary me-2">Manual</span>
              <button className="btn btn-sm btn-outline-secondary" onClick={toggleManual}>
                <i className="fas fa-keyboard"></i> Paste Custom Email
              </button>
              <button className="btn btn-sm btn-outline-secondary" onClick={toggleUpload}>
                <i className="fas fa-upload"></i> Upload .eml File
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
                <i className="fas fa-paste"></i> Manual Email Scan
              </h6>
              <p className="text-muted">
                Paste full email text (headers + body) for ML classification and forensic analysis.
              </p>
              <div className="mb-3">
                <small className="text-muted d-block mb-2">
                  <i className="fas fa-magic"></i> Quick Insert — Pre-built Emails:
                </small>
                <div className="d-flex flex-wrap gap-2">
                  {QUICK_INSERTS.map((q) => (
                    <button
                      key={q.key}
                      className="btn btn-sm"
                      style={{ ...parseCss(INSERT_BG[q.kind]) }}
                      onClick={() => insertSample(q.key)}
                    >
                      <i className={'fas ' + q.icon}></i> {q.label}
                    </button>
                  ))}
                </div>
              </div>
              <textarea
                ref={textAreaRef}
                className="form-control mb-3 mono"
                rows={18}
                style={{ minHeight: 300, fontSize: '0.9rem' }}
                placeholder={
                  'Paste full email here (headers + body)...\n\nExample:\nFrom: security@paypa1-alerts.com\nSubject: URGENT: Your Account Has Been Limited!\n...'
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
                  <i className={'fas ' + (busy === 'text' ? 'fa-spinner fa-spin' : 'fa-brain')}></i>{' '}
                  Analyze with ML
                </button>
                <button className="btn btn-outline-secondary" onClick={() => setText('')}>
                  <i className="fas fa-eraser"></i> Clear
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
                <i className="fas fa-file-upload"></i> Upload .eml File
              </h6>
              <p className="text-muted">Upload an email file (.eml) for forensic analysis.</p>
              <div className="input-group mb-3">
                <input
                  ref={fileRef}
                  type="file"
                  className="form-control"
                  accept=".eml,.txt"
                  onChange={(e) => e.target.files?.[0] && onEmlFile(e.target.files[0])}
                />
                <button className="btn btn-info" onClick={analyzeEml} disabled={busy !== null}>
                  <i className={'fas ' + (busy === 'eml' ? 'fa-spinner fa-spin' : 'fa-search')}></i>{' '}
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
