import { useState } from 'react'

interface ForensicAIProps {
  caseData?: any
  isOpen?: boolean
  onClose?: () => void
}

export default function ForensicAI({ caseData, isOpen = true, onClose }: ForensicAIProps) {
  const [query, setQuery] = useState('')
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'ai'; text: string; time: string }>>([
    {
      role: 'ai',
      text: `Hello Investigator. I am FORENSIC AI. I have indexed all headers, routing hops, URLs, and authentication records for this case. Ask me anything about this investigation.`,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ])
  const [loading, setLoading] = useState(false)

  const SUGGESTED_QUESTIONS = [
    'Why is this email classified as phishing?',
    'Show suspicious evidence',
    'Trace the sender & origin IP',
    'Explain the risk score breakdown',
    'Find related attack campaign',
    'Identify MITRE ATT&CK technique',
  ]

  const handleSend = (textToSend?: string) => {
    const q = textToSend || query
    if (!q.trim()) return

    const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const userMsg = { role: 'user' as const, text: q, time: now }
    setMessages((prev) => [...prev, userMsg])
    if (!textToSend) setQuery('')
    setLoading(true)

    setTimeout(() => {
      let responseText = ''
      const lower = q.toLowerCase()

      if (lower.includes('why') || lower.includes('phishing') || lower.includes('classified')) {
        responseText = `🔴 **Primary Verdict Reasons:**\n1. Display Name Impersonation detected (Claims 'Microsoft Security', but origin domain is 'micros0ft-secure.xyz').\n2. SPF, DKIM, and DMARC checks all **FAILED**.\n3. The email contains a typosquatted credential harvesting URL with 7 VirusTotal flags.`
      } else if (lower.includes('evidence') || lower.includes('suspicious')) {
        responseText = `🔎 **Correlated Evidence Artifacts:**\n• **Origin IP:** 185.220.101.5 (Bulletproof hosting ASN, Moscow, RU)\n• **Domain Age:** Registered 11 days ago via NameCheap\n• **Header Anomaly:** Return-Path mismatch (bounce@scam-mail.net != security@micros0ft-secure.xyz)`
      } else if (lower.includes('trace') || lower.includes('sender') || lower.includes('ip')) {
        responseText = `🌐 **Mail Route Trace:**\n• Hop 1: Attacker Infra (185.220.101.5 - Moscow, RU) [Δt = 0s]\n• Hop 2: Relay Node (104.244.76.12 - Frankfurt, DE) [Δt = 1.4s]\n• Hop 3: Gateway MX (172.217.21.14 - Google Workspace) [Δt = 0.8s]\n• Hop 4: Target Victim Inbox (victim@company.com)`
      } else if (lower.includes('risk') || lower.includes('breakdown') || lower.includes('score')) {
        responseText = `📊 **Risk Score Breakdown (94/100):**\n• URL Malware & Typosquatting: **+28 pts**\n• Authentication Protocol Failures: **+22 pts**\n• Domain Age & Reputation: **+18 pts**\n• ML Neural Model Signals: **+14 pts**\n• Header & Return-Path Mismatches: **+08 pts**\n• Geo Origin Anomaly: **+04 pts**`
      } else if (lower.includes('mitre') || lower.includes('technique') || lower.includes('attack')) {
        responseText = `⚔️ **MITRE ATT&CK Mapping:**\n• **T1566.002** - Spearphishing Link\n• **T1583.001** - Acquire Infrastructure (Domains)\n• **T1036.005** - Masquerading: Impersonation`
      } else {
        responseText = `I have analyzed the evidence for this case. The sender's infrastructure matches known credential harvesting campaign #042 targeting enterprise financial accounts.`
      }

      setMessages((prev) => [
        ...prev,
        { role: 'ai', text: responseText, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) },
      ])
      setLoading(false)
    }, 600)
  }

  if (!isOpen) return null

  return (
    <div className="forensic-ai-card">
      <div className="forensic-ai-header">
        <div className="d-flex align-items-center gap-2">
          <i className="fas fa-brain text-cyan" style={{ fontSize: '1.2rem' }}></i>
          <div>
            <h6 className="mb-0 text-white fw-bold font-monospace">FORENSIC AI</h6>
            <span className="text-muted" style={{ fontSize: '0.72rem' }}>
              Autonomous Evidence Investigator
            </span>
          </div>
        </div>
        {onClose && (
          <button className="btn-close btn-close-white btn-sm" onClick={onClose} aria-label="Close" />
        )}
      </div>

      <div className="forensic-ai-body">
        {messages.map((m, idx) => (
          <div key={idx} className={`ai-msg-row ${m.role}`}>
            <div className="ai-avatar">
              {m.role === 'ai' ? <i className="fas fa-robot text-cyan" /> : <i className="fas fa-user-ninja text-warning" />}
            </div>
            <div className="ai-bubble">
              <div className="ai-bubble-text" style={{ whiteSpace: 'pre-line' }}>{m.text}</div>
              <div className="ai-bubble-time">{m.time}</div>
            </div>
          </div>
        ))}

        {loading && (
          <div className="ai-msg-row ai">
            <div className="ai-avatar"><i className="fas fa-circle-notch fa-spin text-cyan" /></div>
            <div className="ai-bubble">
              <div className="ai-bubble-text text-muted" style={{ fontSize: '0.82rem' }}>
                Analyzing header artifacts and threat intelligence...
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="forensic-ai-chips">
        <div className="text-muted font-monospace mb-1" style={{ fontSize: '0.72rem' }}>
          Suggested Investigator Prompts:
        </div>
        <div className="d-flex flex-wrap gap-1">
          {SUGGESTED_QUESTIONS.map((q, i) => (
            <button key={i} className="chip-btn" onClick={() => handleSend(q)}>
              • {q}
            </button>
          ))}
        </div>
      </div>

      <div className="forensic-ai-footer">
        <input
          type="text"
          className="forensic-ai-input"
          placeholder="Ask about this investigation..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
        />
        <button className="btn-scan px-3" onClick={() => handleSend()} disabled={loading}>
          <i className="fas fa-paper-plane"></i>
        </button>
      </div>
    </div>
  )
}
