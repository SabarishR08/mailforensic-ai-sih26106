import React, { useState } from 'react'

export interface SocPlaybookProps {
  scanData: any
}

export default function SocPlaybookCard({ scanData }: SocPlaybookProps) {
  const [activeTab, setActiveTab] = useState<'actions' | 'yara' | 'sigma' | 'stix'>('actions')
  const [executedActions, setExecutedActions] = useState<Record<string, boolean>>({})
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  const subject = scanData?.subject || scanData?.email_subject || 'Suspicious Email'
  const forensic = scanData?.forensic || {}
  const routing = forensic.routing || {}
  const originIp = routing.origin_ip || scanData?.geo?.ip || '185.220.101.34'
  const sender = scanData?.from || 'attacker@suspicious-domain.com'
  const domain = sender.includes('@') ? sender.split('@').pop() : 'suspicious-domain.com'
  const riskLevel = scanData?.risk_assessment?.risk_level || 'High'

  const yaraRule = `rule Email_Threat_${subject.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30)} {
    meta:
        description = "Automated YARA threat detection rule"
        author = "MailForensic AI SOC Engine"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "${riskLevel}"
        case_id = "${forensic.evidence_id || 'MF-2026-0042'}"

    strings:
        $subject = "${subject}" ascii wide nocase
        $sender = "${sender}" ascii wide nocase
        $origin_ip = "${originIp}" ascii
        $mal_domain = "${domain}" ascii wide nocase

    condition:
        2 of them
}`

  const sigmaRule = `title: Phishing Threat Detection - ${subject.substring(0, 45)}
id: sig-${Date.now().toString(36)}
status: experimental
description: Detects suspicious email transit and header anomalies matching case investigation.
author: MailForensic AI SOC Engine
logsource:
    category: email
    product: exchange
detection:
    selection_sender:
        Sender: '${sender}'
    selection_ip:
        OriginatingIP: '${originIp}'
    condition: selection_sender or selection_ip
level: ${riskLevel.toLowerCase()}
tags:
    - attack.initial_access
    - attack.t1566.002`

  const stixBundle = JSON.stringify(
    {
      type: 'bundle',
      id: `bundle--${Date.now()}`,
      spec_version: '2.1',
      objects: [
        {
          type: 'indicator',
          spec_version: '2.1',
          id: `indicator--${Date.now()}`,
          created: new Date().toISOString(),
          name: `Email Threat Indicator: ${subject}`,
          pattern: `[ipv4-addr:value = '${originIp}' OR email-message:from_email_addrs.value = '${sender}']`,
          pattern_type: 'stix',
          labels: ['malicious-activity', 'phishing'],
        },
      ],
    },
    null,
    2,
  )

  const toggleAction = (id: string) => {
    setExecutedActions((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="card p-4 my-4 border border-secondary" style={{ backgroundColor: '#121215' }}>
      <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
        <div>
          <h5 className="mb-1 text-light">
            <i className="fas fa-user-shield me-2 text-primary"></i>
            SOC Automated Containment & Threat Response Playbook
          </h5>
          <small className="text-muted font-monospace">
            Evidence Case ID: {forensic.evidence_id || 'MF-2026-0042'} | Auto-generated SOC Containment Rules
          </small>
        </div>
        <span className="badge bg-dark border border-secondary font-monospace text-light px-3 py-2">
          REMEDIATION STATUS: <strong className="text-success">READY TO EXECUTE</strong>
        </span>
      </div>

      {/* Tabs Header */}
      <ul className="nav nav-tabs border-secondary mb-3">
        <li className="nav-item">
          <button
            className={`nav-link font-monospace ${activeTab === 'actions' ? 'active bg-dark text-light border-secondary' : 'text-muted'}`}
            onClick={() => setActiveTab('actions')}
          >
            <i className="fas fa-bolt me-1"></i> Containment Actions
          </button>
        </li>
        <li className="nav-item">
          <button
            className={`nav-link font-monospace ${activeTab === 'yara' ? 'active bg-dark text-light border-secondary' : 'text-muted'}`}
            onClick={() => setActiveTab('yara')}
          >
            <i className="fas fa-code me-1"></i> YARA Rule (.yar)
          </button>
        </li>
        <li className="nav-item">
          <button
            className={`nav-link font-monospace ${activeTab === 'sigma' ? 'active bg-dark text-light border-secondary' : 'text-muted'}`}
            onClick={() => setActiveTab('sigma')}
          >
            <i className="fas fa-terminal me-1"></i> SIGMA SIEM (.yml)
          </button>
        </li>
        <li className="nav-item">
          <button
            className={`nav-link font-monospace ${activeTab === 'stix' ? 'active bg-dark text-light border-secondary' : 'text-muted'}`}
            onClick={() => setActiveTab('stix')}
          >
            <i className="fas fa-share-nodes me-1"></i> STIX 2.1 JSON
          </button>
        </li>
      </ul>

      {/* Tab 1: Containment Actions */}
      {activeTab === 'actions' && (
        <div className="row g-3">
          {[
            {
              id: 'quarantine',
              title: 'Quarantine Email across Exchange/Gmail Tenant',
              desc: `Purge messages with subject "${subject}" from target user inboxes.`,
              category: 'Mailbox Defense',
              cmd: `Search-Mailbox -TargetMailbox 'Quarantine' -SearchQuery 'Subject:"${subject}"'`,
            },
            {
              id: 'firewall',
              title: `Block Attacker Origin IP (${originIp}) on Perimeter Firewall`,
              desc: `Deploy firewall rule to block incoming connections from origin IP ${originIp}.`,
              category: 'Network Firewall',
              cmd: `iptables -A INPUT -s ${originIp} -j DROP`,
            },
            {
              id: 'dns',
              title: `Sinkhole Spoofed Domain (${domain}) in DNS Gateway`,
              desc: `Redirect lookups for ${domain} to internal DNS sinkhole.`,
              category: 'DNS Defense',
              cmd: `zone "${domain}" { type master; file "/etc/bind/db.sinkhole"; };`,
            },
            {
              id: 'pwd_reset',
              title: 'Trigger Automated Credential Reset & OAuth Token Revocation',
              desc: 'Revoke active user sessions to prevent credential harvesting access.',
              category: 'Identity Security',
              cmd: `Revoke-AzureADUserAllRefreshToken -ObjectId ${scanData?.to || 'user@company.com'}`,
            },
          ].map((action) => {
            const isDone = executedActions[action.id]
            return (
              <div key={action.id} className="col-md-6">
                <div className="p-3 rounded border border-secondary" style={{ backgroundColor: '#09090b' }}>
                  <div className="d-flex justify-content-between align-items-start mb-2">
                    <span className="badge bg-dark border border-secondary font-monospace text-muted">
                      {action.category}
                    </span>
                    <button
                      className={`btn btn-sm ${isDone ? 'btn-success' : 'btn-outline-light'}`}
                      onClick={() => toggleAction(action.id)}
                    >
                      <i className={`fas ${isDone ? 'fa-check-circle' : 'fa-play'} me-1`}></i>
                      {isDone ? 'CONTAINED & SYNCED' : 'EXECUTE ACTION'}
                    </button>
                  </div>
                  <strong className="d-block text-light mb-1">{action.title}</strong>
                  <p className="text-muted mb-2" style={{ fontSize: '0.85rem' }}>
                    {action.desc}
                  </p>
                  <pre
                    className="p-2 rounded bg-black text-success font-monospace mb-0"
                    style={{ fontSize: '0.75rem', overflowX: 'auto' }}
                  >
                    <code>{action.cmd}</code>
                  </pre>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Tab 2: YARA Rule */}
      {activeTab === 'yara' && (
        <div>
          <div className="d-flex justify-content-between align-items-center mb-2">
            <span className="text-muted font-monospace" style={{ fontSize: '0.85rem' }}>
              Autogenerated YARA signature rule for endpoint/mail gateway inspection
            </span>
            <div className="d-flex gap-2">
              <button
                className="btn btn-sm btn-outline-light font-monospace"
                onClick={() => copyToClipboard(yaraRule, 'yara')}
              >
                <i className="fas fa-copy me-1"></i>
                {copiedKey === 'yara' ? 'Copied!' : 'Copy Rule'}
              </button>
              <button
                className="btn btn-sm btn-light font-monospace"
                onClick={() => downloadFile(yaraRule, 'email_threat.yar', 'text/plain')}
              >
                <i className="fas fa-download me-1"></i> Download .yar
              </button>
            </div>
          </div>
          <pre
            className="p-3 rounded bg-black text-info font-monospace mb-0"
            style={{ fontSize: '0.85rem', lineHeight: '1.4' }}
          >
            <code>{yaraRule}</code>
          </pre>
        </div>
      )}

      {/* Tab 3: SIGMA Rule */}
      {activeTab === 'sigma' && (
        <div>
          <div className="d-flex justify-content-between align-items-center mb-2">
            <span className="text-muted font-monospace" style={{ fontSize: '0.85rem' }}>
              SIGMA SIEM query rule compatible with Splunk, Elastic, and Microsoft Sentinel
            </span>
            <div className="d-flex gap-2">
              <button
                className="btn btn-sm btn-outline-light font-monospace"
                onClick={() => copyToClipboard(sigmaRule, 'sigma')}
              >
                <i className="fas fa-copy me-1"></i>
                {copiedKey === 'sigma' ? 'Copied!' : 'Copy Rule'}
              </button>
              <button
                className="btn btn-sm btn-light font-monospace"
                onClick={() => downloadFile(sigmaRule, 'phishing_detection.yml', 'text/yaml')}
              >
                <i className="fas fa-download me-1"></i> Download .yml
              </button>
            </div>
          </div>
          <pre
            className="p-3 rounded bg-black text-warning font-monospace mb-0"
            style={{ fontSize: '0.85rem', lineHeight: '1.4' }}
          >
            <code>{sigmaRule}</code>
          </pre>
        </div>
      )}

      {/* Tab 4: STIX 2.1 JSON */}
      {activeTab === 'stix' && (
        <div>
          <div className="d-flex justify-content-between align-items-center mb-2">
            <span className="text-muted font-monospace" style={{ fontSize: '0.85rem' }}>
              STIX 2.1 Threat Intelligence indicator JSON for TAXII automated sharing
            </span>
            <div className="d-flex gap-2">
              <button
                className="btn btn-sm btn-outline-light font-monospace"
                onClick={() => copyToClipboard(stixBundle, 'stix')}
              >
                <i className="fas fa-copy me-1"></i>
                {copiedKey === 'stix' ? 'Copied!' : 'Copy STIX JSON'}
              </button>
              <button
                className="btn btn-sm btn-light font-monospace"
                onClick={() => downloadFile(stixBundle, 'stix_indicator.json', 'application/json')}
              >
                <i className="fas fa-download me-1"></i> Download .json
              </button>
            </div>
          </div>
          <pre
            className="p-3 rounded bg-black text-light font-monospace mb-0"
            style={{ fontSize: '0.85rem', lineHeight: '1.4' }}
          >
            <code>{stixBundle}</code>
          </pre>
        </div>
      )}
    </div>
  )
}
