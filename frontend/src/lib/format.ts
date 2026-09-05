export const RISK_COLORS: Record<string, string> = {
  critical: '#ef5350',
  high: '#ffa726',
  medium: '#ffee58',
  low: '#66bb6a',
  safe: '#42a5f5',
}

export function riskColor(level?: string | null): string {
  return RISK_COLORS[(level || 'unknown').toLowerCase()] || '#94a3b8'
}

export function riskGradient(level?: string | null): string {
  const l = (level || 'unknown').toLowerCase()
  const gradients: Record<string, string> = {
    critical: 'linear-gradient(135deg,#b71c1c,#ef5350)',
    high: 'linear-gradient(135deg,#e65100,#ff9800)',
    medium: 'linear-gradient(135deg,#f9a825,#ffeb3b)',
    low: 'linear-gradient(135deg,#1b5e20,#66bb6a)',
    safe: 'linear-gradient(135deg,#0d47a1,#42a5f5)',
  }
  return gradients[l] || 'linear-gradient(135deg,#666,#999)'
}

export function riskClass(level?: string | null): string {
  return 'risk-' + (level || 'unknown').toLowerCase()
}

export function predBadgeBg(pred: string): string {
  if (pred === 'phishing') return 'danger'
  if (pred === 'suspicious') return 'warning'
  return 'success'
}

export function riskBadgeBg(level?: string | null): string {
  const l = (level || 'unknown').toLowerCase()
  const map: Record<string, string> = {
    critical: 'danger',
    high: 'warning',
    medium: 'info',
    low: 'success',
    safe: 'secondary',
  }
  return map[l] || 'secondary'
}

export function escapeHtml(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

export function fmtTime(iso?: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

export function fmtClock(iso?: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d.getTime())) return ''
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
