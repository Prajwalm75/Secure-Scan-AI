export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

export type Finding = {
  id: string
  severity: Severity
  title: string
  category: string
  evidence: string
  description: string
  why_it_matters: string
  risk: string
  recommendation: string
  score_impact: number
}

export type HeaderCheck = {
  name: string
  present: boolean
  value?: string | null
  note: string
  severity: Severity
}

export type CookieCheck = {
  name: string
  secure?: boolean | null
  http_only?: boolean | null
  same_site?: string | null
  raw: string
  note: string
}

export type TlsStatus = {
  requested_https: boolean
  available?: boolean | null
  valid_certificate?: boolean | null
  expires_at?: string | null
  protocol?: string | null
  error?: string | null
}

export type ScanReport = {
  scan_id: string
  target_url: string
  normalized_url: string
  hostname: string
  scanned_at: string
  completed_at: string
  reachable: boolean
  status_code?: number | null
  final_url?: string | null
  response_time_ms?: number | null
  request_count: number
  checks_completed: number
  evidence_sufficient: boolean
  score?: number | null
  score_label: string
  score_note: string
  summary: Record<Severity, number>
  tls: TlsStatus
  headers: HeaderCheck[]
  cookies: CookieCheck[]
  public_signals: string[]
  findings: Finding[]
  errors: string[]
  limitations: string[]
}

export type ScanListItem = {
  scan_id: string
  target_url: string
  hostname: string
  scanned_at: string
  score?: number | null
  score_label: string
  finding_count: number
}
