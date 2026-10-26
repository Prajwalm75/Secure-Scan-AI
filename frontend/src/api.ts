import type { ScanListItem, ScanReport } from './types'

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')

async function parseError(response: Response): Promise<never> {
  let message = 'The request could not be completed.'
  try {
    const payload = await response.json() as { detail?: string }
    if (payload.detail) message = payload.detail
  } catch {
    // Keep the safe generic message when the backend response is not JSON.
  }
  throw new Error(message)
}

export async function scanWebsite(target_url: string): Promise<ScanReport> {
  const response = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_url }),
  })
  if (!response.ok) return parseError(response)
  return response.json() as Promise<ScanReport>
}

export async function fetchHistory(): Promise<ScanListItem[]> {
  const response = await fetch(`${API_BASE}/api/scans?limit=8`)
  if (!response.ok) return parseError(response)
  const payload = await response.json() as { items: ScanListItem[] }
  return payload.items
}

export function reportDownloadUrl(scanId: string, format: 'json' | 'pdf'): string {
  return `${API_BASE}/api/scan/${encodeURIComponent(scanId)}/report?format=${format}`
}
