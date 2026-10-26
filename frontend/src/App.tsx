import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { ArrowRight, Check, ChevronRight, CircleHelp, ClipboardCheck, Download, ExternalLink, Github, Globe2, History, LockKeyhole, Menu, Radio, Radar, RefreshCw, ScanLine, ShieldCheck, Sparkles, X } from 'lucide-react'
import { fetchHistory, reportDownloadUrl, scanWebsite } from './api'
import type { ScanListItem, ScanReport, Severity } from './types'
import { FindingCard } from './components/FindingCard'
import { ScanCharts } from './components/ScanCharts'
import { ScoreRing } from './components/ScoreRing'

const scanStages = ['Validating public destination', 'Resolving DNS safely', 'Inspecting response controls', 'Writing evidence report']
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']

function formatDate(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

function StatusDot({ tone = 'teal' }: { tone?: 'teal' | 'amber' | 'red' | 'slate' }) {
  return <span className={`status-dot dot-${tone}`} />
}

function App() {
  const [target, setTarget] = useState('')
  const [report, setReport] = useState<ScanReport | null>(null)
  const [history, setHistory] = useState<ScanListItem[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [stageIndex, setStageIndex] = useState(0)
  const [error, setError] = useState('')
  const [active, setActive] = useState('home')
  const [mobileNav, setMobileNav] = useState(false)

  useEffect(() => {
    fetchHistory().then(setHistory).catch(() => undefined)
  }, [report])

  useEffect(() => {
    if (!isScanning) return
    const timer = window.setInterval(() => setStageIndex((value: number) => Math.min(value + 1, scanStages.length - 1)), 850)
    return () => window.clearInterval(timer)
  }, [isScanning])

  const summaryTotal = useMemo(() => report ? Object.values(report.summary as Record<string, number>).reduce((sum, count) => sum + count, 0) : 0, [report])

  const scrollTo = (id: string) => {
    setActive(id)
    setMobileNav(false)
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  async function handleScan(event?: FormEvent) {
    event?.preventDefault()
    setError('')
    setReport(null)
    setStageIndex(0)
    setIsScanning(true)
    try {
      const next = await scanWebsite(target)
      setReport(next)
      setActive('report')
      window.setTimeout(() => document.getElementById('report')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 120)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The scan could not be completed.')
    } finally {
      setIsScanning(false)
    }
  }

  return <div className="app-shell">
    <header className="topbar">
      <button className="brand" onClick={() => scrollTo('home')} aria-label="Go to SecureScan home">
        <span className="brand-mark"><ShieldCheck size={20} strokeWidth={2.3} /></span>
        <span><b>SecureScan</b><em>AI</em></span>
      </button>
      <nav className={mobileNav ? 'nav-links nav-open' : 'nav-links'}>
        <button className={active === 'home' ? 'nav-active' : ''} onClick={() => scrollTo('home')}>Home</button>
        <button className={active === 'scanner' ? 'nav-active' : ''} onClick={() => scrollTo('scanner')}>Scanner</button>
        <button className={active === 'reports' ? 'nav-active' : ''} onClick={() => scrollTo('reports')}>Reports</button>
        <button className={active === 'about' ? 'nav-active' : ''} onClick={() => scrollTo('about')}>About</button>
      </nav>
      <div className="topbar-actions"><a className="github-link" href="https://github.com/YOUR_USERNAME/securescan-ai" target="_blank" rel="noreferrer"><Github size={15} /> GitHub <ExternalLink size={12} /></a><button className="mobile-menu" onClick={() => setMobileNav((value) => !value)} aria-label="Toggle navigation">{mobileNav ? <X size={21} /> : <Menu size={21} />}</button></div>
    </header>

    <main>
      <section className="hero section-wrap" id="home">
        <div className="hero-gridline" />
        <div className="hero-copy">
          <div className="eyebrow eyebrow-bright"><StatusDot /> PASSIVE SECURITY INTELLIGENCE</div>
          <h1>Understand your website's <span>security signal.</span></h1>
          <p className="hero-lede">SecureScan AI checks public website configuration — headers, HTTPS, cookies and exposure signals — then turns the evidence into a report anyone can understand.</p>
          <div className="hero-actions"><button className="primary-button" onClick={() => scrollTo('scanner')}>Scan a public URL <ArrowRight size={17} /></button><button className="text-button" onClick={() => scrollTo('about')}>How it works <ChevronRight size={16} /></button></div>
          <div className="trust-row"><span><LockKeyhole size={14} /> No login attempts</span><span><Radar size={14} /> Bounded requests</span><span><CircleHelp size={14} /> Evidence-first</span></div>
        </div>
        <div className="hero-visual" aria-label="SecureScan signal visualization">
          <div className="visual-orbit orbit-one" /><div className="visual-orbit orbit-two" /><div className="visual-center"><div className="visual-icon"><ScanLine size={31} /></div><span>SCAN<br /><b>READY</b></span></div>
          <div className="telemetry-card telemetry-top"><span className="telemetry-label">CONTROL PLANE</span><strong>Passive checks <StatusDot /></strong><small>headers · tls · cookies</small></div>
          <div className="telemetry-card telemetry-bottom"><span className="telemetry-label">SAFETY BOUNDARY</span><strong>Public only <StatusDot tone="amber" /></strong><small>redirects revalidated</small></div>
        </div>
      </section>

      <section className="scanner-section section-wrap" id="scanner">
        <div className="section-heading"><div><span className="eyebrow">01 / SCANNER</span><h2>Start with a public URL.</h2></div><p>Use a website you own or have explicit permission to assess. SecureScan never attempts authentication or exploitation.</p></div>
        <form className="scanner-panel" onSubmit={handleScan}>
          <div className="scanner-panel-head"><div className="scanner-title"><span className="panel-icon"><Globe2 size={18} /></span><div><h3>Website target</h3><p>HTTP and HTTPS are supported</p></div></div><span className="safe-chip"><StatusDot /> Safe mode enabled</span></div>
          <div className="input-row"><div className="url-input-wrap"><span className="url-prefix">URL</span><input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://your-website.com" aria-label="Website URL" disabled={isScanning} /><button type="button" className="clear-input" onClick={() => setTarget('')} aria-label="Clear URL" disabled={!target || isScanning}><X size={15} /></button></div><button className="primary-button scan-button" type="submit" disabled={isScanning || !target.trim()}>{isScanning ? <><span className="button-spinner" /> Scanning</> : <>Scan Website <ArrowRight size={17} /> </>}</button></div>
          <div className="example-row"><span>Try an example</span>{['example.com', 'developer.mozilla.org', 'wikipedia.org'].map((example) => <button key={example} type="button" onClick={() => setTarget(`https://${example}`)}>{example}</button>)}</div>
          {isScanning && <div className="scan-progress"><div className="progress-track"><span style={{ width: `${((stageIndex + 1) / scanStages.length) * 100}%` }} /></div><div className="progress-copy"><span><StatusDot /> {scanStages[stageIndex]}…</span><span>{stageIndex + 1}/{scanStages.length}</span></div></div>}
          {error && <div className="error-banner"><CircleHelp size={17} /><div><strong>Scan not completed</strong><p>{error}</p></div><button type="button" onClick={() => setError('')} aria-label="Dismiss error"><X size={16} /></button></div>}
        </form>
      </section>

      {report && <section className="report-section section-wrap" id="report">
        <div className="section-heading report-heading"><div><span className="eyebrow">02 / REPORT</span><h2>Evidence, not guesswork.</h2></div><div className="report-actions"><a className="outline-button" href={reportDownloadUrl(report.scan_id, 'json')} download><Download size={15} /> JSON</a><a className="outline-button" href={reportDownloadUrl(report.scan_id, 'pdf')} download><Download size={15} /> PDF</a><button className="outline-button" onClick={() => scrollTo('scanner')}><RefreshCw size={15} /> Scan again</button></div></div>
        {!report.reachable && <div className="error-banner report-error"><CircleHelp size={17} /><div><strong>No complete assessment was possible</strong><p>The backend returned the actual connection result. Review the error details below and try again only if you have permission.</p></div></div>}
        <div className="report-overview">
          <div className="score-panel"><div className="score-panel-copy"><span className="eyebrow">CONFIGURATION SCORE</span><h3>{report.score_label}</h3><p>{report.score_note}</p><div className="score-meta"><span><StatusDot tone={report.score !== null && report.score !== undefined && report.score >= 75 ? 'teal' : 'amber'} /> {report.reachable ? 'Assessment completed' : 'Assessment incomplete'}</span><span>{formatDate(report.scanned_at)}</span></div></div><ScoreRing score={report.score} label={report.score_label} /></div>
          <div className="summary-panel"><div className="summary-top"><div><span className="eyebrow">FINDINGS OVERVIEW</span><h3>{summaryTotal} observation{summaryTotal === 1 ? '' : 's'}</h3></div><span className="target-host">{report.hostname}</span></div><div className="severity-strip">{severityOrder.map((severity) => <div key={severity} className={`severity-stat severity-stat-${severity}`}><span>{severity === 'informational' ? 'Info' : severity[0].toUpperCase() + severity.slice(1)}</span><strong>{report.summary[severity]}</strong></div>)}</div><div className="summary-facts"><span><LockKeyhole size={15} /> {report.tls.available ? (report.tls.expires_at ? `TLS · expires ${new Date(report.tls.expires_at).toLocaleDateString('en', { month: 'short', year: 'numeric' })}` : 'TLS negotiated') : report.tls.error || 'TLS not assessed'}</span><span><Globe2 size={15} /> {report.final_url ? new URL(report.final_url).protocol.replace(':', '').toUpperCase() : 'No final URL'}</span><span><ClipboardCheck size={15} /> {report.checks_completed} checks · {report.request_count} requests · {report.response_time_ms}ms</span></div></div>
        </div>
        {report.errors.length > 0 && <div className="notice-box"><span className="notice-icon"><CircleHelp size={16} /></span><div><strong>Scanner notes</strong>{report.errors.map((item) => <p key={item}>{item}</p>)}</div></div>}
        <ScanCharts report={report} />
        <div className="detail-section"><div className="subheading"><div><span className="eyebrow">CONTROL CHECKLIST</span><h3>Security headers</h3></div><span className="subheading-note">Visible in final response</span></div><div className="header-check-grid">{report.headers.map((header) => <div key={header.name} className={`header-check ${header.present ? 'header-present' : 'header-missing'}`}><div className="check-icon">{header.present ? <Check size={15} /> : <X size={15} />}</div><div><strong>{header.name}</strong><p>{header.present ? header.value : 'Not visible in the final response'}</p></div></div>)}</div></div>
        <div className="detail-two-col"><div className="detail-section"><div className="subheading"><div><span className="eyebrow">TRANSPORT</span><h3>HTTPS & TLS</h3></div><StatusDot tone={report.tls.valid_certificate ? 'teal' : 'amber'} /></div><div className="tls-card"><div className="tls-line"><span>HTTPS requested</span><strong>{report.tls.requested_https ? 'Yes' : 'No'}</strong></div><div className="tls-line"><span>Certificate</span><strong>{report.tls.valid_certificate === true ? 'Valid' : report.tls.valid_certificate === false ? 'Could not verify' : 'Not assessed'}</strong></div><div className="tls-line"><span>Protocol</span><strong>{report.tls.protocol || '—'}</strong></div><div className="tls-line"><span>Cert expires</span><strong>{report.tls.expires_at ? new Date(report.tls.expires_at).toLocaleDateString('en', { day: 'numeric', month: 'short', year: 'numeric' }) : '—'}</strong></div>{report.tls.error && <p className="muted-note">{report.tls.error}</p>}</div></div><div className="detail-section"><div className="subheading"><div><span className="eyebrow">SESSION STATE</span><h3>Cookie security</h3></div><span className="subheading-note">{report.cookies.length} visible</span></div>{report.cookies.length ? <div className="cookie-list">{report.cookies.map((cookie) => <div className="cookie-row" key={`${cookie.name}-${cookie.raw}`}><div><strong>{cookie.name}</strong><p>{cookie.note}</p></div><div className="cookie-flags"><span className={cookie.secure ? 'flag-on' : 'flag-off'}>Secure</span><span className={cookie.http_only ? 'flag-on' : 'flag-off'}>HttpOnly</span><span className={cookie.same_site ? 'flag-on' : 'flag-off'}>SameSite</span></div></div>)}</div> : <div className="empty-state"><Sparkles size={16} /> No Set-Cookie headers were visible in the response.</div>}</div></div>
        {report.public_signals.length > 0 && <div className="detail-section"><div className="subheading"><div><span className="eyebrow">PUBLIC SIGNALS</span><h3>Observed metadata</h3></div><span className="subheading-note">{report.public_signals.length} signal{report.public_signals.length === 1 ? '' : 's'}</span></div><ul className="signals-list">{report.public_signals.map((sig) => <li key={sig}><Radio size={13} /><span>{sig}</span></li>)}</ul></div>}
        <div className="detail-section findings-section"><div className="subheading"><div><span className="eyebrow">EVIDENCE LOG</span><h3>Detailed findings</h3></div><span className="subheading-note">Click a finding to inspect the reasoning</span></div>{report.findings.length ? <div className="finding-list">{report.findings.map((item) => <FindingCard key={item.id} item={item} />)}</div> : <div className="success-state"><span><Check size={18} /></span><div><strong>No confirmed weaknesses in the checks completed.</strong><p>This is not proof that the website is vulnerability-free; it means these passive controls did not produce a finding.</p></div></div>}</div>
        <div className="limitations-box"><div className="notice-icon"><CircleHelp size={16} /></div><div><strong>Read the scope carefully</strong>{report.limitations.map((item) => <p key={item}>{item}</p>)}</div></div>
      </section>}

      <section className="history-section section-wrap" id="reports"><div className="section-heading"><div><span className="eyebrow">03 / HISTORY</span><h2>Recent scan reports.</h2></div><p>Saved locally for this project. History is optional and can be disabled or moved to managed storage for production.</p></div>{history.length ? <div className="history-table">{history.map((item) => <button key={item.scan_id} className="history-row" onClick={() => { setTarget(item.target_url); scrollTo('scanner') }}><span className="history-site"><span className="history-icon"><History size={16} /></span><span><strong>{item.hostname}</strong><small>{item.target_url}</small></span></span><span className="history-findings">{item.finding_count} findings</span><span className="history-score">{item.score ?? '—'} <small>{item.score_label}</small></span><ChevronRight size={16} /></button>)}</div> : <div className="empty-history"><History size={21} /><h3>Your scan history will appear here.</h3><p>Run a scan above to create your first local report.</p><button className="text-button" onClick={() => scrollTo('scanner')}>Open scanner <ArrowRight size={15} /></button></div>}</section>

      <section className="about-section section-wrap" id="about"><div className="about-grid"><div><span className="eyebrow">04 / ABOUT</span><h2>A safer first look.</h2><p className="about-lede">Security can feel opaque. SecureScan AI focuses on the configuration signals you can verify from the public edge, with explanations that help a beginner decide what to investigate next.</p><button className="primary-button" onClick={() => scrollTo('scanner')}>Run a safe check <ArrowRight size={16} /></button></div><div className="about-cards"><div className="about-card"><span className="panel-icon"><LockKeyhole size={18} /></span><h3>Responsible by design</h3><p>Small request budgets, SSRF protection, redirect validation and no intrusive testing.</p></div><div className="about-card"><span className="panel-icon"><Sparkles size={18} /></span><h3>AI-assisted clarity</h3><p>Local rules turn evidence into plain language without requiring a paid API key.</p></div><div className="about-card"><span className="panel-icon"><Radar size={18} /></span><h3>Honest boundaries</h3><p>Missing headers are configuration observations, not claims of exploitability.</p></div></div></div></section>
    </main>
    <footer className="footer section-wrap"><div className="footer-brand"><span className="brand-mark"><ShieldCheck size={18} /></span><span>SecureScan AI</span></div><p>Passive website configuration checks for clearer security decisions.</p><span className="footer-note">Built for learning · Use with permission</span></footer>
  </div>
}

export default App
