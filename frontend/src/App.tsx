import { FormEvent, ReactNode, useEffect, useMemo, useState } from 'react'
import { API_URL, api, loadSession, login, logout, saveSession } from './api'
import { Empty, Status } from './components'
import { AiPage } from './pages/AiPage'
import { AnalysisHistoryPage, CurrentAnalysisPage, UploadPage } from './pages/AnalysesPage'
import { AdminPage } from './pages/AdminPage'
import { AttackGraphPage, AttackPage } from './pages/AttackPage'
import { AuditPage } from './pages/AuditPage'
import { ConnectorPage } from './pages/ConnectorPage'
import { CasePage, IncidentsPage } from './pages/IncidentsPage'
import { OverviewPage } from './pages/OverviewPage'
import { ReportPage } from './pages/ReportPage'
import { RulesPage } from './pages/RulesPage'
import { SystemPage } from './pages/SystemPage'
import { CaseOperationsPage, DetectionEngineeringPage, GraphIntelligencePage, HuntPage, IdentityPage, RealtimePage, ResponsePage, ThreatIntelPage } from './pages/AdvancedSocPages'
import { Json, Page, Session } from './types'
import { hasPermission, value } from './utils'

type NavItem = [Page, string, string, string]
type NavigationContext = { page: Page; analysisId: string; incidentId: string }
type BrowserNavigationState = NavigationContext & { threatlens: true; index: number }

const pageIds: Page[] = [
  'overview',
  'upload',
  'current',
  'analyses',
  'incidents',
  'case',
  'assistant',
  'audit',
  'rules',
  'quality',
  'attack',
  'graph',
  'connectors',
  'reports',
  'ragadmin',
  'securityadmin',
  'system',
  'realtime',
  'intel',
  'hunts',
  'caseops',
  'response',
  'detections',
  'identity',
  'graphintel',
]

function browserRoute(context: NavigationContext) {
  const params = new URLSearchParams()
  if (context.analysisId) params.set('analysis', context.analysisId)
  if (context.incidentId) params.set('incident', context.incidentId)
  const query = params.toString()
  return `#/${context.page}${query ? `?${query}` : ''}`
}

function readBrowserRoute(): NavigationContext {
  const raw = window.location.hash.replace(/^#\/?/, '')
  const [rawPage = '', rawQuery = ''] = raw.split('?', 2)
  const page = pageIds.includes(rawPage as Page) ? rawPage as Page : 'overview'
  const params = new URLSearchParams(rawQuery)
  return {
    page,
    analysisId: params.get('analysis') || sessionStorage.getItem('threatlens.current.analysis') || '',
    incidentId: params.get('incident') || sessionStorage.getItem('threatlens.current.incident') || '',
  }
}

function persistNavigationContext(context: NavigationContext) {
  if (context.analysisId) sessionStorage.setItem('threatlens.current.analysis', context.analysisId)
  if (context.incidentId) sessionStorage.setItem('threatlens.current.incident', context.incidentId)
}

const groups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'SOC OPERATIONS',
    items: [
      ['overview', 'Overview', '⌁', 'system:read'],
      ['upload', 'Upload & Analyze', '⇧', 'analysis:create'],
      ['current', 'Current Analysis', '▣', 'analysis:read'],
      ['analyses', 'Analysis History', '◫', 'analysis:read'],
      ['incidents', 'Incident Queue', '◇', 'incident:read'],
      ['case', 'Case Details', '◎', 'incident:read'],
      ['realtime', 'Real-Time Ingestion', '↯', 'ingest:read'],
      ['caseops', 'Case Operations', '☷', 'case:operate'],
    ],
  },
  {
    label: 'INVESTIGATION',
    items: [
      ['assistant', 'AI Investigation', '✦', 'rag:query'],
      ['graph', 'Attack Graph', '⌬', 'graph:read'],
      ['attack', 'MITRE ATT&CK', '⌘', 'attack:read'],
      ['rules', 'Rule Catalog', '≋', 'rule:read'],
      ['quality', 'Detection Quality', '≎', 'rule:read'],
      ['audit', 'Audit Trail', '≡', 'audit:read'],
      ['intel', 'Threat Intelligence', '◈', 'intel:read'],
      ['hunts', 'Threat Hunting', '⌕', 'hunt:execute'],
      ['response', 'Response Playbooks', '⇄', 'response:request'],
      ['detections', 'Detection Engineering', '⌁', 'detection:feedback'],
      ['identity', 'Cloud / Identity', '☁', 'ingest:read'],
      ['graphintel', 'Graph Intelligence', '⌬', 'graph:read'],
    ],
  },
  {
    label: 'PLATFORM',
    items: [
      ['connectors', 'Connector Health', '⌁', 'system:read'],
      ['reports', 'Reports', '▤', 'report:read'],
      ['ragadmin', 'AI Knowledge Admin', '◌', 'rag:manage'],
      ['securityadmin', 'Security Admin', '⚿', 'user:read'],
      ['system', 'System Health', '◉', 'system:read'],
    ],
  },
]

function Login({ onSuccess }: { onSuccess: (session: Session) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const session = await login(username, password)
      saveSession(session)
      onSuccess(session)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Login failed.')
    } finally {
      setBusy(false)
    }
  }

  return <main className="login-shell">
    <section className="login-brand">
      <div className="brand-mark">TL</div>
      <p className="eyebrow">THREATLENS AI · v0.13.0</p>
      <h1>Evidence-first<br/><span>SOC intelligence.</span></h1>
      <p className="login-copy">Deterministic detections, governed ATT&CK context, auditable case management and grounded adaptive AI in one production investigation console.</p>
      <div className="trust-row"><Status>RBAC protected</Status><Status>Grounded RAG</Status><Status>Audited</Status><Status>Feature parity</Status></div>
    </section>
    <section className="login-card">
      <p className="eyebrow">SECURE CONSOLE</p><h2>Sign in</h2><p className="muted">Use your ThreatLens analyst account.</p>
      <form onSubmit={submit}>
        <label>Username<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required /></label>
        <label>Password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
        {error && <div className="error-box">{error}</div>}
        <button className="primary" disabled={busy}>{busy ? 'Authenticating…' : 'Enter SOC Console'}</button>
      </form>
      <p className="tiny">API boundary: {API_URL || 'same-origin (/api)'}</p>
    </section>
  </main>
}

export default function App() {
  const [session, setSession] = useState<Session | null>(() => loadSession())
  const [validatingSession, setValidatingSession] = useState(Boolean(session))
  const [initialRoute] = useState<NavigationContext>(() => readBrowserRoute())
  const [page, setPage] = useState<Page>(initialRoute.page)
  const [analysisId, setAnalysisId] = useState(initialRoute.analysisId)
  const [incidentId, setIncidentId] = useState(initialRoute.incidentId)
  const [navigationIndex, setNavigationIndex] = useState(0)
  const userLabel = useMemo(() => session ? value(session.user, ['display_name', 'username'], 'Analyst') : '', [session])

  useEffect(() => {
    const expired = () => setSession(null)
    window.addEventListener('threatlens:session-expired', expired)
    return () => window.removeEventListener('threatlens:session-expired', expired)
  }, [])

  useEffect(() => {
    const current = readBrowserRoute()
    persistNavigationContext(current)

    const existing = window.history.state as BrowserNavigationState | null
    if (existing?.threatlens) {
      setNavigationIndex(existing.index)
    } else {
      window.history.replaceState(
        { ...current, threatlens: true, index: 0 } satisfies BrowserNavigationState,
        '',
        browserRoute(current),
      )
    }

    const onPopState = (event: PopStateEvent) => {
      const state = event.state as BrowserNavigationState | null
      const context = state?.threatlens ? state : readBrowserRoute()
      persistNavigationContext(context)
      setPage(context.page)
      setAnalysisId(context.analysisId)
      setIncidentId(context.incidentId)
      setNavigationIndex(state?.threatlens ? state.index : 0)
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }

    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  useEffect(() => {
    if (!session) {
      setValidatingSession(false)
      return
    }
    let cancelled = false
    setValidatingSession(true)
    void api<Json>(session, '/api/v1/auth/me')
      .then(user => {
        if (cancelled) return
        session.user = user
        saveSession(session)
        setSession({ ...session })
      })
      .catch(() => {
        if (cancelled) return
        // Only an authoritative refresh-token failure clears persisted session state.
        // Temporary API restarts/network failures during UAT must not sign the analyst out.
        if (!loadSession()) setSession(null)
      })
      .finally(() => {
        if (!cancelled) setValidatingSession(false)
      })
    return () => { cancelled = true }
  }, [])

  if (!session) return <Login onSuccess={setSession} />
  if (validatingSession) return <main className="boot-shell"><div><div className="brand-mark">TL</div><p className="eyebrow">SECURE SESSION</p><h2>Validating ThreatLens session…</h2><Empty>Refreshing identity, roles and permissions from the FastAPI authority.</Empty></div></main>

  const allowedGroups = groups
    .map(group => ({ ...group, items: group.items.filter(item => hasPermission(session.user, item[3])) }))
    .filter(group => group.items.length > 0)

  function navigate(next: Page, id = '', recordHistory = true) {
    let nextAnalysisId = analysisId
    let nextIncidentId = incidentId

    if (next === 'current' || next === 'analyses' || next === 'reports' || next === 'graph') {
      if (id) nextAnalysisId = id
    }
    if (next === 'case' || next === 'assistant' || next === 'caseops' || next === 'response' || next === 'graphintel') {
      if (id) nextIncidentId = id
    }

    const context: NavigationContext = {
      page: next,
      analysisId: nextAnalysisId,
      incidentId: nextIncidentId,
    }

    persistNavigationContext(context)
    setPage(context.page)
    setAnalysisId(context.analysisId)
    setIncidentId(context.incidentId)

    if (recordHistory) {
      const nextIndex = navigationIndex + 1
      window.history.pushState(
        { ...context, threatlens: true, index: nextIndex } satisfies BrowserNavigationState,
        '',
        browserRoute(context),
      )
      setNavigationIndex(nextIndex)
    } else {
      window.history.replaceState(
        { ...context, threatlens: true, index: navigationIndex } satisfies BrowserNavigationState,
        '',
        browserRoute(context),
      )
    }

    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  function goBack() {
    if (navigationIndex > 0) window.history.back()
  }

  async function signOut() {
    if (!session) return
    await logout(session)
    setSession(null)
  }

  let content: ReactNode
  if (page === 'overview') content = <OverviewPage session={session} navigate={navigate} />
  else if (page === 'upload') content = <UploadPage session={session} navigate={navigate} />
  else if (page === 'current') content = <CurrentAnalysisPage session={session} selectedId={analysisId} navigate={navigate} />
  else if (page === 'analyses') content = <AnalysisHistoryPage session={session} selectedId={analysisId} navigate={navigate} />
  else if (page === 'incidents') content = <IncidentsPage session={session} analysisId={analysisId} incidentId={incidentId} navigate={navigate} />
  else if (page === 'case') content = <CasePage session={session} incidentId={incidentId} navigate={navigate} />
  else if (page === 'assistant') content = <AiPage session={session} incidentId={incidentId} />
  else if (page === 'realtime') content = <RealtimePage session={session} />
  else if (page === 'intel') content = <ThreatIntelPage session={session} />
  else if (page === 'hunts') content = <HuntPage session={session} />
  else if (page === 'caseops') content = <CaseOperationsPage session={session} incidentId={incidentId} navigate={navigate} />
  else if (page === 'response') content = <ResponsePage session={session} incidentId={incidentId} />
  else if (page === 'detections') content = <DetectionEngineeringPage session={session} />
  else if (page === 'identity') content = <IdentityPage session={session} />
  else if (page === 'graphintel') content = <GraphIntelligencePage session={session} incidentId={incidentId} />
  else if (page === 'attack') content = <AttackPage session={session} />
  else if (page === 'graph') content = <AttackGraphPage session={session} analysisId={analysisId} navigate={navigate} />
  else if (page === 'rules') content = <RulesPage session={session} initialTab="Catalog" />
  else if (page === 'quality') content = <RulesPage session={session} initialTab="Quality" />
  else if (page === 'connectors') content = <ConnectorPage session={session} />
  else if (page === 'reports') content = <ReportPage session={session} analysisId={analysisId} />
  else if (page === 'audit') content = <AuditPage session={session} />
  else if (page === 'securityadmin') content = <AdminPage session={session} />
  else if (page === 'ragadmin') content = <SystemPage session={session} initialTab="Knowledge Index" />
  else content = <SystemPage session={session} initialTab="Health" />

  return <div className="app-shell">
    <aside>
      <div className="brand"><div className="brand-mark small">TL</div><div><strong>ThreatLens AI</strong><small>Industrial SOC · v0.13</small></div></div>
      <nav>{allowedGroups.map(group => <div className="nav-group" key={group.label}><small>{group.label}</small>{group.items.map(([id, label, icon]) => <button key={id} className={page === id ? 'active' : ''} onClick={() => navigate(id)}><span>{icon}</span>{label}</button>)}</div>)}</nav>
      <div className="aside-foot"><Status>API connected</Status><small>Evidence-first · Zero-trust RAG · Feature-parity console</small></div>
    </aside>
    <div className="workspace">
      <div className="topbar"><div className="topbar-left">{navigationIndex > 0 && <button className="back-btn" onClick={goBack}>← Back</button>}<span><span className="pulse"/>Production Web Platform</span></div><div className="user"><span>{userLabel}</span><button onClick={() => void signOut()}>Sign out</button></div></div>
      <div className="workflow-bar"><span>Investigation workflow</span><button className={page === 'analyses' ? 'active' : ''} onClick={() => navigate('analyses')}>Analysis History</button><b>→</b><button className={page === 'current' ? 'active' : ''} onClick={() => navigate('current', analysisId)} disabled={!analysisId}>Current Analysis</button><b>→</b><button className={page === 'incidents' ? 'active' : ''} onClick={() => navigate('incidents')}>Incident Queue</button><b>→</b><button className={page === 'case' ? 'active' : ''} onClick={() => navigate('case', incidentId)} disabled={!incidentId}>Case Details</button><b>→</b><button className={page === 'assistant' ? 'active' : ''} onClick={() => navigate('assistant', incidentId)} disabled={!incidentId || !hasPermission(session.user, 'rag:query')}>AI Investigation</button></div>
      <main className="content">{content}</main>
    </div>
  </div>
}
