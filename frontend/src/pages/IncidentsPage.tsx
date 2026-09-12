import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { AttackGraphCanvas, DataTable, Empty, ErrorBox, Header, KeyValueGrid, Notice, Panel, SearchBox, Segmented, Status, Tabs, useResource } from '../components'
import { Json, ListResponse, Page, Session } from '../types'
import { asJson, asRows, fileSizeMiB, hasPermission, sha256Hex, value } from '../utils'

const STATUS_TRANSITIONS: Record<string, string[]> = {
  open: ['open', 'investigating', 'false_positive'],
  investigating: ['investigating', 'contained', 'resolved', 'false_positive'],
  contained: ['contained', 'investigating', 'resolved'],
  resolved: ['resolved', 'investigating'],
  false_positive: ['false_positive', 'investigating'],
}
const CLOSING = new Set(['resolved', 'false_positive'])

function canModifyCase(session: Session, incident: Json): boolean {
  const updateAny = hasPermission(session.user, 'incident:update:any')
  const updateSelf = hasPermission(session.user, 'incident:update:self')
  const username = value(session.user, ['username'], '').toLowerCase()
  const assignee = value(incident, ['assignee'], '').toLowerCase()
  return updateAny || (updateSelf && (!assignee || assignee === username))
}

export function IncidentsPage({ session, analysisId, incidentId, navigate }: { session: Session; analysisId: string; incidentId: string; navigate: (page: Page, id?: string) => void }) {
  const resource = useResource<ListResponse>(session, '/api/v1/incidents?limit=1000', { items: [] })
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const rows = useMemo(() => (resource.data.items || []).filter(row => (status === 'all' || value(row, ['status'], '').toLowerCase() === status) && JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [query, resource.data.items, status])
  return <>
    <Header kicker="CASE MANAGEMENT" title="Incident Queue" subtitle="Prioritized, evidence-backed investigations with governed workflow and analyst ownership. Open any incident directly into Case Details." actions={<div className="header-actions"><button className="secondary" onClick={() => navigate('analyses')}>← Analysis History</button>{analysisId && <button className="secondary" onClick={() => navigate('current', analysisId)}>Current Analysis</button>}{incidentId && <button className="primary" onClick={() => navigate('case', incidentId)}>Resume Case →</button>}</div>} />
    <div className="toolbar"><Segmented values={['all', 'open', 'investigating', 'contained', 'resolved', 'false_positive']} active={status} onChange={setStatus} /><SearchBox value={query} onChange={setQuery} placeholder="Filter incident evidence…" /></div>
    <Panel title={`Incidents · ${rows.length}`}><ErrorBox message={resource.error} /><DataTable rows={rows} columns={['title', 'status', 'priority', 'severity', 'risk_score', 'confidence', 'assignee', 'source_count', 'entity_count', 'stage_progression', 'updated_at']} loading={resource.loading} onRow={row => navigate('case', value(row, ['incident_uuid'], ''))} rowActionLabel="Open case →" exportName="threatlens-incident-queue" /><Notice>Tip: click anywhere on an incident row or use <b>Open case →</b>. The selected case is retained when moving to AI Investigation, Attack Graph, Reports, or back to the queue.</Notice></Panel>
  </>
}

export function CasePage({ session, incidentId, navigate }: { session: Session; incidentId: string; navigate: (page: Page, id?: string) => void }) {
  const incidents = useResource<ListResponse>(session, '/api/v1/incidents?limit=1000', { items: [] })
  const security = useResource<Json>(session, '/api/v1/system/security', {})
  const [selected, setSelected] = useState(incidentId)
  useEffect(() => { if (incidentId) setSelected(incidentId) }, [incidentId])
  useEffect(() => { if (!selected && incidents.data.items?.length) setSelected(value(incidents.data.items[0], ['incident_uuid'], '')) }, [incidents.data.items, selected])
  const details = useResource<Json>(session, selected ? `/api/v1/incidents/${encodeURIComponent(selected)}` : '/api/v1/health/live', {}, Boolean(selected))
  const [tab, setTab] = useState('Evidence')
  if (!selected && !incidents.loading) return <><Header kicker="INVESTIGATION" title="Case Details" subtitle="Evidence, workflow, graph context and analyst actions." /><Empty>No incident is currently available. Run an analysis first.</Empty></>
  const incident = asJson(details.data.incident)
  const analysisId = value(details.data, ['analysis_session_uuid'], '')
  const canAudit = hasPermission(session.user, 'audit:read') && value(details.data, ['audit_authorized'], 'true') === 'true'
  const tabs = ['Evidence', 'Correlation', 'Workflow', 'Evidence Registry', 'Notes', ...(canAudit ? ['Audit'] : [])]
  const maxEvidenceBytes = Number(asJson(security.data.upload_limits).max_file_bytes || 10 * 1024 * 1024)
  const incidentRows = incidents.data.items || []
  const selectedIndex = incidentRows.findIndex(row => value(row, ['incident_uuid'], '') === selected)
  const previousIncidentId = selectedIndex > 0 ? value(incidentRows[selectedIndex - 1], ['incident_uuid'], '') : ''
  const nextIncidentId = selectedIndex >= 0 && selectedIndex < incidentRows.length - 1 ? value(incidentRows[selectedIndex + 1], ['incident_uuid'], '') : ''

  return <>
    <Header kicker="INVESTIGATION" title={value(incident, ['title', 'incident_name'], 'Case Details')} subtitle={`${selected} · Evidence-first analyst workspace`} actions={<div className="header-actions"><button className="secondary" onClick={() => navigate('incidents')}>← Incident Queue</button>{previousIncidentId && <button className="secondary" onClick={() => navigate('case', previousIncidentId)}>← Previous case</button>}{nextIncidentId && <button className="secondary" onClick={() => navigate('case', nextIncidentId)}>Next case →</button>}{hasPermission(session.user, 'rag:query') && <button className="secondary" onClick={() => navigate('assistant', selected)}>AI Investigation</button>}{analysisId && hasPermission(session.user, 'graph:read') && <button className="secondary" onClick={() => navigate('graph', analysisId)}>Attack Graph</button>}{analysisId && hasPermission(session.user, 'report:read') && <button className="secondary" onClick={() => navigate('reports', analysisId)}>PDF Report</button>}</div>} />
    <Panel title="Select incident"><select className="wide-select" value={selected} onChange={event => navigate('case', event.target.value)}>{(incidents.data.items || []).map(row => { const id = value(row, ['incident_uuid']); return <option value={id} key={id}>{value(row, ['title'], id)} · {value(row, ['status'])}</option> })}</select></Panel>
    <ErrorBox message={details.error || security.error} />
    {details.loading ? <Empty>Loading case evidence…</Empty> : <>
      <div className="case-summary"><div><span>STATUS</span><Status>{value(incident, ['status'])}</Status></div><div><span>PRIORITY</span><b>{value(incident, ['priority'])}</b></div><div><span>SEVERITY</span><b>{value(incident, ['severity'])}</b></div><div><span>RISK</span><b>{value(incident, ['risk_score'])}</b></div><div><span>CONFIDENCE</span><b>{value(incident, ['confidence'])}</b></div><div><span>ASSIGNEE</span><b>{value(incident, ['assignee'])}</b></div></div>
      <Panel title="Case workspace"><Tabs tabs={tabs} active={tabs.includes(tab) ? tab : 'Evidence'} onChange={setTab} /><div className="tab-body">{tab === 'Evidence' ? <EvidenceTab details={details.data} /> : tab === 'Correlation' ? <CorrelationTab details={details.data} session={session} analysisId={analysisId} /> : tab === 'Workflow' ? <WorkflowTab session={session} incidentId={selected} incident={incident} reload={details.reload} /> : tab === 'Evidence Registry' ? <EvidenceRegistry session={session} incidentId={selected} incident={incident} rows={asRows(details.data.evidence)} maxFileBytes={maxEvidenceBytes} reload={details.reload} /> : tab === 'Notes' ? <NotesTab session={session} incidentId={selected} incident={incident} rows={asRows(details.data.notes)} reload={details.reload} /> : canAudit ? <DataTable rows={asRows(details.data.audit)} exportName="threatlens-case-audit" /> : <Notice>Case audit access requires <code>audit:read</code>.</Notice>}</div></Panel>
    </>}
  </>
}

function EvidenceTab({ details }: { details: Json }) {
  const incident = asJson(details.incident)
  return <div className="three-stack"><Panel title="Incident narrative"><p className="body-copy">{value(incident, ['summary'])}</p>{value(incident, ['storyline'], '') !== '—' && <Notice>{value(incident, ['storyline'])}</Notice>}<KeyValueGrid data={incident} keys={['category', 'source_ip', 'source_count', 'representative_alert_count', 'deduplicated_alert_count', 'entity_count', 'relationship_count', 'stage_count', 'stage_progression', 'graph_score', 'correlation_version', 'correlation_id', 'start_time', 'end_time']} /></Panel><Panel title="Alerts"><DataTable rows={asRows(details.alerts)} columns={['detection_id', 'rule_title', 'severity', 'confidence', 'risk_score', 'primary_tactic', 'primary_technique_id', 'hostname', 'username', 'source_ip', 'timestamp']} exportName="threatlens-case-alerts" /></Panel><Panel title="Evidence events"><DataTable rows={asRows(details.events)} columns={['timestamp', 'source_dataset', 'event_type', 'event_action', 'event_outcome', 'hostname', 'username', 'source_ip', 'destination_ip', 'process_name', 'command_line']} exportName="threatlens-case-events" /></Panel></div>
}

function CorrelationTab({ details, session, analysisId }: { details: Json; session: Session; analysisId: string }) {
  const graph = useResource<Json>(session, analysisId ? `/api/v1/graphs/${encodeURIComponent(analysisId)}` : '/api/v1/health/live', {}, Boolean(analysisId))
  return <div className="three-stack"><Panel title="Resolved entities"><DataTable rows={asRows(details.correlation_entities)} exportName="threatlens-case-entities" /></Panel><Panel title="Scored relationships"><DataTable rows={asRows(details.correlation_relationships)} exportName="threatlens-case-relationships" /></Panel><Panel title="Attack graph"><ErrorBox message={graph.error} />{graph.loading ? <Empty>Loading graph snapshot…</Empty> : <><KeyValueGrid data={asJson(graph.data.summary)} /><GraphSummary graph={asJson(graph.data.graph)} /></>}</Panel></div>
}

function GraphSummary({ graph }: { graph: Json }) {
  const nodes = asRows(graph.nodes)
  const edges = asRows(graph.edges)
  return <><div className="metric-grid two"><div className="mini-metric"><span>Nodes</span><b>{nodes.length}</b></div><div className="mini-metric"><span>Edges</span><b>{edges.length}</b></div></div><AttackGraphCanvas graph={graph} /><DataTable rows={nodes} columns={['node_id', 'node_type', 'label', 'severity', 'risk_score', 'tactic', 'technique_id']} exportName="threatlens-graph-nodes" /><DataTable rows={edges} columns={['source', 'target', 'relationship_type', 'edge_type', 'confidence', 'label']} exportName="threatlens-graph-edges" /><Notice>Graph rendering remains evidence-first: node/edge payloads are persisted correlation artifacts, not LLM-generated relationships.</Notice></>
}

function WorkflowTab({ session, incidentId, incident, reload }: { session: Session; incidentId: string; incident: Json; reload: () => Promise<void> }) {
  const canUpdate = canModifyCase(session, incident)
  const canAssignAny = hasPermission(session.user, 'incident:assign')
  const canClose = hasPermission(session.user, 'incident:close')
  const username = value(session.user, ['username'], '')
  const currentStatus = value(incident, ['status'], 'open').toLowerCase()
  const currentAssignee = value(incident, ['assignee'], '') === '—' ? '' : value(incident, ['assignee'], '')
  const statusOptions = (STATUS_TRANSITIONS[currentStatus] || [currentStatus]).filter(item => canClose || !CLOSING.has(item))
  const [status, setStatus] = useState(currentStatus)
  const [priority, setPriority] = useState(value(incident, ['priority'], 'P3'))
  const [assignee, setAssignee] = useState(currentAssignee)
  const [assignSelf, setAssignSelf] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    setStatus(currentStatus)
    setPriority(value(incident, ['priority'], 'P3'))
    setAssignee(currentAssignee)
    setAssignSelf(false)
  }, [incidentId, currentStatus, currentAssignee])

  if (!canUpdate) return <><KeyValueGrid data={incident} keys={['status', 'priority', 'assignee']} /><Notice>Read-only workflow access for this account/case.</Notice></>

  async function submit(event: FormEvent) {
    event.preventDefault()
    setMessage('Updating governed workflow…')
    const requestedAssignee = canAssignAny ? (assignee.trim() || null) : (!currentAssignee && assignSelf ? username : currentAssignee || null)
    try {
      await api(session, `/api/v1/incidents/${encodeURIComponent(incidentId)}/workflow`, { method: 'PATCH', body: JSON.stringify({ status, priority, assignee: requestedAssignee }) })
      setMessage('Workflow updated and audit-recorded when state changed.')
      await reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Workflow update failed.')
    }
  }

  return <form className="form-grid" onSubmit={submit}><label>Status<select value={status} onChange={event => setStatus(event.target.value)}>{statusOptions.map(item => <option key={item}>{item}</option>)}</select></label><label>Priority<select value={priority} onChange={event => setPriority(event.target.value)}>{['P1', 'P2', 'P3', 'P4'].map(item => <option key={item}>{item}</option>)}</select></label>{canAssignAny ? <label>Assignee<input value={assignee} onChange={event => setAssignee(event.target.value)} placeholder="Active investigator username" /></label> : !currentAssignee ? <label className="check"><input type="checkbox" checked={assignSelf} onChange={event => setAssignSelf(event.target.checked)} /> Assign this case to me ({username})</label> : <div className="readonly-field"><span>ASSIGNEE</span><b>{currentAssignee}</b></div>}<button className="primary align-end">Apply case workflow</button>{message && <Notice>{message}</Notice>}</form>
}

function EvidenceRegistry({ session, incidentId, incident, rows, maxFileBytes, reload }: { session: Session; incidentId: string; incident: Json; rows: Json[]; maxFileBytes: number; reload: () => Promise<void> }) {
  const canAdd = canModifyCase(session, incident) && hasPermission(session.user, 'evidence:create')
  const [kind, setKind] = useState('log_file')
  const [description, setDescription] = useState('')
  const [sourceReference, setSourceReference] = useState('')
  const [sha256, setSha256] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!canAdd) return
    setBusy(true)
    try {
      let calculatedHash = sha256.trim() || null
      let reference = sourceReference.trim() || null
      if (file) {
        if (file.size <= 0) throw new Error(`${file.name} is empty.`)
        if (file.size > maxFileBytes) throw new Error(`${file.name} exceeds the ${fileSizeMiB(maxFileBytes)} MiB evidence hashing limit.`)
        calculatedHash = await sha256Hex(file)
        if (!reference) reference = file.name
      }
      await api(session, `/api/v1/incidents/${encodeURIComponent(incidentId)}/evidence`, { method: 'POST', body: JSON.stringify({ evidence_type: kind, description, source_reference: reference, sha256: calculatedHash }) })
      setDescription(''); setSourceReference(''); setSha256(''); setFile(null)
      setMessage('Evidence metadata registered and audited. File bytes were hashed locally and were not uploaded to the evidence endpoint.')
      await reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Evidence registration failed.')
    } finally {
      setBusy(false)
    }
  }

  return <div className="two-col wide-left"><div><DataTable rows={rows} columns={['evidence_type', 'description', 'source_reference', 'sha256', 'registered_by', 'created_at']} exportName="threatlens-evidence-registry" /></div>{canAdd ? <form className="stack" onSubmit={submit}><label>Evidence type<select value={kind} onChange={event => setKind(event.target.value)}>{['log_file', 'screenshot', 'export', 'hash', 'other'].map(item => <option key={item}>{item}</option>)}</select></label><label>Description<textarea value={description} onChange={event => setDescription(event.target.value)} maxLength={10000} required /></label><label>Source reference<input value={sourceReference} onChange={event => setSourceReference(event.target.value)} maxLength={1024} /></label><label>Optional local evidence file<input type="file" onChange={event => setFile(event.target.files?.[0] || null)} /></label>{file && <Notice>{file.name} · {fileSizeMiB(file.size)} MiB. ThreatLens will calculate SHA-256 in the browser; only metadata is submitted.</Notice>}<label>SHA-256 (optional when file selected)<input value={sha256} onChange={event => setSha256(event.target.value)} pattern="[0-9a-fA-F]{64}" maxLength={64} /></label><button className="primary" disabled={busy}>{busy ? 'Hashing / registering…' : 'Register evidence'}</button>{message && <Notice>{message}</Notice>}</form> : <Notice>Read-only evidence access for this account/case.</Notice>}</div>
}

function NotesTab({ session, incidentId, incident, rows, reload }: { session: Session; incidentId: string; incident: Json; rows: Json[]; reload: () => Promise<void> }) {
  const canAdd = canModifyCase(session, incident) && hasPermission(session.user, 'note:create')
  const [note, setNote] = useState('')
  const [message, setMessage] = useState('')
  async function submit(event: FormEvent) {
    event.preventDefault(); if (!canAdd) return
    try {
      await api(session, `/api/v1/incidents/${encodeURIComponent(incidentId)}/notes`, { method: 'POST', body: JSON.stringify({ note }) })
      setNote(''); setMessage('Investigation note saved and audited.'); await reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Note creation failed.')
    }
  }
  return <div className="two-col wide-left"><DataTable rows={rows} columns={['author', 'note', 'created_at']} exportName="threatlens-investigation-notes" />{canAdd ? <form className="stack" onSubmit={submit}><label>Investigation note<textarea value={note} onChange={event => setNote(event.target.value)} maxLength={10000} rows={8} required /></label><button className="primary">Add auditable note</button>{message && <Notice>{message}</Notice>}</form> : <Notice>Read-only notes. Creating investigation notes requires case-modification authority and <code>note:create</code>.</Notice>}</div>
}
