import { FormEvent, useMemo, useState } from 'react'
import { api } from '../api'
import { DataTable, Empty, ErrorBox, Header, JsonView, Metric, Notice, Panel, SearchBox, Status, useResource } from '../components'
import { Json, ListResponse, Session } from '../types'
import { compact, hasPermission, value } from '../utils'

function jsonRows(input: unknown): Json[] {
  return Array.isArray(input) ? input.filter(item => item && typeof item === 'object') as Json[] : []
}

export function RealtimePage({ session }: { session: Session }) {
  const sources = useResource<ListResponse>(session, '/api/v1/ingestion/sources', { items: [] })
  const recent = useResource<ListResponse>(session, '/api/v1/ingestion/recent?limit=150', { items: [] })
  const [name, setName] = useState('Entra Production Stream')
  const [connector, setConnector] = useState('entra_id')
  const [rate, setRate] = useState(1200)
  const [oneTimeKey, setOneTimeKey] = useState('')
  const [message, setMessage] = useState('')

  async function createSource(event: FormEvent) {
    event.preventDefault(); setMessage('')
    try {
      const result = await api<Json>(session, '/api/v1/ingestion/sources', {
        method: 'POST', body: JSON.stringify({ name, connector_id: connector, rate_limit_per_minute: rate, allowed_ip_cidrs: [], metadata: { owner: 'SOC' } }),
      })
      setOneTimeKey(value(result, ['api_key']))
      setMessage('Authenticated ingestion source created. Copy the machine key now; ThreatLens stores only its SHA-256 hash.')
      void sources.reload()
    } catch (caught) { setMessage(caught instanceof Error ? caught.message : 'Source creation failed.') }
  }

  const rows = sources.data.items || []
  const recentRows = recent.data.items || []
  return <>
    <Header kicker="BATCH 6A · REAL-TIME" title="Streaming Ingestion" subtitle="Durable receipt-first HTTP/syslog ingestion with per-source machine credentials, idempotency, source budgets and governed connector normalization." />
    <ErrorBox message={sources.error || recent.error} />
    <div className="metric-grid"><Metric label="Sources" number={String(rows.length)} note="Authenticated machine identities" /><Metric label="Recent receipts" number={String(recentRows.length)} note="Durable ingress ledger" /><Metric label="Entra connector" number={rows.some(r => value(r,['connector_id']) === 'entra_id') ? 'ACTIVE' : 'READY'} note="Cloud identity telemetry" accent /></div>
    <div className="two-col wide-left">
      <Panel title="Ingestion sources"><DataTable rows={rows} columns={['name','connector_id','enabled','rate_limit_per_minute','last_seen_at']} exportName="threatlens-ingestion-sources" /></Panel>
      <Panel title="Create authenticated source"><form className="stack" onSubmit={createSource}><label>Name<input value={name} onChange={e => setName(e.target.value)} required /></label><label>Connector<select value={connector} onChange={e => setConnector(e.target.value)}><option value="entra_id">Microsoft Entra ID</option><option value="windows_security">Windows Security</option><option value="windows_sysmon">Sysmon</option><option value="suricata_eve">Suricata EVE</option><option value="zeek">Zeek</option><option value="linux_auth">Linux Auth</option></select></label><label>Events / minute<input type="number" min="1" max="100000" value={rate} onChange={e => setRate(Number(e.target.value))} /></label><button className="primary" disabled={!hasPermission(session.user,'ingest:manage')}>Create source</button></form>{oneTimeKey && <Notice tone="warning"><b>One-time machine key:</b><br/><code>{oneTimeKey}</code></Notice>}{message && <Notice>{message}</Notice>}</Panel>
    </div>
    <Panel title="Durable ingress receipts"><DataTable rows={recentRows} columns={['received_at','source_uuid','client_event_id','status','analysis_session_uuid','error_code']} exportName="threatlens-realtime-ingress" /></Panel>
    <Notice>Machine senders post JSON records to <code>/api/v1/ingest/realtime</code> with <code>X-ThreatLens-Ingest-Key</code>. Receipt rows are committed before parsing so failed normalization cannot erase evidence that telemetry reached ThreatLens.</Notice>
  </>
}

export function ThreatIntelPage({ session }: { session: Session }) {
  const feeds = useResource<ListResponse>(session, '/api/v1/intel/feeds', { items: [] })
  const indicators = useResource<ListResponse>(session, '/api/v1/intel/indicators?limit=250', { items: [] })
  const hits = useResource<ListResponse>(session, '/api/v1/intel/hits?limit=150', { items: [] })
  const [feedName, setFeedName] = useState('SOC Curated Intelligence')
  const [provider, setProvider] = useState('ThreatLens Lab')
  const [selectedFeed, setSelectedFeed] = useState('')
  const [importText, setImportText] = useState('[{"indicator_type":"domain","value":"malicious.example","confidence":90,"tags":["demo"]}]')
  const [message, setMessage] = useState('')
  const feedRows = feeds.data.items || []

  async function createFeed(event: FormEvent) { event.preventDefault(); try { const created = await api<Json>(session,'/api/v1/intel/feeds',{method:'POST',body:JSON.stringify({name:feedName,provider,feed_format:'curated_json',tlp:'TLP:CLEAR',default_confidence:70,metadata:{}})}); setSelectedFeed(value(created,['feed_uuid'])); setMessage('Threat-intelligence feed created.'); void feeds.reload() } catch(caught){setMessage(caught instanceof Error ? caught.message:'Feed creation failed.')} }
  async function importIntel() { try { const parsed = JSON.parse(importText); const list = Array.isArray(parsed) ? parsed : [parsed]; const target = selectedFeed || value(feedRows[0] || {},['feed_uuid']); if(!target) throw new Error('Create or select a feed first.'); const result = await api<Json>(session,`/api/v1/intel/feeds/${target}/import`,{method:'POST',body:JSON.stringify({indicators:list})}); setMessage(`Import completed: ${compact(result)}`); void indicators.reload() } catch(caught){setMessage(caught instanceof Error ? caught.message:'Import failed.')} }
  return <>
    <Header kicker="BATCH 6B · INTELLIGENCE" title="Threat Intelligence" subtitle="Provenance-preserving IOC ingestion, STIX 2.x import, validity/confidence/TLP controls and enrichment that remains explicitly separate from observed evidence." />
    <ErrorBox message={feeds.error || indicators.error || hits.error} />
    <div className="metric-grid"><Metric label="Feeds" number={String(feedRows.length)} note="Governed intelligence sources" /><Metric label="Active indicators" number={String(indicators.data.count ?? 0)} note="Normalized IOC store" /><Metric label="IOC hits" number={String(hits.data.count ?? 0)} note="External enrichment matches" accent /></div>
    <div className="two-col"><Panel title="Feed registry"><DataTable rows={feedRows} columns={['name','provider','feed_format','tlp','default_confidence','last_import_at']} /></Panel><Panel title="Create feed"><form className="stack" onSubmit={createFeed}><label>Name<input value={feedName} onChange={e=>setFeedName(e.target.value)} /></label><label>Provider<input value={provider} onChange={e=>setProvider(e.target.value)} /></label><button className="primary" disabled={!hasPermission(session.user,'intel:manage')}>Create feed</button></form></Panel></div>
    <Panel title="Curated IOC / STIX staging"><div className="stack"><label>Target feed<select value={selectedFeed} onChange={e=>setSelectedFeed(e.target.value)}><option value="">Newest feed</option>{feedRows.map(row=><option key={value(row,['feed_uuid'])} value={value(row,['feed_uuid'])}>{value(row,['name'])}</option>)}</select></label><label>Curated indicator array<textarea rows={6} value={importText} onChange={e=>setImportText(e.target.value)} /></label><button className="primary" onClick={()=>void importIntel()} disabled={!hasPermission(session.user,'intel:manage')}>Import intelligence</button>{message && <Notice>{message}</Notice>}</div></Panel>
    <Panel title="Indicators"><DataTable rows={indicators.data.items || []} columns={['type','value','confidence','malicious_score','tlp','feed','provider','valid_until']} exportName="threatlens-indicators" /></Panel>
    <Panel title="Observed ↔ intelligence matches"><DataTable rows={hits.data.items || []} columns={['created_at','indicator_type','indicator_value','matched_field','matched_value','confidence','enrichment_only']} exportName="threatlens-intel-hits" /></Panel>
  </>
}

export function HuntPage({ session }: { session: Session }) {
  const saved = useResource<ListResponse>(session, '/api/v1/hunts/saved', { items: [] })
  const [query, setQuery] = useState('')
  const [sourceIp, setSourceIp] = useState('')
  const [username, setUsername] = useState('')
  const [results, setResults] = useState<Json[]>([])
  const [meta, setMeta] = useState<Json>({})
  const [message, setMessage] = useState('')
  async function run() { try { const response=await api<Json>(session,'/api/v1/hunts/execute',{method:'POST',body:JSON.stringify({query:query||null,source_ip:sourceIp||null,username:username||null,limit:250,offset:0,sort:'desc'})}); setResults(jsonRows(response.items)); setMeta(response); setMessage('') } catch(caught){setMessage(caught instanceof Error ? caught.message:'Hunt failed.')} }
  async function save() { try { await api(session,'/api/v1/hunts/saved',{method:'POST',body:JSON.stringify({name:`Hunt ${new Date().toISOString()}`,description:'Saved from analyst workspace',query:{query:query||null,source_ip:sourceIp||null,username:username||null,limit:250,offset:0,sort:'desc'},shared:false})}); void saved.reload(); setMessage('Hunt saved.') } catch(caught){setMessage(caught instanceof Error?caught.message:'Save failed.')} }
  return <>
    <Header kicker="BATCH 6C · HUNTING" title="Threat Hunting" subtitle="Read-only structured hunt grammar across persisted events. No analyst-provided SQL reaches the database." />
    <ErrorBox message={saved.error} />
    <Panel title="Hunt builder"><div className="form-grid"><label>Free-text pivot<input value={query} onChange={e=>setQuery(e.target.value)} placeholder="process, domain, host, message…" /></label><label>Source IP<input value={sourceIp} onChange={e=>setSourceIp(e.target.value)} placeholder="203.0.113.10" /></label><label>Username<input value={username} onChange={e=>setUsername(e.target.value)} placeholder="user@example.com" /></label></div><div className="button-row"><button className="primary" onClick={()=>void run()}>Execute read-only hunt</button><button className="secondary" onClick={()=>void save()} disabled={!hasPermission(session.user,'hunt:manage')}>Save hunt</button></div>{message && <Notice>{message}</Notice>}</Panel>
    <div className="metric-grid three"><Metric label="Matches" number={value(meta,['total'],'0')} note="Server-side count" /><Metric label="Returned" number={String(results.length)} note="Bounded result page" /><Metric label="Latency" number={`${value(meta,['latency_ms'],'0')} ms`} note="Audited hunt execution" /></div>
    <Panel title="Hunt results"><DataTable rows={results} columns={['timestamp','source_product','event_type','event_outcome','source_ip','destination_ip','username','hostname','domain','process_name']} exportName="threatlens-hunt" /></Panel>
    <Panel title="Saved hunts"><DataTable rows={saved.data.items || []} columns={['name','owner','shared','updated_at']} /></Panel>
  </>
}

export function CaseOperationsPage({ session, incidentId }: { session: Session; incidentId: string }) {
  const path = incidentId ? `/api/v1/incidents/${incidentId}/case-operations` : '/api/v1/health/live'
  const resource = useResource<Json>(session, path, {}, Boolean(incidentId))
  const [taskTitle,setTaskTitle]=useState('')
  const [team,setTeam]=useState('SOC Tier 2')
  const [message,setMessage]=useState('')
  if(!incidentId) return <><Header kicker="BATCH 6D · CASE OPS" title="Advanced Case Operations" subtitle="Assignment, SLA, tasks, handoffs and evidence chain-of-custody."/><Empty>Select an incident from the Incident Queue first.</Empty></>
  const tasks=jsonRows(resource.data.tasks); const handoffs=jsonRows(resource.data.handoffs); const profile=(resource.data.profile && typeof resource.data.profile==='object' ? resource.data.profile : {}) as Json
  async function updateProfile(){try{await api(session,`/api/v1/incidents/${incidentId}/case-operations/profile`,{method:'PATCH',body:JSON.stringify({team,containment_status:'in_progress',watchers:[],tags:['batch6']})}); setMessage('Case profile updated.'); void resource.reload()}catch(caught){setMessage(caught instanceof Error?caught.message:'Update failed.')}}
  async function createTask(){if(!taskTitle)return;try{await api(session,`/api/v1/incidents/${incidentId}/tasks`,{method:'POST',body:JSON.stringify({task_type:'investigation',title:taskTitle,description:'Analyst-created investigation task',priority:'P2',approval_required:false})}); setTaskTitle(''); void resource.reload()}catch(caught){setMessage(caught instanceof Error?caught.message:'Task failed.')}}
  return <>
    <Header kicker="BATCH 6D · CASE OPS" title="Advanced Case Operations" subtitle={`SOC workflow controls for incident ${incidentId}.`} />
    <ErrorBox message={resource.error}/><div className="metric-grid"><Metric label="Tasks" number={String(tasks.length)} note="Investigation / containment work" /><Metric label="Handoffs" number={String(handoffs.length)} note="Auditable analyst transfers" /><Metric label="Containment" number={value(profile,['containment_status'],'not_started')} note="Explicit response state" accent /></div>
    <div className="two-col"><Panel title="Case profile"><JsonView data={profile} title="Workflow profile"/><div className="stack"><label>Team<input value={team} onChange={e=>setTeam(e.target.value)}/></label><button className="primary" onClick={()=>void updateProfile()}>Mark containment in progress</button></div></Panel><Panel title="Create investigation task"><div className="stack"><label>Task title<input value={taskTitle} onChange={e=>setTaskTitle(e.target.value)}/></label><button className="primary" onClick={()=>void createTask()}>Create P2 task</button>{message&&<Notice>{message}</Notice>}</div></Panel></div>
    <Panel title="Case tasks"><DataTable rows={tasks} columns={['created_at','task_type','title','status','priority','assignee','due_at']} /></Panel><Panel title="Analyst handoffs"><DataTable rows={handoffs} columns={['created_at','from_actor','to_actor','note','accepted_at']} /></Panel>
  </>
}

export function ResponsePage({ session, incidentId }: { session: Session; incidentId: string }) {
  const playbooks = useResource<ListResponse>(session, '/api/v1/response/playbooks', { items: [] })
  const execPath = incidentId ? `/api/v1/incidents/${incidentId}/response-executions` : '/api/v1/health/live'
  const executions = useResource<ListResponse>(session, execPath, { items: [] }, Boolean(incidentId))
  const [selected, setSelected] = useState('')
  const [selectedExecution, setSelectedExecution] = useState('')
  const [approvalNote, setApprovalNote] = useState('Evidence and response scope reviewed by an authorized analyst.')
  const [outcome, setOutcome] = useState('success')
  const [rollbackNotes, setRollbackNotes] = useState('Simulation record only; no production mutation was performed.')
  const [message, setMessage] = useState('')

  const executionRows = executions.data.items || []
  const actionable = executionRows.filter(row => ['requested', 'approved'].includes(value(row, ['status'], '')))
  const activeExecution = executionRows.find(row => value(row, ['execution_uuid']) === selectedExecution) || actionable[0] || executionRows[0]
  const executionUuid = value(activeExecution, ['execution_uuid'], '')
  const executionStatus = value(activeExecution, ['status'], '')
  const requester = value(activeExecution, ['requested_by'], '')
  const username = value(session.user, ['username'], '')
  const canReview = Boolean(executionUuid) && executionStatus === 'requested' && requester !== username && hasPermission(session.user, 'response:approve')
  const canExecute = Boolean(executionUuid) && executionStatus === 'approved' && hasPermission(session.user, 'response:execute')

  async function request() {
    const id = selected || value((playbooks.data.items || [])[0] || {}, ['playbook_uuid'])
    if (!incidentId || !id) return
    try {
      const created = await api<Json>(session, `/api/v1/incidents/${incidentId}/response-executions`, {
        method: 'POST',
        body: JSON.stringify({ playbook_uuid: id, parameters: { requested_from: 'soc_console' } }),
      })
      setSelectedExecution(value(created, ['execution_uuid'], ''))
      setMessage('Execution requested; a different authorized human must approve it before execution can be recorded.')
      void executions.reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Request failed.')
    }
  }

  async function review(approved: boolean) {
    if (!executionUuid) return
    try {
      await api(session, `/api/v1/response-executions/${executionUuid}/approval`, {
        method: 'POST',
        body: JSON.stringify({ approved, note: approvalNote.trim() || null }),
      })
      setMessage(approved ? 'Response approved by an authorized human.' : 'Response rejected; no execution is permitted.')
      void executions.reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Review failed.')
    }
  }

  async function execute() {
    if (!executionUuid) return
    try {
      await api(session, `/api/v1/response-executions/${executionUuid}/execute`, {
        method: 'POST',
        body: JSON.stringify({
          outcome,
          result: { simulated: true, recorded_from: 'soc_console' },
          rollback_notes: rollbackNotes.trim() || null,
        }),
      })
      setMessage('Approved simulation/integration execution recorded with outcome and rollback evidence.')
      void executions.reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Execution record failed.')
    }
  }

  return <>
    <Header kicker="BATCH 6E · RESPONSE" title="Approval-Gated Response" subtitle="Human-authority playbooks with approval, executor, outcome and rollback evidence. ThreatLens never performs autonomous destructive actions." />
    <ErrorBox message={playbooks.error || executions.error} />
    <Notice tone="warning">Safety boundary: every response execution is approval-gated. Built-in actions are simulation/integration-ready records, not silent endpoint, identity or firewall changes.</Notice>
    <div className="two-col">
      <Panel title="Playbooks"><DataTable rows={playbooks.data.items || []} columns={['name','action_type','risk_level','version','enabled']} /></Panel>
      <Panel title="Request response"><div className="stack"><label>Playbook<select value={selected} onChange={e => setSelected(e.target.value)}><option value="">Select first available</option>{(playbooks.data.items || []).map(row => <option key={value(row, ['playbook_uuid'])} value={value(row, ['playbook_uuid'])}>{value(row, ['name'])}</option>)}</select></label><button className="primary" disabled={!incidentId || !hasPermission(session.user, 'response:request')} onClick={() => void request()}>Request approval</button>{!incidentId && <Empty>Select an incident first.</Empty>}</div></Panel>
    </div>
    <Panel title="Human approval and execution">
      {!activeExecution ? <Empty>No response execution is available.</Empty> : <div className="stack">
        <label>Execution<select value={executionUuid} onChange={e => setSelectedExecution(e.target.value)}>{executionRows.map(row => <option key={value(row, ['execution_uuid'])} value={value(row, ['execution_uuid'])}>{value(row, ['playbook_name'])} · {value(row, ['status'])} · requested by {value(row, ['requested_by'])}</option>)}</select></label>
        <Notice>Current state: <b>{executionStatus}</b>. Requester: <b>{requester}</b>. Approval and execution remain separate audited transitions.</Notice>
        {executionStatus === 'requested' && requester === username && <Notice tone="warning">Separation of duties: the requester cannot approve this response. Sign in as another authorized analyst.</Notice>}
        <label>Approval note<textarea rows={3} value={approvalNote} onChange={e => setApprovalNote(e.target.value)} /></label>
        <div className="button-row"><button className="primary" disabled={!canReview} onClick={() => void review(true)}>Approve response</button><button className="secondary" disabled={!canReview} onClick={() => void review(false)}>Reject response</button></div>
        <label>Execution outcome<select value={outcome} onChange={e => setOutcome(e.target.value)}><option value="success">Success</option><option value="partial">Partial</option><option value="failed">Failed</option><option value="cancelled">Cancelled</option></select></label>
        <label>Rollback / safety notes<textarea rows={3} value={rollbackNotes} onChange={e => setRollbackNotes(e.target.value)} /></label>
        <button className="primary" disabled={!canExecute} onClick={() => void execute()}>Record approved simulated execution</button>
      </div>}
      {message && <Notice>{message}</Notice>}
    </Panel>
    <Panel title="Response execution ledger"><DataTable rows={executionRows} columns={['requested_at','playbook_name','status','requested_by','approved_by','executor','completed_at']} exportName="threatlens-response-executions" /></Panel>
  </>
}

export function DetectionEngineeringPage({ session }: { session: Session }) {
  const metrics = useResource<ListResponse>(session, '/api/v1/detections/effectiveness', { items: [] })
  const tunings = useResource<ListResponse>(
    session,
    '/api/v1/detections/tunings',
    { items: [] },
    hasPermission(session.user, 'detection:manage'),
  )
  const [rule, setRule] = useState('')
  const [rationale, setRationale] = useState(
    'Reduce documented false-positive noise while preserving the governed detection boundary.',
  )
  const [selectedTuning, setSelectedTuning] = useState('')
  const [reviewNote, setReviewNote] = useState('Evidence, fixture impact and rollback scope reviewed by an authorized detection manager.')
  const [message, setMessage] = useState('')

  const rows = metrics.data.items || []
  const tuningRows = tunings.data.items || []
  const openTunings = tuningRows.filter(row => value(row, ['status']) === 'proposed')
  const activeTuning =
    tuningRows.find(row => value(row, ['tuning_uuid']) === selectedTuning) || openTunings[0] || tuningRows[0]
  const tuningUuid = value(activeTuning, ['tuning_uuid'], '')
  const tuningStatus = value(activeTuning, ['status'], '')
  const requester = value(activeTuning, ['requested_by'], '')
  const username = value(session.user, ['username'], '')
  const duplicateOpen = openTunings.find(
    row => value(row, ['rule_id']) === rule.trim() && value(row, ['proposal_type']) === 'threshold',
  )
  const canReview =
    Boolean(tuningUuid) &&
    tuningStatus === 'proposed' &&
    requester !== username &&
    hasPermission(session.user, 'detection:manage')

  async function propose() {
    if (!rule.trim() || duplicateOpen) return
    try {
      const created = await api<Json>(session, '/api/v1/detections/tunings', {
        method: 'POST',
        body: JSON.stringify({
          rule_id: rule.trim(),
          proposal_type: 'threshold',
          proposal: { review_required: true },
          rationale,
        }),
      })
      setSelectedTuning(value(created, ['tuning_uuid'], ''))
      setMessage('Tuning proposal recorded. Runtime YAML was NOT mutated; a different detection manager must review it.')
      void tunings.reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Proposal failed.')
    }
  }

  async function review(decision: 'approved' | 'rejected') {
    if (!tuningUuid) return
    try {
      await api(session, `/api/v1/detections/tunings/${tuningUuid}/review`, {
        method: 'POST',
        body: JSON.stringify({ decision, review_note: reviewNote.trim() || null }),
      })
      setMessage(
        decision === 'approved'
          ? 'Tuning approved as a governed patch record; runtime YAML remains unchanged.'
          : 'Tuning rejected; no runtime mutation occurred.',
      )
      void tunings.reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Review failed.')
    }
  }

  return <>
    <Header
      kicker="BATCH 6F · DETECTION ENGINEERING"
      title="Detection Feedback & Tuning"
      subtitle="Analyst dispositions, rule effectiveness and governed tuning proposals that never silently mutate deterministic rule YAML."
    />
    <ErrorBox message={metrics.error || tunings.error} />
    <div className="metric-grid three">
      <Metric label="Rules with firings" number={String(rows.length)} note="Persisted alert evidence" />
      <Metric
        label="Reviewed feedback"
        number={String(rows.reduce((n, row) => n + Number(row.reviewed || 0), 0))}
        note="Analyst outcomes"
      />
      <Metric label="Open tunings" number={String(openTunings.length)} note="Governance queue" accent />
    </div>
    <Panel title="Rule effectiveness">
      <DataTable
        rows={rows}
        columns={['rule_id', 'alert_firings', 'reviewed', 'true_positive', 'false_positive', 'precision_observed', 'feedback_coverage']}
        exportName="threatlens-detection-effectiveness"
      />
    </Panel>
    <div className="two-col">
      <Panel title="Governed tuning proposal">
        <div className="stack">
          <label>Rule ID<input value={rule} onChange={event => setRule(event.target.value)} /></label>
          <label>Rationale<textarea rows={4} value={rationale} onChange={event => setRationale(event.target.value)} /></label>
          <button
            className="primary"
            disabled={!hasPermission(session.user, 'detection:manage') || !rule.trim() || Boolean(duplicateOpen)}
            onClick={() => void propose()}
          >
            Propose tuning
          </button>
          {duplicateOpen && <Notice>An open threshold proposal already exists for this rule. Review it before creating another.</Notice>}
        </div>
      </Panel>
      <Panel title="Tuning history">
        <DataTable
          rows={tuningRows}
          columns={['created_at', 'rule_id', 'proposal_type', 'status', 'requested_by', 'reviewed_by']}
        />
      </Panel>
    </div>
    <Panel title="Human tuning review">
      {tuningRows.length ? <div className="stack">
        <label>Proposal
          <select value={selectedTuning || tuningUuid} onChange={event => setSelectedTuning(event.target.value)}>
            {tuningRows.map(row => {
              const id = value(row, ['tuning_uuid'])
              return <option key={id} value={id}>
                {value(row, ['rule_id'])} · {value(row, ['proposal_type'])} · {value(row, ['status'])} · requested by {value(row, ['requested_by'])}
              </option>
            })}
          </select>
        </label>
        <Notice>
          Current state: {tuningStatus || 'unknown'}. Requester: {requester || '—'}.
          {requester === username
            ? ' A different detection manager must review this proposal.'
            : ' Approval and rejection are separate audited transitions.'}
        </Notice>
        <label>Review note
          <textarea rows={3} value={reviewNote} onChange={event => setReviewNote(event.target.value)} />
        </label>
        <div>
          <button className="primary" disabled={!canReview} onClick={() => void review('approved')}>Approve tuning</button>
          <button disabled={!canReview} onClick={() => void review('rejected')}>Reject tuning</button>
        </div>
      </div> : <Empty>No tuning proposals are available.</Empty>}
      {message && <Notice>{message}</Notice>}
    </Panel>
  </>
}

export function IdentityPage({ session }: { session: Session }) {
  const connectors=useResource<ListResponse>(session,'/api/v1/connectors',{items:[]})
  const entra=(connectors.data.items||[]).find(row=>value(row,['connector_id'])==='entra_id')
  return <>
    <Header kicker="BATCH 6G · CLOUD / IDENTITY" title="Microsoft Entra ID Telemetry" subtitle="First-class cloud identity normalization for sign-in risk, MFA failures, account activity and privileged role assignments." />
    <div className="metric-grid three"><Metric label="Connector" number={entra?'REGISTERED':'CHECK'} note="entra_id common-schema adapter" accent /><Metric label="Detection pack" number="4" note="Governed identity rules + fixtures" /><Metric label="Ingestion" number="STREAM" note="Compatible with authenticated 6A endpoint" /></div>
    <Panel title="Connector contract">{entra?<JsonView data={entra}/>:<Empty>Entra connector metadata not returned by the API.</Empty>}</Panel>
    <Panel title="Identity detections"><DataTable rows={[
      {detection:'entra_risky_signin',severity:'High',attack:'T1078.004 Cloud Accounts'},
      {detection:'entra_mfa_failure',severity:'Medium',attack:'T1621 MFA Request Generation'},
      {detection:'entra_signin_failure',severity:'Low',attack:'T1110 Brute Force'},
      {detection:'entra_privileged_role_assignment',severity:'High',attack:'T1098.003 Additional Cloud Roles'},
    ]}/></Panel>
    <Notice>Cloud/identity events enter the same deterministic pipeline as Linux, Windows, Sysmon, Suricata and Zeek; AI remains downstream and cannot create detections.</Notice>
  </>
}

export function GraphIntelligencePage({ session, incidentId }: { session: Session; incidentId: string }) {
  const graphPath=incidentId?`/api/v1/incidents/${incidentId}/graph/intelligence?minimum_confidence=0.3`:'/api/v1/health/live'
  const graph=useResource<Json>(session,graphPath,{},Boolean(incidentId))
  const [query,setQuery]=useState(''); const [search,setSearch]=useState<Json[]>([]); const [message,setMessage]=useState('')
  const nodes=jsonRows(graph.data.nodes); const edges=jsonRows(graph.data.edges)
  async function runSearch(){if(query.trim().length<2)return;try{const r=await api<Json>(session,`/api/v1/search?q=${encodeURIComponent(query)}&limit=100`);setSearch(jsonRows(r.items));setMessage('')}catch(caught){setMessage(caught instanceof Error?caught.message:'Search failed.')}}
  return <>
    <Header kicker="BATCH 6H · GRAPH + SEARCH" title="Graph Intelligence & Global Search" subtitle="Evidence-backed entity views, confidence-filtered relationship paths, entity timelines and server-side cross-investigation search." />
    <div className="metric-grid three"><Metric label="Incident nodes" number={String(nodes.length)} note="Resolved evidence entities" /><Metric label="Relationships" number={String(edges.length)} note="Confidence-scored edges" /><Metric label="Search scope" number="5" note="Incidents · alerts · events · entities · IOCs" accent /></div>
    {!incidentId?<Notice>Select an incident to populate graph intelligence.</Notice>:<><ErrorBox message={graph.error}/><Panel title="Evidence-backed nodes"><DataTable rows={nodes} columns={['type','value','confidence','first_seen','last_seen','sources']} exportName="threatlens-graph-nodes" /></Panel><Panel title="Relationship explanations"><DataTable rows={edges} columns={['source','target','type','confidence','reasons','time_delta_seconds']} exportName="threatlens-graph-edges" /></Panel></>}
    <Panel title="Global investigation search"><div className="button-row"><SearchBox value={query} onChange={setQuery} placeholder="Search incident, user, IP, host, process, domain, IOC…"/><button className="primary" onClick={()=>void runSearch()}>Search</button></div>{message&&<Notice>{message}</Notice>}<DataTable rows={search} columns={['type','title','subtitle','timestamp','id']} exportName="threatlens-global-search" /></Panel>
  </>
}
