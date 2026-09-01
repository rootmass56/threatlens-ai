import { FormEvent, useMemo, useState } from 'react'
import { api } from '../api'
import { DataTable, Empty, ErrorBox, Header, JsonView, Metric, Notice, Panel, SearchBox, Status, useResource } from '../components'
import { Json, ListResponse, Page, Session } from '../types'
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
    <Panel title="Hunt builder"><div className="form-grid"><label>Free-text pivot<input value={query} onChange={e=>setQuery(e.target.value)} placeholder="process, domain, host, message…" /></label><label>Source IP<input value={sourceIp} onChange={e=>setSourceIp(e.target.value)} placeholder="203.0.113.10" /></label><label>Username<input value={username} onChange={e=>setUsername(e.target.value)} placeholder="user@example.com" /></label></div><div className="button-row"><button className="primary" onClick={()=>void run()}>Execute read-only hunt</button><button onClick={()=>void save()} disabled={!hasPermission(session.user,'hunt:manage')}>Save hunt</button></div>{message && <Notice>{message}</Notice>}</Panel>
    <div className="metric-grid three"><Metric label="Matches" number={value(meta,['total'],'0')} note="Server-side count" /><Metric label="Returned" number={String(results.length)} note="Bounded result page" /><Metric label="Latency" number={`${value(meta,['latency_ms'],'0')} ms`} note="Audited hunt execution" /></div>
    <Panel title="Hunt results"><DataTable rows={results} columns={['timestamp','source_product','event_type','event_outcome','source_ip','destination_ip','username','hostname','domain','process_name']} exportName="threatlens-hunt" /></Panel>
    <Panel title="Saved hunts"><DataTable rows={saved.data.items || []} columns={['name','owner','shared','updated_at']} /></Panel>
  </>
}

function EvidenceCustodyCard({ session, evidence }: { session: Session; evidence: Json }) {
  const evidenceUuid = value(evidence, ['evidence_uuid'], '')
  const path = evidenceUuid ? `/api/v1/evidence/${encodeURIComponent(evidenceUuid)}/custody` : '/api/v1/health/live'
  const custody = useResource<ListResponse>(session, path, { items: [] }, Boolean(evidenceUuid))
  return <Panel title={`Custody Â· ${evidenceUuid ? evidenceUuid.slice(0, 12) : 'evidence'}`}>
    <JsonView data={evidence} title="Registered evidence metadata" />
    <ErrorBox message={custody.error} />
    <DataTable rows={custody.data.items || []} columns={['created_at','action','from_custodian','to_custodian','location','hash_verified','actor','notes']} exportName={`threatlens-custody-${evidenceUuid || 'evidence'}`} />
  </Panel>
}

export function CaseOperationsPage({ session, incidentId, navigate }: { session: Session; incidentId: string; navigate: (page: Page, id?: string) => void }) {
  const incidents = useResource<ListResponse>(session, '/api/v1/incidents?limit=1000', { items: [] })
  const path = incidentId ? `/api/v1/incidents/${encodeURIComponent(incidentId)}/case-operations` : '/api/v1/health/live'
  const detailsPath = incidentId ? `/api/v1/incidents/${encodeURIComponent(incidentId)}` : '/api/v1/health/live'
  const resource = useResource<Json>(session, path, {}, Boolean(incidentId))
  const details = useResource<Json>(session, detailsPath, {}, Boolean(incidentId))
  const [taskTitle,setTaskTitle]=useState('')
  const [team,setTeam]=useState('SOC Tier 2')
  const [message,setMessage]=useState('')

  const incidentRows = incidents.data.items || []
  const tasks=jsonRows(resource.data.tasks)
  const handoffs=jsonRows(resource.data.handoffs)
  const evidence=jsonRows(details.data.evidence)
  const profile=(resource.data.profile && typeof resource.data.profile==='object' ? resource.data.profile : {}) as Json
  const selectedIncident = incidentRows.find(row => value(row,['incident_uuid']) === incidentId)
  const selectedLabel = selectedIncident ? value(selectedIncident,['title'],incidentId) : incidentId

  const selector = <Panel title="Selected incident">
    <ErrorBox message={incidents.error} />
    <label>Authoritative incident context
      <select className="wide-select" value={incidentId} onChange={event=>navigate('caseops',event.target.value)}>
        <option value="">Select incident</option>
        {incidentRows.map(row => { const id=value(row,['incident_uuid']); return <option key={id} value={id}>{value(row,['title'],id)} Â· {value(row,['status'])} Â· {value(row,['priority'])}</option> })}
      </select>
    </label>
    {incidentId && !selectedIncident && !incidents.loading && <Notice tone="warning">The retained incident context is stale or unavailable in this database. Select a current incident above.</Notice>}
  </Panel>

  if(!incidentId) return <>
    <Header kicker="BATCH 6D Â· CASE OPS" title="Advanced Case Operations" subtitle="Assignment, SLA, tasks, handoffs and evidence chain-of-custody." />
    {selector}
    <Empty>Select an incident from the authoritative Incident Queue.</Empty>
  </>

  async function updateProfile(){try{await api(session,`/api/v1/incidents/${encodeURIComponent(incidentId)}/case-operations/profile`,{method:'PATCH',body:JSON.stringify({team,containment_status:'in_progress',watchers:[],tags:['batch6']})}); setMessage('Case profile updated.'); void resource.reload()}catch(caught){setMessage(caught instanceof Error?caught.message:'Update failed.')}}
  async function createTask(){if(!taskTitle)return;try{await api(session,`/api/v1/incidents/${encodeURIComponent(incidentId)}/tasks`,{method:'POST',body:JSON.stringify({task_type:'investigation',title:taskTitle,description:'Analyst-created investigation task',priority:'P2',approval_required:false})}); setTaskTitle(''); void resource.reload()}catch(caught){setMessage(caught instanceof Error?caught.message:'Task failed.')}}

  return <>
    <Header kicker="BATCH 6D Â· CASE OPS" title="Advanced Case Operations" subtitle={`SOC workflow controls for ${selectedLabel || incidentId}.`} actions={<div className="header-actions"><button className="secondary" onClick={()=>navigate('case',incidentId)}>Case Details</button>{hasPermission(session.user,'response:request') && <button className="secondary" onClick={()=>navigate('response',incidentId)}>Response Playbooks</button>}</div>} />
    {selector}
    <ErrorBox message={resource.error || details.error}/>
    {!resource.error && <>
      <div className="metric-grid"><Metric label="Tasks" number={String(tasks.length)} note="Investigation / containment work" /><Metric label="Handoffs" number={String(handoffs.length)} note="Auditable analyst transfers" /><Metric label="Evidence" number={String(evidence.length)} note="Registered chain-of-custody items" /><Metric label="Containment" number={value(profile,['containment_status'],'not_started')} note="Explicit response state" accent /></div>
      <div className="two-col"><Panel title="Case profile"><JsonView data={profile} title="Workflow profile"/><div className="stack"><label>Team<input value={team} onChange={e=>setTeam(e.target.value)}/></label><button className="primary" onClick={()=>void updateProfile()}>Mark containment in progress</button></div></Panel><Panel title="Create investigation task"><div className="stack"><label>Task title<input value={taskTitle} onChange={e=>setTaskTitle(e.target.value)}/></label><button className="primary" onClick={()=>void createTask()}>Create P2 task</button>{message&&<Notice>{message}</Notice>}</div></Panel></div>
      <Panel title="Case tasks"><DataTable rows={tasks} columns={['created_at','task_type','title','status','priority','assignee','due_at','completed_by','completed_at']} exportName="threatlens-caseops-tasks" /></Panel>
      <Panel title="Analyst handoffs"><DataTable rows={handoffs} columns={['created_at','from_actor','to_actor','note','accepted_at']} exportName="threatlens-caseops-handoffs" /></Panel>
      <Panel title={`Registered evidence Â· ${evidence.length}`}><DataTable rows={evidence} columns={['created_at','evidence_uuid','evidence_type','description','source_reference','sha256','registered_by']} exportName="threatlens-caseops-evidence" /></Panel>
      {evidence.length ? <div className="three-stack">{evidence.map(row=><EvidenceCustodyCard key={value(row,['evidence_uuid'])} session={session} evidence={row}/>)}</div> : <Empty>No registered evidence exists for this incident yet.</Empty>}
    </>}
  </>
}

export function ResponsePage({ session, incidentId }: { session: Session; incidentId: string }) {
  const playbooks=useResource<ListResponse>(session,'/api/v1/response/playbooks',{items:[]})
  const execPath=incidentId?`/api/v1/incidents/${incidentId}/response-executions`:'/api/v1/health/live'
  const executions=useResource<ListResponse>(session,execPath,{items:[]},Boolean(incidentId))
  const [selected,setSelected]=useState(''); const [message,setMessage]=useState('')
  async function request(){const id=selected||value((playbooks.data.items||[])[0]||{},['playbook_uuid']);if(!incidentId||!id)return;try{await api(session,`/api/v1/incidents/${incidentId}/response-executions`,{method:'POST',body:JSON.stringify({playbook_uuid:id,parameters:{requested_from:'soc_console'}})});setMessage('Execution requested; an authorized human must approve it before any execution record can be completed.');void executions.reload()}catch(caught){setMessage(caught instanceof Error?caught.message:'Request failed.')}}
  return <>
    <Header kicker="BATCH 6E · RESPONSE" title="Approval-Gated Response" subtitle="Human-authority playbooks with approval, executor, outcome and rollback evidence. ThreatLens never performs autonomous destructive actions." />
    <Notice tone="warning">Safety boundary: every response execution is approval-gated. Built-in actions are simulation/integration-ready records, not silent endpoint, identity or firewall changes.</Notice>
    <div className="two-col"><Panel title="Playbooks"><DataTable rows={playbooks.data.items||[]} columns={['name','action_type','risk_level','version','enabled']} /></Panel><Panel title="Request response"><div className="stack"><label>Playbook<select value={selected} onChange={e=>setSelected(e.target.value)}><option value="">Select first available</option>{(playbooks.data.items||[]).map(row=><option key={value(row,['playbook_uuid'])} value={value(row,['playbook_uuid'])}>{value(row,['name'])}</option>)}</select></label><button className="primary" disabled={!incidentId||!hasPermission(session.user,'response:request')} onClick={()=>void request()}>Request approval</button>{!incidentId&&<Empty>Select an incident first.</Empty>}{message&&<Notice>{message}</Notice>}</div></Panel></div>
    <Panel title="Response execution ledger"><DataTable rows={executions.data.items||[]} columns={['requested_at','playbook_name','status','requested_by','approved_by','executor','completed_at']} exportName="threatlens-response-executions" /></Panel>
  </>
}

export function DetectionEngineeringPage({ session }: { session: Session }) {
  const metrics=useResource<ListResponse>(session,'/api/v1/detections/effectiveness',{items:[]})
  const tunings=useResource<ListResponse>(session,'/api/v1/detections/tunings',{items:[]},hasPermission(session.user,'detection:manage'))
  const [rule,setRule]=useState(''); const [rationale,setRationale]=useState('Reduce documented false-positive noise while preserving the governed detection boundary.'); const [message,setMessage]=useState('')
  async function propose(){if(!rule)return;try{await api(session,'/api/v1/detections/tunings',{method:'POST',body:JSON.stringify({rule_id:rule,proposal_type:'threshold',proposal:{review_required:true},rationale})});setMessage('Tuning proposal recorded. Runtime YAML was NOT mutated.');void tunings.reload()}catch(caught){setMessage(caught instanceof Error?caught.message:'Proposal failed.')}}
  const rows=metrics.data.items||[]
  return <>
    <Header kicker="BATCH 6F · DETECTION ENGINEERING" title="Detection Feedback & Tuning" subtitle="Analyst dispositions, rule effectiveness and governed tuning proposals that never silently mutate deterministic rule YAML." />
    <ErrorBox message={metrics.error||tunings.error}/><div className="metric-grid three"><Metric label="Rules with firings" number={String(rows.length)} note="Persisted alert evidence" /><Metric label="Reviewed feedback" number={String(rows.reduce((n,r)=>n+Number(r.reviewed||0),0))} note="Analyst outcomes" /><Metric label="Open tunings" number={String((tunings.data.items||[]).filter(r=>value(r,['status'])==='proposed').length)} note="Governance queue" accent /></div>
    <Panel title="Rule effectiveness"><DataTable rows={rows} columns={['rule_id','alert_firings','reviewed','true_positive','false_positive','precision_observed','feedback_coverage']} exportName="threatlens-detection-effectiveness" /></Panel>
    <div className="two-col"><Panel title="Governed tuning proposal"><div className="stack"><label>Rule ID<input value={rule} onChange={e=>setRule(e.target.value)}/></label><label>Rationale<textarea rows={4} value={rationale} onChange={e=>setRationale(e.target.value)}/></label><button className="primary" disabled={!hasPermission(session.user,'detection:manage')} onClick={()=>void propose()}>Propose tuning</button>{message&&<Notice>{message}</Notice>}</div></Panel><Panel title="Tuning history"><DataTable rows={tunings.data.items||[]} columns={['created_at','rule_id','proposal_type','status','requested_by','reviewed_by']} /></Panel></div>
  </>
}

export function IdentityPage({ session }: { session: Session }) {
  const connectors = useResource<ListResponse>(session, '/api/v1/connectors', { items: [] })
  const sources = useResource<ListResponse>(session, '/api/v1/ingestion/sources', { items: [] })
  const recent = useResource<ListResponse>(session, '/api/v1/ingestion/recent?limit=250', { items: [] })
  const analyses = useResource<ListResponse>(session, '/api/v1/analyses?limit=250', { items: [] })

  const entra = (connectors.data.items || []).find(row => value(row, ['connector_id']) === 'entra_id')
  const entraSources = (sources.data.items || []).filter(row => value(row, ['connector_id']) === 'entra_id')
  const entraSourceIds = new Set(
    entraSources
      .map(row => value(row, ['source_uuid']))
      .filter(Boolean),
  )
  const entraAnalyses = (analyses.data.items || []).filter(
    row => value(row, ['connector_id']) === 'entra_id',
  )
  const latestAnalysis = entraAnalyses[0] || {}
  const latestAnalysisUuid = value(latestAnalysis, ['session_uuid'])
  const latestReceipts = (recent.data.items || []).filter(row => {
    if (!entraSourceIds.has(value(row, ['source_uuid']))) return false
    return latestAnalysisUuid
      ? value(row, ['analysis_session_uuid']) === latestAnalysisUuid
      : true
  })

  return <>
    <Header
      kicker="BATCH 6G Â· CLOUD / IDENTITY"
      title="Microsoft Entra ID Telemetry"
      subtitle="First-class cloud identity normalization with live persisted evidence for sign-in risk, MFA failures, account activity and privileged role assignments."
    />
    <ErrorBox message={connectors.error || sources.error || recent.error || analyses.error} />

    <div className="metric-grid">
      <Metric
        label="Connector"
        number={entra ? 'REGISTERED' : 'CHECK'}
        note="entra_id common-schema adapter"
        accent
      />
      <Metric
        label="Detection pack"
        number="4"
        note="Governed identity rules + fixtures"
      />
      <Metric
        label="Latest events"
        number={value(latestAnalysis, ['events'], '0')}
        note="Normalized Entra evidence"
      />
      <Metric
        label="Latest alerts"
        number={value(latestAnalysis, ['alerts'], '0')}
        note="Deterministic identity detections"
      />
      <Metric
        label="Durable receipts"
        number={String(latestReceipts.length)}
        note="Receipt-first ingress ledger"
      />
    </div>

    <div className="two-col wide-left">
      <Panel title="Latest Entra analysis">
        {latestAnalysisUuid
          ? <DataTable
              rows={[latestAnalysis]}
              columns={[
                'name',
                'status',
                'connector_id',
                'events',
                'alerts',
                'incidents',
                'completed_at',
                'session_uuid',
              ]}
              exportName="threatlens-entra-latest-analysis"
            />
          : <Empty>No persisted Entra analysis is available yet.</Empty>}
      </Panel>

      <Panel title="Connector contract">
        {entra
          ? <JsonView data={entra} />
          : <Empty>Entra connector metadata not returned by the API.</Empty>}
      </Panel>
    </div>

    <Panel title="Latest Entra durable receipts">
      {latestReceipts.length
        ? <DataTable
            rows={latestReceipts}
            columns={[
              'received_at',
              'source_uuid',
              'client_event_id',
              'status',
              'analysis_session_uuid',
              'error_code',
            ]}
            exportName="threatlens-entra-receipts"
          />
        : <Empty>No durable receipts are linked to the latest Entra analysis.</Empty>}
    </Panel>

    <Panel title="Authenticated Entra sources">
      <DataTable
        rows={entraSources}
        columns={[
          'name',
          'source_uuid',
          'enabled',
          'rate_limit_per_minute',
          'last_seen_at',
        ]}
        exportName="threatlens-entra-sources"
      />
    </Panel>

    <Panel title="Identity detections">
      <DataTable rows={[
        { detection: 'entra_risky_signin', severity: 'High', attack: 'T1078.004 Cloud Accounts' },
        { detection: 'entra_mfa_failure', severity: 'Medium', attack: 'T1621 MFA Request Generation' },
        { detection: 'entra_signin_failure', severity: 'Low', attack: 'T1110 Brute Force' },
        { detection: 'entra_privileged_role_assignment', severity: 'High', attack: 'T1098.003 Additional Cloud Roles' },
      ]} />
    </Panel>

    <Notice>
      Cloud/identity telemetry is shown from PostgreSQL-backed analyses and durable ingress receipts.
      Deterministic rules remain the detection authority; AI stays downstream and cannot create detections.
    </Notice>
  </>
}

export function GraphIntelligencePage({ session, incidentId }: { session: Session; incidentId: string }) {
  const incidents = useResource<ListResponse>(session, '/api/v1/incidents?limit=1000', { items: [] })
  const [incidentOverride,setIncidentOverride]=useState('')
  const [minimumConfidence,setMinimumConfidence]=useState(0.3)
  const [entityType,setEntityType]=useState('')
  const [pathSource,setPathSource]=useState('')
  const [pathTarget,setPathTarget]=useState('')
  const [pathResult,setPathResult]=useState<Json>({})
  const [timelineEntity,setTimelineEntity]=useState('')
  const [timelineResult,setTimelineResult]=useState<Json>({})
  const [query,setQuery]=useState('')
  const [searchType,setSearchType]=useState('')
  const [search,setSearch]=useState<Json[]>([])
  const [searchOffset,setSearchOffset]=useState(0)
  const [searchTotal,setSearchTotal]=useState('')
  const [message,setMessage]=useState('')
  const searchLimit=25

  const activeIncidentId=incidentOverride || incidentId
  const graphPath=activeIncidentId
    ? `/api/v1/incidents/${encodeURIComponent(activeIncidentId)}/graph/intelligence?minimum_confidence=${minimumConfidence}${entityType?`&entity_type=${encodeURIComponent(entityType)}`:''}`
    : '/api/v1/health/live'
  const graph=useResource<Json>(session,graphPath,{},Boolean(activeIncidentId))
  const nodes=jsonRows(graph.data.nodes)
  const edges=jsonRows(graph.data.edges)

  const incidentRows=incidents.data.items || []
  const entityTypes=Array.from(new Set(nodes.map(row=>value(row,['type','entity_type'],'')).filter(Boolean))).sort()
  const nodeOptions=nodes
    .map(row=>({
      key:value(row,['node_key','key','id'],''),
      label:value(row,['value','display_value','canonical_value','node_key','key','id'],''),
      entityUuid:value(row,['entity_uuid'],''),
      type:value(row,['type','entity_type'],''),
    }))
    .filter(row=>Boolean(row.key))
  const timelineOptions=nodeOptions.filter(row=>Boolean(row.entityUuid))
  const pathEndpointKeys=Array.from(new Set(
    edges.flatMap(row=>[
      value(row,['source','source_node_key'],''),
      value(row,['target','target_node_key'],''),
    ]).filter(Boolean),
  ))
  const pathEndpointOptions=pathEndpointKeys.map(key=>{
    const matchingNode=nodes.find(row=>value(row,['node_key','key','id'],'')===key)
    const label=matchingNode
      ? `${value(matchingNode,['type','entity_type'],'node')} | ${value(matchingNode,['value','display_value','canonical_value'],key)}`
      : key
    return {key,label}
  })

  async function runPath(){
    if(!activeIncidentId){setMessage('Select an incident before evaluating a graph path.');return}
    if(edges.length===0){setMessage('The selected incident has no persisted relationships at the current confidence filter.');return}
    if(!pathSource || !pathTarget){setMessage('Choose both relationship endpoints before explaining the path.');return}
    try{
      const result=await api<Json>(
        session,
        `/api/v1/incidents/${encodeURIComponent(activeIncidentId)}/graph/path`,
        {
          method:'POST',
          body:JSON.stringify({
            source_node_key:pathSource,
            target_node_key:pathTarget,
            minimum_confidence:minimumConfidence,
          }),
        },
      )
      setPathResult(result)
      setMessage('')
    }catch(caught){
      setMessage(caught instanceof Error?caught.message:'Graph path evaluation failed.')
    }
  }

  async function loadTimeline(entityUuid?:string){
    const selected=(entityUuid || timelineEntity).trim()
    if(!selected){setMessage('Choose or enter an entity UUID first.');return}
    try{
      const result=await api<Json>(
        session,
        `/api/v1/entities/${encodeURIComponent(selected)}/timeline?limit=250`,
      )
      setTimelineEntity(selected)
      setTimelineResult(result)
      setMessage('')
    }catch(caught){
      setMessage(caught instanceof Error?caught.message:'Entity timeline failed.')
    }
  }

  async function runSearch(offset=0){
    if(query.trim().length<2){setMessage('Global search requires at least two characters.');return}
    try{
      const types=searchType?`&entity_types=${encodeURIComponent(searchType)}`:''
      const result=await api<Json>(
        session,
        `/api/v1/search?q=${encodeURIComponent(query.trim())}&limit=${searchLimit}&offset=${offset}${types}`,
      )
      const rows=jsonRows(result.items)
      setSearch(rows)
      setSearchOffset(offset)
      setSearchTotal(String(value(result,['total','count'],'')))
      setMessage('')
    }catch(caught){
      setMessage(caught instanceof Error?caught.message:'Global search failed.')
    }
  }

  const pathRows=jsonRows(pathResult.path)
  const timelineRows=jsonRows(timelineResult.items)
  const canNextSearch=search.length===searchLimit
  const selectedIncident=incidentRows.find(row=>value(row,['incident_uuid'])===activeIncidentId)
  const incidentLabel=selectedIncident
    ? `${value(selectedIncident,['title','incident_name'],activeIncidentId)} | ${value(selectedIncident,['status'],'')} | ${value(selectedIncident,['priority'],'')}`
    : activeIncidentId

  return <>
    <Header
      kicker="BATCH 6H | GRAPH + SEARCH"
      title="Graph Intelligence & Global Search"
      subtitle="Evidence-backed entity relationships, confidence filtering, path explanations, entity timelines and server-side cross-investigation search."
    />

    <ErrorBox message={incidents.error || graph.error} />
    {message && <Notice>{message}</Notice>}

    <Panel title="Investigation context">
      <div className="button-row">
        <select value={activeIncidentId} onChange={event=>{setIncidentOverride(event.target.value);setPathResult({});setTimelineResult({})}}>
          <option value="">Select persisted incident</option>
          {incidentRows.map(row=>{
            const id=value(row,['incident_uuid'])
            const label=`${value(row,['title','incident_name'],id)} | ${value(row,['status'],'')} | ${value(row,['priority'],'')}`
            return <option key={id} value={id}>{label}</option>
          })}
        </select>
        {activeIncidentId && <span className="muted">{incidentLabel}</span>}
      </div>
    </Panel>

    <div className="metric-grid">
      <Metric label="Incident nodes" number={String(nodes.length)} note="Resolved evidence entities" />
      <Metric label="Relationships" number={String(edges.length)} note="Confidence-scored edges" />
      <Metric label="Confidence floor" number={minimumConfidence.toFixed(2)} note="Server-side graph filter" />
      <Metric label="Search scope" number="5" note="Incidents | alerts | events | entities | IOCs" accent />
    </div>

    <Panel title="Graph filters">
      <div className="button-row">
        <label>
          Minimum confidence {minimumConfidence.toFixed(2)}
          <input
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={minimumConfidence}
            onChange={event=>setMinimumConfidence(Number(event.target.value))}
          />
        </label>
        <select value={entityType} onChange={event=>setEntityType(event.target.value)}>
          <option value="">All entity types</option>
          {entityTypes.map(type=><option key={type} value={type}>{type}</option>)}
        </select>
        <button className="secondary" onClick={()=>{setMinimumConfidence(0.3);setEntityType('')}}>
          Reset filters
        </button>
      </div>
    </Panel>

    {!activeIncidentId
      ? <Notice>Select an incident to populate graph intelligence.</Notice>
      : <>
          <Panel title="Evidence-backed nodes">
            <DataTable
              rows={nodes}
              columns={['type','value','confidence','first_seen','last_seen','sources','entity_uuid','node_key']}
              exportName="threatlens-graph-nodes"
            />
          </Panel>

          <Panel title="Relationship explanations">
            <DataTable
              rows={edges}
              columns={['source','target','type','confidence','reasons','time_delta_seconds']}
              exportName="threatlens-graph-edges"
            />
          </Panel>
        </>}

    <Panel title="Interactive evidence path">
      <Notice>
        Path traversal uses the persisted relationship endpoint keys returned by the graph API.
        Entity nodes below remain available for entity timeline investigation.
      </Notice>
      <div className="button-row">
        <select value={pathSource} onChange={event=>setPathSource(event.target.value)}>
          <option value="">Source graph node</option>
          {pathEndpointOptions.map(option=><option key={`source-${option.key}`} value={option.key}>{option.label}</option>)}
        </select>
        <select value={pathTarget} onChange={event=>setPathTarget(event.target.value)}>
          <option value="">Target graph node</option>
          {pathEndpointOptions.map(option=><option key={`target-${option.key}`} value={option.key}>{option.label}</option>)}
        </select>
        <button
          className="primary"
          disabled={edges.length===0 || !pathSource || !pathTarget}
          onClick={()=>void runPath()}
        >
          Explain path
        </button>
      </div>

      {Object.keys(pathResult).length>0 && <>
        <div className="metric-grid three">
          <Metric label="Path found" number={String(value(pathResult,['found'],'false'))} note="Evidence-backed traversal" accent />
          <Metric label="Hop count" number={String(value(pathResult,['hop_count'],'0'))} note="Relationship hops" />
          <Metric label="Confidence floor" number={minimumConfidence.toFixed(2)} note="Applied path threshold" />
        </div>
        <JsonView data={pathResult} title="Path explanation and provenance" />
        <DataTable rows={pathRows} exportName="threatlens-graph-path" />
      </>}
    </Panel>

    <Panel title="Entity timeline">
      <div className="button-row">
        <select value={timelineEntity} onChange={event=>setTimelineEntity(event.target.value)}>
          <option value="">Entity from current graph</option>
          {timelineOptions.map(option=><option key={`timeline-${option.entityUuid}`} value={option.entityUuid}>{option.type} | {option.label}</option>)}
        </select>
        <SearchBox
          value={timelineEntity}
          onChange={setTimelineEntity}
          placeholder="Or enter entity UUID"
        />
        <button className="primary" onClick={()=>void loadTimeline()}>Load timeline</button>
      </div>

      {Object.keys(timelineResult).length>0 && <>
        <JsonView data={timelineResult} title="Entity timeline context" />
        <DataTable rows={timelineRows} exportName="threatlens-entity-timeline" />
      </>}
    </Panel>

    <Panel title="Global investigation search">
      <div className="button-row">
        <SearchBox
          value={query}
          onChange={setQuery}
          placeholder="Search incident, user, IP, host, process, domain, IOC..."
        />
        <select value={searchType} onChange={event=>{setSearchType(event.target.value);setSearchOffset(0)}}>
          <option value="">All supported types</option>
          <option value="incident">Incidents</option>
          <option value="alert">Alerts</option>
          <option value="event">Events</option>
          <option value="entity">Entities</option>
          <option value="indicator">Indicators / IOCs</option>
        </select>
        <button className="primary" onClick={()=>void runSearch(0)}>Search</button>
      </div>

      <div className="button-row">
        <button
          className="secondary"
          disabled={searchOffset===0}
          onClick={()=>void runSearch(Math.max(0,searchOffset-searchLimit))}
        >
          Previous page
        </button>
        <span className="muted">
          Offset {searchOffset}{searchTotal?` | total ${searchTotal}`:''}
        </span>
        <button
          className="secondary"
          disabled={!canNextSearch}
          onClick={()=>void runSearch(searchOffset+searchLimit)}
        >
          Next page
        </button>
      </div>

      <DataTable
        rows={search}
        columns={['type','title','subtitle','timestamp','id']}
        exportName="threatlens-global-search"
      />
    </Panel>

    <Notice>
      Graph relationships and path explanations are evidence-backed and confidence-scored.
      Search, graph filters and timelines are executed server-side against persisted investigation data.
    </Notice>
  </>
}
