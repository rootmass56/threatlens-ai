import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { DataTable, Empty, ErrorBox, Header, KeyValueGrid, Metric, Notice, Panel, SearchBox, Tabs, useResource } from '../components'
import { Json, ListResponse, Page, Session } from '../types'
import { asJson, asRows, fileSizeMiB, value } from '../utils'

type FileDiagnostic = {
  filename: string
  size_bytes: number
  connector_id: string
  confidence: string
  valid: string
}

export function UploadPage({ session, navigate }: { session: Session; navigate: (page: Page, id?: string) => void }) {
  const connectors = useResource<ListResponse>(session, '/api/v1/connectors', { items: [] })
  const security = useResource<Json>(session, '/api/v1/system/security', {})
  const [files, setFiles] = useState<File[]>([])
  const [analysisName, setAnalysisName] = useState('Multi-Source Security Telemetry Analysis')
  const [analysisYear, setAnalysisYear] = useState(new Date().getUTCFullYear())
  const [connectorOverrides, setConnectorOverrides] = useState<Record<string, string>>({})
  const [allowDuplicate, setAllowDuplicate] = useState(false)
  const [busy, setBusy] = useState(false)
  const [diagnosing, setDiagnosing] = useState(false)
  const [message, setMessage] = useState('')
  const [result, setResult] = useState<Json | null>(null)
  const [diagnostics, setDiagnostics] = useState<FileDiagnostic[]>([])

  const limits = asJson(security.data.upload_limits)
  const maxFileBytes = Number(limits.max_file_bytes || 10 * 1024 * 1024)
  const maxFiles = Number(limits.max_files || 10)
  const maxBatchBytes = Number(limits.max_batch_bytes || maxFileBytes * maxFiles)
  const batchBytes = files.reduce((sum, file) => sum + file.size, 0)

  function chooseFiles(list: FileList | null) {
    const selected = list ? Array.from(list) : []
    setFiles(selected)
    setDiagnostics([])
    setConnectorOverrides(Object.fromEntries(selected.map(file => [file.name, ''])))
  }

  function validateFiles(): string | null {
    if (!files.length) return 'Select at least one telemetry file.'
    if (files.length > maxFiles) return `Select no more than ${maxFiles} files.`
    const empty = files.find(file => file.size <= 0)
    if (empty) return `${empty.name} is empty.`
    const tooLarge = files.find(file => file.size > maxFileBytes)
    if (tooLarge) return `${tooLarge.name} exceeds the ${fileSizeMiB(maxFileBytes)} MiB API file limit.`
    if (batchBytes > maxBatchBytes) return `The selected batch exceeds the ${fileSizeMiB(maxBatchBytes)} MiB API batch limit.`
    return null
  }

  async function diagnoseSources() {
    const problem = validateFiles()
    if (problem) { setMessage(problem); return }
    setDiagnosing(true)
    setMessage('Running safe connector diagnostics for selected sources…')
    try {
      const rows: FileDiagnostic[] = []
      for (const file of files) {
        const form = new FormData()
        form.append('file', file)
        const response = await api<ListResponse>(session, '/api/v1/connectors/diagnose', { method: 'POST', body: form })
        const top = response.items?.[0] || {}
        rows.push({
          filename: file.name,
          size_bytes: file.size,
          connector_id: value(top, ['connector_id'], 'unknown'),
          confidence: value(top, ['confidence'], '0'),
          valid: value(top, ['valid'], 'false'),
        })
      }
      setDiagnostics(rows)
      setMessage('Connector diagnostics completed. Review the detected source types before analysis.')
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Connector diagnostics failed.')
    } finally {
      setDiagnosing(false)
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    const problem = validateFiles()
    if (problem) { setMessage(problem); return }
    setBusy(true)
    setMessage('Running deterministic detection and correlation pipeline…')
    setResult(null)

    const form = new FormData()
    files.forEach(file => form.append('files', file))
    form.append('analysis_name', analysisName.trim() || `SOC analysis ${new Date().toISOString()}`)
    form.append('allow_duplicate', String(allowDuplicate))
    form.append('source_metadata', JSON.stringify(files.map(file => ({
      connector_id: connectorOverrides[file.name] || null,
      options: { analysis_year: analysisYear },
    }))))

    try {
      const response = await api<Json>(session, '/api/v1/analyses/upload', { method: 'POST', body: form })
      setResult(response)
      const id = value(response, ['session_uuid', 'duplicate_session_uuid'], '')
      setMessage(value(response, ['duplicate_session_uuid'], '') ? 'Duplicate detected; existing persisted analysis loaded.' : 'Analysis completed and persisted.')
      if (id) {
        sessionStorage.setItem('threatlens.current.analysis', id)
        setTimeout(() => navigate('current', id), 500)
      }
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Analysis upload failed.')
    } finally {
      setBusy(false)
    }
  }

  return <>
    <Header kicker="TELEMETRY INGESTION" title="Upload & Analyze" subtitle="Validate, identify and normalize Linux, Windows, Sysmon, Suricata and Zeek telemetry before deterministic detection and correlation." />
    <ErrorBox message={connectors.error || security.error} />
    <div className="two-col wide-left">
      <Panel title="New governed analysis">
        <form className="stack" onSubmit={submit}>
          <label>Analysis name<input value={analysisName} onChange={event => setAnalysisName(event.target.value)} maxLength={255} /></label>
          <label>Year for yearless Linux syslog<input type="number" min={2000} max={2100} value={analysisYear} onChange={event => setAnalysisYear(Number(event.target.value))} /></label>
          <label>Telemetry files<input type="file" multiple accept=".log,.txt,.json,.jsonl,.ndjson,.csv" onChange={event => chooseFiles(event.target.files)} required /></label>
          <label className="check"><input type="checkbox" checked={allowDuplicate} onChange={event => setAllowDuplicate(event.target.checked)} /> Allow intentional duplicate ingestion</label>
          <div className="toolbar compact"><button type="button" className="secondary" disabled={diagnosing || !files.length} onClick={() => void diagnoseSources()}>{diagnosing ? 'Diagnosing…' : 'Diagnose selected sources'}</button><button className="primary" disabled={busy}>{busy ? 'Analyzing…' : 'Analyze uploaded batch'}</button></div>
          {message && <Notice tone={message.includes('exceed') || message.includes('failed') || message.includes('Select') ? 'warning' : 'info'}>{message}</Notice>}
        </form>
      </Panel>
      <Panel title="API upload boundary">
        <dl className="facts"><div><dt>Files maximum</dt><dd>{maxFiles}</dd></div><div><dt>Per-file limit</dt><dd>{fileSizeMiB(maxFileBytes)} MiB</dd></div><div><dt>Batch limit</dt><dd>{fileSizeMiB(maxBatchBytes)} MiB</dd></div><div><dt>Selected batch</dt><dd>{files.length} files · {fileSizeMiB(batchBytes)} MiB</dd></div></dl>
        <p className="body-copy">React validates the authoritative API limits before transport. FastAPI independently re-validates file count, byte size, filename and content type.</p>
        <div className="pipeline"><span>Connectors</span><b>→</b><span>Common Schema</span><b>→</b><span>42 Rules</span><b>→</b><span>Correlation</span><b>→</b><span>Incidents</span></div>
      </Panel>
    </div>

    {files.length > 0 && <Panel title="Selected sources">
      <div className="source-grid">{files.map(file => <div className="source-card" key={`${file.name}:${file.size}`}><div><strong>{file.name}</strong><small>{fileSizeMiB(file.size)} MiB · {file.type || 'unknown content type'}</small></div><label>Connector override<select value={connectorOverrides[file.name] || ''} onChange={event => setConnectorOverrides(current => ({ ...current, [file.name]: event.target.value }))}><option value="">Auto-detect</option>{(connectors.data.items || []).map(row => { const id = value(row, ['connector_id', 'id']); return <option key={id} value={id}>{id}</option> })}</select></label></div>)}</div>
    </Panel>}

    {diagnostics.length > 0 && <Panel title="Pre-analysis connector diagnostics"><DataTable rows={diagnostics as unknown as Json[]} columns={['filename', 'size_bytes', 'connector_id', 'confidence', 'valid']} exportName="threatlens-upload-diagnostics" /></Panel>}
    {result && <Panel title="Execution response"><KeyValueGrid data={result} keys={['persisted', 'session_uuid', 'duplicate_session_uuid']} /></Panel>}
  </>
}

export function AnalysisHistoryPage({ session, selectedId, navigate }: { session: Session; selectedId: string; navigate: (page: Page, id?: string) => void }) {
  const history = useResource<ListResponse>(session, '/api/v1/analyses?limit=1000', { items: [] })
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => (history.data.items || []).filter(row => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [history.data.items, query])
  return <>
    <Header kicker="ANALYSIS WORKSPACE" title="Analysis History" subtitle="Persisted investigations remain available independently of browser state. Open an analysis directly or continue into its incident workflow." actions={<div className="header-actions"><button className="secondary" onClick={() => navigate('incidents')}>Incident Queue →</button><button className="primary" onClick={() => navigate('upload')}>+ Upload telemetry</button></div>} />
    <Panel title={`Persisted analyses · ${filtered.length}`} action={<SearchBox value={query} onChange={setQuery} placeholder="Filter sessions…" />}>
      <ErrorBox message={history.error} />
      <DataTable rows={filtered} columns={['name', 'status', 'source_type', 'connector_id', 'events', 'alerts', 'incidents', 'quarantined', 'parse_success_rate', 'created_at']} onRow={row => navigate('current', value(row, ['session_uuid'], ''))} rowActionLabel="Open analysis →" exportName="threatlens-analysis-history" />
    </Panel>
    {selectedId && <Notice>Current browser analysis: <code>{selectedId}</code>. Select any row to load another persisted analysis.</Notice>}
  </>
}

export function CurrentAnalysisPage({ session, selectedId, navigate }: { session: Session; selectedId: string; navigate: (page: Page, id?: string) => void }) {
  const history = useResource<ListResponse>(session, '/api/v1/analyses?limit=1000', { items: [] })
  const [selected, setSelected] = useState(selectedId)
  useEffect(() => { if (selectedId) setSelected(selectedId) }, [selectedId])
  useEffect(() => {
    if (!selected && history.data.items?.length) {
      const id = value(history.data.items[0], ['session_uuid'], '')
      if (id) setSelected(id)
    }
  }, [history.data.items, selected])

  if (!selected && !history.loading) return <><Header kicker="CURRENT ANALYSIS" title="Current Analysis" subtitle="Load a persisted session from history or run a new analysis." /><Empty>No persisted analysis is available yet.</Empty></>

  return <>
    <Header kicker="CURRENT ANALYSIS" title="Current Analysis" subtitle="Complete normalized evidence, detections, timeline and correlation artifacts for the selected persisted session." actions={<div className="header-actions"><button className="secondary" onClick={() => navigate('analyses')}>← Analysis History</button><button className="secondary" onClick={() => navigate('incidents')}>Incident Queue →</button><button className="primary" onClick={() => navigate('upload')}>+ New analysis</button></div>} />
    <Panel title="Select persisted session"><select className="wide-select" value={selected} onChange={event => { setSelected(event.target.value); sessionStorage.setItem('threatlens.current.analysis', event.target.value) }}>{(history.data.items || []).map(row => { const id = value(row, ['session_uuid']); return <option value={id} key={id}>{value(row, ['name'], id)} · {value(row, ['created_at'])}</option> })}</select></Panel>
    {selected && <AnalysisDetail session={session} sessionId={selected} navigate={navigate} />}
  </>
}

function AnalysisDetail({ session, sessionId, navigate }: { session: Session; sessionId: string; navigate: (page: Page, id?: string) => void }) {
  const resource = useResource<Json>(session, `/api/v1/analyses/${encodeURIComponent(sessionId)}`, {}, Boolean(sessionId))
  const correlationResource = useResource<Json>(session, `/api/v1/analyses/${encodeURIComponent(sessionId)}/correlation`, {}, Boolean(sessionId))
  const [tab, setTab] = useState('Summary')
  const pipeline = asJson(resource.data.pipeline)
  const metadata = asJson(resource.data.session)
  const correlation = Object.keys(correlationResource.data).length ? correlationResource.data : asJson(pipeline.correlation)
  const tabs = ['Summary', 'Sources', 'Events', 'Alerts', 'Incidents', 'Timeline', 'Quarantine', 'Correlation']
  let content
  if (tab === 'Summary') content = <><div className="metric-grid"><Metric label="Events" number={value(metadata, ['events'], String(asRows(pipeline.events).length))} note="Normalized events" /><Metric label="Alerts" number={value(metadata, ['alerts'], String(asRows(pipeline.alerts).length))} note="Deterministic detections" /><Metric label="Incidents" number={value(metadata, ['incidents'], String(asRows(pipeline.incidents).length))} note="Correlated cases" accent /><Metric label="Parse success" number={value(metadata, ['parse_success_rate'], '—')} note="Connector normalization" compactNumber /></div><KeyValueGrid data={metadata} keys={['session_uuid','name','status','source_type','connector_id','schema_version','rule_catalog_version','parser_version','engine_version','file_sha256','analysis_fingerprint','started_at','completed_at']} /></>
  else if (tab === 'Sources') content = <DataTable rows={asRows(pipeline.source_manifest)} exportName="threatlens-source-manifest" />
  else if (tab === 'Events') content = <DataTable rows={asRows(pipeline.events)} columns={['timestamp','source_dataset','event_type','event_action','event_outcome','hostname','username','source_ip','destination_ip','process_name','command_line']} exportName="threatlens-events" maxRows={1000} />
  else if (tab === 'Alerts') content = <DataTable rows={asRows(pipeline.alerts)} columns={['detection_id','rule_title','severity','confidence','risk_score','primary_tactic','primary_technique_id','hostname','username','source_ip','timestamp']} exportName="threatlens-alerts" />
  else if (tab === 'Incidents') content = <DataTable rows={asRows(pipeline.incidents)} columns={['title','status','priority','severity','risk_score','confidence','stage_progression','graph_score','assignee']} onRow={row => navigate('case', value(row, ['incident_uuid'], ''))} rowActionLabel="Open case →" exportName="threatlens-incidents" />
  else if (tab === 'Timeline') content = <DataTable rows={asRows(pipeline.timeline)} exportName="threatlens-timeline" maxRows={1000} />
  else if (tab === 'Quarantine') content = <DataTable rows={asRows(pipeline.quarantined)} exportName="threatlens-quarantine" />
  else content = <div className="three-stack"><Panel title="Correlation metrics"><KeyValueGrid data={asJson(correlation.metrics || correlation)} /></Panel><Panel title="Resolved entities"><DataTable rows={asRows(correlation.entities)} exportName="threatlens-entities" /></Panel><Panel title="Scored relationships"><DataTable rows={asRows(correlation.relationships)} exportName="threatlens-relationships" /></Panel></div>
  return <Panel title={value(metadata, ['name'], sessionId)} action={<div className="header-actions"><button className="text-btn" onClick={() => navigate('incidents')}>Incident queue →</button><button className="text-btn" onClick={() => navigate('graph', sessionId)}>Attack graph →</button><button className="text-btn" onClick={() => navigate('reports', sessionId)}>Generate report →</button></div>}><ErrorBox message={resource.error || correlationResource.error} />{resource.loading ? <Empty>Loading persisted analysis…</Empty> : <><Tabs tabs={tabs} active={tab} onChange={setTab} /><div className="tab-body">{content}</div></>}</Panel>
}
