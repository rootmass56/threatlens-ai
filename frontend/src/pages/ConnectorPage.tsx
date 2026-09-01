import { FormEvent, useMemo, useState } from 'react'
import { api } from '../api'
import { DataTable, ErrorBox, Header, Metric, Notice, Panel, SearchBox, useResource } from '../components'
import { Json, ListResponse, Session } from '../types'
import { value } from '../utils'

export function ConnectorPage({ session }: { session: Session }) {
  const catalog = useResource<ListResponse>(session, '/api/v1/connectors', { items: [] })
  const rules = useResource<ListResponse>(session, '/api/v1/rules', { items: [] })
  const [query, setQuery] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [diagnostics, setDiagnostics] = useState<Json[]>([])
  const [message, setMessage] = useState('')
  const rows = useMemo(() => (catalog.data.items || []).filter(row => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [catalog.data.items, query])
  const ruleRows = rules.data.items || []
  const coverage = rows.map(connector => { const id = value(connector, ['connector_id','id'], ''); return { connector_id: id, display_name: value(connector, ['display_name','name']), detection_rules: ruleRows.filter(rule => JSON.stringify(rule).includes(id) || value(rule, ['dataset','source_dataset'], '') === id).length } as Json })
  async function diagnose(event: FormEvent) { event.preventDefault(); if (!file) return; setMessage('Running connector diagnostics…'); const form = new FormData(); form.append('file', file); try { const response = await api<ListResponse>(session, '/api/v1/connectors/diagnose', { method: 'POST', body: form }); setDiagnostics(response.items || []); setMessage('Connector diagnostic completed.') } catch (caught) { setMessage(caught instanceof Error ? caught.message : 'Connector diagnostic failed.') } }
  return <>
    <Header kicker="TELEMETRY" title="Connector Health" subtitle="Enabled telemetry registry, normalization coverage and safe file-level connector diagnostics." />
    <ErrorBox message={catalog.error || rules.error} />
    <div className="metric-grid two"><Metric label="Registered connectors" number={String(catalog.data.count ?? rows.length)} note="Supported source families" /><Metric label="Mapped rule references" number={String(coverage.reduce((sum,row) => sum + Number(row.detection_rules || 0), 0))} note="Detection coverage indicator" /></div>
    <div className="two-col wide-left"><Panel title="Connector registry" action={<SearchBox value={query} onChange={setQuery} />}><DataTable rows={rows} exportName="threatlens-connectors" /></Panel><Panel title="Diagnose telemetry file"><form className="stack" onSubmit={diagnose}><label>Sample file<input type="file" onChange={event => setFile(event.target.files?.[0] || null)} required /></label><button className="primary">Run connector diagnostic</button>{message && <Notice>{message}</Notice>}</form></Panel></div>
    {diagnostics.length > 0 && <Panel title="Diagnostic result"><DataTable rows={diagnostics} exportName="threatlens-connector-diagnostic" /></Panel>}
    <Panel title="Coverage by connector"><DataTable rows={coverage} /></Panel>
  </>
}
