import { useMemo, useState } from 'react'
import { DataTable, ErrorBox, Header, Metric, Panel, SearchBox, useResource } from '../components'
import { ListResponse, Session } from '../types'

export function AuditPage({ session }: { session: Session }) {
  const audit = useResource<ListResponse>(session, '/api/v1/audit?limit=1000', { items: [] })
  const [query, setQuery] = useState('')
  const rows = useMemo(() => (audit.data.items || []).filter(row => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [audit.data.items, query])
  const actors = new Set(rows.map(row => String(row.actor || '')).filter(Boolean)).size
  const actions = new Set(rows.map(row => String(row.action || '')).filter(Boolean)).size
  return <>
    <Header kicker="AUDITABILITY" title="Audit Trail" subtitle="Append-only operational evidence for authentication, case actions, RAG administration and other governed mutations." />
    <ErrorBox message={audit.error} />
    <div className="metric-grid two"><Metric label="Audit records" number={String(rows.length)} note="Current filtered view" /><Metric label="Actors / actions" number={`${actors} / ${actions}`} note="Distinct accountable activity" compactNumber /></div>
    <Panel title="Audit records" action={<SearchBox value={query} onChange={setQuery} placeholder="Filter actor, action, entity…" />}><DataTable rows={rows} columns={['created_at','actor','action','entity_type','entity_id','details']} exportName="threatlens-audit-trail" maxRows={1000} /></Panel>
  </>
}
