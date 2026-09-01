import { useEffect, useMemo, useState } from 'react'
import { api, apiBlob } from '../api'
import { AttackGraphCanvas, DataTable, Empty, ErrorBox, Header, KeyValueGrid, Metric, Notice, Panel, SearchBox, Tabs, useResource } from '../components'
import { Json, ListResponse, Page, Session } from '../types'
import { asJson, asRows, downloadBlob, hasPermission, value } from '../utils'

export function AttackPage({ session }: { session: Session }) {
  const catalogs = useResource<ListResponse>(session, '/api/v1/attack/catalogues', { items: [] })
  const mappings = useResource<ListResponse>(session, '/api/v1/attack/mappings', { items: [] })
  const [domain, setDomain] = useState('enterprise-attack')
  const [tab, setTab] = useState('Techniques')
  const [query, setQuery] = useState('')
  const [message, setMessage] = useState('')
  const canSync = hasPermission(session.user, 'attack:sync')
  const detail = useResource<Json>(session, `/api/v1/attack/catalogues/${encodeURIComponent(domain)}`, {})
  const techniques = useResource<ListResponse>(session, `/api/v1/attack/catalogues/${encodeURIComponent(domain)}/techniques`, { items: [] })
  const objectTypes = useResource<ListResponse>(session, `/api/v1/attack/catalogues/${encodeURIComponent(domain)}/object-types`, { items: [] })

  useEffect(() => {
    if (catalogs.data.items?.length && !catalogs.data.items.some(row => value(row, ['domain']) === domain)) {
      setDomain(value(catalogs.data.items[0], ['domain'], 'enterprise-attack'))
    }
  }, [catalogs.data.items, domain])

  const techniqueRows = useMemo(() => (techniques.data.items || []).filter(row => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [query, techniques.data.items])
  const mappingRows = mappings.data.items || []
  const uniqueMapped = new Set(mappingRows.map(row => value(row, ['attack_id', 'technique_id'], '')).filter(Boolean)).size

  async function sync(forceDownload = false) {
    if (!canSync) return
    setMessage('Synchronizing pinned ATT&CK catalogues…')
    try {
      const result = await api<Json>(session, '/api/v1/attack/synchronize', { method: 'POST', body: JSON.stringify({ force_download: forceDownload }) })
      setMessage(`Synchronization complete: ${value(result, ['status'], 'updated')}`)
      await Promise.all([catalogs.reload(), detail.reload(), techniques.reload(), objectTypes.reload(), mappings.reload()])
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'ATT&CK synchronization failed.')
    }
  }

  async function navigator() {
    try {
      const response = await apiBlob(session, '/api/v1/attack/navigator')
      downloadBlob(response.filename || 'threatlens_attack_navigator.json', response.blob)
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Navigator export failed.')
    }
  }

  const status = asJson(detail.data)
  return <>
    <Header kicker="THREAT INTELLIGENCE" title="MITRE ATT&CK Coverage" subtitle="Pinned all-domain catalogue awareness with explicit separation between catalogue knowledge and evidence-backed rule coverage." actions={<div className="header-actions"><button className="secondary" onClick={() => void navigator()}>Navigator JSON ↓</button>{canSync && <><button className="secondary" onClick={() => void sync(true)}>Force refresh</button><button className="primary" onClick={() => void sync(false)}>Synchronize ATT&CK</button></>}</div>} />
    <ErrorBox message={catalogs.error || mappings.error || detail.error || techniques.error || objectTypes.error} />
    {message && <Notice>{message}</Notice>}
    <div className="metric-grid"><Metric label="Catalogues" number={String(catalogs.data.count ?? 0)} note="Enterprise · Mobile · ICS" /><Metric label="Techniques" number={value(status, ['technique_count'], String(techniqueRows.length))} note={domain} /><Metric label="Rule mappings" number={String(mappingRows.length)} note={`${uniqueMapped} unique mapped IDs`} accent /><Metric label="Catalogue version" number={value(status, ['version'], '19.1')} note="Pinned release" compactNumber /></div>
    <Panel title="Catalogue">
      <div className="toolbar"><select value={domain} onChange={event => setDomain(event.target.value)}>{(catalogs.data.items || []).map(row => { const id = value(row, ['domain']); return <option value={id} key={id}>{value(row, ['display_name'], id)} · {value(row, ['version'])}</option> })}</select><SearchBox value={query} onChange={setQuery} placeholder="Search ATT&CK…" /></div>
      <Tabs tabs={['Techniques', 'Rule Mappings', 'Coverage Gaps', 'STIX Inventory', 'Metadata']} active={tab} onChange={setTab} />
      <div className="tab-body">{tab === 'Techniques' ? <DataTable rows={techniqueRows} columns={['attack_id', 'name', 'is_subtechnique', 'parent_attack_id', 'tactics', 'platforms', 'modified']} exportName={`threatlens-${domain}-techniques`} maxRows={1000} /> : tab === 'Rule Mappings' ? <DataTable rows={domain === 'enterprise-attack' ? mappingRows : []} exportName="threatlens-attack-rule-mappings" /> : tab === 'Coverage Gaps' ? <CoverageGaps techniques={techniqueRows} mappings={domain === 'enterprise-attack' ? mappingRows : []} /> : tab === 'STIX Inventory' ? <DataTable rows={objectTypes.data.items || []} exportName={`threatlens-${domain}-stix-inventory`} /> : <KeyValueGrid data={status} />}</div>
    </Panel>
  </>
}

function CoverageGaps({ techniques, mappings }: { techniques: Json[]; mappings: Json[] }) {
  const mapped = new Set(mappings.map(row => value(row, ['attack_id', 'technique_id'], '')).filter(Boolean))
  const gaps = techniques.filter(row => !mapped.has(value(row, ['attack_id', 'technique_id'], '')))
  return <><Notice>Coverage gaps are explicit engineering backlog items. They are not presented as detected behavior unless a governed rule maps to supporting telemetry.</Notice><DataTable rows={gaps} columns={['attack_id', 'name', 'tactics', 'platforms', 'is_subtechnique']} exportName="threatlens-attack-coverage-gaps" maxRows={1000} /></>
}

export function AttackGraphPage({ session, analysisId, navigate }: { session: Session; analysisId: string; navigate: (page: Page, id?: string) => void }) {
  const analyses = useResource<ListResponse>(session, '/api/v1/analyses?limit=1000', { items: [] })
  const [selected, setSelected] = useState(analysisId)
  useEffect(() => { if (analysisId) setSelected(analysisId) }, [analysisId])
  useEffect(() => {
    if (!selected && analyses.data.items?.length) setSelected(value(analyses.data.items[0], ['session_uuid'], ''))
  }, [analyses.data.items, selected])
  const graph = useResource<Json>(session, selected ? `/api/v1/graphs/${encodeURIComponent(selected)}` : '/api/v1/health/live', {}, Boolean(selected))
  const graphPayload = asJson(graph.data.graph)
  const nodes = asRows(graphPayload.nodes)
  const edges = asRows(graphPayload.edges)

  function exportGraph() {
    const blob = new Blob([JSON.stringify(graph.data, null, 2)], { type: 'application/json' })
    downloadBlob(`threatlens-attack-graph-${selected || 'analysis'}.json`, blob)
  }

  return <>
    <Header kicker="ATTACK GRAPH INVESTIGATION" title="Persisted Attack Graph" subtitle="Interactive evidence graph across incidents, alerts, entities, ATT&CK tactics and techniques. Relationships are deterministic correlation artifacts." actions={<div className="header-actions"><button className="secondary" disabled={!selected} onClick={exportGraph}>Graph JSON ↓</button><button className="secondary" disabled={!selected} onClick={() => navigate('current', selected)}>Open current analysis</button></div>} />
    <ErrorBox message={analyses.error || graph.error} />
    {!analyses.data.items?.length && !analyses.loading ? <Empty>No persisted analysis is available. Run an analysis first.</Empty> : <>
      <Panel title="Select analysis"><select className="wide-select" value={selected} onChange={event => { setSelected(event.target.value); sessionStorage.setItem('threatlens.current.analysis', event.target.value) }}>{(analyses.data.items || []).map(row => { const id = value(row, ['session_uuid']); return <option key={id} value={id}>{value(row, ['name'], id)} · {value(row, ['created_at'])}</option> })}</select></Panel>
      <Panel title="Graph investigation">
        {graph.loading ? <Empty>Loading persisted attack graph…</Empty> : <>
          <KeyValueGrid data={asJson(graph.data.summary)} />
          <AttackGraphCanvas graph={graphPayload} />
          <Tabs tabs={['Nodes', 'Edges']} active={nodes.length ? 'Nodes' : 'Edges'} onChange={() => undefined} />
          <div className="two-col"><div><h3>Graph nodes</h3><DataTable rows={nodes} columns={['node_id', 'node_type', 'label', 'severity', 'risk_score', 'tactic', 'technique_id']} exportName="threatlens-attack-graph-nodes" maxRows={1000} /></div><div><h3>Graph edges</h3><DataTable rows={edges} columns={['source', 'target', 'relationship_type', 'edge_type', 'confidence', 'label', 'reasons']} exportName="threatlens-attack-graph-edges" maxRows={1000} /></div></div>
        </>}
      </Panel>
    </>}
  </>
}
