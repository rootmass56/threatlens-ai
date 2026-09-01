import { useEffect, useMemo, useState } from 'react'
import { DataTable, ErrorBox, Header, JsonView, KeyValueGrid, Metric, Notice, Panel, SearchBox, Tabs, useResource } from '../components'
import { Json, ListResponse, Session } from '../types'
import { asJson, asRows, rowsFromList, value } from '../utils'

export function RulesPage({ session, initialTab = 'Catalog' }: { session: Session; initialTab?: string }) {
  const catalog = useResource<ListResponse>(session, '/api/v1/rules', { items: [] })
  const validation = useResource<Json>(session, '/api/v1/rules/validation', {})
  const fixtures = useResource<ListResponse>(session, '/api/v1/rules/fixtures', { items: [] })
  const quality = useResource<Json>(session, '/api/v1/rules/quality/summary', {})
  const qualityRows = useResource<ListResponse>(session, '/api/v1/rules/quality/records', { items: [] })
  const profiles = useResource<ListResponse>(session, '/api/v1/rules/profiles', { items: [] })
  const [tab, setTab] = useState(initialTab)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState('')
  useEffect(() => { setTab(initialTab) }, [initialTab])
  const detail = useResource<Json>(session, selected ? `/api/v1/rules/${encodeURIComponent(selected)}` : '/api/v1/health/live', {}, Boolean(selected))
  const rows = useMemo(() => (catalog.data.items || []).filter(row => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [catalog.data.items, query])
  const q = asJson(quality.data)
  return <>
    <Header kicker="DETECTION ENGINEERING" title="Rule Catalog & Quality" subtitle="Governed deterministic detections, fixture evidence, lifecycle quality and ATT&CK mapping remain the security decision authority." />
    <ErrorBox message={catalog.error || validation.error || fixtures.error || quality.error || qualityRows.error || profiles.error} />
    <div className="metric-grid"><Metric label="Rules" number={String(catalog.data.count ?? rows.length)} note="Governed catalogue" /><Metric label="Enabled" number={value(q, ['enabled_rules'], '—')} note="Active detections" /><Metric label="Fixtures" number={value(q, ['fixture_cases'], String(fixtures.data.count ?? 0))} note="Positive / negative / boundary" /><Metric label="Governance" number={value(q, ['governance_score_percent'], '100')} note="Review + lifecycle quality" compactNumber /></div>
    <Panel title="Detection engineering"><div className="toolbar"><SearchBox value={query} onChange={setQuery} placeholder="Search rules, tactic, dataset…" /></div><Tabs tabs={['Catalog','Rule Detail','Validation','Fixtures','Quality','Profiles']} active={tab} onChange={setTab} /><div className="tab-body">{tab === 'Catalog' ? <DataTable rows={rows} columns={['rule_id','title','status','severity','dataset','attack_ids','tactics','enabled','review_due']} onRow={row => { setSelected(value(row, ['rule_id'])); setTab('Rule Detail') }} exportName="threatlens-rule-catalog" /> : tab === 'Rule Detail' ? selected ? <><KeyValueGrid data={detail.data} /><JsonView data={detail.data} title="Complete governed rule definition" /></> : <Notice>Select a rule from the Catalog tab.</Notice> : tab === 'Validation' ? <><KeyValueGrid data={validation.data} /><DataTable rows={asRows(validation.data.issues_detail)} exportName="threatlens-rule-validation-issues" /></> : tab === 'Fixtures' ? <DataTable rows={fixtures.data.items || []} exportName="threatlens-rule-fixtures" maxRows={1000} /> : tab === 'Quality' ? <><KeyValueGrid data={q} /><DataTable rows={qualityRows.data.items || []} exportName="threatlens-rule-quality" /></> : <DataTable rows={profiles.data.items || []} exportName="threatlens-rule-profiles" />}</div></Panel>
  </>
}
