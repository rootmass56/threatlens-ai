import { ErrorBox, Header, Metric, Panel, Status, DataTable, useResource } from '../components'
import { Json, ListResponse, Page, Session } from '../types'
import { asJson, hasPermission, rowsFromList, value } from '../utils'

export function OverviewPage({ session, navigate }: { session: Session; navigate: (page: Page, id?: string) => void }) {
  const analyses = useResource<ListResponse>(session, '/api/v1/analyses?limit=100', { items: [] })
  const incidents = useResource<ListResponse>(session, '/api/v1/incidents?limit=250', { items: [] })
  const rag = useResource<Json>(session, '/api/v1/rag/health', {})
  const quality = useResource<Json>(session, '/api/v1/rules/quality/summary', {})
  const connector = useResource<Json>(session, '/api/v1/connectors', {})
  const analysisRows = analyses.data.items || []
  const incidentRows = incidents.data.items || []
  const active = incidentRows.filter(row => ['open', 'investigating'].includes(value(row, ['status'], '').toLowerCase())).length
  const high = incidentRows.filter(row => value(row, ['priority'], '').toUpperCase() === 'P1' || ['critical', 'high'].includes(value(row, ['severity'], '').toLowerCase())).length
  const ragHealth = asJson(rag.data)
  const connectors = rowsFromList(connector.data)
  return <>
    <Header kicker="OPERATIONS" title="SOC Overview" subtitle="Evidence-first posture across telemetry, detections, incidents, ATT&CK and grounded AI." actions={hasPermission(session.user, 'analysis:create') ? <button className="secondary" onClick={() => navigate('upload')}>+ New analysis</button> : undefined} />
    <ErrorBox message={analyses.error || incidents.error || rag.error || quality.error || connector.error} />
    <div className="metric-grid">
      <Metric label="Analysis sessions" number={String(analyses.data.count ?? analysisRows.length)} note="Persisted investigations" />
      <Metric label="Active incidents" number={String(active)} note="Open + investigating" accent />
      <Metric label="High priority" number={String(high)} note="P1 / critical attention" />
      <Metric label="RAG status" number={value(ragHealth, ['status'], '…').toUpperCase()} note={`${value(ragHealth, ['indexed_chunks'], '0')} indexed chunks`} compactNumber />
    </div>
    <div className="metric-grid two">
      <Metric label="Detection governance" number={value(quality.data, ['governance_score_percent', 'status'], 'READY')} note="Fixture-backed rule quality" compactNumber />
      <Metric label="Telemetry connectors" number={String(connectors.length)} note="Linux · Windows · Sysmon · Suricata · Zeek" />
    </div>
    <div className="two-col">
      <Panel title="Incident queue" action={<button className="text-btn" onClick={() => navigate('incidents')}>View all →</button>}>
        <DataTable rows={incidentRows.slice(0, 8)} columns={['title', 'status', 'priority', 'severity', 'risk_score', 'assignee']} onRow={row => navigate('case', value(row, ['incident_uuid'], ''))} empty="No incidents returned by the current data set." />
      </Panel>
      <Panel title="AI runtime">
        <dl className="facts">
          <div><dt>Standard</dt><dd>{value(ragHealth, ['llm_model'])}</dd></div>
          <div><dt>Deep</dt><dd>{value((Array.isArray(ragHealth.model_profiles) ? ragHealth.model_profiles.find(item => value(asJson(item), ['mode']) === 'deep') as Json : {}), ['model'])}</dd></div>
          <div><dt>Embedding</dt><dd>{value(ragHealth, ['embedding_model'])}</dd></div>
          <div><dt>Vector backend</dt><dd>{value(ragHealth, ['vector_backend'])}</dd></div>
        </dl>
        <Status>{value(ragHealth, ['status'], 'unknown')}</Status>
        <button className="secondary full gap-top" onClick={() => navigate('assistant')}>Open AI Investigation</button>
      </Panel>
    </div>
    <Panel title="Recent analyses" action={<button className="text-btn" onClick={() => navigate('analyses')}>Open history →</button>}>
      <DataTable rows={analysisRows.slice(0, 10)} columns={['name', 'status', 'source_type', 'events', 'alerts', 'incidents', 'parse_success_rate', 'created_at']} onRow={row => navigate('current', value(row, ['session_uuid'], ''))} />
    </Panel>
  </>
}
