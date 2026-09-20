import { useEffect, useState } from 'react'
import { api } from '../api'
import { ErrorBox, Header, JsonView, KeyValueGrid, Metric, Notice, Panel, Status, Tabs, useResource } from '../components'
import { Json, Session } from '../types'
import { asJson, asRows, hasPermission, value } from '../utils'

export function SystemPage({ session, initialTab = 'Health' }: { session: Session; initialTab?: string }) {
  const ready = useResource<Json>(session, '/api/v1/health/ready', {})
  const security = useResource<Json>(session, '/api/v1/system/security', {})
  const observability = useResource<Json>(session, '/api/v1/system/observability', {})
  const rag = useResource<Json>(session, '/api/v1/rag/health', {})
  const knowledge = useResource<Json>(session, '/api/v1/rag/knowledge/status', {})
  const [tab, setTab] = useState(initialTab)
  const canManageRag = hasPermission(session.user, 'rag:manage')
  useEffect(() => { setTab(initialTab) }, [initialTab])
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const reindexState = value(knowledge.data, ['reindex', 'state'], 'idle')

  useEffect(() => {
    if (reindexState !== 'running') return
    const timer = window.setInterval(() => { void knowledge.reload() }, 3000)
    return () => window.clearInterval(timer)
  }, [knowledge.reload, reindexState])

  useEffect(() => {
    if (reindexState === 'completed') {
      const outcome = value(knowledge.data, ['reindex', 'result_status'], 'completed')
      const chunks = value(knowledge.data, ['reindex', 'indexed_chunks'], value(knowledge.data, ['index', 'indexed_chunks'], '0'))
      setMessage(`Knowledge ${outcome} · ${chunks} chunks`)
      void rag.reload()
    } else if (reindexState === 'failed') {
      setMessage(value(knowledge.data, ['reindex', 'detail'], 'Knowledge re-index failed. Review the API logs before retrying.'))
    }
  }, [knowledge.data, rag.reload, reindexState])

  async function reindex(force: boolean) {
    setBusy(true)
    setMessage('Starting governed knowledge re-index… This operation continues safely in the background.')
    try {
      const result = await api<Json>(session, '/api/v1/rag/knowledge/reindex', { method: 'POST', body: JSON.stringify({ force }) })
      const state = value(result, ['reindex', 'state'], value(result, ['status'], 'accepted'))
      setMessage(state === 'running'
        ? 'Governed knowledge re-index is running in the background. Status refreshes automatically.'
        : `Knowledge re-index ${state}.`)
      await knowledge.reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'RAG re-index request failed.')
    } finally {
      setBusy(false)
    }
  }
  const health = asJson(rag.data)
  return <>
    <Header kicker="RUNTIME" title="System & AI Knowledge" subtitle="Production readiness, security configuration, vector/index health and governed knowledge administration." />
    <ErrorBox message={ready.error || security.error || observability.error || rag.error || knowledge.error} />
    <div className="metric-grid"><Metric label="API" number={value(ready.data, ['status'], '…').toUpperCase()} note="Database readiness" /><Metric label="RAG" number={value(health, ['status'], '…').toUpperCase()} note={value(health, ['vector_backend'])} /><Metric label="Knowledge" number={value(health, ['indexed_chunks'], '0')} note="Indexed chunks" /><Metric label="Version" number={value(ready.data, ['version'], '0.14.0')} note="Production Web Platform" compactNumber /></div>
    <Panel title="Runtime administration"><Tabs tabs={['Health','Observability','RAG Runtime','Knowledge Index','Security']} active={tab} onChange={setTab} /><div className="tab-body">{tab === 'Health' ? <KeyValueGrid data={ready.data} /> : tab === 'Observability' ? <><Notice>Batch 7 operational telemetry. Prometheus/Grafana are available only when the Docker <code>observability</code> profile is running.</Notice><JsonView data={observability.data} title="Application observability snapshot" /></> : tab === 'RAG Runtime' ? <><Status>{value(health, ['status'])}</Status><div className="profile-strip">{asRows(health.model_profiles).map((profile,index)=><div key={index}><b>{value(profile,['profile_name','mode'])}</b><span>{value(profile,['model'])}</span><span>{value(profile,['num_ctx'])} ctx</span><Status>{value(profile,['available'],'false') === 'true' ? 'ready' : 'unavailable'}</Status></div>)}</div><JsonView data={health} title="Complete RAG health" /></> : tab === 'Knowledge Index' ? <>{canManageRag ? <div className="toolbar"><button className="secondary" disabled={busy || reindexState === 'running'} onClick={() => void reindex(false)}>Refresh changed knowledge</button><button className="secondary" disabled={busy || reindexState === 'running'} onClick={() => void reindex(true)}>Force full re-index</button></div> : <Notice>Read-only RAG status. Knowledge re-indexing requires <code>rag:manage</code>.</Notice>}{message && <Notice>{message}</Notice>}<JsonView data={knowledge.data} title="Knowledge status" /></> : <JsonView data={security.data} title="Security controls" />}</div></Panel>
  </>
}
