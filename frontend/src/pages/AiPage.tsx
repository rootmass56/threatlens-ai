import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { BadgeList, DataTable, Empty, ErrorBox, Header, JsonView, Notice, Panel, Segmented, Status, useResource } from '../components'
import { Json, ListResponse, Session } from '../types'
import { asJson, asRows, value } from '../utils'

const TERMINAL = new Set(['succeeded', 'failed', 'cancelled'])

function idempotencyKey(incidentId: string, mode: string, question: string) {
  const material = `${incidentId}:${mode}:${question}:${Date.now()}:${Math.random()}`
  return `ui-${material.replace(/[^a-zA-Z0-9]/g, '').slice(-80)}`
}

export function AiPage({ session, incidentId }: { session: Session; incidentId: string }) {
  const incidents = useResource<ListResponse>(session, '/api/v1/incidents?limit=500', { items: [] })
  const rag = useResource<Json>(session, '/api/v1/rag/health', {})
  const queue = useResource<Json>(session, '/api/v1/assistant/jobs/health', {})
  const [selected, setSelected] = useState(incidentId)
  const [mode, setMode] = useState('auto')
  const [question, setQuestion] = useState('Explain what happened in this incident using only supported evidence. Separate observed evidence from governed ATT&CK knowledge and analyst inference.')
  const [result, setResult] = useState<Json | null>(null)
  const [job, setJob] = useState<Json | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => { if (incidentId) setSelected(incidentId) }, [incidentId])
  useEffect(() => {
    if (!selected && incidents.data.items?.length) setSelected(value(incidents.data.items[0], ['incident_uuid'], ''))
  }, [incidents.data.items, selected])

  const history = useResource<ListResponse>(session, selected ? `/api/v1/incidents/${encodeURIComponent(selected)}/assistant/history?limit=50` : '/api/v1/incidents?limit=1', { items: [] }, Boolean(selected))
  const jobs = useResource<ListResponse>(session, selected ? `/api/v1/incidents/${encodeURIComponent(selected)}/assistant/jobs?limit=50` : '/api/v1/incidents?limit=1', { items: [] }, Boolean(selected))
  const reloadHistory = history.reload
  const reloadJobs = jobs.reload
  const jobUuid = job ? value(job, ['job_uuid'], '') : ''
  const jobStatus = job ? value(job, ['status'], '') : ''

  useEffect(() => {
    if (!jobUuid || TERMINAL.has(jobStatus)) return
    const poll = async () => {
      try {
        const current = await api<Json>(session, `/api/v1/assistant/jobs/${encodeURIComponent(jobUuid)}`)
        setJob(current)
        const status = value(current, ['status'], '')
        if (status === 'succeeded') {
          setResult(asJson(current.result))
          setBusy(false)
          await reloadHistory()
          await reloadJobs()
        } else if (status === 'failed' || status === 'cancelled') {
          setBusy(false)
          if (status === 'failed') setError(value(current, ['error_message'], 'AI investigation job failed.'))
          await reloadJobs()
        }
      } catch (caught) {
        setBusy(false)
        setError(caught instanceof Error ? caught.message : 'Unable to refresh the durable AI job.')
      }
    }
    void poll()
    const timer = window.setInterval(() => { void poll() }, 1500)
    return () => window.clearInterval(timer)
  }, [jobStatus, jobUuid, reloadHistory, reloadJobs, session])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!selected) return
    setBusy(true)
    setError('')
    setResult(null)
    setJob(null)
    try {
      const created = await api<Json>(session, `/api/v1/incidents/${encodeURIComponent(selected)}/assistant/jobs`, {
        method: 'POST',
        headers: { 'Idempotency-Key': idempotencyKey(selected, mode, question) },
        body: JSON.stringify({ question, analysis_mode: mode }),
      })
      setJob(created)
      await reloadJobs()
    } catch (caught) {
      setBusy(false)
      setError(caught instanceof Error ? caught.message : 'AI investigation submission failed.')
    }
  }

  function openSavedJob(saved: Json) {
    const status = value(saved, ['status'], '')
    const savedMode = value(saved, ['analysis_mode'], 'auto')
    setJob(saved)
    setQuestion(value(saved, ['question'], ''))
    if (['auto', 'standard', 'deep'].includes(savedMode)) setMode(savedMode)
    setResult(status === 'succeeded' && saved.result ? asJson(saved.result) : null)
    setBusy(status === 'queued' || status === 'running')
    setError(status === 'failed' ? value(saved, ['error_message'], 'This saved job failed.') : '')
    if (status === 'succeeded') window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  async function cancelQueued() {
    if (!jobUuid || jobStatus !== 'queued') return
    try {
      const cancelled = await api<Json>(session, `/api/v1/assistant/jobs/${encodeURIComponent(jobUuid)}/cancel`, { method: 'POST' })
      setJob(cancelled)
      setBusy(false)
      await reloadJobs()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Unable to cancel the queued AI job.')
    }
  }

  const citations = result ? asRows(result.citations) : []
  const findings = result ? asRows(result.key_findings) : []
  const actions = result ? asRows(result.recommended_actions) : []
  const techniques = result ? asRows(result.technique_explanations) : []
  const profiles = asRows(rag.data.model_profiles)
  const routing = useMemo(() => result ? [value(result, ['requested_mode']), value(result, ['resolved_mode']), value(result, ['served_model','llm_model'])].join(' → ') : '', [result])

  return <>
    <Header kicker="GROUNDED RAG · DURABLE JOBS" title="AI Investigation" subtitle="Adaptive Qwen analysis is queued durably in PostgreSQL, delivered through Redis workers, and constrained by authorized evidence, governed knowledge and post-generation citation validation." />
    <div className="metric-grid">
      <div className="metric"><span>Queue</span><strong>{value(queue.data, ['reachable'], 'false') === 'true' ? 'READY' : 'CHECK'}</strong><small>{value(queue.data, ['pending'], '0')} pending</small></div>
      <div className="metric"><span>Workers</span><strong>{value(queue.data, ['workers'], '0')}</strong><small>Durable AI executors</small></div>
      <div className="metric"><span>Current job</span><strong>{jobStatus || 'idle'}</strong><small>{job ? `delivery ${value(job, ['queue_delivery_state'], '—')}` : 'No active request'}</small></div>
      <div className="metric"><span>Result UUID</span><strong className="compact">{job ? value(job, ['result_query_uuid'], '—') || '—' : '—'}</strong><small>Persisted RAG query</small></div>
    </div>
    <div className="assistant-grid">
      <Panel title="Investigation request">
        <form className="stack" onSubmit={submit}>
          <label>Incident<select value={selected} onChange={event => { setSelected(event.target.value); setJob(null); setResult(null) }}>{(incidents.data.items || []).map(row => { const id = value(row, ['incident_uuid']); return <option key={id} value={id}>{value(row, ['title'], id)}</option> })}</select></label>
          <label>Analysis mode<Segmented values={['auto','standard','deep']} active={mode} onChange={setMode} /></label>
          <label>Question<textarea rows={8} maxLength={2000} value={question} onChange={event => setQuestion(event.target.value)} /></label>
          <button className="primary" disabled={busy || !selected}>{busy ? 'Durable job running…' : 'Queue grounded investigation'}</button>
          {jobStatus === 'queued' && <button type="button" className="secondary" onClick={() => void cancelQueued()}>Cancel queued job</button>}
          <ErrorBox message={error} />
        </form>
        <div className="profile-strip">{profiles.map((profile, index) => <div key={index}><b>{value(profile, ['profile_name','mode'])}</b><span>{value(profile, ['model'])}</span><Status>{value(profile, ['available'], 'false') === 'true' ? 'ready' : 'unavailable'}</Status></div>)}</div>
        {job && <JsonView data={job} title="Durable job state" />}
      </Panel>
      <Panel title="Grounded response">
        {!result ? <Empty>{busy ? 'The durable AI job is queued/running. This page polls PostgreSQL-backed job state until completion.' : 'Select an incident and queue an investigation question.'}</Empty> : <div className="answer">
          <div className="answer-meta"><Status>{value(result, ['status'])}</Status><span>Grounding {value(result, ['grounding_score'])}</span><span>{routing}</span><span>{value(result, ['total_latency_ms'])} ms</span></div>
          {value(result, ['fallback_used'], 'false') === 'true' && <Notice tone="warning">Model fallback was used: {value(result, ['fallback_reason'])}</Notice>}
          <h3>Assessment</h3><p>{value(result, ['assessment'])}</p>
          <h3>Key findings</h3>{findings.length ? findings.map((item, index) => <div className="claim" key={index}><p>{value(item, ['text'])}</p><BadgeList values={Array.isArray(item.citation_ids) ? item.citation_ids.map(String) : []} /></div>) : <p className="muted">No supported findings returned.</p>}
          <h3>Recommended actions</h3>{actions.map((item, index) => <div className="claim" key={index}><p>{value(item, ['text'])}</p><BadgeList values={Array.isArray(item.citation_ids) ? item.citation_ids.map(String) : []} /></div>)}
          <h3>Technique explanations</h3>{techniques.map((item, index) => <div className="technique" key={index}><strong>{value(item, ['technique_id'])} · {value(item, ['technique_name'])}</strong><p><b>Observed:</b> {value(item, ['observed_evidence'])}</p><p><b>Governed:</b> {value(item, ['governed_explanation'])}</p>{value(item, ['analyst_inference'], '') && <p><b>Inference:</b> {value(item, ['analyst_inference'])}</p>}</div>)}
          <h3>Limitations</h3>{Array.isArray(result.limitations) ? result.limitations.map((item, index) => <Notice key={index} tone="warning">{String(item)}</Notice>) : null}
          <h3>Grounding / citations</h3><DataTable rows={citations} columns={['citation_id','source_type','title','snippet','source_reference','relevance']} exportName="threatlens-ai-citations" />
          <JsonView data={asJson(result.retrieval)} title="Retrieval diagnostics" /><JsonView data={asJson(result.query_plan)} title="Query plan" />
        </div>}
      </Panel>
    </div>
    <Panel title="Durable AI jobs"><p className="body-copy">Select a completed job to reopen its persisted question and grounded answer without generating a new response.</p><DataTable rows={jobs.data.items || []} columns={['created_at','job_uuid','status','analysis_mode','attempts','queue_delivery_state','worker_id','result_query_uuid','error_code','completed_at']} onRow={openSavedJob} rowActionLabel={row => value(row, ['status'], '') === 'succeeded' ? 'Open saved answer →' : 'View job →'} exportName="threatlens-ai-jobs" /></Panel>
    <Panel title="Previous assistant queries"><DataTable rows={history.data.items || []} columns={['created_at','actor','question','response_status','requested_mode','resolved_mode','served_model','fallback_used','routing_score','grounding_score','citation_count','total_latency_ms']} exportName="threatlens-ai-history" /></Panel>
  </>
}
