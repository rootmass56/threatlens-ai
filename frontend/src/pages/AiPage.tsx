import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { BadgeList, DataTable, Empty, ErrorBox, Header, JsonView, Notice, Panel, Segmented, Status, useResource } from '../components'
import { Json, ListResponse, Session } from '../types'
import { asJson, asRows, value } from '../utils'

const TERMINAL_JOB_STATES = new Set(['succeeded', 'failed', 'cancelled'])

function resultFromJob(job: Json | null): Json {
  if (!job) return {}
  return asJson(job.result_json ?? job.result ?? job.response ?? {})
}

function idempotencyKey(): string {
  return `web-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

export function AiPage({ session, incidentId }: { session: Session; incidentId: string }) {
  const incidents = useResource<ListResponse>(session, '/api/v1/incidents?limit=500', { items: [] })
  const rag = useResource<Json>(session, '/api/v1/rag/health', {})
  const [selected, setSelected] = useState(incidentId)
  const [mode, setMode] = useState('auto')
  const [question, setQuestion] = useState(
    'Explain what happened in this incident using only supported evidence. Separate observed evidence from governed ATT&CK knowledge and analyst inference.',
  )
  const [activeJob, setActiveJob] = useState<Json | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (incidentId) {
      setSelected(incidentId)
      setActiveJob(null)
    }
  }, [incidentId])

  useEffect(() => {
    if (!selected && incidents.data.items?.length) {
      setSelected(value(incidents.data.items[0], ['incident_uuid'], ''))
    }
  }, [incidents.data.items, selected])

  const jobs = useResource<ListResponse>(
    session,
    selected
      ? `/api/v1/incidents/${encodeURIComponent(selected)}/assistant/jobs?limit=50`
      : '/api/v1/incidents?limit=1',
    { items: [] },
    Boolean(selected),
  )

  const history = useResource<ListResponse>(
    session,
    selected
      ? `/api/v1/incidents/${encodeURIComponent(selected)}/assistant/history?limit=50`
      : '/api/v1/incidents?limit=1',
    { items: [] },
    Boolean(selected),
  )

  const activeJobUuid = value(activeJob || {}, ['job_uuid'], '')
  const activeStatus = value(activeJob || {}, ['status'], '')

  async function inspectJob(row: Json) {
    const uuid = value(row, ['job_uuid'], '')
    if (!uuid) return
    try {
      const job = await api<Json>(
        session,
        `/api/v1/assistant/jobs/${encodeURIComponent(uuid)}`,
      )
      setActiveJob(job)
      setError('')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'AI job could not be loaded.')
    }
  }

  useEffect(() => {
    if (!activeJob && jobs.data.items?.length) {
      const latest = jobs.data.items[0]
      const uuid = value(latest, ['job_uuid'], '')
      if (uuid) void inspectJob(latest)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobs.data.items, activeJob])

  useEffect(() => {
    if (!activeJobUuid || !['queued', 'running'].includes(activeStatus)) return

    let disposed = false

    async function poll() {
      try {
        const job = await api<Json>(
          session,
          `/api/v1/assistant/jobs/${encodeURIComponent(activeJobUuid)}`,
        )
        if (disposed) return
        setActiveJob(job)

        if (TERMINAL_JOB_STATES.has(value(job, ['status'], ''))) {
          await jobs.reload()
          await history.reload()
        }
      } catch (caught) {
        if (!disposed) {
          setError(caught instanceof Error ? caught.message : 'Durable AI job polling failed.')
        }
      }
    }

    void poll()
    const timer = window.setInterval(() => void poll(), 2000)

    return () => {
      disposed = true
      window.clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeJobUuid, activeStatus, session.accessToken])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!selected || !question.trim()) return

    setBusy(true)
    setError('')
    try {
      const job = await api<Json>(
        session,
        `/api/v1/incidents/${encodeURIComponent(selected)}/assistant/jobs`,
        {
          method: 'POST',
          headers: { 'Idempotency-Key': idempotencyKey() },
          body: JSON.stringify({
            question: question.trim(),
            analysis_mode: mode,
          }),
        },
      )
      setActiveJob(job)
      await jobs.reload()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Durable AI investigation could not be queued.')
    } finally {
      setBusy(false)
    }
  }

  async function cancelQueuedJob() {
    if (!activeJobUuid || activeStatus !== 'queued') return

    try {
      const job = await api<Json>(
        session,
        `/api/v1/assistant/jobs/${encodeURIComponent(activeJobUuid)}/cancel`,
        { method: 'POST' },
      )
      setActiveJob(job)
      setError('')
      await jobs.reload()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Queued AI job could not be cancelled.')
    }
  }

  const result = resultFromJob(activeJob)
  const hasResult = Object.keys(result).length > 0
  const citations = hasResult ? asRows(result.citations) : []
  const findings = hasResult ? asRows(result.key_findings) : []
  const actions = hasResult ? asRows(result.recommended_actions) : []
  const techniques = hasResult ? asRows(result.technique_explanations) : []
  const profiles = asRows(rag.data.model_profiles)
  const jobRows = jobs.data.items || []

  const routing = useMemo(
    () =>
      hasResult
        ? [
            value(result, ['requested_mode']),
            value(result, ['resolved_mode']),
            value(result, ['served_model', 'llm_model']),
          ].join(' → ')
        : '',
    [hasResult, result],
  )

  return <>
    <Header
      kicker="GROUNDED RAG · DURABLE AI"
      title="AI Investigation"
      subtitle="Redis-coordinated, PostgreSQL-durable Qwen analysis constrained by authorized incident evidence, governed knowledge and post-generation citation validation."
    />

    <div className="assistant-grid">
      <Panel title="Investigation request">
        <form className="stack" onSubmit={submit}>
          <label>
            Incident
            <select
              value={selected}
              onChange={event => {
                setSelected(event.target.value)
                setActiveJob(null)
                setError('')
              }}
            >
              {(incidents.data.items || []).map(row => {
                const id = value(row, ['incident_uuid'])
                return <option key={id} value={id}>{value(row, ['title'], id)}</option>
              })}
            </select>
          </label>

          <label>
            Analysis mode
            <Segmented values={['auto', 'standard', 'deep']} active={mode} onChange={setMode} />
          </label>

          <label>
            Question
            <textarea
              rows={8}
              maxLength={2000}
              value={question}
              onChange={event => setQuestion(event.target.value)}
            />
          </label>

          <button className="primary" disabled={busy || !selected || !question.trim()}>
            {busy ? 'Queueing durable investigation…' : 'Queue grounded investigation'}
          </button>

          <ErrorBox message={error || jobs.error || history.error} />
        </form>

        <div className="profile-strip">
          {profiles.map((profile, index) =>
            <div key={index}>
              <b>{value(profile, ['profile_name', 'mode'])}</b>
              <span>{value(profile, ['model'])}</span>
              <Status>{value(profile, ['available'], 'false') === 'true' ? 'ready' : 'unavailable'}</Status>
            </div>,
          )}
        </div>
      </Panel>

      <Panel title="Durable job state">
        {!activeJob
          ? <Empty>Select a persisted job or queue a new investigation.</Empty>
          : <>
              <div className="answer-meta">
                <Status>{activeStatus}</Status>
                <span>Job {activeJobUuid}</span>
                <span>Attempts {value(activeJob, ['attempts'], '0')}</span>
                <span>Delivery {value(activeJob, ['queue_delivery_state'], '—')}</span>
              </div>

              {activeStatus === 'queued' &&
                <button className="secondary" onClick={() => void cancelQueuedJob()}>
                  Cancel queued job
                </button>}

              {activeStatus === 'running' &&
                <Notice>
                  This job is already running. ThreatLens intentionally rejects unsafe hard-cancellation after execution begins.
                </Notice>}

              {activeStatus === 'failed' &&
                <Notice tone="warning">
                  {value(activeJob, ['error_message'], 'The durable AI job failed.')}
                </Notice>}

              {activeStatus === 'cancelled' &&
                <Notice>Queued execution was cancelled before model execution.</Notice>}
            </>}
      </Panel>
    </div>

    <Panel title="Persistent assistant jobs">
      <DataTable
        rows={jobRows}
        columns={[
          'created_at',
          'job_uuid',
          'status',
          'question',
          'analysis_mode',
          'attempts',
          'queue_delivery_state',
          'result_query_uuid',
          'error_code',
        ]}
        onRow={row => void inspectJob(row)}
        rowActionLabel="Inspect job →"
        exportName="threatlens-ai-jobs"
      />
    </Panel>

    <Panel title="Grounded response">
      {!hasResult
        ? <Empty>
            {['queued', 'running'].includes(activeStatus)
              ? 'The durable worker is processing this investigation.'
              : 'A succeeded job result will appear here.'}
          </Empty>
        : <div className="answer">
            <div className="answer-meta">
              <Status>{value(result, ['status'], 'answered')}</Status>
              <span>Grounding {value(result, ['grounding_score'])}</span>
              <span>{routing}</span>
              <span>{value(result, ['total_latency_ms'])} ms</span>
            </div>

            {value(result, ['fallback_used'], 'false') === 'true' &&
              <Notice tone="warning">
                Model fallback was used: {value(result, ['fallback_reason'])}
              </Notice>}

            <h3>Assessment</h3>
            <p>{value(result, ['assessment'])}</p>

            <h3>Key findings</h3>
            {findings.length
              ? findings.map((item, index) =>
                  <div className="claim" key={index}>
                    <p>{value(item, ['text'])}</p>
                    <BadgeList values={Array.isArray(item.citation_ids) ? item.citation_ids.map(String) : []} />
                  </div>,
                )
              : <p className="muted">No supported findings returned.</p>}

            <h3>Recommended actions</h3>
            {actions.map((item, index) =>
              <div className="claim" key={index}>
                <p>{value(item, ['text'])}</p>
                <BadgeList values={Array.isArray(item.citation_ids) ? item.citation_ids.map(String) : []} />
              </div>,
            )}

            <h3>Technique explanations</h3>
            {techniques.map((item, index) =>
              <div className="technique" key={index}>
                <strong>{value(item, ['technique_id'])} · {value(item, ['technique_name'])}</strong>
                <p><b>Observed:</b> {value(item, ['observed_evidence'])}</p>
                <p><b>Governed:</b> {value(item, ['governed_explanation'])}</p>
                {value(item, ['analyst_inference'], '') &&
                  <p><b>Inference:</b> {value(item, ['analyst_inference'])}</p>}
              </div>,
            )}

            <h3>Limitations</h3>
            {Array.isArray(result.limitations)
              ? result.limitations.map((item, index) =>
                  <Notice key={index} tone="warning">{String(item)}</Notice>,
                )
              : null}

            <h3>Grounding / citations</h3>
            <DataTable
              rows={citations}
              columns={[
                'citation_id',
                'source_type',
                'title',
                'snippet',
                'source_reference',
                'relevance',
              ]}
              exportName="threatlens-ai-citations"
            />

            <JsonView data={asJson(result.retrieval)} title="Retrieval diagnostics" />
            <JsonView data={asJson(result.query_plan)} title="Query plan" />
          </div>}
    </Panel>

    <Panel title="Previous assistant queries">
      <DataTable
        rows={history.data.items || []}
        columns={[
          'created_at',
          'actor',
          'question',
          'response_status',
          'requested_mode',
          'resolved_mode',
          'served_model',
          'fallback_used',
          'routing_score',
          'grounding_score',
          'citation_count',
          'total_latency_ms',
        ]}
        exportName="threatlens-ai-history"
      />
    </Panel>
  </>
}
