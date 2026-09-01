import { useEffect, useState } from 'react'
import { apiBlob } from '../api'
import { DataTable, Empty, ErrorBox, Header, Notice, Panel, useResource } from '../components'
import { ListResponse, Session } from '../types'
import { downloadBlob, sha256Hex, value } from '../utils'

export function ReportPage({ session, analysisId }: { session: Session; analysisId: string }) {
  const analyses = useResource<ListResponse>(session, '/api/v1/analyses?limit=1000', { items: [] })
  const [selected, setSelected] = useState(analysisId)
  const [message, setMessage] = useState('')
  useEffect(() => { if (analysisId) setSelected(analysisId) }, [analysisId])
  useEffect(() => { if (!selected && analyses.data.items?.length) setSelected(value(analyses.data.items[0], ['session_uuid'], '')) }, [analyses.data.items, selected])
  async function download() {
    if (!selected) return
    setMessage('Generating authorized incident report…')
    try {
      const response = await apiBlob(session, `/api/v1/reports/analyses/${encodeURIComponent(selected)}/incident.pdf`)
      const localSha256 = await sha256Hex(response.blob)
      if (response.sha256 && response.sha256.toLowerCase() !== localSha256) {
        throw new Error('Report integrity verification failed: browser SHA-256 does not match the server digest.')
      }
      downloadBlob(response.filename, response.blob)
      setMessage(`Report integrity verified. SHA-256: ${localSha256}`)
    } catch (caught) { setMessage(caught instanceof Error ? caught.message : 'Report generation failed.') }
  }
  return <>
    <Header kicker="REPORTING" title="Reports" subtitle="Generate authenticated investigation PDFs from persisted analysis and case evidence." />
    <ErrorBox message={analyses.error} />
    <div className="two-col wide-left"><Panel title="Generate PDF"><div className="stack"><label>Analysis session<select value={selected} onChange={event => setSelected(event.target.value)}>{(analyses.data.items || []).map(row => { const id = value(row, ['session_uuid']); return <option key={id} value={id}>{value(row, ['name'], id)} · {value(row, ['created_at'])}</option> })}</select></label><button className="primary" disabled={!selected} onClick={() => void download()}>Generate PDF Incident Report</button>{message && <Notice>{message}</Notice>}</div></Panel><Panel title="Report integrity"><p className="body-copy">The backend builds the PDF from persisted evidence, removes the temporary server file after response construction and returns an <code>X-Content-SHA256</code> integrity digest.</p></Panel></div>
    <Panel title="Available analyses">{analyses.loading ? <Empty>Loading analyses…</Empty> : <DataTable rows={analyses.data.items || []} columns={['name','session_uuid','events','alerts','incidents','created_at']} onRow={row => setSelected(value(row, ['session_uuid'], ''))} />}</Panel>
  </>
}
