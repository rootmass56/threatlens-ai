import { ReactNode, useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Json, Session } from './types'
import { compact, csvFromRows, downloadText, humanize, toneForStatus, value } from './utils'

export function useResource<T>(session: Session, path: string, initial: T, enabled = true) {
  const [data, setData] = useState<T>(initial)
  const [loading, setLoading] = useState(enabled)
  const [error, setError] = useState('')
  const reload = useCallback(async () => {
    if (!enabled) return
    setLoading(true)
    setError('')
    try {
      setData(await api<T>(session, path))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Request failed.')
    } finally {
      setLoading(false)
    }
  }, [enabled, path, session])
  useEffect(() => { void reload() }, [reload])
  return { data, loading, error, reload, setData }
}

export function Status({ children, tone }: { children: ReactNode; tone?: 'ok' | 'warn' | 'bad' | 'neutral' }) {
  const text = String(children ?? '')
  return <span className={`status ${tone ?? toneForStatus(text)}`}><i />{children}</span>
}

export function ErrorBox({ message }: { message: string }) {
  return message ? <div className="error-box">{message}</div> : null
}

export function Notice({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'success' | 'warning' }) {
  return <div className={`notice ${tone}`}>{children}</div>
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Header({ kicker, title, subtitle, actions }: { kicker: string; title: string; subtitle: string; actions?: ReactNode }) {
  return <header className="page-header"><div><p className="eyebrow">{kicker}</p><h1>{title}</h1><p>{subtitle}</p></div>{actions && <div className="header-actions">{actions}</div>}</header>
}

export function Panel({ title, action, children, className = '' }: { title: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="panel-head"><h2>{title}</h2>{action}</div>{children}</section>
}

export function Metric({ label, number, note, accent, compactNumber }: { label: string; number: string; note: string; accent?: boolean; compactNumber?: boolean }) {
  return <div className={`metric ${accent ? 'accent' : ''}`}><span>{label}</span><strong className={compactNumber ? 'compact' : ''}>{number}</strong><small>{note}</small></div>
}

export function Fact({ k, v }: { k: string; v: string }) {
  return <div><dt>{k}</dt><dd>{v}</dd></div>
}

export function KeyValueGrid({ data, keys }: { data: Json; keys?: string[] }) {
  const entries = (keys ?? Object.keys(data)).map(key => [key, data[key]] as const)
  if (!entries.length) return <Empty>No metadata available.</Empty>
  return <dl className="kv-grid">{entries.map(([key, item]) => <div key={key}><dt>{humanize(key)}</dt><dd>{compact(item)}</dd></div>)}</dl>
}

export function JsonView({ data, title = 'Raw JSON' }: { data: unknown; title?: string }) {
  return <details className="json-details"><summary>{title}</summary><pre className="json">{JSON.stringify(data, null, 2)}</pre></details>
}

export function Tabs({ tabs, active, onChange }: { tabs: string[]; active: string; onChange: (value: string) => void }) {
  return <div className="tabs">{tabs.map(tab => <button key={tab} className={active === tab ? 'active' : ''} onClick={() => onChange(tab)}>{tab}</button>)}</div>
}

export function SearchBox({ value: current, onChange, placeholder = 'Filter records…' }: { value: string; onChange: (value: string) => void; placeholder?: string }) {
  return <input className="search" placeholder={placeholder} value={current} onChange={event => onChange(event.target.value)} />
}

export function DataTable({ rows, columns, loading, onRow, rowActionLabel, empty = 'No records available.', exportName, maxRows = 500 }: {
  rows: Json[]
  columns?: string[]
  loading?: boolean
  onRow?: (row: Json) => void
  rowActionLabel?: string | ((row: Json) => string)
  empty?: string
  exportName?: string
  maxRows?: number
}) {
  const displayRows = rows.slice(0, maxRows)
  const displayColumns = useMemo(() => {
    if (columns?.length) return columns
    return Array.from(new Set(displayRows.slice(0, 25).flatMap(row => Object.keys(row)))).slice(0, 12)
  }, [columns, displayRows])
  if (loading) return <Empty>Loading records…</Empty>
  if (!rows.length) return <Empty>{empty}</Empty>
  return <>
    {exportName && <div className="table-tools"><button className="text-btn" onClick={() => downloadText(`${exportName}.csv`, csvFromRows(rows), 'text/csv')}>Export CSV ↓</button><span>{rows.length > maxRows ? `Showing first ${maxRows} of ${rows.length}` : `${rows.length} records`}</span></div>}
    <div className="table-wrap"><table><thead><tr>{displayColumns.map(column => <th key={column}>{humanize(column)}</th>)}{onRow && rowActionLabel && <th>ACTION</th>}</tr></thead><tbody>{displayRows.map((row, index) => <tr key={`${value(row, ['id', 'uuid', 'session_uuid', 'incident_uuid', 'alert_uuid', 'event_uuid'], String(index))}-${index}`} onClick={() => onRow?.(row)} className={onRow ? 'clickable' : ''} tabIndex={onRow ? 0 : undefined} onKeyDown={event => { if (onRow && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); onRow(row) } }}>{displayColumns.map(column => <td key={column} title={compact(row[column])}>{compact(row[column])}</td>)}{onRow && rowActionLabel && <td className="action-cell"><button className="row-action" onClick={event => { event.stopPropagation(); onRow(row) }}>{typeof rowActionLabel === 'function' ? rowActionLabel(row) : rowActionLabel}</button></td>}</tr>)}</tbody></table></div>
  </>
}

export function Segmented({ values, active, onChange }: { values: string[]; active: string; onChange: (value: string) => void }) {
  return <div className="mode-row">{values.map(item => <button type="button" key={item} className={active === item ? 'mode active' : 'mode'} onClick={() => onChange(item)}>{item}</button>)}</div>
}

export function BadgeList({ values }: { values: string[] }) {
  if (!values.length) return <span className="muted">None</span>
  return <div className="badges">{values.map(item => <span key={item}>{item}</span>)}</div>
}

export function AttackGraphCanvas({ graph }: { graph: Json }) {
  const nodes = Array.isArray(graph.nodes) ? graph.nodes.filter(item => item && typeof item === 'object') as Json[] : []
  const edges = Array.isArray(graph.edges) ? graph.edges.filter(item => item && typeof item === 'object') as Json[] : []
  const nodeTypes = useMemo(() => Array.from(new Set(nodes.map(node => value(node, ['node_type'], 'unknown')))).sort(), [nodes])
  const [enabledTypes, setEnabledTypes] = useState<string[]>(nodeTypes)
  const [threshold, setThreshold] = useState(0.4)
  useEffect(() => { setEnabledTypes(nodeTypes) }, [nodeTypes.join('|')])
  const visibleNodes = nodes.filter(node => enabledTypes.includes(value(node, ['node_type'], 'unknown')))
  const nodeIds = new Set(visibleNodes.map(node => value(node, ['node_id','id','node_key'], '')))
  const visibleEdges = edges.filter(edge => {
    const source = value(edge, ['source','source_node_key'], '')
    const target = value(edge, ['target','target_node_key'], '')
    const confidence = Number(value(edge, ['confidence'], '1'))
    return nodeIds.has(source) && nodeIds.has(target) && (Number.isFinite(confidence) ? confidence : 1) >= threshold
  })
  const rawPositions = visibleNodes.map((node, index) => ({
    id: value(node, ['node_id','id','node_key'], String(index)),
    x: Number(value(node, ['x'], String(Math.cos(index * 0.9) * 10))),
    y: Number(value(node, ['y'], String(Math.sin(index * 0.9) * 10))),
    node,
  }))
  const xs = rawPositions.map(item => Number.isFinite(item.x) ? item.x : 0)
  const ys = rawPositions.map(item => Number.isFinite(item.y) ? item.y : 0)
  const minX = Math.min(...xs, 0); const maxX = Math.max(...xs, 1)
  const minY = Math.min(...ys, 0); const maxY = Math.max(...ys, 1)
  const scale = (v: number, min: number, max: number, size: number) => 55 + ((v - min) / Math.max(max - min, 1)) * (size - 110)
  const positioned = rawPositions.map(item => ({ ...item, sx: scale(item.x, minX, maxX, 980), sy: scale(item.y, minY, maxY, 520) }))
  const byId = new Map(positioned.map(item => [item.id, item]))
  function toggle(type: string) { setEnabledTypes(current => current.includes(type) ? current.filter(item => item !== type) : [...current, type]) }
  if (!nodes.length) return <Empty>No persisted attack-graph nodes are available.</Empty>
  return <div className="graph-shell">
    <div className="graph-controls"><div><span>Node layers</span><div className="badges">{nodeTypes.map(type => <button type="button" className={enabledTypes.includes(type) ? 'graph-filter active' : 'graph-filter'} key={type} onClick={() => toggle(type)}>{type}</button>)}</div></div><label>Minimum confidence <input type="range" min="0" max="1" step="0.05" value={threshold} onChange={event => setThreshold(Number(event.target.value))} /><b>{threshold.toFixed(2)}</b></label></div>
    <svg className="attack-graph" viewBox="0 0 980 520" role="img" aria-label="ThreatLens persisted attack graph">
      <g className="graph-edges">{visibleEdges.map((edge, index) => { const source = byId.get(value(edge, ['source','source_node_key'], '')); const target = byId.get(value(edge, ['target','target_node_key'], '')); if (!source || !target) return null; return <line key={index} x1={source.sx} y1={source.sy} x2={target.sx} y2={target.sy}><title>{value(edge, ['relationship_type','edge_type'], 'relationship')} · confidence {value(edge, ['confidence'])} · {value(edge, ['reasons'])}</title></line> })}</g>
      <g className="graph-nodes">{positioned.map(item => { const kind = value(item.node, ['node_type'], 'unknown'); return <g key={item.id} transform={`translate(${item.sx} ${item.sy})`} className={`graph-node ${kind}`}><circle r={kind === 'incident' ? 13 : 9} /><text y={22} textAnchor="middle">{value(item.node, ['label','title','name','technique_id','node_id'], item.id).slice(0, 24)}</text><title>{JSON.stringify(item.node)}</title></g> })}</g>
    </svg>
    <div className="graph-foot">Showing {positioned.length} nodes and {visibleEdges.length} edges. Hover nodes/edges for persisted evidence details.</div>
  </div>
}
