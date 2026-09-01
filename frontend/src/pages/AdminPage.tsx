import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { BadgeList, DataTable, ErrorBox, Header, JsonView, Notice, Panel, Tabs, useResource } from '../components'
import { Json, ListResponse, Session } from '../types'
import { downloadBlob, hasPermission, value } from '../utils'

export function AdminPage({ session }: { session: Session }) {
  const users = useResource<ListResponse>(session, '/api/v1/users', { items: [] })
  const roles = useResource<ListResponse>(session, '/api/v1/users/roles', { items: [] })
  const security = useResource<Json>(session, '/api/v1/system/security', {})
  const canManage = hasPermission(session.user, 'user:manage')
  const tabs = canManage ? ['Users', 'Create Account', 'Roles', 'Security Status', 'Protected OpenAPI'] : ['Users', 'Roles', 'Security Status', 'Protected OpenAPI']
  const [tab, setTab] = useState('Users')
  const [selected, setSelected] = useState('')
  const selectedUser = useMemo(() => (users.data.items || []).find(row => value(row, ['user_uuid']) === selected) || {}, [selected, users.data.items])

  return <>
    <Header kicker="ADMINISTRATION" title="Security Administration" subtitle="Six-role RBAC, complete account lifecycle, session revocation, lockout recovery, security posture and protected API contract." />
    <ErrorBox message={users.error || roles.error || security.error} />
    {!canManage && <Notice>Read-only user directory. Account mutation requires <code>user:manage</code>.</Notice>}
    <Panel title="Administrative console">
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      <div className="tab-body">{tab === 'Users' ? <div className="two-col wide-left"><DataTable rows={users.data.items || []} columns={['username', 'display_name', 'email', 'is_active', 'roles', 'failed_login_count', 'locked_until', 'last_login_at']} onRow={row => setSelected(value(row, ['user_uuid'], ''))} exportName="threatlens-users" /><UserEditor session={session} user={selectedUser} roles={roles.data.items || []} canManage={canManage} reload={users.reload} /></div> : tab === 'Create Account' ? <CreateUser session={session} roles={roles.data.items || []} reload={users.reload} /> : tab === 'Roles' ? <RolesView rows={roles.data.items || []} /> : tab === 'Security Status' ? <JsonView data={security.data} title="Security posture" /> : <OpenApiView session={session} />}</div>
    </Panel>
  </>
}

function UserEditor({ session, user, roles, canManage, reload }: { session: Session; user: Json; roles: Json[]; canManage: boolean; reload: () => Promise<void> }) {
  const userId = value(user, ['user_uuid'], '')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [selectedRoles, setSelectedRoles] = useState<string[]>([])
  const [message, setMessage] = useState('')

  useEffect(() => {
    setDisplayName(value(user, ['display_name'], ''))
    setEmail(value(user, ['email'], '') === '—' ? '' : value(user, ['email'], ''))
    setPassword('')
    setSelectedRoles(Array.isArray(user.roles) ? user.roles.map(String) : [])
    setMessage('')
  }, [userId])

  async function mutate(payload: Json) {
    if (!userId || !canManage) return
    try {
      await api(session, `/api/v1/users/${encodeURIComponent(userId)}`, { method: 'PATCH', body: JSON.stringify(payload) })
      setMessage('Account updated and audited. Security-sensitive changes revoke active sessions.')
      setPassword('')
      await reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Account update failed.')
    }
  }

  function toggleRole(role: string) {
    setSelectedRoles(current => current.includes(role) ? current.filter(item => item !== role) : [...current, role])
  }

  if (!userId) return <Notice>Select a user to inspect account state and roles.</Notice>
  if (!canManage) return <div className="stack"><h3>{value(user, ['display_name', 'username'])}</h3><BadgeList values={Array.isArray(user.roles) ? user.roles.map(String) : []} /><JsonView data={user} title="User record" /></div>

  const active = value(user, ['is_active'], 'true') === 'true'
  return <div className="stack">
    <h3>{value(user, ['username'])}</h3>
    <label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} maxLength={255} /></label>
    <label>Email<input type="email" value={email} onChange={event => setEmail(event.target.value)} maxLength={320} /></label>
    <fieldset><legend>Roles</legend>{roles.map(role => { const name = value(role, ['name']); return <label className="check" key={name}><input type="checkbox" checked={selectedRoles.includes(name)} onChange={() => toggleRole(name)} /> {name}</label> })}</fieldset>
    <label>New password (optional)<input type="password" value={password} onChange={event => setPassword(event.target.value)} minLength={12} maxLength={256} autoComplete="new-password" /></label>
    <button className="primary" disabled={!displayName.trim() || !selectedRoles.length} onClick={() => void mutate({ display_name: displayName.trim(), email: email.trim() || null, roles: selectedRoles, ...(password ? { password } : {}) })}>Save profile / roles / password</button>
    <div className="toolbar compact"><button className="secondary" onClick={() => void mutate({ is_active: !active, revoke_sessions: true })}>{active ? 'Deactivate account' : 'Activate account'}</button><button className="secondary" onClick={() => void mutate({ unlock: true })}>Unlock account</button><button className="secondary" onClick={() => void mutate({ revoke_sessions: true })}>Revoke all sessions</button></div>
    {message && <Notice>{message}</Notice>}
  </div>
}

function CreateUser({ session, roles, reload }: { session: Session; roles: Json[]; reload: () => Promise<void> }) {
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [selectedRoles, setSelectedRoles] = useState<string[]>(['analyst'])
  const [message, setMessage] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    try {
      await api(session, '/api/v1/users', { method: 'POST', body: JSON.stringify({ username, display_name: displayName, email: email || null, password, roles: selectedRoles }) })
      setMessage('Account created and audited.')
      setUsername(''); setDisplayName(''); setEmail(''); setPassword('')
      await reload()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Account creation failed.')
    }
  }

  function toggle(role: string) { setSelectedRoles(current => current.includes(role) ? current.filter(item => item !== role) : [...current, role]) }

  return <form className="stack max-form" onSubmit={submit}>
    <label>Username<input value={username} onChange={event => setUsername(event.target.value)} required minLength={3} maxLength={64} pattern="[a-zA-Z0-9_.-]+" /></label>
    <label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} required maxLength={255} /></label>
    <label>Email<input type="email" value={email} onChange={event => setEmail(event.target.value)} maxLength={320} /></label>
    <label>Initial password<input type="password" value={password} onChange={event => setPassword(event.target.value)} required minLength={12} maxLength={256} autoComplete="new-password" /></label>
    <fieldset><legend>Roles</legend>{roles.map(role => { const name = value(role, ['name']); return <label className="check" key={name}><input type="checkbox" checked={selectedRoles.includes(name)} onChange={() => toggle(name)} /> {name} — {value(role, ['description'])}</label> })}</fieldset>
    <button className="primary" disabled={!selectedRoles.length}>Create ThreatLens account</button>
    {message && <Notice>{message}</Notice>}
  </form>
}

function RolesView({ rows }: { rows: Json[] }) {
  return <div className="role-grid">{rows.map(role => <div className="role-card" key={value(role, ['name'])}><h3>{value(role, ['name'])}</h3><p>{value(role, ['description'])}</p><BadgeList values={Array.isArray(role.permissions) ? role.permissions.map(String) : []} /></div>)}</div>
}

function OpenApiView({ session }: { session: Session }) {
  const schema = useResource<Json>(session, '/api/v1/system/openapi', {})
  return <><button className="secondary" onClick={() => { const blob = new Blob([JSON.stringify(schema.data, null, 2)], { type: 'application/json' }); downloadBlob('threatlens-openapi.json', blob) }}>Download protected OpenAPI ↓</button><JsonView data={schema.data} title="Authenticated API contract" /></>
}
