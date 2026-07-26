import React, { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, PieChart, Pie, Tooltip
} from 'recharts'

const API = '/api'

function useApi(path, deps = []) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  useEffect(() => {
    let alive = true
    fetch(API + path).then(r => r.json()).then(d => { if (alive) setData(d) })
      .catch(e => alive && setErr(e))
    return () => { alive = false }
  }, deps)
  return [data, err]
}

const TYPE_COLORS = {
  'Brute Force': '#f6a623', 'Credential Stuffing': '#ef8b3a',
  'Impossible Travel': '#ef4d4d', 'Device Spoofing': '#8b7cf6',
  'Lateral Movement': '#e0507e', 'Low-and-Slow Exfiltration': '#f6c343',
  'Insider Drift (benign)': '#35d0ba',
}
const threatColor = (s) => s >= 80 ? 'var(--alert-hot)' : s >= 65 ? 'var(--alert)' : 'var(--trust)'

function ThreatRing({ score, size = 132 }) {
  const r = size / 2 - 10, c = 2 * Math.PI * r
  const off = c * (1 - score / 100)
  const col = threatColor(score)
  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--line)" strokeWidth="7" />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={col} strokeWidth="7"
          strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s cubic-bezier(.22,1,.36,1)' }} />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="mono" style={{ fontSize: 34, fontWeight: 700, color: col, lineHeight: 1 }}>{score}</div>
          <div className="eyebrow" style={{ marginTop: 4 }}>Threat</div>
        </div>
      </div>
    </div>
  )
}

function Attribution({ factors }) {
  if (!factors || !factors.length) return null
  const max = Math.max(...factors.map(f => Math.abs(f.z)), 1)
  return (
    <div style={{ display: 'grid', gap: 10 }}>
      {factors.map((f, i) => (
        <div key={i}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span className="mono" style={{ fontSize: 12, color: 'var(--ink-dim)' }}>{f.feature}</span>
            <span className="mono" style={{ fontSize: 12, color: f.z > 0 ? 'var(--alert)' : 'var(--trust)' }}>
              {f.z > 0 ? '+' : ''}{f.z}σ</span>
          </div>
          <div style={{ height: 6, background: 'var(--panel-2)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${Math.abs(f.z) / max * 100}%`,
              background: f.z > 0 ? 'var(--alert)' : 'var(--trust)', borderRadius: 3,
              transition: 'width .8s cubic-bezier(.22,1,.36,1)' }} />
          </div>
        </div>
      ))}
    </div>
  )
}

const Panel = ({ children, style }) => (
  <div style={{ background: 'var(--panel)', border: '1px solid var(--line)', borderRadius: 12,
    padding: 20, ...style }}>{children}</div>
)

function Dashboard({ onOpen }) {
  const [dash] = useApi('/dashboard')
  const [inc] = useApi('/incidents?limit=8')
  const [metrics] = useApi('/metrics')
  if (!dash || !inc) return <Loading />

  const typeData = Object.entries(dash.by_type).map(([name, value]) => ({ name, value }))
  const d = dash.dashboard

  return (
    <div style={{ display: 'grid', gap: 18 }}>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 14 }}>
        <Kpi label="Organisation Trust" value={d.org_trust + '%'} tone={d.org_trust >= 70 ? 'trust' : 'alert'} sub="live index" />
        <Kpi label="Critical Incidents" value={d.critical_incidents} tone="alert-hot" sub={`of ${d.total_incidents} total`} />
        <Kpi label="Detection ROC-AUC" value={metrics ? metrics.detection.roc_auc : '—'} tone="trust" sub="held-out test" />
        <Kpi label="Monitored Events" value={(dash.meta.n_test_events/1000).toFixed(0) + 'k'} tone="ink" sub={`${dash.meta.n_employees} employees`} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 18 }}>
        <Panel>
          <div className="eyebrow" style={{ marginBottom: 14 }}>Attack Distribution</div>
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={typeData} layout="vertical" margin={{ left: 10, right: 20 }}>
              <XAxis type="number" stroke="var(--ink-faint)" fontSize={11} />
              <YAxis type="category" dataKey="name" stroke="var(--ink-faint)" fontSize={10} width={130} />
              <Tooltip contentStyle={{ background: 'var(--panel-2)', border: '1px solid var(--line)', borderRadius: 8, color: 'var(--ink)' }} cursor={{ fill: 'rgba(255,255,255,.03)' }} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {typeData.map((e, i) => <Cell key={i} fill={TYPE_COLORS[e.name] || 'var(--ink-dim)'} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>
        <Panel>
          <div className="eyebrow" style={{ marginBottom: 14 }}>Incidents by Department</div>
          <ResponsiveContainer width="100%" height={230}>
            <PieChart>
              <Pie data={Object.entries(dash.by_department).map(([name, value]) => ({ name, value }))}
                dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={80} paddingAngle={2}>
                {Object.keys(dash.by_department).map((_, i) => (
                  <Cell key={i} fill={['#f6a623','#ef4d4d','#8b7cf6','#35d0ba','#e0507e','#f6c343','#ef8b3a'][i % 7]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--panel-2)', border: '1px solid var(--line)', borderRadius: 8, color: 'var(--ink)' }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel>
        <div className="eyebrow" style={{ marginBottom: 14 }}>Highest-Threat Incidents</div>
        <div style={{ display: 'grid', gap: 8 }}>
          {inc.incidents.map(i => (
            <button key={i.incident_id} onClick={() => onOpen(i.incident_id)}
              style={{ display: 'grid', gridTemplateColumns: '90px 1fr auto', alignItems: 'center', gap: 14,
                padding: '12px 14px', background: 'var(--panel-2)', border: '1px solid var(--line)',
                borderRadius: 9, textAlign: 'left', transition: 'border-color .15s' }}
              onMouseEnter={e => e.currentTarget.style.borderColor = threatColor(i.threat_score)}
              onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--line)'}>
              <span className="mono" style={{ fontSize: 12, color: 'var(--ink-faint)' }}>{i.incident_id}</span>
              <span>
                <div style={{ fontSize: 14, fontWeight: 600 }}>{i.entity_name}
                  <span style={{ color: 'var(--ink-faint)', fontWeight: 400 }}> · {i.department}</span></div>
                <div style={{ fontSize: 12, color: TYPE_COLORS[i.type_label] || 'var(--ink-dim)' }}>{i.type_label}</div>
              </span>
              <span className="mono" style={{ fontSize: 20, fontWeight: 700, color: threatColor(i.threat_score) }}>{i.threat_score}</span>
            </button>
          ))}
        </div>
      </Panel>
    </div>
  )
}

function Kpi({ label, value, sub, tone }) {
  const col = tone === 'trust' ? 'var(--trust)' : tone === 'alert' ? 'var(--alert)'
    : tone === 'alert-hot' ? 'var(--alert-hot)' : 'var(--ink)'
  return (
    <Panel style={{ padding: 16 }}>
      <div className="eyebrow">{label}</div>
      <div className="mono" style={{ fontSize: 30, fontWeight: 700, color: col, margin: '6px 0 2px' }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--ink-faint)' }}>{sub}</div>
    </Panel>
  )
}

function Injection({ onOpen }) {
  const [types] = useApi('/attack_types')
  const [selected, setSelected] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const run = (t) => {
    setSelected(t); setLoading(true); setResult(null)
    fetch(`${API}/inject?type=${t}`).then(r => r.json()).then(d => {
      setTimeout(() => { setResult(d); setLoading(false) }, 600)
    })
  }
  if (!types) return <Loading />
  const available = types.scenarios

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 18 }}>
      <Panel>
        <div className="eyebrow" style={{ marginBottom: 14 }}>Inject Attack</div>
        <div style={{ display: 'grid', gap: 8 }}>
          {types.types.filter(([k]) => available.includes(k)).map(([k, label]) => (
            <button key={k} onClick={() => run(k)}
              style={{ padding: '11px 13px', textAlign: 'left', borderRadius: 8,
                background: selected === k ? 'var(--panel-2)' : 'transparent',
                border: `1px solid ${selected === k ? (TYPE_COLORS[label] || 'var(--alert)') : 'var(--line)'}`,
                fontSize: 13, fontWeight: 500, transition: 'all .15s' }}>
              {label}
            </button>
          ))}
        </div>
        <div style={{ marginTop: 16, fontSize: 11, color: 'var(--ink-faint)', lineHeight: 1.5 }}>
          Injects a session matching the chosen pattern and runs it through the detection pipeline.
        </div>
      </Panel>

      <div>
        {!selected && <Panel style={{ display: 'grid', placeItems: 'center', minHeight: 320 }}>
          <div style={{ textAlign: 'center', color: 'var(--ink-faint)' }}>
            <div className="mono" style={{ fontSize: 13 }}>Select an attack to inject</div>
          </div>
        </Panel>}
        {loading && <Panel style={{ display: 'grid', placeItems: 'center', minHeight: 320 }}>
          <div className="mono pulse" style={{ color: 'var(--alert)', fontSize: 13 }}>Analysing behaviour…</div>
        </Panel>}
        {result && result.incident && <IncidentCard data={result} onOpen={onOpen} />}
      </div>
    </div>
  )
}

function IncidentCard({ data, onOpen }) {
  const inc = data.incident
  return (
    <div style={{ display: 'grid', gap: 16, animation: 'rise .5s cubic-bezier(.22,1,.36,1)' }}>
      <Panel>
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 22, alignItems: 'center' }}>
          <ThreatRing score={inc.threat_score} />
          <div>
            <div className="eyebrow">{inc.incident_id} · {inc.type_label}</div>
            <div style={{ fontSize: 20, fontWeight: 700, margin: '6px 0' }}>{inc.entity_name}
              <span style={{ color: 'var(--ink-faint)', fontWeight: 400, fontSize: 15 }}> · {inc.department}</span></div>
            <p style={{ fontSize: 14, color: 'var(--ink-dim)', lineHeight: 1.6, maxWidth: 620 }}>{inc.narrative}</p>
          </div>
        </div>
      </Panel>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Panel>
          <div className="eyebrow" style={{ marginBottom: 14 }}>Why it was flagged</div>
          <Attribution factors={inc.top_factors} />
        </Panel>
        <Panel>
          <div className="eyebrow" style={{ marginBottom: 14 }}>Recommended actions</div>
          <div style={{ display: 'grid', gap: 8 }}>
            {inc.recommended_actions.map((a, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 13,
                padding: '9px 12px', background: 'var(--panel-2)', borderRadius: 7 }}>
                <span style={{ width: 6, height: 6, borderRadius: 3, background: 'var(--alert)' }} />{a}
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel>
        <div className="eyebrow" style={{ marginBottom: 16 }}>Event Timeline</div>
        <div style={{ display: 'grid', gap: 0 }}>
          {inc.events.slice(0, 7).map((e, i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 16, position: 'relative', paddingBottom: i < Math.min(inc.events.length,7)-1 ? 16 : 0 }}>
              <div className="mono" style={{ fontSize: 11, color: 'var(--ink-faint)', textAlign: 'right' }}>
                {new Date(e.timestamp).toLocaleString('en-GB', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
              </div>
              <div style={{ borderLeft: '2px solid var(--line)', paddingLeft: 16, paddingBottom: 4 }}>
                <span style={{ position: 'absolute', left: 146, width: 8, height: 8, borderRadius: 4,
                  background: e.os_mismatch || !e.auth_success ? 'var(--alert)' : 'var(--trust)', marginTop: 3, transform: 'translateX(-5px)' }} />
                <div style={{ fontSize: 13 }}>{e.resource} <span style={{ color: 'var(--ink-faint)' }}>· {e.geo}</span></div>
                <div style={{ fontSize: 11, color: 'var(--ink-faint)' }}>
                  {e.device}{e.os_mismatch ? ' · fingerprint mismatch' : ''}{!e.auth_success ? ' · auth failed' : ''}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {data.correlations && data.correlations.length > 0 && (
        <Panel style={{ borderColor: 'var(--violet)' }}>
          <div className="eyebrow" style={{ marginBottom: 6, color: 'var(--violet)' }}>◇ Threat Memory — correlated incidents</div>
          <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', marginBottom: 14, lineHeight: 1.5 }}>
            This incident's behavioural signature resembles prior incidents — a possible shared campaign or actor.
          </p>
          <div style={{ display: 'grid', gap: 8 }}>
            {data.correlations.map((c, i) => (
              <button key={i} onClick={() => onOpen && onOpen(c.incident_id)}
                style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '11px 14px', background: 'var(--panel-2)', border: '1px solid var(--line)',
                  borderRadius: 8, textAlign: 'left' }}>
                <span><span className="mono" style={{ fontSize: 12, color: 'var(--violet)' }}>{c.incident_id}</span>
                  <span style={{ fontSize: 13, marginLeft: 10 }}>{c.type}</span></span>
                <span className="mono" style={{ fontSize: 13, color: 'var(--violet)' }}>{(c.similarity * 100).toFixed(0)}% match</span>
              </button>
            ))}
          </div>
        </Panel>
      )}
    </div>
  )
}

// ================= Incident detail (from dashboard click) =================
function IncidentDetail({ id, onOpen }) {
  const [data] = useApi(`/incident/${id}`, [id])
  if (!data) return <Loading />
  return <IncidentCard data={data} onOpen={onOpen} />
}

// ================= shell =================
function Loading() {
  return <div className="mono pulse" style={{ color: 'var(--ink-faint)', padding: 40, fontSize: 13 }}>Loading…</div>
}

// ================= AI Security Copilot =================
function Copilot() {
  const [messages, setMessages] = useState([
    { role: 'bot', text: "I'm your SOC copilot. Ask me about incidents, risky users, attacks by department, or mitigations." }
  ])
  const [input, setInput] = useState('')
  const [suggestions, setSuggestions] = useState([])
  const [busy, setBusy] = useState(false)
  const endRef = React.useRef(null)

  useEffect(() => {
    fetch(API + '/copilot/suggestions').then(r => r.json()).then(d => setSuggestions(d.suggestions || []))
  }, [])
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages])

  const send = (text) => {
    const q = (text ?? input).trim()
    if (!q || busy) return
    setMessages(m => [...m, { role: 'user', text: q }])
    setInput(''); setBusy(true)
    fetch(API + '/copilot', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: q })
    }).then(r => r.json()).then(d => {
      setTimeout(() => {
        setMessages(m => [...m, { role: 'bot', text: d.answer, cite: d.cite }])
        setBusy(false)
      }, 350)
    }).catch(() => { setBusy(false); setMessages(m => [...m, { role: 'bot', text: 'Something went wrong.' }]) })
  }

  return (
    <div style={{ maxWidth: 780, margin: '0 auto' }}>
      <Panel style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ width: 9, height: 9, borderRadius: 5, background: 'var(--trust)', boxShadow: '0 0 10px var(--trust)' }} />
          <span style={{ fontWeight: 600, fontSize: 15 }}>Security Copilot</span>
          <span className="eyebrow" style={{ marginLeft: 'auto' }}>grounded in incident data</span>
        </div>
        <div style={{ height: 420, overflowY: 'auto', padding: 18, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {messages.map((m, i) => (
            <div key={i} style={{ alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '82%' }}>
              <div style={{ padding: '10px 14px', borderRadius: 12, fontSize: 13.5, lineHeight: 1.55, whiteSpace: 'pre-line',
                background: m.role === 'user' ? 'var(--trust-dim)' : 'var(--panel-2)',
                border: `1px solid ${m.role === 'user' ? 'var(--trust)' : 'var(--line)'}`,
                color: m.role === 'user' ? '#eafff9' : 'var(--ink)' }}>
                {m.text}
              </div>
            </div>
          ))}
          {busy && <div style={{ alignSelf: 'flex-start' }}>
            <div className="pulse" style={{ padding: '10px 14px', borderRadius: 12, background: 'var(--panel-2)',
              border: '1px solid var(--line)', fontSize: 13, color: 'var(--ink-faint)' }}>analysing…</div>
          </div>}
          <div ref={endRef} />
        </div>
        {suggestions.length > 0 && messages.length <= 1 && (
          <div style={{ padding: '0 18px 12px', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {suggestions.map((s, i) => (
              <button key={i} onClick={() => send(s)}
                style={{ padding: '7px 12px', borderRadius: 20, fontSize: 12, color: 'var(--ink-dim)',
                  background: 'var(--panel-2)', border: '1px solid var(--line)' }}>{s}</button>
            ))}
          </div>
        )}
        <div style={{ padding: 14, borderTop: '1px solid var(--line)', display: 'flex', gap: 10 }}>
          <input value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && send()}
            placeholder="Ask about incidents, users, departments, mitigations…"
            style={{ flex: 1, padding: '11px 14px', borderRadius: 9, background: 'var(--panel-2)',
              border: '1px solid var(--line)', color: 'var(--ink)', fontSize: 13.5, outline: 'none' }} />
          <button onClick={() => send()} disabled={busy}
            style={{ padding: '11px 20px', borderRadius: 9, background: 'var(--trust)', color: '#08201d',
              fontWeight: 600, fontSize: 13.5, opacity: busy ? 0.5 : 1 }}>Send</button>
        </div>
      </Panel>
    </div>
  )
}

export default function App() {
  const [view, setView] = useState('dashboard')
  const [incidentId, setIncidentId] = useState(null)
  const open = (id) => { setIncidentId(id); setView('incident') }

  const nav = [['dashboard', 'Dashboard'], ['inject', 'Injection Studio'], ['copilot', 'Copilot']]
  return (
    <div style={{ minHeight: '100vh', display: 'grid', gridTemplateRows: 'auto 1fr' }}>
      <header style={{ display: 'flex', alignItems: 'center', gap: 28, padding: '16px 30px',
        borderBottom: '1px solid var(--line)', position: 'sticky', top: 0, background: 'rgba(14,20,32,.85)', backdropFilter: 'blur(10px)', zIndex: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 12, height: 12, borderRadius: 3, background: 'var(--trust)', boxShadow: '0 0 12px var(--trust)' }} />
          <span style={{ fontWeight: 700, fontSize: 17, letterSpacing: '-0.01em' }}>Sentinel</span>
          <span className="eyebrow" style={{ marginLeft: 2 }}>SOC</span>
        </div>
        <nav style={{ display: 'flex', gap: 4 }}>
          {nav.map(([k, label]) => (
            <button key={k} onClick={() => setView(k)}
              style={{ padding: '7px 14px', borderRadius: 7, fontSize: 13, fontWeight: 500,
                color: view === k ? 'var(--ink)' : 'var(--ink-faint)',
                background: view === k ? 'var(--panel)' : 'transparent' }}>{label}</button>
          ))}
        </nav>
        <div style={{ marginLeft: 'auto' }} className="eyebrow">Behavioural Threat Detection</div>
      </header>

      <main style={{ padding: '24px 30px', maxWidth: 1240, width: '100%', margin: '0 auto' }}>
        {view === 'dashboard' && <Dashboard onOpen={open} />}
        {view === 'inject' && <Injection onOpen={open} />}
        {view === 'copilot' && <Copilot />}
        {view === 'incident' && (
          <div>
            <button onClick={() => setView('dashboard')} className="mono"
              style={{ fontSize: 12, color: 'var(--ink-faint)', marginBottom: 16 }}>← back to dashboard</button>
            <IncidentDetail id={incidentId} onOpen={open} />
          </div>
        )}
      </main>
      <style>{`
        @keyframes rise { from { opacity: 0; transform: translateY(10px) } to { opacity: 1; transform: none } }
        .pulse { animation: pulse 1.2s ease-in-out infinite }
        @keyframes pulse { 0%,100% { opacity: .5 } 50% { opacity: 1 } }
      `}</style>
    </div>
  )
}
