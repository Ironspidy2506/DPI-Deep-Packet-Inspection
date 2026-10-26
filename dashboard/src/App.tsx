import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  ArrowDownToLine,
  ArrowUpRight,
  Ban,
  Bell,
  ChevronDown,
  CirclePause,
  CirclePlay,
  Database,
  Ellipsis,
  Filter,
  Gauge,
  Network,
  Play,
  Radio,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Zap,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

type Flow = {
  app: string
  domain: string
  source: string
  destination: string
  protocol: 'TCP' | 'UDP'
  bytes: string
  state: 'Forwarded' | 'Inspected' | 'Blocked'
  color: string
}

type ThroughputPoint = { time: string; packets: number; forwarded: number; dropped: number }
type DashboardSnapshot = {
  isRunning: boolean
  totalPackets: number
  totalBytes: number
  tcpPackets: number
  udpPackets: number
  forwardedPackets: number
  droppedPackets: number
  parseErrors: number
  classifiedPackets: number
  activeFlows: number
  classifications: Record<string, number>
  blockedApps: string[]
  flows: FlowSnapshotData[]
}
type FlowSnapshotData = {
  sourceIp: string
  destinationIp: string
  sourcePort: number
  destinationPort: number
  protocol: number
  packets: number
  bytes: number
  domain: string
  application: string
  action: 'Forward' | 'Drop'
}

const initialThroughput: ThroughputPoint[] = [
  { time: '14:31:00', packets: 42, forwarded: 39, dropped: 3 },
  { time: '14:31:10', packets: 58, forwarded: 52, dropped: 6 },
  { time: '14:31:20', packets: 48, forwarded: 46, dropped: 2 },
  { time: '14:31:30', packets: 76, forwarded: 69, dropped: 7 },
  { time: '14:31:40', packets: 64, forwarded: 60, dropped: 4 },
  { time: '14:31:50', packets: 91, forwarded: 84, dropped: 7 },
  { time: '14:32:00', packets: 87, forwarded: 82, dropped: 5 },
  { time: '14:32:10', packets: 103, forwarded: 97, dropped: 6 },
]

const appColors = ['#f26b5b', '#69c49a', '#a996e8', '#f1b85e', '#86b9c9']
const baseAppData = [
  { name: 'YouTube', value: 34 },
  { name: 'Spotify', value: 22 },
  { name: 'GitHub', value: 18 },
  { name: 'Discord', value: 15 },
  { name: 'Other', value: 11 },
]

function formatNumber(value: number) {
  return new Intl.NumberFormat('en-US').format(value)
}

function formatBytes(value: number) {
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`
  return `${(value / 1024).toFixed(1)} KB`
}

function flowColor(application: string) {
  const index = ['YouTube', 'Spotify', 'GitHub', 'Discord', 'TikTok'].indexOf(application)
  return appColors[index >= 0 ? index : appColors.length - 1]
}

function mapFlow(flow: FlowSnapshotData): Flow {
  return {
    app: flow.application,
    domain: flow.domain || 'unclassified flow',
    source: `${flow.sourceIp}:${flow.sourcePort}`,
    destination: `${flow.destinationIp}:${flow.destinationPort}`,
    protocol: flow.protocol === 17 ? 'UDP' : 'TCP',
    bytes: formatBytes(flow.bytes),
    state: flow.action === 'Drop' ? 'Blocked' : flow.application !== 'Unknown' ? 'Inspected' : 'Forwarded',
    color: flowColor(flow.application),
  }
}

async function loadLiveFlows(setFlows: (flows: Flow[]) => void) {
  const response = await fetch('/api/flows', { cache: 'no-store' })
  if (!response.ok) throw new Error('Flow endpoint unavailable')
  const payload = await response.json() as unknown[]
  const liveFlows = payload.map((item) => {
    const flow = item as Record<string, unknown>
    return {
      sourceIp: String(flow.sourceIp ?? flow.SourceIp ?? ''),
      destinationIp: String(flow.destinationIp ?? flow.DestinationIp ?? ''),
      sourcePort: Number(flow.sourcePort ?? flow.SourcePort ?? 0),
      destinationPort: Number(flow.destinationPort ?? flow.DestinationPort ?? 0),
      protocol: Number(flow.protocol ?? flow.Protocol ?? 0),
      packets: Number(flow.packets ?? flow.Packets ?? 0),
      bytes: Number(flow.bytes ?? flow.Bytes ?? 0),
      domain: String(flow.domain ?? flow.Domain ?? ''),
      application: String(flow.application ?? flow.Application ?? 'Unknown'),
      action: String(flow.action ?? flow.Action ?? 'Forward') === 'Drop' ? 'Drop' : 'Forward',
    } as FlowSnapshotData
  })
  setFlows(liveFlows.map(mapFlow))
}

function App() {
  const [isLive, setIsLive] = useState(true)
  const [backendConnected, setBackendConnected] = useState(false)
  const [throughput, setThroughput] = useState(initialThroughput)
  const [totalPackets, setTotalPackets] = useState(128402)
  const [forwardedPackets, setForwardedPackets] = useState(123490)
  const [droppedPackets, setDroppedPackets] = useState(4912)
  const [activeFlows, setActiveFlows] = useState(1248)
  const [blockedApps, setBlockedApps] = useState<string[]>([])
  const [flows, setFlows] = useState<Flow[]>([])
  const [search, setSearch] = useState('')
  const [flowFilter, setFlowFilter] = useState<'All' | Flow['state']>('All')
  const [inputPath, setInputPath] = useState('test_dpi.pcap')
  const [outputPath, setOutputPath] = useState('filtered-dashboard.pcap')
  const [blockApps, setBlockApps] = useState<string[]>(['TikTok'])
  const [runMessage, setRunMessage] = useState('Ready to process a capture')
  const [runSubmitting, setRunSubmitting] = useState(false)
  const previousPackets = useRef<number | null>(null)
  const previousDropped = useRef<number | null>(null)

  useEffect(() => {
    if (!isLive) return
    void loadLiveFlows(setFlows).catch(() => undefined)
    const stream = new EventSource('/api/stream')
    stream.onopen = () => setBackendConnected(true)
    const handleSnapshot = (event: MessageEvent<string>) => {
      const snapshot = JSON.parse(event.data) as DashboardSnapshot
      const packetDelta = previousPackets.current === null ? 0 : Math.max(0, snapshot.totalPackets - previousPackets.current)
      const droppedDelta = previousDropped.current === null ? 0 : Math.max(0, snapshot.droppedPackets - previousDropped.current)
      previousPackets.current = snapshot.totalPackets
      previousDropped.current = snapshot.droppedPackets
      setTotalPackets(snapshot.totalPackets)
      setForwardedPackets(snapshot.forwardedPackets)
      setDroppedPackets(snapshot.droppedPackets)
      setActiveFlows(snapshot.activeFlows)
      setBlockedApps(snapshot.blockedApps ?? [])
      void loadLiveFlows(setFlows).catch(() => undefined)
      setThroughput((current) => [...current.slice(-7), {
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        packets: packetDelta,
        forwarded: Math.max(0, packetDelta - droppedDelta),
        dropped: droppedDelta,
      }])
    }
    stream.addEventListener('snapshot', handleSnapshot)
    stream.onerror = () => setBackendConnected(false)
    const flowPoll = window.setInterval(() => {
      void loadLiveFlows(setFlows).catch(() => undefined)
    }, 250)
    return () => {
      stream.removeEventListener('snapshot', handleSnapshot)
      stream.close()
      window.clearInterval(flowPoll)
    }
  }, [isLive])

  async function startCapture(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setRunSubmitting(true)
    setRunMessage('Starting analyzer...')
    previousPackets.current = null
    previousDropped.current = null
    try {
      const response = await fetch('/api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ inputPath, outputPath, blockApps, blockApp: blockApps[0] ?? null }),
      })
      const payload = await response.json() as { message?: string; error?: string; blockedApps?: string[] }
      if (!response.ok) throw new Error(payload.error ?? 'Unable to start capture')
      const appliedApps = payload.blockedApps ?? blockApps
      setRunMessage(appliedApps.length > 0 ? `Applied rules: ${appliedApps.join(', ')}` : 'Running without application blocks')
      setFlows([])
      void loadLiveFlows(setFlows).catch(() => undefined)
      const fastRefresh = window.setInterval(() => {
        void loadLiveFlows(setFlows).catch(() => undefined)
      }, 100)
      window.setTimeout(() => window.clearInterval(fastRefresh), 3000)
      setIsLive(true)
    } catch (error) {
      setRunMessage(error instanceof Error ? error.message : 'Unable to start capture')
    } finally {
      setRunSubmitting(false)
    }
  }

  const filteredFlows = useMemo(
    () => flows.filter((flow) => {
      const matchesSearch = `${flow.app} ${flow.domain} ${flow.source}`.toLowerCase().includes(search.toLowerCase())
      const matchesStatus = flowFilter === 'All' || flow.state === flowFilter
      return matchesSearch && matchesStatus
    }),
    [flowFilter, flows, search],
  )

  return (
    <main className="app-shell">
      <aside className="side-rail">
        <div className="brand-mark"><Zap size={18} fill="currentColor" /><span>PX</span></div>
        <nav className="rail-nav" aria-label="Primary navigation">
          <button className="rail-button active" aria-label="Overview"><Gauge size={19} /></button>
          <button className="rail-button" aria-label="Traffic"><Activity size={19} /></button>
          <button className="rail-button" aria-label="Rules"><ShieldCheck size={19} /></button>
          <button className="rail-button" aria-label="Connections"><Network size={19} /></button>
        </nav>
        <div className="rail-bottom"><button className="rail-button" aria-label="Settings"><SlidersHorizontal size={19} /></button><div className="avatar">IS</div></div>
      </aside>

      <section className="content">
        <header className="topbar">
          <div className="crumb"><span>Network operations</span><ChevronDown size={14} /><strong>Packet Analyzer</strong></div>
          <div className="top-actions"><span className={`sync-dot ${backendConnected ? '' : 'offline'}`}><i /> {backendConnected ? 'live from analyzer' : 'analyzer offline'}</span><button className="icon-button" aria-label="Notifications"><Bell size={18} /></button><div className="profile"><div className="avatar small">IS</div><span>Ironspidy</span><ChevronDown size={14} /></div></div>
        </header>

        <div className="page-heading">
          <div><p className="eyebrow"><Radio size={13} /> LIVE INSPECTION / CLUSTER 01</p><h1>Control room <span>overview</span></h1><p className="subtitle">Observe traffic, classify applications, and keep the edge moving.</p></div>
          <div className="heading-actions"><button className="secondary-button"><ArrowDownToLine size={16} /> Export report</button></div>
        </div>

        <form className="run-console" onSubmit={startCapture}>
          <div className="run-console-title"><span className="run-icon"><CirclePlay size={16} /></span><div><strong>Run a real capture</strong><small>{runMessage}</small></div></div>
          <label>Input PCAP<input value={inputPath} onChange={(event) => setInputPath(event.target.value)} /></label>
          <label>Output PCAP<input value={outputPath} onChange={(event) => setOutputPath(event.target.value)} /></label>
          <fieldset className="app-check-group"><legend>Block apps</legend><div className="app-checks">{['YouTube', 'TikTok', 'Facebook', 'Instagram', 'GitHub', 'Discord', 'Spotify', 'Netflix'].map((app) => <label key={app}><input type="checkbox" checked={blockApps.includes(app)} onChange={(event) => setBlockApps((current) => event.target.checked ? [...current, app] : current.filter((selected) => selected !== app))} /><span>{app}</span></label>)}</div></fieldset>
          <button className="run-button" type="submit" disabled={runSubmitting}>{runSubmitting ? <CirclePause size={15} /> : <Play size={15} />}{runSubmitting ? 'Starting' : 'Run analyzer'}</button>
        </form>

        <div className="metric-grid">
          <MetricCard label="Packets inspected" value={formatNumber(totalPackets)} delta="12.8%" positive icon={<Database size={16} />} tone="coral" />
          <MetricCard label="Packets delivered" value={formatNumber(forwardedPackets)} delta="forwarded" positive icon={<ArrowUpRight size={16} />} tone="mint" />
          <MetricCard label="Packets dropped" value={formatNumber(droppedPackets)} delta="blocked by rules" positive={false} icon={<Ban size={16} />} tone="gold" />
          <MetricCard label="Active flows" value={formatNumber(activeFlows)} delta="live connections" positive icon={<Network size={16} />} tone="lilac" />
        </div>

        <div className="main-grid">
          <section className="panel traffic-panel">
            <div className="panel-header"><div><div className="title-line"><h2>Traffic pulse</h2><span className="live-tag"><i /> streaming</span></div><p>Packets per second across all inspection workers</p></div><button className="more-button" aria-label="More traffic options"><Ellipsis size={18} /></button></div>
            <div className="chart-legend"><span><i className="legend-line coral" /> Total traffic</span><span><i className="legend-line mint" /> Forwarded</span><span><i className="legend-line gold" /> Dropped</span><strong>last 80 seconds <ChevronDown size={13} /></strong></div>
            <div className="traffic-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={throughput} margin={{ top: 10, right: 2, left: -24, bottom: 0 }}><defs><linearGradient id="packetsFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f26b5b" stopOpacity={0.28} /><stop offset="100%" stopColor="#f26b5b" stopOpacity={0} /></linearGradient></defs><CartesianGrid vertical={false} stroke="#243033" strokeDasharray="3 4" /><XAxis dataKey="time" tick={{ fill: '#81908b', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: '#81908b', fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#182124', border: '1px solid #334044', borderRadius: 8, color: '#f4f2e9', fontSize: 12 }} /><Area type="monotone" dataKey="packets" stroke="#f26b5b" strokeWidth={2} fill="url(#packetsFill)" /><Area type="monotone" dataKey="forwarded" stroke="#69c49a" strokeWidth={1.5} fill="none" /><Area type="monotone" dataKey="dropped" stroke="#f1b85e" strokeWidth={1.5} fill="none" /></AreaChart></ResponsiveContainer></div>
          </section>

          <section className="panel composition-panel">
            <div className="panel-header"><div><h2>Application mix</h2><p>Classification by inspected payload</p></div><button className="more-button" aria-label="More application options"><Ellipsis size={18} /></button></div>
            <div className="donut-wrap"><ResponsiveContainer width="58%" height={170}><PieChart><Pie data={baseAppData} innerRadius={56} outerRadius={78} paddingAngle={4} dataKey="value" stroke="none"><>{baseAppData.map((entry, index) => <Cell key={entry.name} fill={appColors[index]} />)}</></Pie><Tooltip contentStyle={{ background: '#182124', border: '1px solid #334044', borderRadius: 8, color: '#f4f2e9', fontSize: 12 }} /></PieChart></ResponsiveContainer><div className="donut-total"><strong>84.2%</strong><span>classified</span></div></div>
            <div className="app-legend">{baseAppData.map((entry, index) => <div key={entry.name}><span><i style={{ background: appColors[index] }} />{entry.name}</span><strong>{entry.value}%</strong></div>)}</div>
          </section>
        </div>

        <section className="panel flows-panel">
          <div className="panel-header flows-header"><div><div className="title-line"><h2>Active flows</h2><span className="count-badge">{activeFlows.toLocaleString()}</span></div><p>Most recent connections surfaced by the DPI engine</p></div><div className="flow-tools"><div className="search-box"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search flows" /></div><label className="filter-select"><Filter size={15} /><select value={flowFilter} onChange={(event) => setFlowFilter(event.target.value as 'All' | Flow['state'])}><option value="All">All statuses</option><option value="Inspected">Inspected</option><option value="Forwarded">Forwarded</option><option value="Blocked">Blocked</option></select></label></div></div>
          <div className="table-wrap"><table><thead><tr><th>Application</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Volume</th><th>Status</th></tr></thead><tbody>{filteredFlows.length === 0 ? <tr><td className="empty-flow" colSpan={6}>No active flows returned by the analyzer</td></tr> : filteredFlows.map((flow) => <tr key={`${flow.source}-${flow.destination}`}><td><div className="app-cell"><span className="app-icon" style={{ background: `${flow.color}20`, color: flow.color }}>{flow.app.slice(0, 1)}</span><div><strong>{flow.app}</strong><small>{flow.domain}</small></div></div></td><td className="mono">{flow.source}</td><td className="mono">{flow.destination}</td><td><span className={`protocol ${flow.protocol.toLowerCase()}`}>{flow.protocol}</span></td><td className="volume">{flow.bytes}</td><td><span className={`state ${flow.state.toLowerCase()}`}><i />{flow.state}</span></td></tr>)}</tbody></table></div>
        </section>

        <div className="bottom-grid">
          <section className="panel worker-panel"><div className="panel-header"><div><h2>Worker health</h2><p>Load balance across processing partitions</p></div><span className="healthy"><i /> all healthy</span></div><div className="workers">{['LB-01 / W1', 'LB-01 / W2', 'LB-02 / W1', 'LB-02 / W2'].map((worker, index) => <div className="worker" key={worker}><div className="worker-top"><span>{worker}</span><strong>{[42, 67, 38, 51][index]}%</strong></div><div className="progress"><i style={{ width: `${[42, 67, 38, 51][index]}%` }} /></div><small>{[320, 511, 289, 402][index]} packets/s</small></div>)}</div></section>
          <section className="panel rules-panel"><div className="panel-header"><div><h2>Rule watch</h2><p>Active application blocks from the analyzer</p></div><span className="healthy"><i /> live rules</span></div><div className="rule-highlight"><div className="rule-icon"><ShieldCheck size={18} /></div><div><strong>{blockedApps.length > 0 ? blockedApps.join(', ') : 'No blocked apps'}</strong><span>{blockedApps.length > 0 ? 'Application traffic is being dropped' : 'Run a capture with a block rule'}</span></div></div><div className="rule-stats"><span><b>{blockedApps.length}</b> apps blocked</span><span><b>{formatNumber(droppedPackets)}</b> packets dropped</span></div></section>
        </div>

        <footer><span><Sparkles size={14} /> DPI engine v2.4.1</span><span>Last rules sync 14:31:58 UTC <span className="footer-separator">/</span> <a href="#status">System status</a></span></footer>
      </section>
    </main>
  )
}

function MetricCard({ label, value, suffix, delta, positive, icon, tone }: { label: string; value: string; suffix?: string; delta: string; positive: boolean; icon: React.ReactNode; tone: string }) {
  return <article className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value}{suffix && <small>{suffix}</small>}</div><div className={`metric-delta ${positive ? 'positive' : ''}`}><ArrowUpRight size={13} />{delta}<span>vs last hour</span></div></article>
}

export default App
