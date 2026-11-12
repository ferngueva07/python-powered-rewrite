import { useEffect, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import {
  Activity, ArrowRight, ArrowUpRight, BadgeCheck, Clock3, Fingerprint, Gauge, Info, MapPin, Search,
  ShieldAlert, ShieldCheck, Sparkles, X,
} from "lucide-react";
import type { Engine } from "@/lib/radar/engine";
import type { AnalysisResult, LoginEvent, ModelParams, ProbeResult, ScoredRow } from "@/lib/radar/types";

const fmt = (timestamp: string) => new Intl.DateTimeFormat("en", {
  month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
  timeZoneName: "short",
}).format(new Date(timestamp));
const shortDate = (timestamp: string) => new Intl.DateTimeFormat("en", {
  month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
}).format(new Date(timestamp));

export function Overview({ result, params }: { result: AnalysisResult; params: ModelParams }) {
  const { summary } = result;
  const coverage = summary.injected.total ? Math.round(summary.injected.caught / summary.injected.total * 100) : 0;
  const recent = [...result.rows].filter((r) => r.isAnomaly).sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 5);
  const featureCounts = [
    { name: 'Unusual hour', count: result.rows.filter((r) => r.flags.hour).length, color: 'var(--teal)' },
    { name: 'Long absence', count: result.rows.filter((r) => r.flags.days).length, color: 'var(--gold)' },
    { name: 'New location', count: result.rows.filter((r) => r.flags.location).length, color: 'var(--coral)' },
    { name: 'Failed attempts', count: result.rows.filter((r) => r.flags.failed).length, color: 'var(--navy)' },
  ];
  const maxCount = Math.max(1, ...featureCounts.map((f) => f.count));
  return <section className="overview-content">
    <div className="overview-lead">
      <div><div className="lead-kicker"><span className="pulse" /> CURRENT READOUT <span className="lead-date">{new Date().toLocaleDateString('en', { month: 'short', day: 'numeric' })}</span></div><h2>Know what made<br />a login stand out.</h2><p>Each signal is measured against the sign-in patterns in this dataset. Nothing is a verdict on its own.</p></div>
      <div className="lead-number"><span>FLAGGED</span><strong>{String(summary.flagged).padStart(2, '0')}</strong><small>of {summary.successfulLogins.toLocaleString()} successful logins</small><div className="threshold-line"><span>Model threshold</span><b className="mono">{summary.threshold.toFixed(4)}</b></div></div>
      <div className="lead-stamp">L<br /><span>P</span><i>R</i></div>
    </div>
    <div className="metrics-grid">
      <Metric label="Login attempts" value={summary.totalEvents.toLocaleString()} note={`${summary.failedAttempts} unsuccessful`} icon={<Activity size={16} />} />
      <Metric label="People observed" value={summary.users.toLocaleString()} note="distinct user histories" icon={<Fingerprint size={16} />} />
      <Metric label="New locations" value={summary.newLocationLogins.toLocaleString()} note="first seen for this user" icon={<MapPin size={16} />} />
      <Metric label="Injected examples caught" value={summary.injected.total ? `${coverage}%` : '—'} note={summary.injected.total ? `${summary.injected.caught} of ${summary.injected.total} planted examples` : 'No labelled examples'} icon={<ShieldCheck size={16} />} />
    </div>
    <div className="overview-columns">
      <section className="surface signals-surface">
        <div className="section-head"><div><div className="eyebrow small-eyebrow">WHAT MOVES THE NEEDLE</div><h3>Signals in this dataset</h3></div><span className="count-label">{result.rows.length} SCORED</span></div>
        <div className="signal-bars">{featureCounts.map((item) => <div className="signal-row" key={item.name}><div className="signal-title"><span className="signal-key" style={{ background: item.color }} />{item.name}<b>{item.count}</b></div><div className="signal-track"><span style={{ width: `${item.count ? Math.max(4, item.count / maxCount * 100) : 0}%`, background: item.color }} /></div></div>)}</div>
        <div className="signal-caption"><Info size={14} /><span>Signals can overlap. The model combines them to surface the least typical successful logins.</span></div>
      </section>
      <section className="surface recent-surface">
        <div className="section-head"><div><div className="eyebrow small-eyebrow">REVIEW QUEUE</div><h3>Recently flagged</h3></div><Link to="/activity" className="text-link">All activity <ArrowRight size={14} /></Link></div>
        {recent.length ? <div className="recent-list">{recent.map((row) => <Link to="/activity" className="recent-row" key={row.eventId}><div className="review-mark"><ShieldAlert size={15} /></div><div className="recent-main"><b>{row.userId}</b><span>{row.location} <i>·</i> {row.reasons[0] ?? 'Unusual combination of signals'}</span></div><div className="recent-meta"><b className="mono">{row.score.toFixed(3)}</b><span>{shortDate(row.timestamp)}</span></div><ArrowUpRight size={14} className="recent-arrow" /></Link>)}</div> : <div className="empty-inline"><ShieldCheck size={19} /><span>No logins are flagged with these model settings.</span></div>}
        <div className="review-foot"><span>THRESHOLD</span><b className="mono">{result.summary.threshold.toFixed(4)}</b><span>·</span><span>CONTAMINATION</span><b className="mono">{Math.round(params.contamination * 100)}%</b></div>
      </section>
    </div>
    <div className="explain-band"><div className="explain-badge"><Info size={17} /></div><div><b>Explainable by design</b><p>Open any successful login to see the individual signals, their contribution to the score, and the plain-language reason behind a flag.</p></div><Link to="/activity" className="button button-outline">Explore activity <ArrowRight size={15} /></Link></div>
  </section>;
}

function Metric({ label, value, note, icon }: { label: string; value: string; note: string; icon: ReactNode }) {
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{note}</small></div>;
}

export function ActivityPage({ events, result, search, setSearch, statusFilter, setStatusFilter, selectedId, setSelectedId, selectedRow }: {
  events: LoginEvent[]; result: AnalysisResult; search: string; setSearch: (s: string) => void;
  statusFilter: string; setStatusFilter: (s: string) => void; selectedId: string | null;
  setSelectedId: (s: string | null) => void; selectedRow: ScoredRow | null;
}) {
  const rowById = new Map(result.rows.map((r) => [r.eventId, r]));
  const filtered = [...events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).filter((event) => {
    const row = rowById.get(event.id);
    const queryMatch = `${event.userId} ${event.location} ${event.timestamp}`.toLowerCase().includes(search.toLowerCase());
    const statusMatch = statusFilter === 'all' || (statusFilter === 'failed' ? !event.success : statusFilter === 'flagged' ? !!row?.isAnomaly : statusFilter === 'normal' ? !!row && !row.isAnomaly : event.success);
    return queryMatch && statusMatch;
  });
  const chooseRow = (event: LoginEvent) => {
    if (!event.success) return;
    setSelectedId(selectedId === event.id ? null : event.id);
  };
  return <section className="activity-layout">
    <div className="activity-toolbar">
      <div className="activity-count"><b>{filtered.length.toLocaleString()}</b><span>events shown</span><i>·</i><span>{result.summary.flagged} flagged</span></div>
      <div className="filter-controls">
        <label className="search-box"><Search size={15} /><input type="search" placeholder="Search user or location" value={search} onChange={(e) => setSearch(e.target.value)} data-testid="input-search-events" /><kbd>/</kbd></label>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter event status" data-testid="select-event-filter"><option value="all">All events</option><option value="flagged">Flagged logins</option><option value="normal">Not flagged</option><option value="failed">Failed attempts</option><option value="success">Successful logins</option></select>
      </div>
    </div>
    <div className={`activity-grid ${selectedRow ? 'has-detail' : ''}`}>
      <div className="surface table-surface">
        <div className="table-wrap scrollbar-thin"><table><thead><tr><th>RESULT</th><th>USER</th><th>WHEN <span>UTC</span></th><th>LOCATION</th><th>SCORE</th><th></th></tr></thead><tbody>
          {filtered.map((event) => {
            const row = rowById.get(event.id);
            const isSelected = selectedId === event.id;
            return <tr key={event.id} onClick={() => chooseRow(event)} className={`${event.success ? 'selectable-row' : ''} ${isSelected ? 'row-selected' : ''} ${row?.isAnomaly ? 'flag-row' : ''}`} data-testid={`row-event-${event.id}`}>
              <td><StatusPill event={event} row={row} /></td><td className="user-cell">{event.userId}</td><td className="date-cell">{shortDate(event.timestamp)}</td><td>{event.location}</td><td className="score-cell">{row ? <span className={`score-value ${row.isAnomaly ? 'score-hot' : ''}`}>{row.score.toFixed(3)}</span> : <span className="no-score">—</span>}</td><td>{event.success && <ArrowUpRight size={14} className="row-open" />}</td>
            </tr>;
          })}
        </tbody></table>
        {!filtered.length && <div className="table-empty"><div className="empty-icon"><Search size={18} /></div><b>No matching events</b><span>Try another search or filter, or reset the controls.</span><button onClick={() => { setSearch(''); setStatusFilter('all'); }} className="text-link">Clear filters</button></div>}
        </div>
        <div className="table-bottom"><span>Showing {filtered.length.toLocaleString()} of {events.length.toLocaleString()} events</span><span>Successful logins are selectable</span></div>
      </div>
      {selectedRow ? <ExplanationPanel row={selectedRow} threshold={result.summary.threshold} onClose={() => setSelectedId(null)} /> : <div className="detail-placeholder"><div className="detail-illustration"><Activity size={21} /></div><span className="eyebrow small-eyebrow">SIGNAL BREAKDOWN</span><h3>Select a successful<br />login to inspect it.</h3><p>See how hour, history, location, and nearby failed attempts shaped its score.</p><div className="placeholder-keys"><span>01 / HOUR</span><span>02 / HISTORY</span><span>03 / LOCATION</span><span>04 / ATTEMPTS</span></div></div>}
    </div>
  </section>;
}

function StatusPill({ event, row }: { event: LoginEvent; row?: ScoredRow | undefined }) {
  if (!event.success) return <span className="pill pill-failed"><span />Failed</span>;
  if (row?.isAnomaly) return <span className="pill pill-flagged"><span />Flagged</span>;
  return <span className="pill pill-ok"><span />Within pattern</span>;
}

const signalMeta = [
  { key: 'hour' as const, label: 'Unusual hour', detail: (r: ScoredRow) => `${String(r.hourOfDay).padStart(2, '0')}:00 UTC`, icon: Clock3 },
  { key: 'days' as const, label: 'Time away', detail: (r: ScoredRow) => r.daysSinceLastLogin === null ? 'First login' : `${Math.round(r.daysSinceLastLogin)} days`, icon: Activity },
  { key: 'location' as const, label: 'Location', detail: (r: ScoredRow) => r.location, icon: MapPin },
  { key: 'failed' as const, label: 'Failed attempts', detail: (r: ScoredRow) => `${r.failedAttemptCount} nearby`, icon: ShieldAlert },
];
function ExplanationPanel({ row, threshold, onClose }: { row: ScoredRow; threshold: number; onClose: () => void }) {
  const parts = signalMeta.map((signal) => ({ ...signal, amount: row.contributions[signal.key], flagged: row.flags[signal.key] }));
  const total = Math.max(...parts.map((p) => p.amount), 0.0001);
  return <aside className="explanation-panel" aria-label="Login explanation" data-testid="panel-explanation">
    <div className="explain-top"><div><div className="eyebrow small-eyebrow">LOGIN EXPLANATION</div><div className="explain-user">{row.userId}</div></div><button className="icon-button" onClick={onClose} aria-label="Close explanation"><X size={17} /></button></div>
    <div className="explain-location"><MapPin size={14} />{row.location}<span>·</span>{fmt(row.timestamp)}</div>
    <div className={`verdict ${row.isAnomaly ? 'verdict-flagged' : 'verdict-ok'}`}><div>{row.isAnomaly ? <ShieldAlert size={18} /> : <ShieldCheck size={18} />}</div><span><b>{row.isAnomaly ? 'Flagged as unusual' : 'Within expected pattern'}</b><small>{row.isAnomaly ? 'This login crossed the current model threshold.' : 'This login scored below the current threshold.'}</small></span></div>
    <div className="score-dial-row"><div><span>ANOMALY SCORE</span><b className="mono">{row.score.toFixed(4)}</b></div><div className="score-meter"><span style={{ width: `${Math.min(100, row.score * 100)}%` }} /></div><div className="threshold-read"><span>THRESHOLD</span><b className="mono">{row.isAnomaly ? '≥' : '<'} {threshold.toFixed(4)}</b></div></div>
    <div className="detail-section-title"><b>Signal by signal</b><span>CONTRIBUTION</span></div>
    <div className="contribution-list">{parts.map((part) => <div className={`contribution-row ${part.flagged ? 'contribution-active' : ''}`} key={part.key}><div className="contribution-head"><span className="contribution-icon"><part.icon size={14} /></span><span className="contribution-name">{part.label}<small>{part.detail(row)}</small></span><span className="contribution-score mono">{part.amount.toFixed(4)}</span></div><div className="contribution-track"><span style={{ width: `${part.amount ? Math.max(3, part.amount / total * 100) : 0}%` }} /></div></div>)}</div>
    <div className="reason-box"><div className="reason-heading"><Info size={14} /> WHY IT MATTERS</div>{row.reasons.length ? <ul>{row.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p>No single signal crossed its individual alert condition. The model score reflects the combined pattern.</p>}</div>
    <div className="explain-foot"><span>EVENT ID</span><code>{row.eventId}</code></div>
  </aside>;
}

const toLocalInput = (timestamp: string) => {
  const d = new Date(timestamp);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
};

export function TestPage({ engine, events, result, params }: { engine: Engine; events: LoginEvent[]; result: AnalysisResult; params: ModelParams }) {
  const defaultUser = result.users[0]?.userId ?? '';
  // Each person's most recent successful login: gives their real place and time.
  const latestLogin = (id: string) => events
    .filter((e) => e.userId === id && e.success)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];
  const infoFor = (id: string) => {
    const last = latestLogin(id);
    const profile = result.users.find((u) => u.userId === id);
    return {
      location: last?.location ?? profile?.knownLocations[0] ?? '',
      when: last ? toLocalInput(last.timestamp) : '2026-11-10T09:00',
    };
  };
  const [userId, setUserId] = useState(defaultUser);
  const [location, setLocation] = useState(() => infoFor(defaultUser).location);
  const [when, setWhen] = useState(() => infoFor(defaultUser).when);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    if (result.users.length && !result.users.some((user) => user.userId === userId)) {
      const first = result.users[0]!.userId;
      const info = infoFor(first);
      setUserId(first);
      setLocation(info.location);
      setWhen(info.when);
      setProbeResult(null);
    }
  }, [result.users, userId]);
  const presets = [
    { name: 'Usual morning', desc: 'Known place, familiar hour', time: '2026-11-10T09:00', attempts: 0, place: 'known' },
    { name: 'Late night', desc: 'Same place, unusual hour', time: '2026-11-10T02:20', attempts: 0, place: 'known' },
    { name: 'New location', desc: 'Known hour, new place', time: '2026-11-10T09:00', attempts: 0, place: 'new' },
    { name: 'Password burst', desc: 'Several failures beforehand', time: '2026-11-10T09:00', attempts: 7, place: 'known' },
  ];
  const person = result.users.find((u) => u.userId === userId);
  function setPreset(preset: typeof presets[number]) {
    setWhen(preset.time); setFailedAttempts(preset.attempts);
    setLocation(preset.place === 'new' ? 'Lagos, NG' : person?.knownLocations[0] ?? '');
    setProbeResult(null); setError('');
  }
  function runSimulation() {
    setError(''); setProbeResult(null);
    try {
      const scored = engine.scoreProbe(events, params, { userId, timestamp: new Date(when).toISOString(), location: location.trim(), failedAttempts });
      setProbeResult(scored);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'This scenario could not be scored.');
    }
  }
  return <section className="test-layout">
    <div className="test-intro"><div className="eyebrow small-eyebrow">A SAFE PLACE TO ASK WHAT IF</div><h2>Change one thing.<br /><em>See what moves.</em></h2><p>Score a hypothetical sign-in against one person’s history in the current dataset. This does not create an event or change your data.</p><div className="test-trust"><ShieldCheck size={15} />Runs locally against the selected user’s history</div></div>
    <div className="test-workspace">
      <div className="surface scenario-form">
        <div className="form-head"><div><div className="eyebrow small-eyebrow">SCENARIO INPUT</div><h3>Describe the login</h3></div><span className="step-number">01—04</span></div>
        <div className="preset-list"><span className="field-label">START WITH A SCENARIO</span><div className="preset-grid">{presets.map((preset) => <button key={preset.name} className="preset-button" onClick={() => setPreset(preset)} data-testid={`button-preset-${preset.name.toLowerCase().replaceAll(' ', '-')}`}><b>{preset.name}</b><span>{preset.desc}</span><ArrowUpRight size={13} /></button>)}</div></div>
        <div className="form-fields">
          <label className="field-block"><span className="field-label">PERSON</span><select value={userId} onChange={(e) => { const info = infoFor(e.target.value); setUserId(e.target.value); setLocation(info.location); setWhen(info.when); setFailedAttempts(0); setProbeResult(null); setError(''); }} data-testid="select-probe-user">{result.users.map((u) => <option key={u.userId} value={u.userId}>{u.userId} · {u.logins} logins</option>)}</select><small>{person ? `${person.logins} successful logins · usual around ${String(Math.round(person.typicalHour)).padStart(2, '0')}:00 UTC` : 'No history available'}</small></label>
          <div className="field-pair"><label className="field-block"><span className="field-label">WHEN <i>LOCAL TIME</i></span><input type="datetime-local" value={when} onChange={(e) => { setWhen(e.target.value); setProbeResult(null); }} data-testid="input-probe-time" /></label>
            <label className="field-block"><span className="field-label">WHERE</span><input value={location} onChange={(e) => { setLocation(e.target.value); setProbeResult(null); }} placeholder="City, country" data-testid="input-probe-location" /></label></div>
          <label className="field-block attempts-field"><span className="field-label">FAILED ATTEMPTS JUST BEFORE <b>{failedAttempts}</b></span><input type="range" min="0" max="12" value={failedAttempts} onChange={(e) => { setFailedAttempts(Number(e.target.value)); setProbeResult(null); }} data-testid="input-probe-attempts" /><div className="range-labels"><span>None</span><span>12 attempts</span></div></label>
        </div>
        <div className="form-submit"><span><Info size={14} /> Scored against {result.users.length} user histories</span><button className="button button-dark run-button" onClick={runSimulation} disabled={!userId || !location.trim() || !when} data-testid="button-run-simulation"><Sparkles size={15} /> Score this login <ArrowRight size={15} /></button></div>
        {error && <div className="notice error"><ShieldAlert size={15} />{error}</div>}
      </div>
      <div className={`surface probe-result ${probeResult ? 'result-ready' : ''}`}>
        {probeResult ? <ProbeExplanation probe={probeResult} /> : <div className="result-prompt"><div className="result-radar"><span /><span /><i><Gauge size={19} /></i></div><span className="eyebrow small-eyebrow">SCENARIO RESULT</span><h3>Waiting for your<br />first scenario.</h3><p>Choose a preset or enter the sign-in details. The explanation will show what changed the score.</p><div className="result-prompt-foot"><span>THRESHOLD</span><b className="mono">{result.summary.threshold.toFixed(4)}</b></div></div>}
      </div>
    </div>
    <div className="test-note"><Info size={15} /><p><b>How to read this:</b> A score at or above the threshold is flagged by the current model. Contributions show how much each feature influenced the result; they are not probabilities or proof of risk.</p></div>
  </section>;
}

function ProbeExplanation({ probe }: { probe: ProbeResult }) {
  const row = probe.row;
  return <div className="probe-explanation" data-testid="panel-probe-result">
    <div className="probe-result-head"><span className="eyebrow small-eyebrow">SCENARIO RESULT</span><span className="result-check"><BadgeCheck size={15} /> SCORED</span></div>
    <div className={`probe-verdict ${row.isAnomaly ? 'probe-alert' : ''}`}><div className="probe-score mono">{row.score.toFixed(3)}</div><div><b>{row.isAnomaly ? 'This login would be flagged.' : 'This login fits the pattern.'}</b><span>{row.isAnomaly ? 'Its score meets or exceeds the model threshold.' : 'Its score falls below the model threshold.'}</span></div></div>
    <div className="probe-threshold"><span>MODEL THRESHOLD</span><div className="probe-track"><span style={{ left: `${Math.min(94, probe.threshold * 100)}%` }} /><i style={{ width: `${Math.min(100, row.score * 100)}%` }} /></div><b className="mono">{probe.threshold.toFixed(4)}</b></div>
    {probe.profile && <div className="profile-strip"><Fingerprint size={15} /><span><b>{probe.profile.userId}</b><small>History: {probe.profile.logins} successful sign-ins · {probe.profile.knownLocations.length} known locations</small></span><span className="profile-hours">TYPICAL HOUR <b className="mono">{String(Math.round(probe.profile.typicalHour)).padStart(2, '0')}:00</b></span></div>}
    <div className="probe-signals-title"><b>What shaped the score</b><span>FEATURE CONTRIBUTION</span></div>
    <div className="probe-signal-list">{signalMeta.map((signal) => {
      const Icon = signal.icon;
      const amount = row.contributions[signal.key];
      return <div className={`probe-signal ${row.flags[signal.key] ? 'probe-signal-on' : ''}`} key={signal.key}><span className="probe-signal-icon"><Icon size={14} /></span><span className="probe-signal-name">{signal.label}<small>{signal.detail(row)}</small></span><span className="probe-signal-bar"><i style={{ width: `${Math.min(100, amount / Math.max(...Object.values(row.contributions), 0.0001) * 100)}%` }} /></span><b className="mono">{amount.toFixed(4)}</b></div>;
    })}</div>
    <div className="probe-reasons">{row.reasons.length ? row.reasons.map((reason) => <div key={reason}><ShieldAlert size={14} /><span>{reason}</span></div>) : <div><ShieldCheck size={14} /><span>No individual signal crossed its alert condition.</span></div>}</div>
    <div className="probe-foot"><span>SCORE PERCENTILE</span><b className="mono">{probe.scorePercentile.toFixed(1)}th</b><span>·</span><span>NOT A PROBABILITY</span></div>
  </div>;
}

