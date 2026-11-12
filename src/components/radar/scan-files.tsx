import { useId, useRef, useState, type DragEvent } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { ArrowRight, ChevronDown, FileSearch, FileUp, ShieldAlert, ShieldCheck, UploadCloud } from 'lucide-react';
import { loadEngine } from '@/lib/radar/engine';
import { formatLabel, type FileReport, type LoginEvent, type ModelParams, type Severity, type UploadScanResult } from '@/lib/radar/types';

const SEVERITY_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

function bytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}
export function SeverityPill({ severity }: { severity: Severity | null }) {
  if (!severity) return <span className="pill pill-ok"><span />No matches</span>;
  return <span className={`pill sev-${severity}`}><span />{SEVERITY_LABEL[severity]}</span>;
}

function FileCard({ report }: { report: FileReport }) {
  const [open, setOpen] = useState(report.worst === 'critical' || report.worst === 'high' || !!report.error || report.truncated || report.skippedLogRecords > 0);
  return <div className={`scan-file ${report.worst ? `scan-file-${report.worst}` : ''}`} data-testid={`scan-file-${report.name}`}>
    <button className="scan-file-head" onClick={() => setOpen(!open)} aria-expanded={open}>
      {report.error ? <span className="pill sev-high"><span />Not scanned</span> : <SeverityPill severity={report.worst} />}
      <span className="scan-file-name"><b>{report.name}</b><small>{bytes(report.size)}{report.kind ? ` · ${report.kind}` : ''}{report.logFormat ? ` · ${formatLabel(report.logFormat)} (${report.loginEvents.toLocaleString()} logins)` : ''}</small></span>
      <span className="scan-file-count">{report.error ? 'Read failed' : `${report.truncated ? 'Partial scan · ' : ''}${report.findings.length ? `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}` : 'No matches'}`}</span>
      <ChevronDown size={15} className={open ? 'chev-open' : ''} />
    </button>
    {open && <div className="scan-file-body">
      {report.error && <div className="notice error"><ShieldAlert size={15} />{report.error}</div>}
      {report.truncated && !report.error && <div className="notice error"><ShieldAlert size={15} />Only the first 20 MiB were scanned; the rest was not read. No full-file SHA-256 was calculated.</div>}
      {report.skippedLogRecords > 0 && <div className="notice error"><ShieldAlert size={15} />{report.skippedLogRecords.toLocaleString()} login records were skipped because they were invalid or exceeded the 50,000-record limit.</div>}
      {report.findings.map((f) => <div className="finding" key={f.ruleId}>
        <div className="finding-head"><SeverityPill severity={f.severity} /><b>{f.title}</b><span className="finding-cat">{f.category.toUpperCase()}</span>{f.count > 1 && <span className="finding-count mono">×{f.count}</span>}</div>
        <p>{f.description}</p>
        {f.samples.length > 0 && <ul className="finding-samples">{f.samples.map((s, i) => <li key={i}>{s.line ? <span className="mono">L{s.line}</span> : s.record ? <span className="mono">R{s.record}</span> : null}<code>{s.text}</code></li>)}</ul>}
      </div>)}
      {report.sha256 && <div className="scan-hash"><span>SHA-256</span><code>{report.sha256}</code></div>}
      {!report.sha256 && !report.truncated && !report.error && <div className="scan-hash">SHA-256 unavailable in this browser.</div>}
    </div>}
  </div>;
}

export function FileUpload({ params, onScan, compact = false }: {
  params: ModelParams;
  onScan: (scan: UploadScanResult) => void;
  compact?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);
  const scanningRef = useRef(false);
  const inputId = useId();

  async function run(files: FileList | null | undefined) {
    if (scanningRef.current) return;
    if (!files?.length) {
      setError('No files were selected. Drop files rather than folders.');
      return;
    }
    scanningRef.current = true;
    setBusy(true); setError('');
    try {
      // Copy the list first: the input is cleared right after this call starts.
      const list = Array.from(files);
      const engine = await loadEngine();
      onScan(await engine.scanUploads(list, params));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The files could not be scanned.');
    } finally {
      scanningRef.current = false;
      setBusy(false);
    }
  }
  function onDrop(e: DragEvent) {
    e.preventDefault(); setDragging(false);
    void run(e.dataTransfer.files);
  }
  const input = <input id={inputId} ref={fileRef} type="file" multiple className="sr-only" disabled={busy} onChange={(e) => { if (e.target.files?.length) void run(e.target.files); e.target.value = ''; }} data-testid={compact ? 'input-upload-file' : 'input-scan-files'} />;
  const limits = 'Pattern matching is not antivirus. Only the first 20 MiB of each file is scanned; archives are not unpacked and binary files are not fully analyzed.';

  return <>
    {compact ? <div className={`upload-zone ${dragging ? 'upload-zone-active' : ''}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} aria-busy={busy} data-testid="dropzone-upload">
      <div className="upload-icon"><UploadCloud size={21} /></div>
      <div className="upload-copy"><b>{busy ? 'Scanning your files…' : 'Upload a file'}</b><span>Drop files to inspect security logs and suspicious content locally. Supported login histories also update this dashboard.</span></div>
      <button className="button button-dark" type="button" disabled={busy} onClick={() => fileRef.current?.click()}>{busy ? 'Scanning…' : 'Choose file'}</button>
      {input}
    </div> : <label htmlFor={inputId} className={`scan-drop ${dragging ? 'scan-drop-active' : ''}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} aria-busy={busy} data-testid="dropzone-scan">
      <div className="scan-drop-icon">{busy ? <FileSearch size={24} /> : <UploadCloud size={24} />}</div>
      <b>{busy ? 'Scanning…' : 'Drop files here or click to upload'}</b>
      <span>Any file type. Inspect cloud, identity, firewall, web, endpoint, and other security logs in JSON/JSONL, CSV, XML, or text exports.</span>
      <span className="scan-drop-note"><ShieldCheck size={13} /> Scanned entirely in your browser — nothing is uploaded to a server.</span>
      <span>{limits}</span>
      {input}
    </label>}
    {compact && <p className="upload-limits">{limits}</p>}
    {error && <div className="notice error" role="alert"><ShieldAlert size={16} />{error}</div>}
  </>;
}

export function ScanFilesPage({ params, scan, setScan, onLoadEvents }: {
  params: ModelParams;
  scan: UploadScanResult | null;
  setScan: (s: UploadScanResult | null) => void;
  onLoadEvents: (events: LoginEvent[], source: string) => void;
}) {
  const navigate = useNavigate();
  const issues = scan ? scan.totals.critical + scan.totals.high + scan.totals.medium + scan.totals.low : 0;

  return <section className="scan-layout">
    <FileUpload params={params} onScan={setScan} />
    {scan && <>
      <div className="metrics-grid">
        <div className="metric-card"><div className="metric-top"><span>Files checked</span><i><FileUp size={16} /></i></div><strong>{scan.files.filter((f) => !f.error).length} / {scan.files.length}</strong><small>{scan.files.filter((f) => f.error).length} could not be read</small></div>
        <div className="metric-card"><div className="metric-top"><span>Critical / high</span><i><ShieldAlert size={16} /></i></div><strong className={scan.totals.critical + scan.totals.high ? 'metric-hot' : ''}>{scan.totals.critical + scan.totals.high}</strong><small>{scan.totals.critical} critical · {scan.totals.high} high</small></div>
        <div className="metric-card"><div className="metric-top"><span>Medium / low</span><i><ShieldCheck size={16} /></i></div><strong>{scan.totals.medium + scan.totals.low}</strong><small>review when convenient</small></div>
        <div className="metric-card"><div className="metric-top"><span>Unusual logins</span><i><FileSearch size={16} /></i></div><strong>{scan.analysis ? scan.flaggedLogins.length : '—'}</strong><small>of {scan.events.filter((e) => e.success).length.toLocaleString()} successful logins parsed</small></div>
      </div>

      {!issues && !scan.flaggedLogins.length && !scan.analysisError && scan.files.every((f) => !f.error && !f.truncated && !f.skippedLogRecords) && <div className="notice success"><ShieldCheck size={16} />No configured patterns matched. This does not mean the files are safe.</div>}

      <section className="surface scan-files">
        <div className="section-head"><div><div className="eyebrow small-eyebrow">PER-FILE REPORT</div><h3>What we found</h3></div><button className="text-link" onClick={() => setScan(null)}>Clear results</button></div>
        {[...scan.files].sort((a, b) => (a.worst ? ['critical', 'high', 'medium', 'low'].indexOf(a.worst) : 9) - (b.worst ? ['critical', 'high', 'medium', 'low'].indexOf(b.worst) : 9)).map((r, i) => <FileCard key={`${r.name}-${i}`} report={r} />)}
      </section>

      {scan.events.length > 0 && <section className="surface scan-files">
        <div className="section-head"><div><div className="eyebrow small-eyebrow">ANOMALY MODEL</div><h3>Unusual logins in uploaded logs</h3></div>
          {scan.analysis && <button className="button button-dark" onClick={() => { onLoadEvents(scan.events, `Uploaded files (${scan.files.filter((f) => f.loginEvents).length})`); void navigate({ to: '/activity' }); }} data-testid="button-open-activity">Open in Activity <ArrowRight size={14} /></button>}</div>
        <div className="signal-caption"><ShieldAlert size={14} /><span>Scores rank patterns within these logs, not the probability of an attack. Similar scores can cause more logins to be flagged than the selected percentage.</span></div>
        {scan.analysisError ? <div className="notice error" role="alert"><ShieldAlert size={15} />{scan.analysisError}</div> : !scan.analysis ? <div className="empty-inline"><ShieldAlert size={19} />No successful logins were found to score.</div> : scan.flaggedLogins.length ? <div className="table-wrap scrollbar-thin"><table><thead><tr><th>SCORE</th><th>USER</th><th>WHEN <span>UTC</span></th><th>SOURCE</th><th>WHY</th><th>FILE</th></tr></thead><tbody>
          {scan.flaggedLogins.slice(0, 100).map((r) => <tr key={r.eventId} className="flag-row"><td className="score-cell"><span className="score-value score-hot">{r.score.toFixed(3)}</span></td><td className="user-cell">{r.userId}</td><td className="date-cell">{r.timestamp.replace('T', ' ').slice(0, 16)}</td><td>{r.location}</td><td>{r.reasons[0] ?? 'Unusual combination of signals'}</td><td className="date-cell">{r.file}</td></tr>)}
        </tbody></table></div> : <div className="empty-inline"><ShieldCheck size={19} /><span>No successful logins crossed the model threshold.</span></div>}
        {scan.flaggedLogins.length > 100 && <div className="table-bottom"><span>Showing the 100 highest-scoring of {scan.flaggedLogins.length}</span></div>}
      </section>}
    </>}
  </section>;
}
