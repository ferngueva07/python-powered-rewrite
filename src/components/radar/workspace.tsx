import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { Link, Outlet, useLocation } from "@tanstack/react-router";
import {
  Activity, ArrowDownToLine, ArrowRight, BadgeCheck, FileUp, Fingerprint, Gauge, Info, Menu, Moon,
  RotateCcw, ScanSearch, ShieldAlert, SlidersHorizontal, Sparkles, Sun, X,
} from "lucide-react";
import { loadEngine, type Engine } from "@/lib/radar/engine";
import type { AnalysisResult, LoginEvent, ModelParams, ScoredRow, UploadScanResult } from "@/lib/radar/types";
import { FileUpload } from "./scan-files";

const SEED = 7;
const DEFAULT_PARAMS: ModelParams = { contamination: 0.08, windowMinutes: 30, seed: SEED };
type Theme = "light" | "dark";

function readThemePreference(): Theme | null {
  try {
    const saved = localStorage.getItem("lpr-theme");
    return saved === "light" || saved === "dark" ? saved : null;
  } catch (error) {
    console.warn("Theme preference could not be read.", error);
    return null;
  }
}
function readStoredEvents(engine: Engine): LoginEvent[] {
  try {
    const saved = localStorage.getItem("lpr-events-v1");
    return saved ? (JSON.parse(saved) as LoginEvent[]) : engine.sampleEvents(SEED);
  } catch {
    return engine.sampleEvents(SEED);
  }
}
function readStoredParams(): ModelParams {
  try {
    const saved = localStorage.getItem("lpr-params-v1");
    return saved ? { ...DEFAULT_PARAMS, ...(JSON.parse(saved) as Partial<ModelParams>) } : DEFAULT_PARAMS;
  } catch {
    return DEFAULT_PARAMS;
  }
}
function readStoredSource(): string {
  try { return localStorage.getItem("lpr-events-v1") ? "Imported dataset" : "Generated sample"; }
  catch { return "Generated sample"; }
}

interface WorkspaceState {
  engine: Engine;
  events: LoginEvent[];
  result: AnalysisResult | null;
  params: ModelParams;
  search: string;
  setSearch: (s: string) => void;
  statusFilter: string;
  setStatusFilter: (s: string) => void;
  selectedId: string | null;
  setSelectedId: (s: string | null) => void;
  selectedRow: ScoredRow | null;
  scan: UploadScanResult | null;
  setScan: (s: UploadScanResult | null) => void;
  loadScannedEvents: (events: LoginEvent[], label: string) => void;
}

const WorkspaceContext = createContext<WorkspaceState | null>(null);

export function useWorkspace(): WorkspaceState {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("useWorkspace must be used inside the workspace.");
  return value;
}

/** Starts the Python engine, then shows the dashboard. */
export function Workspace() {
  const [engine, setEngine] = useState<Engine | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const saved = readThemePreference();
    const dark = saved ? saved === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.classList.toggle("dark", dark);
  }, []);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    loadEngine().then(
      (next) => { if (!cancelled) setEngine(next); },
      (err) => { if (!cancelled) setError(err instanceof Error ? err.message : "The analysis engine could not be started."); },
    );
    return () => { cancelled = true; };
  }, [attempt]);

  if (!engine) {
    return (
      <div className="app-root min-h-[100dvh]">
        <div className="app-noise" aria-hidden="true" />
        <main className="engine-boot">
          <div className="engine-boot-card" role="status" data-testid="engine-boot">
            <div className="brand-mark"><Fingerprint size={22} strokeWidth={1.7} /></div>
            <h1>{error ? "The analysis engine didn’t start" : "Starting the analysis engine"}</h1>
            <p>{error ?? "Loading Python in your browser. This takes a few seconds the first time; nothing leaves this device."}</p>
            {error
              ? <button className="button button-dark" onClick={() => setAttempt((n) => n + 1)}><RotateCcw size={14} /> Try again</button>
              : <div className="loading-bar"><span /> Preparing local analysis…</div>}
          </div>
        </main>
      </div>
    );
  }
  return <Dashboard engine={engine} />;
}

function Dashboard({ engine }: { engine: Engine }) {
  const [themePreference, setThemePreference] = useState<Theme | null>(readThemePreference);
  const [systemDark, setSystemDark] = useState(() => window.matchMedia("(prefers-color-scheme: dark)").matches);
  const theme = themePreference ?? (systemDark ? "dark" : "light");
  const [events, setEvents] = useState<LoginEvent[]>(() => readStoredEvents(engine));
  const [params, setParams] = useState<ModelParams>(readStoredParams);
  const [source, setSource] = useState(readStoredSource);
  const [fileStatus, setFileStatus] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [scan, setScan] = useState<UploadScanResult | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const path = useLocation({ select: (location) => location.pathname });

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const updateSystemTheme = (event: MediaQueryListEvent) => setSystemDark(event.matches);
    setSystemDark(media.matches);
    media.addEventListener("change", updateSystemTheme);
    return () => media.removeEventListener("change", updateSystemTheme);
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setThemePreference(next);
    try { localStorage.setItem("lpr-theme", next); }
    catch (error) { console.warn("Theme preference could not be saved.", error); }
  }

  const analysisState = useMemo(() => {
    if (!events.length) return { result: null, error: null } as { result: AnalysisResult | null; error: string | null };
    try {
      return { result: engine.analyze(events, params), error: null } as { result: AnalysisResult | null; error: string | null };
    } catch (err) {
      return { result: null, error: err instanceof Error ? err.message : "Analysis could not be completed." };
    }
  }, [engine, events, params]);
  const result = analysisState.result;
  const selectedRow = result?.rows.find((row) => row.eventId === selectedId) ?? null;

  function updateEvents(next: LoginEvent[], nextSource: string) {
    setEvents(next);
    setSource(nextSource);
    setSelectedId(null);
    try { localStorage.setItem("lpr-events-v1", JSON.stringify(next)); } catch { /* local session remains usable */ }
  }
  function updateParams(next: ModelParams) {
    setParams(next);
    try { localStorage.setItem("lpr-params-v1", JSON.stringify(next)); } catch { /* controls still work in memory */ }
  }
  async function importFile(file?: File) {
    if (!file) return;
    setLoading(true);
    setFileStatus(null);
    try {
      const text = await file.text();
      const parsed = engine.importLoginText(text, file.name);
      updateEvents(parsed, file.name);
      setFileStatus({ kind: "success", text: `Imported ${parsed.length.toLocaleString()} events from ${file.name}.` });
    } catch (err) {
      setFileStatus({ kind: "error", text: err instanceof Error ? err.message : "This file could not be read." });
    } finally {
      setLoading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }
  function exportEvents() {
    const blob = new Blob([engine.eventsToCsv(events)], { type: "text/csv;charset=utf-8" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = "login-pattern-events.csv";
    anchor.click();
    URL.revokeObjectURL(href);
  }
  function resetDemo() {
    updateEvents(engine.sampleEvents(SEED), "Generated sample");
    updateParams(DEFAULT_PARAMS);
    setFileStatus({ kind: "success", text: "Demo events and model controls have been restored." });
  }
  function scanInline(next: UploadScanResult) {
    setScan(next);
    const checked = next.files.filter((file) => !file.error).length;
    if (next.analysis) {
      updateEvents(next.events, next.files.length === 1 ? next.files[0]!.name : `Uploaded files (${next.files.length})`);
    }
    setFileStatus({
      kind: checked < next.files.length || next.analysisError ? "error" : "success",
      text: `Checked ${checked} of ${next.files.length} files. ${next.analysis ? `Dashboard updated with ${next.events.length.toLocaleString()} login events.` : `Dashboard unchanged. ${next.analysisError ?? "No scorable login history was found."}`} Review the scan report for findings and coverage.`,
    });
  }
  function loadScannedEvents(next: LoginEvent[], label: string) {
    updateEvents(next, label);
    setFileStatus({ kind: "success", text: `Loaded ${next.length.toLocaleString()} login events from uploaded files.` });
  }

  const nav = [
    { href: "/", title: "Overview", icon: Gauge, hint: "01" },
    { href: "/activity", title: "Activity", icon: Activity, hint: "02" },
    { href: "/test", title: "Test a login", icon: Sparkles, hint: "03" },
    { href: "/scan", title: "Scan files", icon: ScanSearch, hint: "04" },
  ] as const;
  const isScan = path === "/scan";
  const pageTitle = path === "/activity" ? "Login activity" : path === "/test" ? "Test a login" : isScan ? "Scan files" : "Analysis overview";
  const state: WorkspaceState = {
    engine, events, result, params, search, setSearch, statusFilter, setStatusFilter,
    selectedId, setSelectedId, selectedRow, scan, setScan, loadScannedEvents,
  };
  return (
    <WorkspaceContext.Provider value={state}>
      <div className="app-root min-h-[100dvh]">
        <div className="app-noise" aria-hidden="true" />
        <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
          <div className="brand-lockup">
            <div className="brand-mark"><Fingerprint size={22} strokeWidth={1.7} /></div>
            <div><div className="brand-name">pattern<span>radar</span></div><div className="brand-sub">LOGIN INTELLIGENCE</div></div>
            <button className="mobile-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={18} /></button>
          </div>
          <div className="workspace-label">WORKSPACE <span>LOCAL</span></div>
          <nav className="nav-list" aria-label="Main navigation">
            {nav.map((item) => (
              <Link key={item.href} to={item.href} className={`nav-item ${path === item.href ? "nav-active" : ""}`} onClick={() => setMobileNav(false)} data-testid={`link-nav-${item.title.toLowerCase().replaceAll(" ", "-")}`}>
                <item.icon size={17} strokeWidth={1.8} /><span>{item.title}</span><small>{item.hint}</small>
              </Link>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <div className="local-status"><span className="status-dot" /><span><b>Browser-only analysis</b><small>No data leaves this device</small></span></div>
            <div className="sidebar-foot">LPR / 0.8.1 <span>·</span> PRIVATE BY DESIGN</div>
          </div>
        </aside>
        {mobileNav && <button className="mobile-scrim" onClick={() => setMobileNav(false)} aria-label="Close menu overlay" />}
        <main className="main-shell">
          <header className="topbar">
            <button className="mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19} /></button>
            <div className="breadcrumb"><span>WORKSPACE</span><i>/</i><b>{pageTitle}</b></div>
            <div className="topbar-right"><span className="local-chip"><span className="status-dot" /> LOCAL ANALYSIS</span><span className="topbar-divider" /><span className="sample-name">{source}</span><button type="button" className="theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} data-testid="button-theme">{theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}</button></div>
          </header>
          <div className="page-body page-enter">
            <div className="page-heading">
              <div><div className="eyebrow"><span className="eyebrow-line" />SIGN-IN BEHAVIOR / {path === "/" ? "CURRENT READOUT" : path === "/activity" ? "EVENT EXPLORER" : isScan ? "THREAT SCAN" : "SCENARIO LAB"}</div><h1 className="display">{pageTitle}</h1></div>
              <div className="heading-actions">
                <label className="button button-quiet import-button" htmlFor="csv-import"><FileUp size={15} /> Import log</label>
                <input id="csv-import" ref={fileRef} type="file" accept=".csv,.json,.jsonl,.log,.txt,text/csv,application/json,text/plain" className="sr-only" onChange={(e) => void importFile(e.target.files?.[0])} data-testid="input-import-csv" />
                <button className="button button-dark" onClick={exportEvents} disabled={!events.length} data-testid="button-export-events"><ArrowDownToLine size={15} /> Export</button>
              </div>
            </div>
            <div className="source-strip"><Info size={14} /><span><b>{source === "Generated sample" ? "Generated sample data" : "Local dataset"}</b> — analysis runs in your browser. No live connection.</span>
              <button onClick={resetDemo} className="reset-link" data-testid="button-reset-demo"><RotateCcw size={13} /> Reset demo</button>
            </div>
            {path === "/" && <>
              <FileUpload compact params={params} onScan={scanInline} />
              {scan && <div className="upload-result"><span>{scan.files.length} {scan.files.length === 1 ? "file" : "files"} in the latest scan</span><Link to="/scan" className="text-link" data-testid="link-scan-report">View scan report <ArrowRight size={14} /></Link></div>}
            </>}
            {fileStatus && <div className={`notice ${fileStatus.kind}`} role="status" data-testid="status-import">{fileStatus.kind === "success" ? <BadgeCheck size={16} /> : <ShieldAlert size={16} />}<span>{fileStatus.text}</span><button onClick={() => setFileStatus(null)} aria-label="Dismiss message"><X size={15} /></button></div>}
            {loading && <div className="loading-bar" role="status"><span /> Reading your local file…</div>}
            <div className="model-controls">
              <div className="control-intro"><SlidersHorizontal size={15} /><b>Model controls</b><span>Re-score as you tune</span></div>
              <label className="control-field"><span>Analysis window</span><select value={params.windowMinutes} onChange={(e) => updateParams({ ...params, windowMinutes: Number(e.target.value) })} data-testid="select-window"><option value={5}>± 5 minutes</option><option value={15}>± 15 minutes</option><option value={30}>± 30 minutes</option><option value={60}>± 60 minutes</option></select></label>
              <label className="control-field contamination-control"><span>Contamination <b className="mono">{Math.round(params.contamination * 100)}%</b></span><input type="range" min="2" max="20" step="1" value={Math.round(params.contamination * 100)} onChange={(e) => updateParams({ ...params, contamination: Number(e.target.value) / 100 })} data-testid="input-contamination" /></label>
              <span className="control-recalc"><span className="recalc-dot" /> LIVE RECALC</span>
            </div>
            {!isScan && analysisState.error && <div className="error-panel"><ShieldAlert size={21} /><div><b>We couldn’t score these events</b><p>{analysisState.error}</p><button onClick={resetDemo} className="button button-dark"><RotateCcw size={14} /> Restore demo data</button></div></div>}
            {!isScan && !analysisState.error && !result && <div className="empty-panel"><div className="empty-icon"><Activity size={22} /></div><h2>No events to analyze</h2><p>Import a CSV with at least one successful login, or start again with the generated sample.</p><button className="button button-dark" onClick={resetDemo}>Load demo events <ArrowRight size={15} /></button></div>}
            <Outlet />
            <footer className="page-footer"><span>LOGIN PATTERN RADAR</span><span>Signals, not verdicts. Every flag has a reason.</span></footer>
          </div>
        </main>
      </div>
    </WorkspaceContext.Provider>
  );
}
