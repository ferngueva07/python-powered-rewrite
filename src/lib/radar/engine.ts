/**
 * Browser bridge to the Python analysis engine (src/python/lpr).
 *
 * Pyodide runs CPython in the page. The Python sources are bundled as text,
 * written into Pyodide's file system, and imported once. After loading, every
 * call is synchronous, like the original TypeScript functions were.
 */
import type {
  AnalysisResult,
  LoginEvent,
  ModelParams,
  Probe,
  ProbeResult,
  UploadScanResult,
} from "./types";

const PYODIDE_VERSION = "0.29.5";
const PYODIDE_URL = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;
/** Must match MAX_SCAN_BYTES in src/python/lpr/scanner/content_scan.py. */
export const MAX_SCAN_BYTES = 20 * 1024 * 1024;

type PyFn = (...args: unknown[]) => string;
/** Functions exported by src/python/lpr/api.py. */
interface PythonApi {
  sample_events: PyFn;
  to_csv: PyFn;
  analyze: PyFn;
  score_probe: PyFn;
  import_login_text: PyFn;
  scan_uploads: PyFn;
}
interface PyodideLike {
  loadPackage(names: string | string[]): Promise<unknown>;
  runPython(code: string): unknown;
  pyimport(name: string): PythonApi;
  FS: { mkdirTree(path: string): void; writeFile(path: string, data: string): void };
}
declare global {
  interface Window {
    loadPyodide?: (options: { indexURL: string }) => Promise<PyodideLike>;
  }
}

export interface Engine {
  sampleEvents(seed: number): LoginEvent[];
  eventsToCsv(events: LoginEvent[]): string;
  analyze(events: LoginEvent[], params: ModelParams): AnalysisResult | null;
  scoreProbe(events: LoginEvent[], params: ModelParams, probe: Probe): ProbeResult;
  importLoginText(text: string, fileName: string): LoginEvent[];
  scanUploads(
    files: Iterable<Pick<File, "name" | "size" | "slice">>,
    params: ModelParams,
  ): Promise<UploadScanResult>;
}

type Reply<T> = { ok: true; value: T } | { ok: false; error: string };

function unwrap<T>(raw: string): T {
  const reply = JSON.parse(raw) as Reply<T>;
  if (!reply.ok) throw new Error(reply.error);
  return reply.value;
}

// Re-serialising the same event list on every slider move is wasteful.
const jsonCache = new WeakMap<object, string>();
function eventsJson(events: LoginEvent[]): string {
  let json = jsonCache.get(events);
  if (json === undefined) {
    json = JSON.stringify(events);
    jsonCache.set(events, json);
  }
  return json;
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[data-pyodide="${src}"]`);
    if (existing && window.loadPyodide) return resolve();
    const script = existing ?? document.createElement("script");
    script.src = src;
    script.async = true;
    script.dataset["pyodide"] = src;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("The analysis engine could not be downloaded."));
    if (!existing) document.head.appendChild(script);
  });
}

async function boot(): Promise<Engine> {
  const sourceLoaders = import.meta.glob("../../python/lpr/**/*.py", {
    query: "?raw",
    import: "default",
  }) as Record<string, () => Promise<string>>;
  const [, sources] = await Promise.all([
    loadScript(`${PYODIDE_URL}pyodide.js`),
    Promise.all(
      Object.entries(sourceLoaders).map(async ([path, load]) => [path, await load()] as const),
    ),
  ]);
  if (!window.loadPyodide) throw new Error("The analysis engine could not be started.");
  const pyodide = await window.loadPyodide({ indexURL: PYODIDE_URL });
  await pyodide.loadPackage("numpy");

  const root = "/home/pyodide/engine";
  for (const [path, code] of sources) {
    const relative = path.slice(path.indexOf("python/") + "python/".length);
    const target = `${root}/${relative}`;
    pyodide.FS.mkdirTree(target.slice(0, target.lastIndexOf("/")));
    pyodide.FS.writeFile(target, code);
  }
  pyodide.runPython(`import sys\nsys.path.insert(0, "${root}")`);
  const api = pyodide.pyimport("lpr.api");
  const fn = {
    sampleEvents: api.sample_events,
    toCsv: api.to_csv,
    analyze: api.analyze,
    scoreProbe: api.score_probe,
    importLoginText: api.import_login_text,
    scanUploads: api.scan_uploads,
  };

  return {
    sampleEvents: (seed) => unwrap(fn.sampleEvents(seed)),
    eventsToCsv: (events) => unwrap(fn.toCsv(eventsJson(events))),
    analyze: (events, params) => unwrap(fn.analyze(eventsJson(events), JSON.stringify(params))),
    scoreProbe: (events, params, probe) =>
      unwrap(fn.scoreProbe(eventsJson(events), JSON.stringify(params), JSON.stringify(probe))),
    importLoginText: (text, fileName) => unwrap(fn.importLoginText(text, fileName)),
    async scanUploads(files, params) {
      const payload: { name: string; size: number; data: Uint8Array | null; error: string | null }[] = [];
      for (const file of files) {
        try {
          const data = new Uint8Array(await file.slice(0, MAX_SCAN_BYTES).arrayBuffer());
          payload.push({ name: file.name, size: file.size, data, error: null });
        } catch (err) {
          payload.push({
            name: file.name,
            size: file.size,
            data: null,
            error: err instanceof Error ? err.message : "The file could not be read.",
          });
        }
      }
      return unwrap<UploadScanResult>(fn.scanUploads(payload, JSON.stringify(params)));
    },
  };
}

let enginePromise: Promise<Engine> | null = null;

/** Starts the engine once per page; later calls share the same instance. */
export function loadEngine(): Promise<Engine> {
  if (!enginePromise) {
    enginePromise = boot().catch((err) => {
      enginePromise = null;
      throw err;
    });
  }
  return enginePromise;
}
