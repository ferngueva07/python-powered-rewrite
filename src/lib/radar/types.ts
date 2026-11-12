/** Shapes of the data the Python engine returns (same as the original app). */

/** A single raw login attempt (successful or failed). Timestamps are ISO-8601, interpreted in UTC. */
export interface LoginEvent {
  id: string;
  userId: string;
  timestamp: string;
  location: string;
  success: boolean;
  /** Minutes the user's local clock is behind UTC (JS `getTimezoneOffset`). Absent = UTC. */
  tzOffsetMin?: number | undefined;
  /** Ground-truth tag for injected anomalies in the sample dataset (null for normal events). */
  label: AnomalyLabel | null;
}

export type AnomalyLabel = "odd_hour" | "dormant_return" | "new_location" | "brute_force";

export interface FeatureRow {
  eventId: string;
  userId: string;
  timestamp: string;
  location: string;
  label: AnomalyLabel | null;
  tzOffsetMin?: number;
  hourOfDay: number;
  daysSinceLastLogin: number | null;
  locationChangeFlag: 0 | 1;
  failedAttemptCount: number;
}

export interface FeatureContributions {
  hour: number;
  days: number;
  location: number;
  failed: number;
}

export interface FeatureFlags {
  hour: boolean;
  days: boolean;
  location: boolean;
  failed: boolean;
}

export interface ScoredRow extends FeatureRow {
  score: number;
  isAnomaly: boolean;
  contributions: FeatureContributions;
  reasons: string[];
  flags: FeatureFlags;
}

export interface UserProfile {
  userId: string;
  logins: number;
  knownLocations: string[];
  typicalHour: number;
  lastLogin: string;
}

export interface Bucket {
  bucket: string;
  normal: number;
  flagged: number;
}

export interface AnalysisSummary {
  totalEvents: number;
  successfulLogins: number;
  failedAttempts: number;
  users: number;
  flagged: number;
  threshold: number;
  newLocationLogins: number;
  burstLogins: number;
  injected: { total: number; caught: number };
  byLabel: Partial<Record<AnomalyLabel, { total: number; caught: number }>>;
}

export interface AnalysisResult {
  summary: AnalysisSummary;
  rows: ScoredRow[];
  users: UserProfile[];
  distributions: { hours: Bucket[]; days: Bucket[]; failed: Bucket[]; location: Bucket[] };
  params: ModelParams;
}

export interface ProbeResult {
  row: ScoredRow;
  threshold: number;
  profile: UserProfile | null;
  scorePercentile: number;
}

export interface ModelParams {
  contamination: number;
  windowMinutes: number;
  seed: number;
}

export interface Probe {
  userId: string;
  timestamp: string;
  location: string;
  failedAttempts: number;
}

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: "secret" | "malware" | "attack" | "file-type" | "login";
  description: string;
  count: number;
  samples: { line?: number; record?: number; text: string }[];
}

export type LogFormat = "login-csv" | "windows-security" | "json" | "auth-log" | "auditd";

export interface FileReport {
  name: string;
  size: number;
  sha256: string | null;
  kind: string | null;
  logFormat: LogFormat | null;
  loginEvents: number;
  skippedLogRecords: number;
  truncated: boolean;
  error: string | null;
  findings: Finding[];
  worst: Severity | null;
}

export interface UploadScanResult {
  files: FileReport[];
  events: LoginEvent[];
  flaggedLogins: (ScoredRow & { file: string })[];
  analysis: AnalysisResult | null;
  analysisError: string | null;
  totals: Record<Severity, number>;
}

const FORMAT_LABEL: Record<LogFormat, string> = {
  "login-csv": "Login CSV",
  "windows-security": "Windows Security log",
  json: "JSON / JSONL log",
  "auth-log": "Linux auth.log (sshd)",
  auditd: "Linux auditd",
};
export const formatLabel = (f: LogFormat) => FORMAT_LABEL[f];
