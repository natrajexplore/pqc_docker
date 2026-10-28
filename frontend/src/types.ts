// Mirrors backend/app/models.py and backend/app/analyzer/*.py. Keep in sync.

export type Protocol = "ipsec" | "tls" | "ssh" | "macsec" | "mixed";

export interface ScenarioInfo {
  id: string;
  title: string;
  protocol: Protocol;
  stack: string;
  pillar: "key-exchange" | "authentication" | "both";
  group: string;
  order: number;
  summary: string;
  upstream_lab: string | null;
  learn_more: string[];
  available: boolean;
  missing: string[];
  steps: { id: string; title: string; narration: string }[];
  expected_numbers: Record<string, unknown>;
}

export interface Packet {
  n: number;
  frame: number;
  agent: string;
  ts: number;
  rel_ms: number;
  src: string;
  dst: string;
  length: number;
  proto: string;
  kind: "handshake" | "data" | "control" | "other";
  direction: "l2r" | "r2l" | "unknown";
  label: string;
  info: string;
  tags: string[];
  detail: Record<string, unknown>;
}

export type StepStatus = "pending" | "running" | "ok" | "failed" | "skipped";

export interface StepState {
  id: string;
  title: string;
  narration: string;
  status: StepStatus;
  started_at: number | null;
  duration_ms: number | null;
  output: string;
  message: string;
}

export interface PillarVerdict {
  status: string; // pq-hybrid | pq-ppk | pq | classical | downgraded | refused | unknown
  algorithm: string | null;
  evidence: "wire" | "endpoint" | "declared";
  detail: string;
}

export interface Verdict {
  key_exchange: PillarVerdict;
  authentication: PillarVerdict;
  color: "green" | "amber" | "red" | "grey";
  summary: string;
}

export interface AssertionResult {
  id: string;
  kind: string;
  passed: boolean;
  message: string;
  expected: Record<string, unknown>;
}

export interface Metrics {
  frames_total: number;
  handshake_frames: number;
  handshake_bytes: number;
  data_frames: number;
  handshake_duration_ms: number;
  flights: number;
  largest_frame: number;
  fragments: number;
  protocol: Record<string, Record<string, unknown>>;
}

export type RunStatus = "queued" | "running" | "analyzing" | "completed" | "failed" | "aborted";

export interface RunSummary {
  run_id: string;
  scenario_id: string;
  scenario_title: string;
  protocol: Protocol;
  group: string;
  status: RunStatus;
  created_at: number;
  finished_at: number | null;
  steps: StepState[];
  metrics: Metrics | null;
  verdict: Verdict | null;
  assertions: AssertionResult[];
  pcap_files: string[];
  keylog_file: string | null;
  error: string | null;
  imported: boolean;
  packet_count: number;
}

export type RunEvent =
  | { type: "run.status"; run_id: string; status: RunStatus; error: string | null }
  | { type: "step.status"; run_id: string; step: StepState }
  | { type: "step.output"; run_id: string; step_id: string; text: string }
  | { type: "packet"; run_id: string; packet: Packet }
  | { type: "run.result"; run_id: string; metrics: Metrics; verdict: Verdict; assertions: AssertionResult[] }
  | { type: "ping" };

export interface PacketDetail {
  packet: Packet;
  frame: number;
  tree: Record<string, unknown>;
  hex: string;
  decrypted: boolean;
}

export interface CompareResult {
  a: { run_id: string; scenario: string; verdict: Verdict | null; metrics: Metrics | null };
  b: { run_id: string; scenario: string; verdict: Verdict | null; metrics: Metrics | null };
  delta: Record<string, number>;
  bytes_ratio: number | null;
}
