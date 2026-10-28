import { useEffect, useReducer } from "react";
import { api, wsUrl } from "./api";
import type { AssertionResult, Metrics, Packet, RunEvent, RunStatus, StepState, Verdict } from "./types";

export interface LiveRun {
  runId: string | null;
  status: RunStatus | "idle";
  error: string | null;
  steps: StepState[];
  output: Record<string, string>; // step_id -> streamed text
  packets: Packet[];
  metrics: Metrics | null;
  verdict: Verdict | null;
  assertions: AssertionResult[];
  keylog: boolean;
  connected: boolean;
}

const empty = (runId: string | null): LiveRun => ({
  runId, status: runId ? "queued" : "idle", error: null, steps: [], output: {}, packets: [],
  metrics: null, verdict: null, assertions: [], keylog: false, connected: false,
});

type Action =
  | { kind: "reset"; runId: string | null }
  | { kind: "event"; e: RunEvent }
  | { kind: "connected"; value: boolean }
  | { kind: "keylog"; value: boolean };

function reducer(s: LiveRun, a: Action): LiveRun {
  switch (a.kind) {
    case "reset":
      return empty(a.runId);
    case "connected":
      return { ...s, connected: a.value };
    case "keylog":
      return { ...s, keylog: a.value };
    case "event": {
      const e = a.e;
      switch (e.type) {
        case "run.status":
          return { ...s, status: e.status, error: e.error };
        case "step.status": {
          const i = s.steps.findIndex((x) => x.id === e.step.id);
          const steps = i < 0 ? [...s.steps, e.step] : s.steps.map((x, j) => (j === i ? e.step : x));
          return { ...s, steps };
        }
        case "step.output":
          return { ...s, output: { ...s.output, [e.step_id]: (s.output[e.step_id] ?? "") + e.text } };
        case "packet":
          // replay after reconnect can resend packets; keep n unique
          if (s.packets.length && s.packets[s.packets.length - 1].n >= e.packet.n) return s;
          return { ...s, packets: [...s.packets, e.packet] };
        case "run.result":
          return { ...s, metrics: e.metrics, verdict: e.verdict, assertions: e.assertions };
        default:
          return s;
      }
    }
  }
}

/** Subscribe to a run: replayed history first, then live events. */
export function useRun(runId: string | null): LiveRun {
  const [state, dispatch] = useReducer(reducer, runId, empty);

  useEffect(() => {
    dispatch({ kind: "reset", runId });
    if (!runId) return;
    let closed = false;
    let ws: WebSocket | null = null;
    let retry: number | undefined;

    const connect = () => {
      ws = new WebSocket(wsUrl(`/ws/runs/${runId}`));
      ws.onopen = () => dispatch({ kind: "connected", value: true });
      ws.onmessage = (m) => {
        const e = JSON.parse(m.data) as RunEvent;
        if (e.type !== "ping") dispatch({ kind: "event", e });
      };
      ws.onclose = () => {
        dispatch({ kind: "connected", value: false });
        if (!closed) retry = window.setTimeout(connect, 1500);
      };
    };
    // Runs loaded from history (backend restarted) have no event replay: hydrate from REST.
    api.run(runId).then(async (r) => {
      dispatch({ kind: "keylog", value: Boolean(r.keylog_file) });
      if (r.status === "completed" || r.status === "failed" || r.status === "aborted") {
        const packets = await api.packets(runId);
        dispatch({ kind: "event", e: { type: "run.status", run_id: runId, status: r.status, error: r.error } });
        r.steps.forEach((st) => dispatch({ kind: "event", e: { type: "step.status", run_id: runId, step: st } }));
        packets.forEach((p) => dispatch({ kind: "event", e: { type: "packet", run_id: runId, packet: p } }));
        if (r.metrics && r.verdict)
          dispatch({ kind: "event", e: { type: "run.result", run_id: runId, metrics: r.metrics, verdict: r.verdict, assertions: r.assertions } });
      }
    }).catch(() => { /* surfaced by the WS state */ });
    connect();
    return () => {
      closed = true;
      window.clearTimeout(retry);
      ws?.close();
    };
  }, [runId]);

  return state;
}
