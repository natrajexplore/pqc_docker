import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import { ComparePanel } from "./components/ComparePanel";
import { Ladder } from "./components/Ladder";
import { PacketDetail } from "./components/PacketDetail";
import { PacketTable } from "./components/PacketTable";
import { ScenarioBrief } from "./components/ScenarioBrief";
import { ScenarioRail } from "./components/ScenarioRail";
import { StepLog } from "./components/StepLog";
import { VerdictStrip } from "./components/VerdictStrip";
import { PROTOCOL_NAMES } from "./format";
import type { Protocol, RunSummary, ScenarioInfo } from "./types";
import { useRun } from "./useRun";

type View = "run" | "compare" | "history";

const PRESENTER_KEY = "pqcw.presenter";

function savedPresenter(): boolean {
  try { return localStorage.getItem(PRESENTER_KEY) === "1"; } catch { return false; }
}

export default function App() {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [view, setView] = useState<View>("run");
  const [selectedPacket, setSelectedPacket] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [presenter, setPresenter] = useState(savedPresenter);
  const fileInput = useRef<HTMLInputElement>(null);

  const live = useRun(runId);
  const scenario = scenarios.find((s) => s.id === selectedId) ?? null;
  const runSummary = runs.find((r) => r.run_id === runId);
  const protocol: Protocol = (scenario?.protocol ?? runSummary?.protocol ?? "mixed") as Protocol;
  const isLive = live.status === "running" || live.status === "queued" || live.status === "analyzing";

  const refresh = useCallback(async () => {
    try {
      const [sc, rs] = await Promise.all([api.scenarios(), api.runs()]);
      setScenarios(sc);
      setRuns(rs);
      setSelectedId((cur) => {
        if (cur) return cur;
        const first = sc.find((s) => s.available) ?? sc[0];
        if (first) setRunId((r) => r ?? rs.find((x) => x.scenario_id === first.id)?.run_id ?? null);
        return first?.id ?? null;
      });
    } catch (e) {
      setNotice(`Cannot reach the backend: ${(e as Error).message}. Is the stack up? Try: make up`);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    try { localStorage.setItem(PRESENTER_KEY, presenter ? "1" : "0"); } catch { /* private mode: not remembered */ }
  }, [presenter]);
  // P toggles presenter mode, Esc leaves it; ignored while typing in a field
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (e.ctrlKey || e.metaKey || e.altKey || el.closest("input, textarea, select")) return;
      if (e.key === "p" || e.key === "P") setPresenter((v) => !v);
      else if (e.key === "Escape") setPresenter(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  // refresh the run list when a run finishes so compare/history see it
  useEffect(() => {
    if (live.status === "completed" || live.status === "failed" || live.status === "aborted") refresh();
  }, [live.status, refresh]);

  const selectScenario = (id: string) => {
    setSelectedId(id);
    setView("run");
    setSelectedPacket(null);
    const latest = runs.find((r) => r.scenario_id === id);
    setRunId(latest?.run_id ?? null);
  };

  const start = async () => {
    if (!scenario) return;
    setStarting(true);
    setNotice(null);
    setSelectedPacket(null);
    try {
      const { run_id } = await api.start(scenario.id);
      setRunId(run_id);
    } catch (e) {
      setNotice((e as Error).message);
    } finally {
      setStarting(false);
    }
  };

  const onImport = async (f: File | undefined) => {
    if (!f) return;
    try {
      const { run_id, packets } = await api.importPcap(f, f.name);
      setNotice(`Imported ${f.name}: ${packets} packets analyzed.`);
      setSelectedId(null);
      setRunId(run_id);
      setView("run");
      refresh();
    } catch (e) {
      setNotice(`Import failed: ${(e as Error).message}`);
    }
  };

  const title = scenario?.title ?? runSummary?.scenario_title ?? "Pick a scenario";
  // Latest narration reached in this run; it stays up after a fast step finishes.
  const narration = [...live.steps].reverse().find((s) => s.status !== "pending" && s.narration)?.narration ?? null;

  const statusWord = useMemo(() => ({
    idle: "Not run yet", queued: "Starting", running: "Running", analyzing: "Analyzing the capture",
    completed: "Finished", failed: "Failed", aborted: "Stopped",
  })[live.status], [live.status]);

  return (
    <div className={`app${presenter ? " presenter" : ""}`}>
      <header className="top">
        <h1>PQC WireScope</h1>
        <p className="tagline">Post-quantum handshakes, captured and explained.</p>
        <nav className="views" aria-label="Views">
          {(["run", "compare", "history"] as View[]).map((v) => (
            <button key={v} className={view === v ? "is-current" : ""} onClick={() => setView(v)} aria-pressed={view === v}>
              {v === "run" ? "Run" : v === "compare" ? "Compare runs" : "History"}
            </button>
          ))}
        </nav>
        <button className="quiet" onClick={() => setPresenter((v) => !v)} aria-pressed={presenter} title="Toggle with P, leave with Esc">
          {presenter ? "Exit presenter" : "Presenter"}
        </button>
        <button className="quiet" onClick={() => fileInput.current?.click()}>Import a capture</button>
        <input ref={fileInput} type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => onImport(e.target.files?.[0])} />
      </header>

      <ScenarioRail scenarios={scenarios} selected={selectedId} onSelect={selectScenario} />

      <main className="main">
        {notice && <p className="notice" role="status">{notice} <button className="quiet" onClick={() => setNotice(null)}>Dismiss</button></p>}

        {view === "compare" && <ComparePanel runs={runs} initialA={runId} />}

        {view === "history" && (
          <table className="history">
            <thead><tr><th scope="col">When</th><th scope="col">Scenario</th><th scope="col">Result</th><th scope="col">Verdict</th></tr></thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.run_id} onClick={() => { setSelectedId(r.imported ? null : r.scenario_id); setRunId(r.run_id); setView("run"); }} tabIndex={0}>
                  <td>{new Date(r.created_at * 1000).toLocaleString()}</td>
                  <td>{r.scenario_title}</td>
                  <td>{r.status}</td>
                  <td><span className={`dot ${r.verdict?.color ?? "grey"}`} aria-hidden="true" /> {r.verdict?.summary ?? "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {view === "run" && (
          <>
            <section className="scenario-head">
              <div>
                <h2>{title}</h2>
                {!scenario && runSummary?.imported && <p className="summary">{PROTOCOL_NAMES.mixed}, analyzed with the same decoder as live runs.</p>}
              </div>
              <div className="actions">
                <p className={`run-status s-${live.status}`} aria-live="polite">{statusWord}{live.error ? `: ${live.error}` : ""}</p>
                {scenario && (
                  <button className="primary" onClick={start} disabled={!scenario.available || isLive || starting}>
                    {isLive ? "Running…" : runId ? "Run again" : "Run scenario"}
                  </button>
                )}
                {isLive && runId && <button className="quiet" onClick={() => api.abort(runId)}>Stop</button>}
                {runId && !isLive && live.packets.length > 0 && (
                  <a className="quiet" href={api.pcapUrl(runId)} download>Download pcapng</a>
                )}
                {scenario?.upstream_lab && (
                  <a className="quiet" href={`https://github.com/juliogomez/pqc/tree/main/${scenario.upstream_lab}`} target="_blank" rel="noreferrer">
                    Upstream lab guide
                  </a>
                )}
              </div>
            </section>

            {scenario && !presenter && <ScenarioBrief scenario={scenario} />}

            <VerdictStrip verdict={live.verdict} metrics={live.metrics} />

            {presenter && narration && <p className="presenter-narration" aria-live="polite">{narration}</p>}

            <div className="wire">
              <Ladder packets={live.packets} protocol={protocol} selected={selectedPacket} onSelect={setSelectedPacket} live={isLive} exportName={runId ?? "ladder"} hideControl={presenter} />
              <PacketTable packets={live.packets} selected={selectedPacket} onSelect={setSelectedPacket} follow={isLive} />
            </div>

            <div className="lower">
              <StepLog steps={live.steps} plan={scenario?.steps ?? live.steps} output={live.output} assertions={live.assertions} />
              {runId && selectedPacket != null && (
                <PacketDetail runId={runId} n={selectedPacket} canDecrypt={live.keylog} onClose={() => setSelectedPacket(null)} />
              )}
            </div>
          </>
        )}
      </main>
    </div>
  );
}
