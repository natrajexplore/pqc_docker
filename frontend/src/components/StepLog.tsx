import { useState } from "react";
import type { AssertionResult, StepState } from "../types";
import { ms } from "../format";

const ICON: Record<string, string> = { pending: "○", running: "◐", ok: "●", failed: "✕", skipped: "–" };
const STATUS: Record<string, string> = { pending: "Waiting", running: "Running", ok: "Done", failed: "Failed", skipped: "Skipped" };

interface Props {
  steps: StepState[];
  plan: { id: string; title: string; narration: string }[];
  output: Record<string, string>;
  assertions: AssertionResult[];
}

/** The scenario as a numbered procedure: one card per step, then the checks against the capture. */
export function StepLog({ steps, plan, output, assertions }: Props) {
  // steps the user opened or closed; unset steps follow the default (failed ones open)
  const [open, setOpen] = useState<Record<string, boolean>>({});
  // Show the scenario's plan before the run starts, live state once it does.
  const rows: StepState[] = plan.map(
    (p) => steps.find((s) => s.id === p.id) ?? { ...p, status: "pending", started_at: null, duration_ms: null, output: "", message: "" },
  );
  const done = rows.filter((r) => r.status === "ok" || r.status === "failed" || r.status === "skipped").length;
  const current = rows.findIndex((r) => r.status === "running");
  const passed = assertions.filter((a) => a.passed).length;

  return (
    <div className="steps">
      <div className="procedure-head">
        <h3>Procedure</h3>
        <span className="dim">
          {current >= 0 ? `Step ${current + 1} of ${rows.length}` : `${done} of ${rows.length} steps done`}
        </span>
      </div>
      <div className="progress" role="progressbar" aria-label="Procedure progress"
           aria-valuemin={0} aria-valuemax={rows.length} aria-valuenow={done}>
        <span style={{ width: `${rows.length ? (done / rows.length) * 100 : 0}%` }} />
      </div>

      <ol className="step-cards">
        {rows.map((s, i) => {
          const text = output[s.id] || s.output;
          const isOpen = open[s.id] ?? s.status === "failed";
          return (
            <li key={s.id} className={`step st-${s.status}`}>
              <div className="step-card-head">
                <span className="step-num" aria-hidden="true">{i + 1}</span>
                <span className="step-title">{s.title}</span>
                <span className="step-state"><span aria-hidden="true">{ICON[s.status]}</span> {STATUS[s.status]}</span>
                <span className="step-time">{s.duration_ms != null ? ms(s.duration_ms) : ""}</span>
              </div>
              {s.narration && <p className="step-narration">{s.narration}</p>}
              {s.message && <p className="step-msg">{s.message}</p>}
              {text && (
                <>
                  <button className="step-toggle" onClick={() => setOpen({ ...open, [s.id]: !isOpen })} aria-expanded={isOpen}>
                    {isOpen ? "Hide output" : "Show output"}
                  </button>
                  {isOpen && <pre className="step-out" aria-label={`Output of step ${i + 1}`}>{text}</pre>}
                </>
              )}
            </li>
          );
        })}
      </ol>

      {assertions.length > 0 && (
        <>
          <p className={`result-box ${passed === assertions.length ? "ok" : "bad"}`} role="status">
            {passed === assertions.length
              ? `All ${assertions.length} checks passed against the capture.`
              : `${assertions.length - passed} of ${assertions.length} checks failed. The failed ones are listed first.`}
          </p>
          <h3 className="checks-title">Checks against the capture</h3>
          <ul className="checks">
            {[...assertions].sort((a, b) => Number(a.passed) - Number(b.passed)).map((a) => (
              <li key={a.id} className={a.passed ? "pass" : "fail"}>
                <span aria-hidden="true">{a.passed ? "✓" : "✕"}</span>
                <span>{a.message}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
