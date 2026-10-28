import { useState } from "react";
import type { AssertionResult, StepState } from "../types";
import { ms } from "../format";

const ICON: Record<string, string> = { pending: "○", running: "◐", ok: "●", failed: "✕", skipped: "–" };

interface Props {
  steps: StepState[];
  plan: { id: string; title: string; narration: string }[];
  output: Record<string, string>;
  assertions: AssertionResult[];
}

export function StepLog({ steps, plan, output, assertions }: Props) {
  const [open, setOpen] = useState<string | null>(null);
  // Show the scenario's plan before the run starts, live state once it does.
  const rows: StepState[] = plan.map(
    (p) => steps.find((s) => s.id === p.id) ?? { ...p, status: "pending", started_at: null, duration_ms: null, output: "", message: "" },
  );
  const running = rows.find((r) => r.status === "running");

  return (
    <div className="steps">
      {running?.narration && <p className="narration" aria-live="polite">{running.narration}</p>}
      <ol>
        {rows.map((s) => {
          const text = output[s.id] || s.output;
          return (
            <li key={s.id} className={`step st-${s.status}`}>
              <button
                className="step-head"
                onClick={() => setOpen(open === s.id ? null : s.id)}
                aria-expanded={open === s.id}
                disabled={!text && !s.message}
              >
                <span className="icon" aria-hidden="true">{ICON[s.status]}</span>
                <span className="step-title">{s.title}</span>
                <span className="step-time">{s.duration_ms != null ? ms(s.duration_ms) : ""}</span>
              </button>
              {s.message && <p className="step-msg">{s.message}</p>}
              {open === s.id && text && <pre className="step-out">{text}</pre>}
            </li>
          );
        })}
      </ol>
      {assertions.length > 0 && (
        <>
          <h3 className="checks-title">Checks against the capture</h3>
          <ul className="checks">
            {assertions.map((a) => (
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
