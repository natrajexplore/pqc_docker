import type { ScenarioInfo } from "../types";

/**
 * The scenario as a procedure: what it shows, what has to be running first, and the
 * reference numbers recorded from real runs. Everything comes from GET /api/scenarios.
 */

const PILLAR_WORDS: Record<ScenarioInfo["pillar"], string> = {
  "key-exchange": "Key exchange",
  authentication: "Authentication",
  both: "Key exchange and authentication",
};

function label(key: string): string {
  const s = key.replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function value(v: unknown): string {
  if (typeof v === "number") return v.toLocaleString("en");
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

// prose entries read better as a footnote than as a table row
const NOTE_KEYS = new Set(["note", "observed", "upstream", "source"]);

export function ScenarioBrief({ scenario }: { scenario: ScenarioInfo }) {
  const watch = scenario.steps.filter((s) => s.narration);
  const numbers = Object.entries(scenario.expected_numbers).filter(([k]) => !NOTE_KEYS.has(k));
  const notes = Object.entries(scenario.expected_numbers).filter(([k]) => NOTE_KEYS.has(k));

  return (
    <div className="brief">
      <section className="brief-card about" aria-labelledby="brief-about">
        <h3 id="brief-about">About this scenario</h3>
        <p className="brief-pillar">{PILLAR_WORDS[scenario.pillar]}</p>
        <p>{scenario.summary}</p>
        {watch.length > 0 && (
          <>
            <h4>What to watch</h4>
            <ul>{watch.map((s) => <li key={s.id}>{s.narration}</li>)}</ul>
          </>
        )}
      </section>

      <section className={`brief-card needs ${scenario.available ? "ready" : "blocked"}`} aria-labelledby="brief-needs">
        <h3 id="brief-needs">What you need</h3>
        <ul className="needs-list">
          <li className={scenario.available ? "ok" : "missing"}>
            <span aria-hidden="true">{scenario.available ? "✓" : "✕"}</span>
            The <code>{scenario.stack}</code> stack is {scenario.available ? "running" : "not running"}
          </li>
          {scenario.missing.map((c) => (
            <li key={c} className="missing"><span aria-hidden="true">✕</span> <code>{c}</code> is not up</li>
          ))}
        </ul>
        {!scenario.available && (
          <>
            <p className="dim">Start it, then reload this page:</p>
            <pre className="cmd">make up PROFILES="{scenario.stack}"</pre>
            <p className="dim">Without make:</p>
            <pre className="cmd">docker compose --profile {scenario.stack} up -d</pre>
          </>
        )}
        <p className="dim">{scenario.steps.length} steps. One run per stack at a time.</p>
      </section>

      {(numbers.length > 0 || notes.length > 0) && (
        <section className="brief-card numbers" aria-labelledby="brief-numbers">
          <h3 id="brief-numbers">Reference numbers</h3>
          {numbers.length > 0 && (
            <table>
              <tbody>
                {numbers.map(([k, v]) => (
                  <tr key={k}><th scope="row">{label(k)}</th><td>{value(v)}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {notes.map(([k, v]) => <p key={k} className="dim note"><strong>{label(k)}:</strong> {value(v)}</p>)}
        </section>
      )}
    </div>
  );
}
