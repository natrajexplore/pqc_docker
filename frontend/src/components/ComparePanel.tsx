import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { CompareResult, RunSummary } from "../types";
import { STATUS_WORDS, bytes, ms } from "../format";

const ROWS: { key: keyof NonNullable<CompareResult["a"]["metrics"]>; label: string; fmt: (n: number) => string }[] = [
  { key: "handshake_bytes", label: "Handshake bytes", fmt: bytes },
  { key: "handshake_frames", label: "Handshake frames", fmt: String },
  { key: "flights", label: "Flights (direction changes)", fmt: String },
  { key: "fragments", label: "Fragments", fmt: String },
  { key: "largest_frame", label: "Largest frame", fmt: bytes },
  { key: "handshake_duration_ms", label: "Handshake duration", fmt: ms },
];

export function ComparePanel({ runs, initialA }: { runs: RunSummary[]; initialA: string | null }) {
  const done = useMemo(() => runs.filter((r) => r.metrics), [runs]);
  const [a, setA] = useState<string>(initialA ?? done[1]?.run_id ?? "");
  const [b, setB] = useState<string>(done[0]?.run_id ?? "");
  const [res, setRes] = useState<CompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!a || !b || a === b) { setRes(null); return; }
    api.compare(a, b).then((r) => { setRes(r); setError(null); }).catch((e: Error) => setError(e.message));
  }, [a, b]);

  const label = (r: RunSummary) => `${r.scenario_title} (${new Date(r.created_at * 1000).toLocaleTimeString()})`;

  if (done.length < 2) {
    return <p className="empty">Run two scenarios from the same group, for example the classical and hybrid IKEv2 runs, then compare them here.</p>;
  }

  return (
    <div className="compare">
      <div className="compare-pick">
        <label>Baseline
          <select value={a} onChange={(e) => setA(e.target.value)}>
            {done.map((r) => <option key={r.run_id} value={r.run_id}>{label(r)}</option>)}
          </select>
        </label>
        <label>Compared run
          <select value={b} onChange={(e) => setB(e.target.value)}>
            {done.map((r) => <option key={r.run_id} value={r.run_id}>{label(r)}</option>)}
          </select>
        </label>
      </div>
      {error && <p className="error">{error}</p>}
      {res?.a.metrics && res.b.metrics && (
        <>
          <p className="compare-headline">
            {res.bytes_ratio != null && `The compared run used ${res.bytes_ratio}× the handshake bytes of the baseline.`}
          </p>
          <table className="compare-table">
            <thead>
              <tr><th scope="col" /><th scope="col">Baseline</th><th scope="col">Compared</th><th scope="col" className="bars-col">Relative size <span className="legend"><span className="bar a" /> baseline <span className="bar b" /> compared</span></th></tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row">Key exchange</th>
                <td>{STATUS_WORDS[res.a.verdict?.key_exchange.status ?? "unknown"]}</td>
                <td>{STATUS_WORDS[res.b.verdict?.key_exchange.status ?? "unknown"]}</td>
                <td />
              </tr>
              <tr>
                <th scope="row">Authentication</th>
                <td>{STATUS_WORDS[res.a.verdict?.authentication.status ?? "unknown"]}</td>
                <td>{STATUS_WORDS[res.b.verdict?.authentication.status ?? "unknown"]}</td>
                <td />
              </tr>
              {ROWS.map(({ key, label, fmt }) => {
                const va = Number(res.a.metrics![key]) || 0;
                const vb = Number(res.b.metrics![key]) || 0;
                const max = Math.max(va, vb, 1);
                return (
                  <tr key={key}>
                    <th scope="row">{label}</th>
                    <td className="num">{fmt(va)}</td>
                    <td className="num">{fmt(vb)}</td>
                    <td className="bars">
                      <span className="bar a" style={{ width: `${(va / max) * 100}%` }} />
                      <span className="bar b" style={{ width: `${(vb / max) * 100}%` }} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
