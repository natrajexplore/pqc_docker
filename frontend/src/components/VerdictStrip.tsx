import type { Metrics, PillarVerdict, Verdict } from "../types";
import { EVIDENCE_WORDS, STATUS_WORDS, bytes, ms } from "../format";

function pillarTone(v: PillarVerdict): string {
  if (v.status === "refused") return "pq";
  if (v.status.startsWith("pq")) return "pq";
  if (v.status === "downgraded") return "downgrade";
  if (v.status === "classical") return "classical";
  return "neutral";
}

function Pillar({ name, why, v }: { name: string; why: string; v: PillarVerdict | undefined }) {
  if (!v) {
    return (
      <section className="pillar neutral">
        <h3>{name}</h3>
        <p className="pillar-status idle">Waiting for a run</p>
        <p className="pillar-why">{why}</p>
      </section>
    );
  }
  const verdict = v;
  return (
    <section className={`pillar ${pillarTone(verdict)}`}>
      <h3>{name}</h3>
      <p className="pillar-status">{STATUS_WORDS[verdict.status] ?? verdict.status}</p>
      {verdict.algorithm && <p className="pillar-alg">{verdict.algorithm}</p>}
      <p className={`evidence ev-${verdict.evidence}`}>{EVIDENCE_WORDS[verdict.evidence]}</p>
      {verdict.detail && <p className="pillar-detail">{verdict.detail}</p>}
      <p className="pillar-why">{why}</p>
    </section>
  );
}

export function VerdictStrip({ verdict, metrics }: { verdict: Verdict | null; metrics: Metrics | null }) {
  return (
    <div className="verdict">
      <Pillar
        name="Key exchange"
        why="Protects against harvest now, decrypt later. Urgent: the damage is retroactive."
        v={verdict?.key_exchange}
      />
      <Pillar
        name="Authentication"
        why="Protects against future forgery. Certificates and CAs must outlive the quantum computer."
        v={verdict?.authentication}
      />
      <dl className="cost">
        <div><dt>Handshake</dt><dd>{bytes(metrics?.handshake_bytes)}</dd></div>
        <div><dt>Frames</dt><dd>{metrics?.handshake_frames ?? "–"}</dd></div>
        <div><dt>Flights</dt><dd>{metrics?.flights ?? "–"}</dd></div>
        <div><dt>Fragments</dt><dd>{metrics?.fragments ?? "–"}</dd></div>
        <div><dt>Largest frame</dt><dd>{bytes(metrics?.largest_frame)}</dd></div>
        <div><dt>Duration</dt><dd>{ms(metrics?.handshake_duration_ms)}</dd></div>
      </dl>
    </div>
  );
}
