import { useEffect, useState } from "react";
import { api } from "../api";
import type { PacketDetail as Detail } from "../types";

function hexDump(hex: string): string {
  const clean = hex.replace(/[^0-9a-f]/gi, "");
  const lines: string[] = [];
  for (let off = 0; off < clean.length; off += 32) {
    const chunk = clean.slice(off, off + 32);
    const pairs = chunk.match(/.{1,2}/g) ?? [];
    const ascii = pairs.map((h) => {
      const c = parseInt(h, 16);
      return c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
    }).join("");
    lines.push(`${(off / 2).toString(16).padStart(4, "0")}  ${pairs.join(" ").padEnd(47)}  ${ascii}`);
  }
  return lines.join("\n");
}

function Tree({ node, depth = 0 }: { node: unknown; depth?: number }) {
  if (node === null || typeof node !== "object") return <span className="leaf">{String(node)}</span>;
  const entries = Array.isArray(node) ? node.map((v, i) => [String(i), v] as const) : Object.entries(node);
  return (
    <ul className="tree">
      {entries.map(([k, v]) =>
        v !== null && typeof v === "object" ? (
          <li key={k}>
            <details open={depth < 1}>
              <summary>{k}</summary>
              <Tree node={v} depth={depth + 1} />
            </details>
          </li>
        ) : (
          <li key={k}><span className="key">{k}</span> <Tree node={v} depth={depth + 1} /></li>
        ),
      )}
    </ul>
  );
}

interface Props {
  runId: string;
  n: number;
  canDecrypt: boolean;
  onClose: () => void;
}

export function PacketDetail({ runId, n, canDecrypt, onClose }: Props) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decrypt, setDecrypt] = useState(false);
  const [tab, setTab] = useState<"decoded" | "hex">("decoded");

  useEffect(() => {
    setDetail(null);
    setError(null);
    api.packet(runId, n, decrypt).then(setDetail).catch((e: Error) => setError(e.message));
  }, [runId, n, decrypt]);

  return (
    <section className="detail" aria-label={`Packet ${n} detail`}>
      <header>
        <h3>Packet {n}</h3>
        {canDecrypt && (
          <label className="toggle">
            <input type="checkbox" checked={decrypt} onChange={(e) => setDecrypt(e.target.checked)} />
            Decrypt with the lab TLS key log
          </label>
        )}
        <button onClick={onClose} className="quiet">Close</button>
      </header>
      {error && <p className="error">Could not dissect packet {n}: {error}</p>}
      {!detail && !error && <p className="dim">Dissecting…</p>}
      {detail && (
        <div className="detail-body">
          <div className="tab-bar" role="tablist" aria-label="Packet view">
            {(["decoded", "hex"] as const).map((t) => (
              <button key={t} role="tab" id={`pd-tab-${t}`} aria-controls="pd-panel" aria-selected={tab === t}
                      className={tab === t ? "is-current" : ""} onClick={() => setTab(t)}>
                {t === "decoded" ? "Decoded" : `Hex (${detail.hex.replace(/[^0-9a-f]/gi, "").length / 2} B)`}
              </button>
            ))}
          </div>
          <div id="pd-panel" role="tabpanel" aria-labelledby={`pd-tab-${tab}`}>
            {tab === "decoded"
              ? <div className="detail-tree"><Tree node={detail.tree} /></div>
              : <pre className="hex" aria-label="Raw bytes">{hexDump(detail.hex)}</pre>}
          </div>
        </div>
      )}
    </section>
  );
}
