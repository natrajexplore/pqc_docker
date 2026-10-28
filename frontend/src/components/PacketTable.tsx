import { useEffect, useRef } from "react";
import type { Packet } from "../types";
import { tone } from "../format";

const TAG_WORDS: Record<string, string> = {
  "pq-kex": "PQ key exchange",
  "pq-kex-offer": "PQ offered",
  "pq-auth-offer": "ML-DSA offered",
  "classical-kex": "classical",
  downgrade: "downgrade",
  fragment: "fragment",
  encrypted: "encrypted",
  ppk: "PPK",
  cleartext: "cleartext",
};

interface Props {
  packets: Packet[];
  selected: number | null;
  onSelect: (n: number) => void;
  follow: boolean;
}

export function PacketTable({ packets, selected, onSelect, follow }: Props) {
  const end = useRef<HTMLTableRowElement>(null);
  useEffect(() => {
    if (follow) end.current?.scrollIntoView({ block: "nearest" });
  }, [packets.length, follow]);

  return (
    <div className="packets" role="region" aria-label="Captured packets" tabIndex={0}>
      <table>
        <thead>
          <tr>
            <th scope="col">#</th>
            <th scope="col">ms</th>
            <th scope="col" aria-label="Direction" />
            <th scope="col">Protocol</th>
            <th scope="col" className="num">Bytes</th>
            <th scope="col">What happened</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((p) => (
            <tr
              key={p.n}
              className={`${tone(p)} ${selected === p.n ? "is-selected" : ""}`}
              onClick={() => onSelect(p.n)}
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && onSelect(p.n)}
            >
              <td className="num dim">{p.n}</td>
              <td className="num dim">{p.rel_ms.toFixed(1)}</td>
              <td className="dir">{p.direction === "l2r" ? "→" : p.direction === "r2l" ? "←" : "·"}</td>
              <td>{p.proto}</td>
              <td className="num mono">{p.length}</td>
              <td>
                <span className="lbl">{p.label}</span>
                {p.tags.filter((t) => TAG_WORDS[t]).map((t) => (
                  <span key={t} className={`tag tag-${t}`}>{TAG_WORDS[t]}</span>
                ))}
              </td>
            </tr>
          ))}
          <tr ref={end} aria-hidden="true" className="sentinel"><td colSpan={6} /></tr>
        </tbody>
      </table>
    </div>
  );
}
