import { useEffect, useMemo, useRef, useState } from "react";
import { copySvg, downloadSvg, ladderSvgMarkup } from "../exportSvg";
import type { Packet, Protocol } from "../types";
import { LANES, bytes, tone } from "../format";

/**
 * The handshake as a sequence diagram where every arrow's stroke width is
 * proportional to the square root of its frame size. Classical exchanges read
 * as hairlines; ML-KEM and ML-DSA messages visibly thicken; fragments are dashed.
 * Runs of data-plane packets collapse into one row so the handshake stays readable.
 */

type Row =
  | { type: "packet"; p: Packet }
  | { type: "data"; first: Packet; count: number; proto: string; total: number; dirs: Set<string> };

const W = 640;
const LEFT_X = 118;
const RIGHT_X = 560;
const ROW_H = 34;
const TOP = 56;

function weight(len: number): number {
  return Math.max(1.25, Math.min(14, Math.sqrt(len) / 3.6));
}

function collapse(packets: Packet[], hideControl: boolean): Row[] {
  const rows: Row[] = [];
  for (const p of packets) {
    if (p.kind === "other" || p.proto === "ARP") continue;
    if (hideControl && p.kind === "control") continue;
    const last = rows[rows.length - 1];
    if (p.kind === "data" && last?.type === "data" && last.proto === p.proto) {
      last.count += 1;
      last.total += p.length;
      last.dirs.add(p.direction);
      continue;
    }
    if (p.kind === "data") rows.push({ type: "data", first: p, count: 1, proto: p.proto, total: p.length, dirs: new Set([p.direction]) });
    else rows.push({ type: "packet", p });
  }
  return rows;
}

interface Props {
  packets: Packet[];
  protocol: Protocol;
  selected: number | null;
  onSelect: (n: number) => void;
  live: boolean;
  /** title + file name stem for the SVG export, e.g. the scenario id */
  exportName: string;
  /** presenter mode: drop TCP SYN/ACK/FIN-style control rows so the handshake fits one screen */
  hideControl?: boolean;
}

export function Ladder({ packets, protocol, selected, onSelect, live, exportName, hideControl = false }: Props) {
  const rows = useMemo(() => collapse(packets, hideControl), [packets, hideControl]);
  const svgRef = useRef<SVGSVGElement>(null);
  const [exported, setExported] = useState("");
  const canExport = rows.length > 0 && !live;
  useEffect(() => setExported(""), [exportName]);

  const exportAs = async (how: "copy" | "download") => {
    if (!svgRef.current) return;
    const markup = ladderSvgMarkup(svgRef.current, exportName);
    try {
      if (how === "copy") {
        await copySvg(markup);
        setExported("SVG copied. Paste it into Figma, Inkscape or a slide tool that accepts SVG.");
      } else {
        downloadSvg(markup, `${exportName}-ladder.svg`);
        setExported("SVG downloaded.");
      }
    } catch {
      setExported("The browser blocked clipboard access. Use Download SVG instead.");
    }
  };
  const [leftName, rightName] = LANES[protocol] ?? LANES.mixed;
  const height = TOP + Math.max(rows.length, 3) * ROW_H + 28;

  return (
    <figure className="ladder" aria-label="Handshake sequence diagram">
      <svg ref={svgRef} viewBox={`0 0 ${W} ${height}`} role="img" preserveAspectRatio="xMidYMin meet">
        <text x={LEFT_X} y={22} className="lane-name" textAnchor="middle">{leftName}</text>
        <text x={RIGHT_X} y={22} className="lane-name" textAnchor="middle">{rightName}</text>
        <line x1={LEFT_X} x2={LEFT_X} y1={34} y2={height - 12} className="lane" />
        <line x1={RIGHT_X} x2={RIGHT_X} y1={34} y2={height - 12} className="lane" />

        {rows.length === 0 && (
          <text x={W / 2} y={TOP + 40} textAnchor="middle" className="ladder-empty">
            {live ? "Waiting for the first packet…" : "Run a scenario to draw its handshake here."}
          </text>
        )}

        {rows.map((row, i) => {
          const y = TOP + i * ROW_H + 12;
          if (row.type === "data") {
            const both = row.dirs.has("l2r") && row.dirs.has("r2l");
            return (
              <g key={`d${row.first.n}`} className="row data" onClick={() => onSelect(row.first.n)}>
                <text x={12} y={y + 4} className="t">{row.first.rel_ms.toFixed(1)}</text>
                {Array.from({ length: Math.min(row.count, 24) }).map((_, k) => (
                  <line key={k} x1={LEFT_X + 10 + k * 7} x2={LEFT_X + 10 + k * 7} y1={y - 6} y2={y + 6} className="tick" />
                ))}
                <text x={(LEFT_X + RIGHT_X) / 2} y={y - 10} textAnchor="middle" className="msg">
                  {row.count} {row.proto} packets{both ? " in both directions" : ""}, payload encrypted
                </text>
                <text x={RIGHT_X + 8} y={y + 4} className="b">{bytes(row.total)}</text>
              </g>
            );
          }
          const p = row.p;
          const l2r = p.direction !== "r2l";
          const x1 = l2r ? LEFT_X : RIGHT_X;
          const x2 = l2r ? RIGHT_X - 8 : LEFT_X + 8;
          const w = weight(p.length);
          const dashed = p.tags.includes("fragment");
          const t = tone(p);
          return (
            <g
              key={p.n}
              className={`row ${t} ${selected === p.n ? "is-selected" : ""}`}
              onClick={() => onSelect(p.n)}
              tabIndex={0}
              role="button"
              aria-label={`${p.label}, ${p.length} bytes`}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect(p.n)}
            >
              <rect x={0} y={y - ROW_H / 2 - 2} width={W} height={ROW_H} className="hit" />
              <text x={12} y={y + 4} className="t">{p.rel_ms.toFixed(1)}</text>
              <line x1={x1} x2={x2} y1={y} y2={y} strokeWidth={w} strokeDasharray={dashed ? `${w * 2} ${w * 1.4}` : undefined} className="arrow" />
              <polygon
                points={l2r ? `${RIGHT_X},${y} ${RIGHT_X - 10 - w},${y - 5 - w / 2} ${RIGHT_X - 10 - w},${y + 5 + w / 2}`
                            : `${LEFT_X},${y} ${LEFT_X + 10 + w},${y - 5 - w / 2} ${LEFT_X + 10 + w},${y + 5 + w / 2}`}
                className="head"
              />
              <text x={(LEFT_X + RIGHT_X) / 2} y={y - w / 2 - 6} textAnchor="middle" className="msg">
                {p.label.length > 70 ? `${p.label.slice(0, 68)}…` : p.label}
              </text>
              <text x={l2r ? RIGHT_X + 8 : LEFT_X - 8} y={y + 4} textAnchor={l2r ? "start" : "end"} className="b">
                {bytes(p.length)}
              </text>
            </g>
          );
        })}
      </svg>
      <figcaption>
        <span>
          Arrow thickness grows with frame size. Dashed arrows are fragments. Times are milliseconds from the first captured frame.
          {hideControl && " TCP control packets are hidden here; the packet table has every frame."}
        </span>
        {canExport && (
          <span className="ladder-export">
            <button className="quiet" onClick={() => exportAs("copy")}>Copy SVG</button>
            <button className="quiet" onClick={() => exportAs("download")}>Download SVG</button>
            <span role="status" className="export-msg">{exported}</span>
          </span>
        )}
      </figcaption>
    </figure>
  );
}
