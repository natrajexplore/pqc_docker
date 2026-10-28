import type { Protocol, ScenarioInfo } from "../types";
import { PROTOCOL_NAMES } from "../format";

const ORDER: Protocol[] = ["ipsec", "tls", "macsec", "ssh"];
const PILLAR_WORDS = { "key-exchange": "key exchange", authentication: "authentication", both: "both pillars" };

interface Props {
  scenarios: ScenarioInfo[];
  selected: string | null;
  onSelect: (id: string) => void;
}

export function ScenarioRail({ scenarios, selected, onSelect }: Props) {
  return (
    <nav className="rail" aria-label="Scenarios">
      {ORDER.map((proto) => {
        // key-exchange groups before authentication groups, then the scenario's own order
        const rank = (s: ScenarioInfo) => (s.pillar === "key-exchange" ? 0 : 1);
        const items = scenarios.filter((s) => s.protocol === proto)
          .sort((a, b) => (a.group === b.group ? a.order - b.order : rank(a) - rank(b) || a.group.localeCompare(b.group)));
        if (!items.length) return null;
        const down = items.every((s) => !s.available);
        return (
          <section key={proto}>
            <h2>
              {PROTOCOL_NAMES[proto]}
              {down && <span className="stack-off" title={`Start it with: make up PROFILES="${items[0].stack}"`}>stack stopped</span>}
            </h2>
            <ul>
              {items.map((s) => (
                <li key={s.id}>
                  <button
                    className={`scenario ${selected === s.id ? "is-selected" : ""} ${s.available ? "" : "unavailable"}`}
                    onClick={() => onSelect(s.id)}
                    aria-current={selected === s.id}
                  >
                    <span className="sc-title">{s.title}</span>
                    <span className="sc-pillar">{PILLAR_WORDS[s.pillar]}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </nav>
  );
}
