import type { Packet, Protocol } from "./types";

export const PROTOCOL_NAMES: Record<Protocol, string> = {
  ipsec: "IPsec / IKEv2",
  tls: "TLS 1.3",
  ssh: "SSH",
  macsec: "MACsec / 802.1X",
  mixed: "Imported capture",
};

export const LANES: Record<Protocol, [string, string]> = {
  ipsec: ["Initiator", "Responder"],
  tls: ["Client", "Server"],
  ssh: ["Client", "Server"],
  macsec: ["Supplicant", "Authenticator"],
  mixed: ["Left", "Right"],
};

export function bytes(n: number | null | undefined): string {
  if (n == null) return "–";
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(n < 10240 ? 2 : 1)} KB`;
}

export function ms(n: number | null | undefined): string {
  if (n == null) return "–";
  return n < 1 ? `${(n * 1000).toFixed(0)} µs` : n < 1000 ? `${n.toFixed(1)} ms` : `${(n / 1000).toFixed(2)} s`;
}

/** Visual weight class for a packet: what colour its arrow and row get. */
export function tone(p: Packet): "pq" | "classical" | "downgrade" | "data" | "neutral" {
  if (p.tags.includes("downgrade")) return "downgrade";
  if (p.tags.includes("pq-kex") || p.tags.includes("pq-kex-offer") || p.tags.includes("pq-auth-offer")) return "pq";
  if (p.tags.includes("classical-kex")) return "classical";
  if (p.kind === "data") return "data";
  return "neutral";
}

export const STATUS_WORDS: Record<string, string> = {
  "pq-hybrid": "Post-quantum (hybrid)",
  "pq-ppk": "Post-quantum (PPK)",
  pq: "Post-quantum",
  classical: "Classical",
  downgraded: "Downgraded to classical",
  refused: "Downgrade refused",
  unknown: "Not determined",
};

export const EVIDENCE_WORDS: Record<string, string> = {
  wire: "seen on the wire",
  endpoint: "reported by the endpoint",
  declared: "configured, not observed",
};
