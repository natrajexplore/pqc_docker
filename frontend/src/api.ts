import type { CompareResult, Packet, PacketDetail, RunSummary, ScenarioInfo } from "./types";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      const body = await r.json();
      if (body?.detail) msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new Error(msg);
  }
  return r.json() as Promise<T>;
}

export const api = {
  scenarios: () => req<ScenarioInfo[]>("/api/scenarios"),
  runs: () => req<RunSummary[]>("/api/runs"),
  run: (id: string) => req<RunSummary>(`/api/runs/${id}`),
  packets: (id: string) => req<Packet[]>(`/api/runs/${id}/packets`),
  packet: (id: string, n: number, decrypt: boolean) =>
    req<PacketDetail>(`/api/runs/${id}/packets/${n}?decrypt=${decrypt}`),
  start: (scenario_id: string) =>
    req<{ run_id: string }>("/api/runs", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ scenario_id }),
    }),
  abort: (id: string) => req<{ aborting: string }>(`/api/runs/${id}/abort`, { method: "POST" }),
  compare: (a: string, b: string) => req<CompareResult>(`/api/compare?a=${a}&b=${b}`),
  importPcap: (file: File, label: string) => {
    const fd = new FormData();
    fd.append("file", file);
    return req<{ run_id: string; packets: number }>(`/api/imports?label=${encodeURIComponent(label)}`, {
      method: "POST",
      body: fd,
    });
  },
  pcapUrl: (id: string) => `/api/runs/${id}/pcap`,
};

export function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${path}`;
}
