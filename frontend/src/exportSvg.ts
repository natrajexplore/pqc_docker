/**
 * Turn the live ladder <svg> into a standalone SVG file for slides and posts.
 *
 * The ladder is styled by CSS classes, which a pasted SVG would lose. We render a
 * copy off-screen with the LIGHT theme's tokens set on its container, read each
 * element's computed style, and write it back as presentation attributes - so the
 * export looks right on a white slide even when the UI is in dark mode.
 */

// Light-theme values of the tokens the ladder uses (keep in sync with :root in styles.css).
const LIGHT_TOKENS: Record<string, string> = {
  "--paper": "#e8ecf1",
  "--panel": "#ffffff",
  "--ink": "#16213a",
  "--ink-2": "#4a5670",
  "--rule": "#c9d1dc",
  "--pq": "#2b7a5e",
  "--classical": "#a86a12",
  "--downgrade": "#b33a2e",
  "--data": "#55598f",
};

const PROPS = [
  "fill", "stroke", "stroke-width", "stroke-dasharray", "stroke-linecap",
  "font-family", "font-size", "font-weight", "opacity",
] as const;

export function ladderSvgMarkup(svg: SVGSVGElement, title: string): string {
  const host = document.createElement("div");
  host.setAttribute("aria-hidden", "true");
  host.style.cssText = "position:fixed;left:-10000px;top:0;width:640px;color-scheme:light;";
  for (const [k, v] of Object.entries(LIGHT_TOKENS)) host.style.setProperty(k, v);
  const copy = svg.cloneNode(true) as SVGSVGElement;
  host.appendChild(copy);
  document.body.appendChild(host);
  try {
    // transparent hit areas (and the selection highlight drawn on them) are UI only
    copy.querySelectorAll(".hit").forEach((el) => el.remove());
    for (const el of [copy, ...Array.from(copy.querySelectorAll<SVGElement>("*"))]) {
      const cs = getComputedStyle(el);
      for (const p of PROPS) {
        const v = cs.getPropertyValue(p);
        if (v && v !== "none" && !(p === "opacity" && v === "1")) el.setAttribute(p, v);
        else if (v === "none" && (p === "fill" || p === "stroke")) el.setAttribute(p, "none");
      }
      for (const a of ["class", "tabindex", "role", "aria-label"]) el.removeAttribute(a);
    }
    const vb = copy.viewBox.baseVal;
    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("width", String(vb.width));
    bg.setAttribute("height", String(vb.height));
    bg.setAttribute("fill", LIGHT_TOKENS["--panel"]);
    copy.insertBefore(bg, copy.firstChild);
    const t = document.createElementNS("http://www.w3.org/2000/svg", "title");
    t.textContent = title;
    copy.insertBefore(t, copy.firstChild);
    copy.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    copy.setAttribute("width", String(vb.width));
    copy.setAttribute("height", String(vb.height));
    copy.removeAttribute("style");
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(copy);
  } finally {
    host.remove();
  }
}

export async function copySvg(markup: string): Promise<void> {
  await navigator.clipboard.writeText(markup);
}

export function downloadSvg(markup: string, fileName: string): void {
  const url = URL.createObjectURL(new Blob([markup], { type: "image/svg+xml" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
