// End-to-end UI test: drives the real UI of a running lab in headless Chromium.
// Run it with `make test-ui` (or scripts/ui-test.sh); it needs the mgmt and `tls` stacks up.
//
// The browser asks for http://localhost:8080 but resolves `localhost` to the frontend
// container, so requests carry Host: localhost:8080 - exactly what a user's browser sends -
// and pass the backend's Host/Origin guard without any test-only exception.
import { chromium } from "playwright";
import fs from "node:fs";

const OUT = process.env.OUT_DIR ?? "/out";
const FRONTEND_IP = process.env.FRONTEND_IP ?? "172.29.0.11";  // pinned in stacks/mgmt/compose.yaml
const URL = "http://localhost:8080/";
const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok: !!ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  - " + detail : ""}`);
};
const skip = (name, why) => console.log(`SKIP  ${name}  - ${why}`);

const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP localhost ${FRONTEND_IP}`] });
// dark OS theme on purpose: the SVG export must still come out light
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: "dark", acceptDownloads: true });
await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://localhost:8080" });
const page = await ctx.newPage();
const errors = [];
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
page.on("pageerror", (e) => errors.push(String(e)));

await page.goto(URL);
await page.locator(".rail .scenario").first().waitFor();
check("UI loads through the Host/Origin guard", true);
// fetch from inside the page: only the browser resolves localhost to the frontend container
const api = (path) => page.evaluate(async (p) => (await fetch(p)).json(), path);
const tls = (await api("/api/scenarios")).find((s) => s.id === "tls-kex-hybrid");
if (!tls?.available) {
  console.log('The tls stack is not running. Start it first: make up PROFILES="tls"');
  await browser.close();
  process.exit(2);
}

// --- select a scenario: brief cards ---
await page.getByRole("button", { name: /TLS 1\.3 hybrid key exchange/ }).click();
for (const h of ["About this scenario", "What you need", "Reference numbers"])
  check(`brief card "${h}" visible`, await page.getByRole("heading", { name: h }).isVisible());
check("What you need says the stack is running", (await page.locator(".needs").innerText()).includes("tls stack is running"));
const refText = await page.locator(".brief-card.numbers").innerText();
check("reference numbers show recorded key share", /1,216/.test(refText));
check("header no longer duplicates the summary", (await page.locator(".scenario-head .summary").count()) === 0);

// --- run it: step cards, progress, result box ---
await page.getByRole("button", { name: /^(Run scenario|Run again)$/ }).click();
await page.locator(".run-status.s-running, .run-status.s-queued, .run-status.s-analyzing").first().waitFor({ timeout: 15000 }).catch(() => {});
await page.locator(".run-status.s-completed, .run-status.s-failed").waitFor({ timeout: 90000 });
check("run completed", await page.locator(".run-status.s-completed").isVisible());
const cards = await page.locator(".step-cards > li").count();
const planned = tls.steps.length;
check("one numbered card per step", cards === planned, `${cards} cards, ${planned} planned`);
check("all step cards done", (await page.locator(".step-cards > li.st-ok").count()) === cards);
check("progress bar full", (await page.getByRole("progressbar").getAttribute("aria-valuenow")) === String(cards));
const box = await page.locator(".result-box").innerText();
check("result box reports all checks passed", /^All \d+ checks passed/.test(box), box);
await page.screenshot({ path: `${OUT}/1-run-completed-dark.png`, fullPage: true });

// --- packet detail tabs ---
await page.locator(".ladder .row[role=button]").first().click();
await page.getByRole("tab", { name: "Decoded" }).waitFor();
check("Decoded tab selected by default", (await page.getByRole("tab", { name: "Decoded" }).getAttribute("aria-selected")) === "true");
await page.getByRole("tab", { name: /^Hex/ }).click();
check("Hex tab shows the hex dump", await page.locator("pre.hex").isVisible());
check("Hex tab label shows the byte count", /Hex \(\d+ B\)/.test(await page.getByRole("tab", { name: /^Hex/ }).innerText()));

// --- SVG export (download + clipboard) ---
const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download SVG" }).click()]);
const svgPath = `${OUT}/ladder.svg`;
await dl.saveAs(svgPath);
const svg = fs.readFileSync(svgPath, "utf8");
check("download file name", /-ladder\.svg$/.test(dl.suggestedFilename()), dl.suggestedFilename());
check("SVG is standalone (xmlns, title)", svg.includes('xmlns="http://www.w3.org/2000/svg"') && svg.includes("<title>"));
check("SVG has a white background", /<rect[^>]*width="640"[^>]*fill="#ffffff"/.test(svg));
check("SVG text uses light-theme ink, not dark-mode ink", svg.includes("rgb(22, 33, 58)") && !svg.includes("rgb(228, 233, 242)"));
check("SVG keeps the post-quantum arrow colour", svg.includes("rgb(43, 122, 94)"));
check("SVG has no leftover classes or hit areas", !/class=|tabindex=/.test(svg));
const black = (svg.match(/<(text|line|polygon)[^>]*(fill|stroke)="rgb\(0, 0, 0\)"/g) || []).length;
check("no arrow, head or label exported as black", black === 0, `${black} black elements`);
await page.getByRole("button", { name: "Copy SVG" }).click();
const clip = await page.evaluate(() => navigator.clipboard.readText());
check("Copy SVG puts the same markup on the clipboard", clip === svg, `${clip.length} chars`);
check("copy confirmation shown", (await page.locator(".export-msg").innerText()).startsWith("SVG copied"));
const svgPage = await ctx.newPage();
await svgPage.setContent(`<body style="margin:0;background:#fff">${svg.replace(/^<\?xml[^>]*>/, "")}</body>`);
await svgPage.screenshot({ path: `${OUT}/2-exported-svg.png` });
await svgPage.close();

// --- presenter mode ---
await page.locator("h1").click();
await page.keyboard.press("p");
check("P turns presenter mode on", (await page.locator(".app.presenter").count()) === 1);
check("rail hidden in presenter mode", !(await page.locator(".rail").isVisible()));
check("packet table hidden in presenter mode", !(await page.locator(".packets").isVisible()));
check("procedure hidden in presenter mode", !(await page.locator(".lower").isVisible()));
check("brief hidden in presenter mode", (await page.locator(".brief").count()) === 0);
const narr = page.locator(".presenter-narration");
check("narration caption stays after the run", await narr.isVisible(), (await narr.innerText().catch(() => "")).slice(0, 80));
const lw = await page.locator(".ladder").boundingBox();
check("ladder goes wide", lw && lw.width > 1000, `${Math.round(lw?.width ?? 0)} px`);
await page.evaluate(() => document.querySelector(".main")?.scrollTo(0, 0));
const vh = page.viewportSize().height;
const lb = await page.locator(".ladder").boundingBox();
check("presenter: whole ladder fits on screen without scrolling", lb && lb.y + lb.height <= vh, `ladder bottom ${Math.round((lb?.y ?? 0) + (lb?.height ?? 0))} px of ${vh}`);
check("presenter: narration caption on screen", (await narr.boundingBox()).y < vh);
await page.screenshot({ path: `${OUT}/3-presenter.png` });
check("presenter: no TCP control rows in the ladder", !((await page.locator(".ladder svg").textContent()) ?? "").includes("len=0"));
// the longest handshake in the lab: ML-DSA-65 IKE_AUTH (21 frames), shown from run history
const mldsa = (await api("/api/runs?limit=1000")).some((r) => r.scenario_id === "ipsec-auth-mldsa65" && r.status === "completed");
await page.keyboard.press("Escape");
if (mldsa) {
  await page.getByRole("button", { name: /ML-DSA-65 certificates/ }).first().click();
  await page.locator(".ladder .row").first().waitFor();
  await page.keyboard.press("p");
  await page.evaluate(() => document.querySelector(".main")?.scrollTo(0, 0));
  const lb2 = await page.locator(".ladder").boundingBox();
  check("presenter: longest handshake (ML-DSA-65) fits on screen", lb2 && lb2.y + lb2.height <= vh, `ladder bottom ${Math.round((lb2?.y ?? 0) + (lb2?.height ?? 0))} px of ${vh}`);
  await page.screenshot({ path: `${OUT}/3b-presenter-mldsa65.png` });
} else {
  skip("presenter: longest handshake (ML-DSA-65) fits on screen", "no completed ipsec-auth-mldsa65 run in history yet");
  await page.keyboard.press("p");
}
// presenter stays on: the next check reloads and expects it remembered
await page.reload();
await page.locator(".app").waitFor();
check("presenter mode remembered after reload", (await page.locator(".app.presenter").count()) === 1);
await page.keyboard.press("Escape");
check("Esc leaves presenter mode", (await page.locator(".app.presenter").count()) === 0);
await page.getByRole("button", { name: "Presenter" }).click();
check("header button toggles presenter on", (await page.locator(".app.presenter").count()) === 1);
await page.getByRole("button", { name: "Exit presenter" }).click();
check("header button toggles presenter off", (await page.locator(".app.presenter").count()) === 0);

// --- light theme and phone width ---
const light = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: "light" });
const lp = await light.newPage();
lp.on("pageerror", (e) => errors.push(String(e)));
await lp.goto(URL);
await lp.getByRole("button", { name: /TLS 1\.3 hybrid key exchange/ }).click();
await lp.locator(".step-cards > li.st-ok").first().waitFor();
await lp.screenshot({ path: `${OUT}/4-light.png`, fullPage: true });
await lp.setViewportSize({ width: 390, height: 844 });
const overflow = await lp.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
check("no horizontal page scroll at 390 px", overflow <= 0, `overflow ${overflow}px`);
const cols = await lp.evaluate(() => getComputedStyle(document.querySelector(".brief")).gridTemplateColumns.split(" ").length);
check("phone: brief cards stack in one column", cols === 1, `${cols} columns`);
await lp.screenshot({ path: `${OUT}/5-phone.png`, fullPage: true });

check("no console errors", errors.length === 0, errors.slice(0, 3).join(" | "));
fs.writeFileSync(`${OUT}/results.json`, JSON.stringify({ results, errors }, null, 2));
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
await browser.close();
process.exit(failed ? 1 : 0);
