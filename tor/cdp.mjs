// CDP driver: navigate a Tor-proxied Chrome to a URL and watch whether the
// Cloudflare challenge clears. Node 22 has a global WebSocket.
// usage: node cdp.mjs <url> [waitSeconds]
const url = process.argv[2];
const waitSec = parseInt(process.argv[3] || "90", 10);
const PORT = process.env.CDP_PORT || "9222";

async function rpc(ws, id, method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    const onMsg = (ev) => {
      const d = JSON.parse(ev.data);
      if (d.id === id) {
        ws.removeEventListener("message", onMsg);
        d.error ? reject(new Error(JSON.stringify(d.error))) : resolve(d.result);
      }
    };
    ws.addEventListener("message", onMsg);
    ws.send(JSON.stringify(msg));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ver = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));

let id = 1;
const { targetId } = await rpc(ws, id++, "Target.createTarget", { url: "about:blank" });
const { sessionId } = await rpc(ws, id++, "Target.attachToTarget", { targetId, flatten: true });

await rpc(ws, id++, "Page.enable", {}, sessionId);
await rpc(ws, id++, "Runtime.enable", {}, sessionId);
await rpc(ws, id++, "Network.enable", {}, sessionId);

// Track main-frame responses so we can report status codes and redirects.
const responses = [];
ws.addEventListener("message", (ev) => {
  const d = JSON.parse(ev.data);
  if (d.method === "Network.responseReceived") {
    const r = d.params.response;
    if (r.type === "Document") responses.push({ url: r.url, status: r.status, cf: r.headers["cf-mitigated"] || "" });
  }
});

await rpc(ws, id++, "Page.navigate", { url }, sessionId);

const started = Date.now();
let last = null;
let settled = false;

while ((Date.now() - started) / 1000 < waitSec) {
  await sleep(3000);
  let title = "", href = "", text = "";
  try {
    const r = await rpc(ws, id++, "Runtime.evaluate", {
      expression: `JSON.stringify({t:document.title,u:location.href,n:document.body?document.body.innerText.replace(/\\s+/g,' ').slice(0,220):''})`,
      returnByValue: true,
    }, sessionId);
    ({ t: title, u: href, n: text } = JSON.parse(r.result.value));
  } catch (e) {
    continue;
  }
  const el = ((Date.now() - started) / 1000).toFixed(0);
  const sig = title + "|" + href;
  if (sig !== last) {
    console.log(`[${el}s] title=${JSON.stringify(title)} url=${href}`);
    last = sig;
  }
  const challenged = /just a moment|security challenge|attention required|verifying|checking your browser/i.test(title);
  if (!challenged && href.includes("fastpeoplesearch") && title.trim()) {
    console.log(`[${el}s] SOLVED -> ${JSON.stringify(title)}`);
    console.log(`[${el}s] text: ${text}`);
    settled = true;
    break;
  }
}

console.log("--- document responses ---");
for (const r of responses) console.log(`  ${r.status} cf=${r.cf || "-"} ${r.url.slice(0, 110)}`);

if (!settled) {
  console.log("--- NOT SOLVED within wait; final body excerpt ---");
  try {
    const r = await rpc(ws, id++, "Runtime.evaluate", {
      expression: "document.body?document.body.innerText.replace(/\\s+/g,' ').slice(0,400):''",
      returnByValue: true,
    }, sessionId);
    console.log(r.result.value);
  } catch (e) { console.log("eval failed", e.message); }
}

// Cookies prove the cf_clearance state.
try {
  const c = await rpc(ws, id++, "Network.getAllCookies", {}, sessionId);
  const names = c.cookies.map((x) => `${x.name}@${x.domain}`).join(", ");
  console.log("cookies:", names || "(none)");
} catch (e) {}

ws.close();
process.exit(0);
