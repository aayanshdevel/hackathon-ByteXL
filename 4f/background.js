import { detect } from "./detector.js";

// ---- CONFIG ----
// Your Express endpoint. Adjust path + response shape to match your server.
const BACKEND_URL = "http://localhost:3000/api/check";   // assumed: POST {url} -> {malicious: bool}

const RANK = { clean: 0, unknown: 1, warning: 2, threat: 3 };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const lastScan = new Map();   // tabId -> { url, t }

// Ask backend. Send host + path only (no query string = no leaked tokens).
async function checkBackend(url) {
  try {
    const u = new URL(url);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2000);
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: u.origin + u.pathname }),
      signal: ctrl.signal
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error("API " + res.status);
    const data = await res.json();
    return data.malicious
      ? { verdict: "threat", category: "known_threat", reasons: ["Listed in threat database"] }
      : { verdict: "clean", category: null, reasons: [] };
  } catch {
    // Service down != safe
    return { verdict: "unknown", category: null, reasons: ["Threat service not reachable"] };
  }
}

// Take the worse result. Keep reasons only from results at that level.
function merge(a, b) {
  const top = RANK[b.verdict] > RANK[a.verdict] ? b : a;
  const reasons = [...new Set([a, b].filter(r => RANK[r.verdict] === RANK[top.verdict]).flatMap(r => r.reasons))];
  return { verdict: top.verdict, category: top.category, reasons };
}

// Runs inside the page: read titles for display-name checks.
function getPageInfo() {
  const meta = n => document.querySelector(`meta[property="${n}"]`)?.content || "";
  return { title: document.title || "", ogTitle: meta("og:title"), siteName: meta("og:site_name") };
}

// Runs inside the page: warning banner with Dismiss button.
function showBanner(text, level) {
  const old = document.getElementById("drp-guard-banner");
  if (old) old.remove();
  const b = document.createElement("div");
  b.id = "drp-guard-banner";
  b.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;gap:12px;" +
    "align-items:center;justify-content:center;padding:10px 14px;color:#fff;" +
    "font:bold 15px sans-serif;background:" + (level === "threat" ? "#c62828" : "#ef6c00") + ";";
  const msg = document.createElement("span");
  msg.textContent = text;
  const btn = document.createElement("button");
  btn.textContent = "Dismiss";
  btn.style.cssText = "cursor:pointer;border:1px solid #fff;background:transparent;color:#fff;padding:2px 8px;border-radius:3px;";
  btn.onclick = () => b.remove();
  b.append(msg, btn);
  document.documentElement.appendChild(b);
}

async function scan(tabId, url) {
  const now = Date.now(), last = lastScan.get(tabId);
  if (last && last.url === url && now - last.t < 3000) return;   // skip duplicate events
  lastScan.set(tabId, { url, t: now });

  await sleep(800);   // SPA sites (LinkedIn, X) update title after URL change

  let info = {};
  try {
    const [r] = await chrome.scripting.executeScript({ target: { tabId }, func: getPageInfo });
    info = r?.result || {};
  } catch { /* restricted page: use URL only */ }

  const local = detect(url, info);
  const remote = await checkBackend(url);
  const result = merge(local, remote);

  await chrome.storage.local.set({ ["threat_" + tabId]: result });

  const bad = result.verdict === "threat" || result.verdict === "warning";
  chrome.action.setBadgeText({ tabId, text: bad ? "!" : "" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: result.verdict === "threat" ? "#c62828" : "#ef6c00" });

  if (bad) {
    const text = (result.verdict === "threat" ? "⚠ DRP Guard: Likely impersonation or threat. " : "⚠ DRP Guard: Suspicious look-alike. ")
      + (result.reasons[0] || "") + " Do not enter data.";
    chrome.scripting.executeScript({ target: { tabId }, func: showBanner, args: [text, result.verdict] }).catch(() => {});
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (!tab.url || !tab.url.startsWith("http")) return;
  if (info.status === "complete" || info.url) scan(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.local.remove("threat_" + tabId);
  lastScan.delete(tabId);
});
