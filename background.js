// ---- CONFIG ----
const DEMO_MODE = true;   // true = local checks only. false = call real DRP API
const DRP_API = "https://drp.example.com/api/v1/check"; // placeholder
const DRP_KEY = "YOUR_API_KEY";                          // placeholder (move to proxy later)

// Company brand domains to protect (edit this)
const BRANDS = ["bytexl.ai", "paypal.com"];
// Known-bad test domains (demo only)
const TEST_BAD = ["evil-test.com"];

// Edit distance between two strings
function dist(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(
        d[i - 1][j] + 1, d[i][j - 1] + 1,
        d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
  return d[a.length][b.length];
}

// Local check: known-bad list + look-alike of our brands
function localCheck(url) {
  const host = new URL(url).hostname;
  const root = host.split(".").slice(-2).join(".");     // a.b.paypa1.com -> paypa1.com
  if (TEST_BAD.includes(root)) return "threat";
  for (const brand of BRANDS) {
    const dd = dist(root, brand);
    if (dd > 0 && dd <= 2) return "threat";            // paypa1.com ~ paypal.com
  }
  return "clean";
}

// Returns "threat" | "clean" | "unknown"
async function checkUrl(url) {
  if (DEMO_MODE) return localCheck(url);
  try {
    const res = await fetch(DRP_API, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + DRP_KEY },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error("API " + res.status);
    const data = await res.json();          // assumed: { malicious: true/false }
    return data.malicious ? "threat" : "clean";
  } catch (e) {
    // API down != safe
    return localCheck(url) === "threat" ? "threat" : "unknown";
  }
}

function showBanner() {
  if (document.getElementById("drp-guard-banner")) return;
  const b = document.createElement("div");
  b.id = "drp-guard-banner";
  b.textContent = "⚠ DRP Guard: This site is a known threat. Do not enter data.";
  b.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
    "background:#c62828;color:#fff;padding:12px;text-align:center;" +
    "font:bold 16px sans-serif;";
  document.body.appendChild(b);
}

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== "complete" || !tab.url || !tab.url.startsWith("http")) return;
  const result = await checkUrl(tab.url);
  await chrome.storage.local.set({ ["threat_" + tabId]: result });
  if (result === "threat") {
    chrome.scripting.executeScript({ target: { tabId }, func: showBanner });
  }
});
