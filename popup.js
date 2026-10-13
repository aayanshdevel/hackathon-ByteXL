// Score one cookie -> GREEN / AMBER / RED  (never reads cookie value)
function analyzeCookie(c) {
  let score = 0;
  const issues = [];
  if (!c.secure)   { score += 30; issues.push("No Secure flag"); }
  if (!c.httpOnly) { score += 20; issues.push("No HttpOnly flag"); }
  if (c.sameSite === "no_restriction") { score += 20; issues.push("SameSite=None"); }
  if (c.expirationDate && c.expirationDate - Date.now() / 1000 > 365 * 24 * 3600) {
    score += 10; issues.push("Lives > 1 year");
  }
  const status = score >= 50 ? "RED" : score >= 20 ? "AMBER" : "GREEN";
  return { name: c.name, domain: c.domain, status, issues };
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // 1. Threat status (saved by background.js)
  const key = "threat_" + tab.id;
  const stored = await chrome.storage.local.get(key);
  const t = stored[key] || "unknown";
  const el = document.getElementById("threat");
  el.className = t;
  el.textContent =
    t === "threat" ? "⚠ Known threat site!" :
    t === "clean"  ? "✔ No threat found" :
                     "? Could not verify (not proof of safe)";

  // 2. Cookie report
  if (!tab.url.startsWith("http")) return;
  const cookies = await chrome.cookies.getAll({ url: tab.url });
  const results = cookies.map(analyzeCookie);

  const count = { GREEN: 0, AMBER: 0, RED: 0 };
  results.forEach(r => count[r.status]++);
  document.getElementById("summary").innerHTML =
    `<b>Cookies:</b> 🟢 ${count.GREEN} &nbsp; 🟠 ${count.AMBER} &nbsp; 🔴 ${count.RED}`;

  const order = { RED: 0, AMBER: 1, GREEN: 2 };
  results.sort((a, b) => order[a.status] - order[b.status]);
  document.getElementById("cookies").innerHTML = results.map(r =>
    `<div class="row ${r.status}"><b>${r.name}</b> <small>${r.domain}</small><br>
     <small>${r.issues.join(", ") || "OK"}</small></div>`
  ).join("");
})();
