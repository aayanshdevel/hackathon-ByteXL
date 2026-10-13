const LABEL = {
  known_threat: "Known threat",
  fake_brand_page: "Fake brand website",
  fake_company_page: "Fake company page",
  fake_social_profile: "Fake social profile",
  scam_account: "Scam account using company identity",
  fake_app: "Fake mobile app"
};

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

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;   // textContent: no HTML injection
  return e;
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // 1. Threat status (saved by background.js)
  const key = "threat_" + tab.id;
  const stored = await chrome.storage.local.get(key);
  let r = stored[key] || { verdict: "unknown", category: null, reasons: [] };
  if (typeof r === "string") r = { verdict: r, category: null, reasons: [] };   // old format

  const box = document.getElementById("threat");
  box.className = r.verdict;
  const title =
    r.verdict === "threat"  ? "⚠ " + (LABEL[r.category] || "Threat") :
    r.verdict === "warning" ? "⚠ Suspicious: " + (LABEL[r.category] || "look-alike") :
    r.verdict === "clean"   ? "✔ No threat found" :
                              "? Could not verify (not proof of safe)";
  box.replaceChildren(el("b", "", title));
  if (r.reasons.length) {
    const ul = el("ul");
    r.reasons.forEach(x => ul.appendChild(el("li", "", x)));
    box.appendChild(ul);
  }

  // 2. Cookie report
  if (!tab.url || !tab.url.startsWith("http")) return;
  const cookies = await chrome.cookies.getAll({ url: tab.url });
  const results = cookies.map(analyzeCookie);

  const count = { GREEN: 0, AMBER: 0, RED: 0 };
  results.forEach(x => count[x.status]++);
  document.getElementById("summary").textContent =
    `Cookies: 🟢 ${count.GREEN}   🟠 ${count.AMBER}   🔴 ${count.RED}`;

  const order = { RED: 0, AMBER: 1, GREEN: 2 };
  results.sort((a, b) => order[a.status] - order[b.status]);
  const list = document.getElementById("cookies");
  for (const x of results) {
    const row = el("div", "row " + x.status);
    row.append(el("b", "", x.name), " ", el("small", "", x.domain), el("br"),
               el("small", "", x.issues.join(", ") || "OK"));
    list.appendChild(row);
  }
})();
