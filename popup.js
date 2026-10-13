const LABEL = {
  known_threat: "Known threat",
  fake_brand_page: "Fake brand website",
  fake_company_page: "Fake company page",
  fake_social_profile: "Fake social profile",
  scam_account: "Scam account using company identity",
  fake_app: "Potentially impersonating mobile app"
};

function analyzeCookie(cookie) {
  let score = 0;
  const issues = [];

  if (!cookie.secure) {
    score += 30;
    issues.push("No Secure flag");
  }
  if (!cookie.httpOnly) {
    score += 20;
    issues.push("No HttpOnly flag");
  }
  if (cookie.sameSite === "no_restriction") {
    score += 20;
    issues.push("SameSite=None");
  }
  if (
    cookie.expirationDate &&
    cookie.expirationDate - Date.now() / 1000 > 365 * 24 * 3600
  ) {
    score += 10;
    issues.push("Lives longer than one year");
  }

  const status = score >= 50 ? "RED" : score >= 20 ? "AMBER" : "GREEN";
  return { name: cookie.name, domain: cookie.domain, status, issues };
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function normalizeStoredResult(value) {
  if (typeof value === "string") {
    return { verdict: value, category: null, reasons: [] };
  }
  if (!value || typeof value !== "object") {
    return { verdict: "unknown", category: null, reasons: [] };
  }

  // Support previous versions which stored { status, url, checkedAt }.
  const verdict = value.verdict || value.status || "unknown";
  return {
    verdict: ["threat", "warning", "clean", "unknown"].includes(verdict)
      ? verdict
      : "unknown",
    category: value.category || value.type || null,
    reasons: Array.isArray(value.reasons)
      ? value.reasons
      : value.reason
        ? [value.reason]
        : []
  };
}

(async () => {
  const threatBox = document.getElementById("threat");

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    if (!tab) {
      threatBox.className = "unknown";
      threatBox.textContent = "Unable to identify the active tab.";
      return;
    }

    const key = "threat_" + tab.id;
    const stored = await chrome.storage.local.get(key);
    const result = normalizeStoredResult(stored[key]);

    threatBox.className = result.verdict;
    const heading =
      result.verdict === "threat"
        ? "⚠ " + (LABEL[result.category] || "Potential threat")
        : result.verdict === "warning"
          ? "⚠ Suspicious: " + (LABEL[result.category] || "look-alike")
          : result.verdict === "clean"
            ? "✔ No threat indicators found"
            : "? Could not verify (not proof of safe)";

    threatBox.replaceChildren(makeElement("b", "", heading));
    if (result.reasons.length) {
      const list = makeElement("ul");
      result.reasons.forEach(reason => {
        list.appendChild(makeElement("li", "", reason));
      });
      threatBox.appendChild(list);
    }

    if (!tab.url || !/^https?:\/\//i.test(tab.url)) {
      document.getElementById("summary").textContent =
        "Cookie analysis is only available on HTTP/HTTPS pages.";
      return;
    }

    const cookies = await chrome.cookies.getAll({ url: tab.url });
    const reports = cookies.map(analyzeCookie);
    const counts = { GREEN: 0, AMBER: 0, RED: 0 };
    reports.forEach(report => counts[report.status]++);

    document.getElementById("summary").textContent =
      `Cookies: 🟢 ${counts.GREEN}   🟠 ${counts.AMBER}   🔴 ${counts.RED}`;

    const order = { RED: 0, AMBER: 1, GREEN: 2 };
    reports.sort((a, b) => order[a.status] - order[b.status]);

    const list = document.getElementById("cookies");
    list.replaceChildren();
    for (const report of reports) {
      const row = makeElement("div", "row " + report.status);
      row.append(
        makeElement("b", "", report.name),
        document.createTextNode(" "),
        makeElement("small", "", report.domain),
        makeElement("br"),
        makeElement(
          "small",
          "",
          report.issues.join(", ") ||
            "No flagged cookie attributes (heuristic check only)"
        )
      );
      list.appendChild(row);
    }

    if (reports.length === 0) {
      list.textContent = "No cookies found for this page.";
    }
  } catch (error) {
    console.error("DRP Guard popup error:", error);
    threatBox.className = "unknown";
    threatBox.textContent = "Unable to load this report. Try reopening the popup.";
  }
})();
