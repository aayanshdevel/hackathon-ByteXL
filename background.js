import { detect } from "./detector.js";

"use strict";

const BACKEND_URL = "http://127.0.0.1:3000/api/v1/check";
const RANK = { clean: 0, unknown: 1, warning: 2, threat: 3 };
const lastScan = new Map();

const LEGACY_BAD = ["evil-test.com"];
const LEGACY_BRANDS = ["paypal.com", "bytexl.ai"];

function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    d[i][0] = i;
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return d[a.length][b.length];
}

// Preserve the original demo-domain and simple brand look-alike checks.
function checkLegacy(url) {
  let hostname;
  try {
    hostname = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return { verdict: "unknown", category: null, reasons: ["Invalid URL"] };
  }

  if (LEGACY_BAD.some(domain => hostname === domain || hostname.endsWith("." + domain))) {
    return {
      verdict: "threat",
      category: "known_threat",
      reasons: ["Matches the local DRP Guard demo threat list"]
    };
  }

  const candidate = hostname.split(".").slice(-2).join(".");
  for (const brand of LEGACY_BRANDS) {
    if (hostname === brand || hostname.endsWith("." + brand)) continue;
    const distance = editDistance(candidate, brand);
    if (distance > 0 && distance <= 2) {
      return {
        verdict: "threat",
        category: "fake_brand_page",
        reasons: [`${candidate} resembles the protected brand domain ${brand}`]
      };
    }
  }

  return { verdict: "clean", category: null, reasons: [] };
}

async function checkBackend(url) {
  let timer;
  try {
    const parsed = new URL(url);
    const controller = new AbortController();
    timer = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // The local database checks hostnames; avoid sending query-string tokens.
      body: JSON.stringify({ url: parsed.origin + parsed.pathname }),
      signal: controller.signal
    });

    if (!response.ok) throw new Error(`API returned ${response.status}`);
    const data = await response.json();

    if (data.status === "malicious") {
      return {
        verdict: "threat",
        category: data.type || "known_threat",
        reasons: [data.reason || "Listed in the local threat database"]
      };
    }
    if (data.status === "clean") {
      return { verdict: "clean", category: null, reasons: [] };
    }
    if (data.status === "unknown") {
      return {
        verdict: "unknown",
        category: null,
        reasons: [data.reason || "No matching threat record found"]
      };
    }
    return {
      verdict: "unknown",
      category: null,
      reasons: ["Unrecognized response from the threat service"]
    };
  } catch (error) {
    console.warn("DRP backend could not verify URL:", error.message);
    return {
      verdict: "unknown",
      category: null,
      reasons: ["Threat service unavailable or unable to verify"]
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function mergeResults(...results) {
  const valid = results.filter(Boolean);
  if (!valid.length) {
    return { verdict: "unknown", category: null, reasons: ["No result available"] };
  }

  const topRank = Math.max(...valid.map(result => RANK[result.verdict] ?? 1));
  const top = valid.filter(result => (RANK[result.verdict] ?? 1) === topRank);
  const primary = top.find(result => result.category) || top[0];

  return {
    verdict: primary.verdict,
    category: primary.category || null,
    reasons: [...new Set(top.flatMap(result => result.reasons || []))].slice(0, 4)
  };
}

// Runs in the page context to obtain text that can help identify copied names.
function getPageInfo() {
  const meta = name =>
    document.querySelector(`meta[property="${name}"]`)?.content || "";
  return {
    title: document.title || "",
    ogTitle: meta("og:title"),
    siteName: meta("og:site_name")
  };
}

function showBanner(text, level) {
  const previous = document.getElementById("drp-guard-banner");
  if (previous) previous.remove();

  const banner = document.createElement("div");
  banner.id = "drp-guard-banner";
  banner.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
    "display:flex;gap:12px;align-items:center;justify-content:center;" +
    "padding:10px 14px;color:#fff;font:bold 15px sans-serif;" +
    "background:" + (level === "threat" ? "#c62828" : "#ef6c00") + ";";

  const message = document.createElement("span");
  message.textContent = text;
  const dismiss = document.createElement("button");
  dismiss.textContent = "Dismiss";
  dismiss.style.cssText =
    "cursor:pointer;border:1px solid #fff;background:transparent;" +
    "color:#fff;padding:2px 8px;border-radius:3px;";
  dismiss.addEventListener("click", () => banner.remove());
  banner.append(message, dismiss);
  document.documentElement.appendChild(banner);
}

async function scan(tabId, url) {
  if (!/^https?:\/\//i.test(url)) return;

  const now = Date.now();
  const previous = lastScan.get(tabId);
  if (previous && previous.url === url && now - previous.time < 3000) return;
  lastScan.set(tabId, { url, time: now });

  // Give SPAs a moment to update title and social-page metadata.
  await new Promise(resolve => setTimeout(resolve, 800));

  let pageInfo = {};
  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      func: getPageInfo
    });
    pageInfo = injection?.result || {};
  } catch {
    // Restricted pages still receive URL-only analysis where possible.
  }

  let localResult;
  try {
    localResult = detect(url, pageInfo);
  } catch (error) {
    localResult = {
      verdict: "unknown",
      category: null,
      reasons: ["Local detector failed"]
    };
    console.error("Local detector error:", error);
  }

  const legacyResult = checkLegacy(url);
  const remoteResult = await checkBackend(url);

  // A threat/warning from any detector takes priority. Unknown backend results
  // never get silently converted into a verified-clean verdict.
  const result = mergeResults(localResult, legacyResult, remoteResult);

  const currentTab = await chrome.tabs.get(tabId).catch(() => null);
  if (!currentTab || currentTab.url !== url) return;

  await chrome.storage.local.set({
    ["threat_" + tabId]: {
      ...result,
      url,
      checkedAt: new Date().toISOString()
    }
  });

  const flagged = result.verdict === "threat" || result.verdict === "warning";
  await chrome.action.setBadgeText({ tabId, text: flagged ? "!" : "" });
  await chrome.action.setBadgeBackgroundColor({
    tabId,
    color: result.verdict === "threat" ? "#c62828" :
      result.verdict === "warning" ? "#ef6c00" : "#757575"
  });

  if (flagged) {
    const label = result.verdict === "threat" ? "Potential threat or impersonation" : "Suspicious look-alike";
    const reason = result.reasons?.[0] || "Review this page before entering information.";
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        func: showBanner,
        args: [`⚠ DRP Guard: ${label}. ${reason} Do not enter sensitive data.`, result.verdict]
      });
    } catch (error) {
      console.warn("Could not display DRP Guard warning:", error.message);
    }
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (!tab.url || !/^https?:\/\//i.test(tab.url)) return;
  if (info.status === "complete" || info.url) {
    scan(tabId, tab.url).catch(error => console.error("Scan failed:", error));
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.local.remove("threat_" + tabId);
  lastScan.delete(tabId);
});
