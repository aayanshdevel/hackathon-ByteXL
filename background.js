
"use strict";

// ---- CONFIG ----
const DRP_API = "http://127.0.0.1:3000/api/v1/check";

const BRANDS = ["bytexl.ai", "paypal.com"];
const TEST_BAD = ["evil-test.com"];

// ---- EDIT DISTANCE ----
function dist(a, b) {
  const d = Array.from(
    { length: a.length + 1 },
    (_, i) => [i]
  );

  for (let j = 1; j <= b.length; j++) {
    d[0][j] = j;
  }

  for (let i = 1; i <= a.length; i++) {
    d[i][0] = i;

    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] +
          (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }

  return d[a.length][b.length];
}

// ---- LOCAL THREAT CHECK ----
function localCheck(url) {
  let hostname;

  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return "unknown";
  }

  // Exact hostname match for demonstration threats
  if (TEST_BAD.includes(hostname)) {
    return "threat";
  }

  // Basic brand look-alike detection
  for (const brand of BRANDS) {
    if (hostname === brand || hostname.endsWith("." + brand)) {
      continue;
    }

    if (dist(hostname, brand) > 0 && dist(hostname, brand) <= 2) {
      return "threat";
    }
  }

  return "clean";
}

// ---- DRP BACKEND CHECK ----
async function checkUrl(url) {
  try {
    const response = await fetch(DRP_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(5000)
    });

    if (!response.ok) {
      throw new Error(`DRP API returned ${response.status}`);
    }

    const data = await response.json();

    // Match the response schema from your Node.js backend
    if (data.status === "malicious") {
      return "threat";
    }

    if (data.status === "clean") {
      return "clean";
    }

    // Unknown does not mean safe
    return "unknown";
  } catch (error) {
    console.error("DRP API error:", error);

    // Preserve known local detections if backend is unavailable
    const fallback = localCheck(url);

    return fallback === "threat" ? "threat" : "unknown";
  }
}

// ---- WARNING BANNER ----
function showBanner() {
  if (!document.documentElement) return;

  if (document.getElementById("drp-guard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "drp-guard-banner";

  banner.textContent =
    "⚠ DRP GUARD: This site matches a known threat. Do not enter credentials.";

  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    background: #b91c1c;
    color: #ffffff;
    padding: 16px;
    text-align: center;
    font: bold 16px Arial, sans-serif;
    box-shadow: 0 3px 12px #0005;
  `;

  document.documentElement.appendChild(banner);
}

// ---- NAVIGATION MONITOR ----
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (
    info.status !== "complete" ||
    !tab.url ||
    !/^https?:\/\//i.test(tab.url)
  ) {
    return;
  }

  const url = tab.url;
  const result = await checkUrl(url);

  // Ignore results if the tab navigated elsewhere during the scan
  const currentTab = await chrome.tabs.get(tabId).catch(() => null);

  if (!currentTab || currentTab.url !== url) {
    return;
  }

  await chrome.storage.local.set({
    ["threat_" + tabId]: {
      status: result,
      url,
      checkedAt: new Date().toISOString()
    }
  });

  if (result === "threat") {
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        func: showBanner
      });
    } catch (error) {
      console.warn(
        "Could not inject warning:",
        error.message
      );
    }
  }
});

// ---- CLEAN UP CLOSED TABS ----
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove("threat_" + tabId);
});
