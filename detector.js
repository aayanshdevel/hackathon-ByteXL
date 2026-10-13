// detector.js
// Impersonation checks. Pure JS. No browser APIs, so Node can test it.
// 4 detectors: fake brand website, fake social profile / company page,
// scam account, fake mobile app. All use one look-alike name function.

// ---------- CONFIG: edit for the client ----------
export const CONFIG = {
  brands: [
    {
      names: ["bytexl"],                 // brand name, letters only
      domains: ["bytexl.ai"],            // official root domains
      social: {                          // official handles per platform
        linkedin: ["bytexl"], x: ["bytexl"], facebook: ["bytexl"],
        instagram: ["bytexl"], youtube: ["bytexl"], telegram: []
      },
      apps: { play: ["com.bytexl.app"], ios: [] }  // official package / app ids
    }
  ],
  allowDomains: []                       // other domains that are safe (partners, similar real brands)
};

// Added words flag ONLY if they are in this list. "docs", "blog", "team" do not flag.
const RISK = [
  "login", "signin", "logon", "secure", "security", "verify", "verification",
  "support", "helpdesk", "help", "official", "hr", "career", "careers", "job",
  "jobs", "recruit", "recruiter", "recruitment", "hiring", "giveaway", "reward",
  "rewards", "wallet", "refund", "billing", "payment", "payments", "claim",
  "customercare", "care", "service", "services", "update", "account", "kyc",
  "offer", "offers", "airdrop", "lottery", "bonus", "apk"
];

const HOMOGLYPHS = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
  "@": "a", "$": "s", "!": "i",
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "ѕ": "s", "і": "i", "ј": "j"
};

// ---------- name helpers ----------
const SEP = /[\s._\-]+/g;
const HAS_SEP = /[\s._-]/;

// lowercase, no accents, no separators
const strip = s =>
  String(s).normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(SEP, "");

// strip + map look-alike characters (paypa1 -> paypal, rn -> m)
const skeleton = s =>
  strip(s).split("").map(ch => HOMOGLYPHS[ch] ?? ch).join("").replace(/rn/g, "m").replace(/vv/g, "w");

const RISK_SK = [...new Set(RISK.map(skeleton))];

// Can string s be built only from risk words? ("loginsecure" yes, "earn" no)
function segmentable(s) {
  if (!s) return true;
  const ok = Array(s.length + 1).fill(false);
  ok[0] = true;
  for (let i = 1; i <= s.length; i++)
    for (const w of RISK_SK)
      if (i >= w.length && ok[i - w.length] && s.slice(i - w.length, i) === w) ok[i] = true;
  return ok[s.length];
}

// Edit distance. Counts a swap of 2 neighbor letters as 1 edit.
function dl(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const d = [];
  for (let i = 0; i <= a.length; i++) d[i] = [i];
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1])
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  return d[a.length][b.length];
}

// Compare a candidate (domain label, handle, app name) with the brand name.
// Returns null (no match) or { type, conf }. conf: "high" | "medium". type "exact" = same name.
export function nameMatch(cand, name) {
  const c = strip(cand), b = strip(name);
  if (!c || !b) return null;
  const cs = skeleton(cand), bs = skeleton(name);

  if (c === b) return HAS_SEP.test(String(cand).trim())
    ? { type: "spacing change", conf: "medium" }          // byte-xl, byte.xl, "byte xl"
    : { type: "exact" };
  if (cs === bs) return { type: "look-alike characters", conf: "high" };   // bytex1, bytexI

  if (bs.length >= 4) {                                  // added words (risk words only)
    const i = cs.indexOf(bs);
    if (i >= 0 && segmentable(cs.slice(0, i)) && segmentable(cs.slice(i + bs.length)))
      return { type: "added word", conf: "high" };       // bytexl-login, secure-bytexl
  }

  const maxD = bs.length >= 10 ? 2 : bs.length >= 6 ? 1 : 0;   // short names: no fuzzy match
  if (maxD) {
    const d = dl(cs, bs);
    if (d > 0 && d <= maxD)
      return { type: "character swap", conf: d === 1 && bs.length >= 8 ? "high" : "medium" };  // bytxel
  }
  return null;
}

// ---------- URL helpers ----------
const SECOND_LEVEL = ["co", "com", "org", "net", "gov", "ac", "edu"];
function rootDomain(host) {
  const p = host.split(".");
  if (p.length <= 2) return host;
  if (p[p.length - 1].length === 2 && SECOND_LEVEL.includes(p[p.length - 2])) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}
const cleanHost = u => u.hostname.toLowerCase().replace(/^www\./, "");
const firstSegment = t =>
  String(t || "").replace(/^\(\d+\)\s*/, "").split(/\s[|•–—-]\s/)[0].trim();
const lower = a => (a || []).map(x => x.toLowerCase());

// ---------- Detector 1: fake brand website ----------
function checkDomain(u, brand, cfg) {
  const host = cleanHost(u), root = rootDomain(host);
  if (brand.domains.includes(root) || (cfg.allowDomains || []).includes(root)) return [];
  const out = [], cat = "fake_brand_page";

  for (const d of brand.domains)
    if (host.includes(d))
      out.push({ category: cat, conf: "high", reason: `Official domain ${d} is hidden inside ${host}` });

  const label = root.split(".")[0];
  for (const name of brand.names) {
    const m = nameMatch(label, name);
    if (m) out.push(m.type === "exact"
      ? { category: cat, conf: "medium", reason: `${root} uses the brand name on a different domain` }
      : { category: cat, conf: m.conf, reason: `${root} looks like ${brand.domains[0]} (${m.type})` });

    const subs = host.slice(0, host.length - root.length).split(".").filter(Boolean);
    for (const s of subs) {
      const sm = nameMatch(s, name);
      if (sm) out.push({ category: cat, conf: sm.type === "exact" ? "medium" : sm.conf,
        reason: `Brand name used as subdomain of ${root}` });
    }
  }
  return out;
}

// ---------- Detector 2+3: fake social profile / company page / scam account ----------
const RESERVED = new Set(["home", "explore", "search", "i", "settings", "login", "signup", "notifications",
  "messages", "hashtag", "intent", "share", "about", "help", "privacy", "tos", "p", "reel", "reels",
  "stories", "direct", "accounts", "watch", "groups", "marketplace", "events", "pages", "profile.php",
  "jobs", "feed", "legal", "policies"]);

const SOCIAL = [
  { platform: "linkedin",  hosts: ["linkedin.com"], re: /^\/(?:company|school|showcase)\/([^/]+)/i, kind: "page" },
  { platform: "linkedin",  hosts: ["linkedin.com"], re: /^\/in\/([^/]+)/i, kind: "account" },
  { platform: "x",         hosts: ["x.com", "twitter.com"], re: /^\/([A-Za-z0-9_]{1,15})(?:\/|$)/, kind: "account" },
  { platform: "facebook",  hosts: ["facebook.com", "fb.com"], re: /^\/([^/]+)/, kind: "page" },
  { platform: "instagram", hosts: ["instagram.com"], re: /^\/([^/]+)/, kind: "account" },
  { platform: "telegram",  hosts: ["t.me"], re: /^\/([^/]+)/, kind: "account" },
  { platform: "youtube",   hosts: ["youtube.com"], re: /^\/@([^/]+)/, kind: "page" }
];

function checkSocial(u, brand, info) {
  const host = cleanHost(u);
  const s = SOCIAL.find(x =>
    x.hosts.some(h => host === h || host.endsWith("." + h)) && x.re.test(u.pathname));
  if (!s) return [];

  let handle = u.pathname.match(s.re)[1];
  try { handle = decodeURIComponent(handle); } catch { /* keep raw */ }
  handle = handle.toLowerCase();
  if (RESERVED.has(handle)) return [];

  const official = lower(brand.social?.[s.platform]);
  if (official.includes(handle)) return [];                 // real company account

  const out = [];
  const add = (m, what) => {
    const cat = s.kind === "page" ? "fake_company_page"
      : m.type === "added word" ? "scam_account" : "fake_social_profile";
    if (m.type === "exact")
      out.push({ category: cat, conf: official.length ? "high" : "medium",
        reason: `Unofficial ${s.platform} ${what} uses the exact brand name` });
    else
      out.push({ category: cat, conf: m.conf,
        reason: `${s.platform} ${what} "${handle}" looks like the brand (${m.type})` });
  };

  for (const name of brand.names) {
    const m = nameMatch(handle, name);
    if (m) add(m, "handle");
    const shown = firstSegment(info.ogTitle || info.title);   // display name
    const dm = shown && nameMatch(shown, name);
    if (dm && dm.type === "exact")                             // copied display name, other handle
      out.push({ category: s.kind === "page" ? "fake_company_page" : "fake_social_profile",
        conf: "medium", reason: `Display name copies the brand, but handle "${handle}" is not official` });
    else if (dm) add(dm, "display name");
  }
  return out;
}

// ---------- Detector 4: fake mobile app ----------
function appCompare(tokens, title, brand, where) {
  const out = [], cat = "fake_app";
  for (const name of brand.names) {
    for (const t of tokens) {
      const m = nameMatch(t, name);
      if (m) out.push({ category: cat, conf: m.type === "exact" ? "high" : m.conf,
        reason: m.type === "exact" ? `${where} uses the brand name but is not the official app`
                                   : `${where} looks like the brand (${m.type})` });
    }
    const tm = title && nameMatch(title, name);
    if (tm) out.push({ category: cat, conf: tm.type === "exact" ? "high" : tm.conf,
      reason: `App title "${title}" copies the brand, but ${where} is not official` });
  }
  return out;
}

function checkApps(u, brand, info, cfg) {
  const host = cleanHost(u), path = u.pathname.toLowerCase();
  const title = firstSegment(info.ogTitle || info.title);

  if (host === "play.google.com" && path.startsWith("/store/apps/details")) {
    const id = (u.searchParams.get("id") || "").toLowerCase();
    if (lower(brand.apps?.play).includes(id)) return [];
    return appCompare(id.split("."), title, brand, `Play Store package ${id}`);
  }
  if (host === "apps.apple.com") {
    const m = u.pathname.match(/\/app\/([^/]+)\/(id\d+)/i);
    if (!m || lower(brand.apps?.ios).includes(m[2].toLowerCase())) return [];
    return appCompare([m[1]], title, brand, `App Store id ${m[2]}`);
  }
  // APK sites / direct APK files outside the official domain
  const root = rootDomain(host);
  if (brand.domains.includes(root) || (cfg.allowDomains || []).includes(root)) return [];
  if (/apk|happymod|aptoide/.test(host) || path.endsWith(".apk")) {
    const text = skeleton(u.pathname + " " + (info.title || ""));
    if (brand.names.some(n => text.includes(skeleton(n))))
      return [{ category: "fake_app", conf: "medium", reason: "Brand app offered outside the official stores" }];
  }
  return [];
}

// ---------- main ----------
const CLEAN = { verdict: "clean", category: null, reasons: [] };

// info = { title, ogTitle, siteName } from the page. Optional.
export function detect(url, info = {}, cfg = CONFIG) {
  let u;
  try { u = new URL(url); } catch { return CLEAN; }
  if (!/^https?:$/.test(u.protocol)) return CLEAN;

  const found = [];
  for (const brand of cfg.brands)
    found.push(...checkDomain(u, brand, cfg), ...checkSocial(u, brand, info), ...checkApps(u, brand, info, cfg));
  if (!found.length) return CLEAN;

  const rank = { high: 2, medium: 1 };
  found.sort((a, b) => rank[b.conf] - rank[a.conf]);
  const top = found[0];
  return {
    verdict: top.conf === "high" ? "threat" : "warning",
    category: top.category,
    reasons: [...new Set(found.map(f => f.reason))].slice(0, 3)
  };
}
