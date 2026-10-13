// Run: node test.js
import { detect } from "./detector.js";

const cfg = {
  brands: [{
    names: ["bytexl"], domains: ["bytexl.ai"],
    social: { linkedin: ["bytexl"], x: ["bytexl"] },
    apps: { play: ["com.bytexl.app"], ios: ["id111"] }
  }],
  allowDomains: ["bytel.com"]
};

// [url, expected verdict, optional page info]
const cases = [
  // ---- must flag: fake brand website ----
  ["https://bytex1.ai/",                         "threat"],   // look-alike character
  ["https://bytexl-login.com/",                  "threat"],   // added risk word
  ["https://secure-bytexl.net/",                 "threat"],   // added risk word (front)
  ["https://bytexl.ai.evil-site.net/login",      "threat"],   // official domain hidden inside
  ["https://byte-xl.ai/",                        "warning"],  // spacing change
  ["https://bytexl.com/",                        "warning"],  // same name, other TLD
  ["https://bytxel.ai/",                         "warning"],  // character swap
  ["https://bytexl.evil.com/",                   "warning"],  // brand as subdomain
  // ---- must flag: social ----
  ["https://www.linkedin.com/company/bytexl-careers", "threat"],   // fake company page
  ["https://www.linkedin.com/in/bytexl-hr-recruiter", "threat"],   // scam account
  ["https://x.com/bytex1_support",               "threat"],   // scam account, look-alike
  ["https://www.instagram.com/byte.xl/",         "warning"],  // spacing change
  ["https://www.facebook.com/profile-page", "clean", { title: "Priya | Facebook" }],
  ["https://www.facebook.com/some.page", "warning", { ogTitle: "ByteXL | Facebook" }], // copied display name
  // ---- must flag: apps ----
  ["https://play.google.com/store/apps/details?id=com.bytexl.pro", "threat", { title: "ByteXL - Apps on Google Play" }],
  ["https://apps.apple.com/in/app/bytexl/id999", "threat"],
  ["https://apkpure.com/bytexl/com.x.y",         "warning"],
  // ---- must NOT flag ----
  ["https://bytexl.ai/",                         "clean"],
  ["https://app.bytexl.ai/dashboard",            "clean"],
  ["https://www.google.com/search?q=bytexl.ai",  "clean"],
  ["https://bytexlearn.com/",                    "clean"],    // brand inside a normal word
  ["https://bytexl-docs.example.org/",           "clean"],    // harmless added word
  ["https://bytel.com/",                         "clean"],    // allow-listed similar name
  ["https://github.com/bytexl/repo",             "clean"],
  ["https://www.linkedin.com/company/bytexl",    "clean"],    // official page
  ["https://www.linkedin.com/in/priya-sharma-bytexl", "clean"], // employee profile
  ["https://x.com/bytexl",                       "clean"],    // official handle
  ["https://x.com/home",                         "clean"],
  ["https://play.google.com/store/apps/details?id=com.bytexl.app", "clean", { title: "ByteXL - Apps on Google Play" }],
  ["https://play.google.com/store/apps/details?id=com.spotify.music", "clean", { title: "Spotify - Apps on Google Play" }],
  ["https://learn.microsoft.com/en-us/azure/",   "clean"]
];

let fail = 0;
for (const [url, want, info] of cases) {
  const r = detect(url, info || {}, cfg);
  const ok = r.verdict === want;
  if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  want=${want.padEnd(7)} got=${r.verdict.padEnd(7)} ${url}${ok ? "" : "  -> " + r.reasons.join("; ")}`);
}
console.log(`\n${cases.length - fail}/${cases.length} passed`);
process.exit(fail ? 1 : 0);
