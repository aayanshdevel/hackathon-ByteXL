const database = require("../data/threats.json");

function checkThreat(input) {
  let parsed;

  try {
    parsed = new URL(input);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported");
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");

  const match = database.threats.find(
    (item) => item.domain.toLowerCase() === hostname
  );

  if (match) {
    return {
      status: "malicious",
      severity: match.severity,
      type: match.type,
      brand: match.brand,
      reason: match.reason
    };
  }

  return {
    status: "unknown",
    severity: "none",
    reason: "No matching threat record found"
  };
}

module.exports = { checkThreat };   