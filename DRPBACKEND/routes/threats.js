
const express = require("express");
const { checkThreat } = require("../services/threatChecker");

const router = express.Router();

router.post("/check", (req, res) => {
  const { url } = req.body || {};

  if (typeof url !== "string" || url.length > 2048) {
    return res.status(400).json({
      error: "A valid URL is required"
    });
  }

  try {
    const result = checkThreat(url);

    return res.json({
      checkedUrl: url,
      ...result,
      checkedAt: new Date().toISOString()
    });
  } catch (error) {
    return res.status(400).json({
      error: error.message
    });
  }
});

module.exports = router;
