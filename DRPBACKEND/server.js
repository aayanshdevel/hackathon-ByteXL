require("dotenv").config();

const express = require("express");
const cors = require("cors");
const threatRoutes = require("./routes/threats");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors()); // Local prototype only; restrict origins for deployment
app.use(express.json({ limit: "10kb" }));

app.get("/health", (req, res) => {
  res.json({ status: "online", service: "DRP Guard API" });
});

app.use("/api/v1", threatRoutes);

app.listen(PORT, "127.0.0.1", () => {
  console.log(`DRP backend running at http://127.0.0.1:${PORT}`);
});