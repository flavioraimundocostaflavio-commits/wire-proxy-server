const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const keys = new Map();

app.get("/", (req, res) => {
  res.send("WIRE-PROXY: servidor online");
});

app.post("/admin/keys", (req, res) => {
  const { days } = req.body || {};

  if (![1, 7, 30].includes(days)) {
    return res.status(400).json({
      error: "Validade deve ser 1, 7 ou 30 dias"
    });
  }

  const key = crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + days * 86400000;

  keys.set(key, { expiresAt, activated: false });

  res.json({ key, days, expiresAt });
});

app.post("/validate", (req, res) => {
  const { key } = req.body || {};
  const item = keys.get(key);

  if (!item || item.expiresAt <= Date.now()) {
    return res.status(401).json({
      valid: false,
      error: "Chave inválida ou expirada"
    });
  }

  item.activated = true;

  res.json({
    valid: true,
    expiresAt: item.expiresAt
  });
});

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log("WIRE-PROXY online na porta " + port);
});
