const express = require("express");
const app = express();

app.use(express.json());

// Chave secreta para autenticar requests vindas da Edge Function
const RELAY_SECRET = process.env.RELAY_SECRET || "TROQUE_POR_UMA_CHAVE_SECRETA_FORTE";

app.post("/pix-payment", async (req, res) => {
  // Validar autenticação
  const auth = req.headers["x-relay-secret"];
  if (auth !== RELAY_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { ci, cs, payload } = req.body;
  if (!ci || !cs || !payload) {
    return res.status(400).json({ error: "Missing ci, cs, or payload" });
  }

  try {
    const response = await fetch("https://ws.suitpay.app/api/v1/gateway/pix-payment", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ci,
        cs,
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error("SuitPay error:", err);
    res.status(500).json({ error: String(err) });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`SuitPay relay running on port ${PORT}`);
});
