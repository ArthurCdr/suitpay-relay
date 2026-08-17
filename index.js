const express = require("express");
const app = express();

app.use(express.json());

// Chave secreta para autenticar requests vindas da Edge Function
const RELAY_SECRET = process.env.RELAY_SECRET || "TROQUE_POR_UMA_CHAVE_SECRETA_FORTE";

// Domínios liberados (separados por vírgula), ex: "meusite.com,app.meusite.com"
// Se ALLOWED_DOMAINS não estiver definida, o bloqueio por domínio fica desativado.
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || "")
  .split(",")
  .map((d) => d.trim().toLowerCase())
  .filter(Boolean);

function extractHostname(value) {
  if (!value) return null;
  try {
    // Origin/Referer vêm como URL completa (https://site.com/...)
    return new URL(value).hostname.toLowerCase();
  } catch {
    // Header x-forwarded-host / host vêm como "site.com:porta"
    return value.split(":")[0].toLowerCase();
  }
}

function isDomainAllowed(hostname) {
  if (!hostname) return false;
  return ALLOWED_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );
}

// Barra qualquer requisição que não venha dos domínios liberados
app.use((req, res, next) => {
  if (ALLOWED_DOMAINS.length === 0) return next();

  const source =
    req.headers["origin"] ||
    req.headers["referer"] ||
    req.headers["x-forwarded-host"];
  const hostname = extractHostname(source);

  if (!isDomainAllowed(hostname)) {
    console.warn(`Blocked request from unauthorized domain: ${hostname || "unknown"} (${req.method} ${req.path})`);
    return res.status(403).json({ error: "Forbidden: domain not allowed" });
  }

  return next();
});

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

// Diagnóstico em produção: IP público visto pelo relay
app.get("/my-ip", async (req, res) => {
  const r = await fetch("https://api.ipify.org?format=json");
  const data = await r.json();
  res.json(data);
});
