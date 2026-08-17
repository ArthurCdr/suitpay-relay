const express = require("express");
const app = express();

app.use(express.json());

// Chave secreta para autenticar requests vindas da Edge Function
const RELAY_SECRET = process.env.RELAY_SECRET || "TROQUE_POR_UMA_CHAVE_SECRETA_FORTE";

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

// Domínios liberados (separados por vírgula). Aceita tanto "meusite.com"
// quanto "https://meusite.com/" — normalizamos tudo para hostname puro.
// Se ALLOWED_DOMAINS não estiver definida, o bloqueio por domínio fica desativado.
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || "")
  .split(",")
  .map((d) => extractHostname(d.trim().replace(/\/+$/, "")))
  .filter(Boolean);

function isDomainAllowed(hostname) {
  if (!hostname) return false;
  return ALLOWED_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );
}

// Barra qualquer requisição que não venha dos domínios liberados.
// Só Origin/Referer contam — host/x-forwarded-host são sempre o domínio do
// próprio relay e permitiriam bypass se ele estivesse em ALLOWED_DOMAINS.
// Chamadas servidor→servidor legítimas passam pelo RELAY_SECRET.
app.use((req, res, next) => {
  if (ALLOWED_DOMAINS.length === 0) {
    console.warn("ALLOWED_DOMAINS vazio — filtro de domínio DESATIVADO");
    return next();
  }

  if (req.headers["x-relay-secret"] === RELAY_SECRET) return next();

  const source = req.headers["origin"] || req.headers["referer"];
  const hostname = extractHostname(source);

  if (!isDomainAllowed(hostname)) {
    console.warn(`Blocked request from unauthorized domain: ${hostname || "unknown"} (${req.method} ${req.path})`);
    return res.status(403).json({ error: "Forbidden: domain not allowed" });
  }

  // CORS: browsers dos domínios liberados podem chamar cross-origin
  if (req.headers["origin"]) {
    res.setHeader("Access-Control-Allow-Origin", req.headers["origin"]);
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "content-type, x-relay-secret");
  if (req.method === "OPTIONS") return res.sendStatus(204);

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

// Teste de cash-out: envia R$ 0,10 para a chave PIX de teste (telefone).
// Protegido pelo RELAY_SECRET via query string: /test-pix?secret=SEU_RELAY_SECRET
// Credenciais SuitPay via env (SUITPAY_CI / SUITPAY_CS) ou query (?ci=...&cs=...).
app.get("/test-pix", async (req, res) => {
  if (req.query.secret !== RELAY_SECRET) {
    return res.status(401).json({ error: "Unauthorized: informe ?secret=RELAY_SECRET" });
  }

  const ci = process.env.SUITPAY_CI || req.query.ci;
  const cs = process.env.SUITPAY_CS || req.query.cs;
  if (!ci || !cs) {
    return res.status(400).json({
      error: "Credenciais ausentes: defina SUITPAY_CI/SUITPAY_CS no ambiente ou passe ?ci=...&cs=...",
    });
  }

  const payload = {
    value: 0.1,
    key: "19996246801",
    typeKey: "phoneNumber",
    externalId: `test-pix-${Date.now()}`,
  };

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

    const data = await response.json().catch(() => ({}));
    res.status(response.status).json({
      suitpayStatus: response.status,
      sent: payload,
      response: data,
    });
  } catch (err) {
    console.error("SuitPay test-pix error:", err);
    res.status(500).json({ error: String(err) });
  }
});
