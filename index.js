const express = require("express");
const { createAudit } = require("./audit");
const path = require("node:path");

function createApp({ audit, fetchImpl = fetch } = {}) {
  const app = express();
  app.use(audit.middleware);
  app.use(express.json());

  // Chave secreta para autenticar requests vindas da Edge Function
  const RELAY_SECRET = process.env.RELAY_SECRET;
  if (!RELAY_SECRET) throw new Error("RELAY_SECRET is required");

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
  // Endpoints de diagnóstico acessíveis direto pelo navegador, sem filtro
  const PUBLIC_PATHS = ["/health", "/my-ip"];

  app.use((req, res, next) => {
    if (PUBLIC_PATHS.includes(req.path)) return next();

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

    const { ci, cs, payload } = req.body || {};
    if (!ci || !cs || !payload) {
      return res.status(400).json({ error: "Missing ci, cs, or payload" });
    }

    try {
      const response = await fetchImpl("https://ws.suitpay.app/api/v1/gateway/pix-payment", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ci,
          cs,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000),
      });

      req.audit.upstream_status = response.status;
      const data = await response.json();
      res.status(response.status).json(data);
    } catch (err) {
      req.audit.error_code = err.name === "TimeoutError" ? "UPSTREAM_TIMEOUT" : "UPSTREAM_ERROR";
      res.status(502).json({ error: "SuitPay request failed" });
    }
  });

  // Health check
  app.get("/health", (req, res) => {
    res.json({ status: "ok" });
  });


  // Diagnóstico em produção: IP público visto pelo relay
  app.get("/my-ip", async (req, res) => {
    try {
      const r = await fetchImpl("https://api.ipify.org?format=json", { signal: AbortSignal.timeout(10000) });
      if (!r.ok) throw new Error("IP service failed");
      res.json(await r.json());
    } catch {
      req.audit.error_code = "IP_SERVICE_ERROR";
      res.status(502).json({ error: "IP service unavailable" });
    }
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
      const response = await fetchImpl("https://ws.suitpay.app/api/v1/gateway/pix-payment", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ci,
          cs,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000),
      });

      req.audit.upstream_status = response.status;
      const data = await response.json();
      res.status(response.status).json({
        suitpayStatus: response.status,
        sent: payload,
        response: data,
      });
    } catch (err) {
      req.audit.error_code = err.name === "TimeoutError" ? "UPSTREAM_TIMEOUT" : "UPSTREAM_ERROR";
      res.status(502).json({ error: "SuitPay request failed" });
    }
  });

  app.use((req, res) => res.status(404).json({ error: "Not found" }));
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    req.audit.error_code = err.type || "INTERNAL_ERROR";
    const status = err.status >= 400 && err.status < 500 ? err.status : 500;
    res.status(status).json({ error: status === 500 ? "Internal server error" : "Invalid request body" });
  });
  return app;
}

if (require.main === module) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key || !process.env.RELAY_SECRET) {
    throw new Error("Set SUPABASE_URL, SUPABASE_SECRET_KEY (or SUPABASE_SERVICE_ROLE_KEY), and RELAY_SECRET");
  }
  const audit = createAudit({ directory: process.env.AUDIT_SPOOL_DIR || path.join(__dirname, "audit-spool"), url, key });
  const app = createApp({ audit });
  const server = app.listen(process.env.PORT || 3001, () => console.log("SuitPay relay started with audit logging"));
  for (const signal of ["SIGTERM", "SIGINT"]) process.once(signal, () => {
    server.close(async () => { audit.close(); await audit.flush(); process.exit(0); });
    setTimeout(() => process.exit(0), 15000).unref();
  });
}
module.exports = { createApp };
