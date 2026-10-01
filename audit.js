const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

const SENSITIVE = /^(ci|cs|secret|.*secret.*|.*token.*|authorization|cookie|password|api[_-]?key)$/i;
function sanitize(value, secrets = [], depth = 0) {
  if (depth > 12) return '[depth limit]';
  if (typeof value === 'string') {
    for (const secret of secrets.filter(Boolean)) value = value.split(secret).join('[REDACTED]');
    return value.length > 8192 ? value.slice(0, 8192) + '[truncated]' : value;
  }
  if (Array.isArray(value)) return value.slice(0, 100).map(v => sanitize(v, secrets, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).slice(0, 100).map(([k, v]) =>
      [k, SENSITIVE.test(k) ? '[REDACTED]' : sanitize(v, secrets, depth + 1)]));
  }
  return value;
}
function originOnly(value) {
  try { return new URL(value).origin; } catch { return null; }
}

// A persistent volume is required in production. Never retry the payment itself.
function createAudit({ directory, url, key, fetchImpl = fetch, intervalMs = 5000 }) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  let running = false;
  function save(row) {
    const target = path.join(directory, `${row.id}.json`);
    const temporary = target + '.tmp';
    const fd = fs.openSync(temporary, 'w', 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(row)); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    fs.renameSync(temporary, target);
    const dir = fs.openSync(directory, 'r');
    try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  }
  // A process restart cannot establish whether an in-flight payment completed.
  for (const file of fs.readdirSync(directory).filter(f => f.endsWith('.json'))) {
    const row = JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8'));
    if (row.outcome === 'received') {
      row.outcome = 'interrupted';
      row.error_code = 'PROCESS_RESTARTED';
      save(row);
    }
  }
  async function flush() {
    if (running) return;
    running = true;
    try {
      for (const file of fs.readdirSync(directory).filter(f => f.endsWith('.json'))) {
        const target = path.join(directory, file);
        const snapshot = fs.readFileSync(target, 'utf8');
        const row = JSON.parse(snapshot);
        const { id, ...fields } = row;
        const databaseRow = { ...fields, session_id: id, record_type: 'relay_request', payout_status: null };
        const headers = { apikey: key, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' };
        if (!key.startsWith('sb_secret_')) headers.Authorization = `Bearer ${key}`;
        const response = await fetchImpl(`${url.replace(/\/$/, '')}/rest/v1/info09_pix_requests?on_conflict=session_id`, {
          method: 'POST', headers, body: JSON.stringify(databaseRow), signal: AbortSignal.timeout(10000),
        });
        // Do not print database responses: they can contain request data.
        if (!response.ok) throw new Error(`Supabase HTTP ${response.status}`);
        if (row.outcome !== 'received' && fs.readFileSync(target, 'utf8') === snapshot) fs.unlinkSync(target);
      }
    } catch {
      console.error('Audit sync failed; records remain in the persistent queue for retry.');
    } finally { running = false; }
  }
  const timer = setInterval(() => void flush(), intervalMs);
  timer.unref();
  const middleware = (req, res, next) => {
    const start = Date.now();
    const secrets = () => [key, process.env.RELAY_SECRET, req.headers['x-relay-secret'], req.query.secret,
      req.query.ci, req.query.cs, req.body?.ci, req.body?.cs, process.env.SUITPAY_CI, process.env.SUITPAY_CS].filter(v => typeof v === 'string');
    const row = {
      id: randomUUID(), created_at: new Date().toISOString(), method: req.method,
      path: sanitize(req.path, secrets()), query: sanitize(req.query, secrets()),
      peer_ip: req.socket.remoteAddress || null,
      origin: originOnly(req.headers.origin), referer: originOnly(req.headers.referer),
      outcome: 'received',
    };
    req.audit = row;
    res.setHeader('X-Request-Id', row.id);
    try { save(row); } catch {
      console.error('Audit disk write failed; request rejected before processing.');
      return res.status(503).json({ error: 'Audit storage unavailable', requestId: row.id });
    }
    let responseBody;
    const json = res.json;
    res.json = function (body) { responseBody = body; return json.call(this, body); };
    let completed = false;
    function finalize(aborted) {
      if (completed) return;
      completed = true;
      const status = res.statusCode;
      Object.assign(row, {
        completed_at: new Date().toISOString(), duration_ms: Date.now() - start,
        http_status: aborted ? null : status,
        outcome: aborted ? 'aborted' : [401, 403].includes(status) ? 'blocked' : status >= 400 ? 'error' : 'success',
        request_body: req.body === undefined ? null : sanitize(req.body, secrets()),
        response_body: responseBody === undefined ? null : sanitize(responseBody, secrets()),
      });
      try { save(row); } catch { console.error('Audit finalization failed; initial record remains queued.'); }
      void flush();
    }
    res.once('finish', () => finalize(false));
    res.once('close', () => finalize(!res.writableFinished));
    next();
  };
  return { middleware, flush, close: () => clearInterval(timer) };
}
module.exports = { createAudit, sanitize };
