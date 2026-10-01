const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createAudit } = require('../audit');
const { createApp } = require('../index');

process.env.RELAY_SECRET = 'test-relay-secret';
process.env.ALLOWED_DOMAINS = 'allowed.example';
async function setup(t, upstream = async () => Response.json({ id: 'mock-transaction' })) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-audit-'));
  const rows = new Map();
  let unavailable = false;
  const database = async (url, options) => {
    assert.match(url, /info09_pix_relay_logs\?on_conflict=id$/);
    if (unavailable) return new Response('', { status: 503 });
    const row = JSON.parse(options.body);
    rows.set(row.id, row);
    return new Response(null, { status: 204 });
  };
  const audit = createAudit({ directory, url: 'https://mock.supabase.co', key: 'sb_secret_test', fetchImpl: database, intervalMs: 20 });
  const server = createApp({ audit, fetchImpl: upstream }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    audit.close();
    await audit.flush();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return { audit, rows, directory, database, url: `http://127.0.0.1:${server.address().port}`, offline: v => { unavailable = v; } };
}
async function waitFor(check) {
  for (let i = 0; i < 100; i++) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('Audit condition did not become true');
}
const headers = { 'content-type': 'application/json', 'x-relay-secret': 'test-relay-secret' };
const body = JSON.stringify({ ci: 'credential-ci', cs: 'credential-cs', payload: { value: 0.1, key: 'mock-key', typeKey: 'phoneNumber', externalId: 'test-only' } });

test('records all routes and rejection paths, without credentials', async t => {
  const ctx = await setup(t);
  const cases = [
    ['/health', {}, 200],
    ['/my-ip', {}, 200],
    ['/missing', { headers }, 404],
    ['/pix-payment', { method: 'POST', headers: { 'content-type': 'application/json' }, body }, 403],
    ['/pix-payment', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://allowed.example' }, body }, 401],
    ['/pix-payment', { method: 'POST', headers, body: '{}' }, 400],
    ['/pix-payment', { method: 'POST', headers, body: '{"cs":"raw-secret",' }, 400],
    ['/pix-payment', { method: 'POST', headers, body: JSON.stringify({ large: 'x'.repeat(110000) }) }, 413],
    ['/pix-payment', { method: 'OPTIONS', headers: { origin: 'https://allowed.example' } }, 204],
    ['/pix-payment', { method: 'POST', headers, body }, 200],
    ['/test-pix?secret=test-relay-secret&ci=credential-ci&cs=credential-cs', { headers }, 200],
    ['/test-pix?secret=wrong', { headers }, 401],
  ];
  for (const [route, options, status] of cases) {
    const response = await fetch(ctx.url + route, options);
    assert.equal(response.status, status, route);
    await response.text();
    const id = response.headers.get('x-request-id');
    await waitFor(() => ctx.rows.get(id)?.completed_at);
    assert.equal(ctx.rows.get(id).http_status, status);
    assert.equal(ctx.rows.get(id).outcome, [401, 403].includes(status) ? 'blocked' : status >= 400 ? 'error' : 'success');
  }
  assert.equal(ctx.rows.size, cases.length);
  const serialized = JSON.stringify([...ctx.rows.values()]);
  for (const secret of ['test-relay-secret', 'credential-ci', 'credential-cs', 'raw-secret']) assert.ok(!serialized.includes(secret));
});

test('upstream error status and network/invalid JSON failures are recorded', async t => {
  for (const [upstream, expected, upstreamStatus] of [
    [async () => Response.json({ error: 'refused' }, { status: 422 }), 422, 422],
    [async () => { throw new Error('connection failed'); }, 502, undefined],
    [async () => new Response('not JSON'), 502, 200],
  ]) {
    const ctx = await setup(t, upstream);
    const response = await fetch(ctx.url + '/pix-payment', { method: 'POST', headers, body });
    assert.equal(response.status, expected);
    await response.text();
    await waitFor(() => [...ctx.rows.values()].some(row => row.completed_at));
    const row = [...ctx.rows.values()][0];
    assert.equal(row.outcome, 'error');
    assert.equal(row.upstream_status, upstreamStatus);
  }
});

test('database outage survives restart; retry never repeats payments', async t => {
  let payments = 0;
  const ctx = await setup(t, async () => { payments++; return Response.json({ ok: true }); });
  ctx.offline(true);
  const response = await fetch(ctx.url + '/pix-payment', { method: 'POST', headers, body });
  await response.text();
  await waitFor(() => fs.readdirSync(ctx.directory).some(f => f.endsWith('.json')));
  ctx.audit.close();
  assert.equal(payments, 1);
  ctx.offline(false);
  const restarted = createAudit({ directory: ctx.directory, url: 'https://mock.supabase.co', key: 'sb_secret_test', fetchImpl: ctx.database, intervalMs: 100000 });
  t.after(() => restarted.close());
  await restarted.flush();
  assert.equal(ctx.rows.size, 1);
  assert.equal([...ctx.rows.values()][0].outcome, 'success');
  assert.equal(fs.readdirSync(ctx.directory).length, 0);
  assert.equal(payments, 1);
});

test('client disconnect is logged', async t => {
  let release;
  const ctx = await setup(t, () => new Promise(resolve => { release = resolve; }));
  const req = http.request(ctx.url + '/pix-payment', { method: 'POST', headers });
  req.on('error', () => {});
  req.end(body);
  await waitFor(() => release);
  req.destroy();
  await waitFor(() => [...ctx.rows.values()].some(row => row.outcome === 'aborted'));
  release(Response.json({ ok: true }));
});

test('disk failure rejects before issuing a payment', async t => {
  let payments = 0;
  const ctx = await setup(t, async () => { payments++; return Response.json({ ok: true }); });
  fs.rmSync(ctx.directory, { recursive: true });
  const response = await fetch(ctx.url + '/pix-payment', { method: 'POST', headers, body });
  assert.equal(response.status, 503);
  await response.text();
  assert.equal(payments, 0);
  fs.mkdirSync(ctx.directory);
});

test('restart marks unfinished records as interrupted, without assuming failure of payment', async t => {
  const ctx = await setup(t);
  ctx.audit.close();
  const id = require('node:crypto').randomUUID();
  fs.writeFileSync(path.join(ctx.directory, id + '.json'), JSON.stringify({ id, created_at: new Date().toISOString(), method: 'POST', path: '/pix-payment', outcome: 'received' }));
  const restarted = createAudit({ directory: ctx.directory, url: 'https://mock.supabase.co', key: 'sb_secret_test', fetchImpl: ctx.database, intervalMs: 100000 });
  t.after(() => restarted.close());
  await restarted.flush();
  assert.equal(ctx.rows.get(id).outcome, 'interrupted');
  assert.equal(ctx.rows.get(id).error_code, 'PROCESS_RESTARTED');
});
