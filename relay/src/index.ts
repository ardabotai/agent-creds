import { DurableObject } from 'cloudflare:workers';
import { deliverAlert, pushConfigured } from './push';

export interface Env {
  ROOMS: DurableObjectNamespace<RelayRoom>;
  EDGE_LIMIT: RateLimit;
  REGISTER_LIMIT: RateLimit;
  APNS_TEAM_ID?: string;
  APNS_KEY_ID?: string;
  APNS_PRIVATE_KEY?: string;
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOKEN = /^[0-9a-f]{64}$/;
const MAX_FRAME = 1_400_000;
const result = (status: number, error: string) => Response.json({ error }, { status, headers: { 'Cache-Control': 'no-store' } });
async function digest(text: string) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), x => x.toString(16).padStart(2, '0')).join('');
}
async function json(request: Request): Promise<Record<string, unknown>> {
  // Bound streamed input too; Content-Length alone is attacker-controlled.
  const reader = request.body?.getReader(); if (!reader) throw new Error('body');
  let size = 0; const chunks: Uint8Array[] = [];
  for (;;) { const { value, done } = await reader.read(); if (done) break; size += value.length; if (size > 4096) { await reader.cancel(); throw new Error('size'); } chunks.push(value); }
  const bytes = new Uint8Array(size); let offset = 0; for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
  return size ? JSON.parse(new TextDecoder().decode(bytes)) : {};
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/health') return Response.json({ service: 'agentcreds-relay', protocol: 1 });
    // Native clients use Authorization headers; browser origins and query credentials are rejected.
    if (request.headers.has('Origin') || url.search) return result(400, 'Invalid request');
    const parts = url.pathname.split('/');
    if (parts[1] !== 'v1' || parts[2] !== 'rooms' || !UUID.test(parts[3] ?? '')) return result(404, 'Not found');
    const token = request.headers.get('Authorization')?.replace(/^Bearer /, '') ?? '';
    if (!TOKEN.test(token)) return result(401, 'Unauthorized');
    if (!(await env.EDGE_LIMIT.limit({ key: request.headers.get('CF-Connecting-IP') ?? 'local' })).success) return result(429, 'Rate limited');
    if (request.method === 'PUT' && parts.length === 4 && !(await env.REGISTER_LIMIT.limit({ key: request.headers.get('CF-Connecting-IP') ?? 'local' })).success) return result(429, 'Enrollment rate limited');
    try {
      // Materialize the bounded control body before crossing the DO boundary.
      const forwarded = request.body ? new Request(request, { body: JSON.stringify(await json(request)) }) : request;
      return await env.ROOMS.getByName(parts[3]).fetch(forwarded);
    } catch { return result(400, 'Invalid request'); }
  }
} satisfies ExportedHandler<Env>;

type Device = { id: string; hash: string; expires: number; push: string | null };
type Attachment = { role: 'host' | 'phone'; channel?: string; pairing?: string; phase?: string; expires: number; count: number; window?: number };
export class RelayRoom extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, hash TEXT NOT NULL, expires REAL NOT NULL, push TEXT);
      CREATE TABLE IF NOT EXISTS pushes (id TEXT PRIMARY KEY, expires REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next REAL NOT NULL);`);
  }
  private root() { return this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM meta WHERE key='root'").toArray()[0]?.value; }
  private device(id: string) { return this.ctx.storage.sql.exec<Device>('SELECT * FROM devices WHERE id=? AND expires>?', id, Date.now()).toArray()[0]; }
  private host() { return this.ctx.getWebSockets('host').find(ws => ws.readyState === WebSocket.OPEN); }
  private phones() { return this.ctx.getWebSockets('phone').filter(ws => ws.readyState === WebSocket.OPEN); }
  private closePhones(pairing?: string) {
    for (const ws of this.phones()) { const a = ws.deserializeAttachment() as Attachment; if (!pairing || a.pairing === pairing) ws.close(4001, 'Reconnect'); }
  }
  private async schedule() {
    const row = this.ctx.storage.sql.exec<{ time: number | null }>('SELECT MIN(next) AS time FROM pushes').one();
    // Hourly GC also expires abandoned invitations and device registrations.
    await this.ctx.storage.setAlarm(Math.min(row.time ?? Infinity, Date.now() + 3_600_000));
  }
  async fetch(request: Request): Promise<Response> {
    try {
      const parts = new URL(request.url).pathname.split('/').slice(4);
      const token = request.headers.get('Authorization')?.replace(/^Bearer /, '') ?? '';
      if (!TOKEN.test(token)) return result(401, 'Unauthorized');
      const hash = await digest(token);
      if (request.method === 'PUT' && parts.length === 0) {
        const root = this.root(); if (root && root !== hash) return result(403, 'Unauthorized');
        this.ctx.storage.sql.exec("INSERT OR IGNORE INTO meta VALUES ('root', ?)", hash);
        await this.schedule(); return Response.json({ registered: true });
      }
      const isHost = hash === this.root();
      if (parts[0] === 'phone' && parts.length === 2 && UUID.test(parts[1])) {
        const device = this.device(parts[1]);
        if (!device || device.hash !== hash) return result(403, 'Unauthorized');
        if (request.method !== 'GET' || request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return result(426, 'WebSocket required');
        if (!this.host()) return result(503, 'Mac offline');
        if (this.phones().length >= 16) return result(429, 'Too many connections');
        const pair = new WebSocketPair(), channel = crypto.randomUUID();
        this.ctx.acceptWebSocket(pair[1], ['phone']);
        pair[1].serializeAttachment({ role: 'phone', channel, pairing: device.id, phase: 'opening', expires: Math.min(device.expires, Date.now() + 180_000), count: 0 } satisfies Attachment);
        this.host()!.send(JSON.stringify({ type: 'open', channel, pairingID: device.id }));
        return new Response(null, { status: 101, webSocket: pair[0] });
      }
      if (!isHost) return result(403, 'Unauthorized');
      if (parts.length === 0 && request.method === 'DELETE') {
        this.closePhones(); for (const host of this.ctx.getWebSockets('host')) host.close(4001, 'Revoked');
        await this.ctx.storage.deleteAll(); await this.ctx.storage.deleteAlarm(); return Response.json({ revoked: true });
      }
      if (parts[0] === 'host' && parts.length === 1 && request.method === 'GET') {
        if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return result(426, 'WebSocket required');
        // Reconnect supersedes stale sockets, invalidating their in-flight challenges.
        this.closePhones(); for (const ws of this.ctx.getWebSockets('host')) ws.close(4001, 'Reconnected');
        const pair = new WebSocketPair(); this.ctx.acceptWebSocket(pair[1], ['host']);
        pair[1].serializeAttachment({ role: 'host', expires: Date.now() + 86_400_000, count: 0 } satisfies Attachment);
        return new Response(null, { status: 101, webSocket: pair[0] });
      }
      if (parts[0] === 'devices' && parts.length === 1 && request.method === 'GET') return Response.json({ devices: this.ctx.storage.sql.exec<{ id: string }>('SELECT id FROM devices').toArray().map(row => row.id) });
      if (parts[0] === 'devices' && parts.length === 2 && UUID.test(parts[1])) {
        const id = parts[1];
        if (request.method === 'DELETE') { this.ctx.storage.sql.exec('DELETE FROM devices WHERE id=?', id); this.closePhones(id); return Response.json({ revoked: true }); }
        if (request.method === 'PUT') {
          const body = await json(request);
          if (typeof body.token !== 'string' || !TOKEN.test(body.token) || typeof body.expiresAt !== 'number' || body.expiresAt <= Date.now() || body.expiresAt > Date.now() + 366 * 86_400_000) return result(400, 'Invalid registration');
          const hash = await digest(body.token);
          if (!this.device(id) && this.ctx.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM devices WHERE expires>?', Date.now()).one().n >= 8) return result(409, 'Device limit');
          this.ctx.storage.sql.exec('INSERT INTO devices(id,hash,expires) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET hash=excluded.hash, expires=excluded.expires', id, hash, body.expiresAt);
          // Existing enrollment channel may deliver its final E2E-encrypted response;
          // the Mac rejects the old pairing key immediately after enrollment.
          await this.schedule(); return Response.json({ registered: true });
        }
      }
      if (parts[0] === 'push' && parts.length === 2 && UUID.test(parts[1])) {
        const device = this.device(parts[1]); if (!device) return result(404, 'Device unavailable');
        if (request.method === 'DELETE') { this.ctx.storage.sql.exec('UPDATE devices SET push=NULL WHERE id=?', device.id); return Response.json({ disabled: true }); }
        if (request.method === 'PUT') {
          const body = await json(request);
          if (typeof body.token !== 'string' || !/^[0-9a-f]{32,512}$/.test(body.token) || body.token.length % 2 || !['sandbox', 'production'].includes(String(body.environment))) return result(400, 'Invalid push registration');
          this.ctx.storage.sql.exec('UPDATE devices SET push=? WHERE id=?', JSON.stringify({ token: body.token, environment: body.environment }), device.id);
          return Response.json({ notificationStatus: pushConfigured(this.env) ? 'Registered with relay; delivery not yet verified' : 'Relay push signing is not configured' });
        }
      }
      if (parts[0] === 'notify' && parts.length === 1 && request.method === 'POST') {
        const body = await json(request);
        if (typeof body.requestID !== 'string' || !UUID.test(body.requestID) || typeof body.expiresAt !== 'number' || body.expiresAt <= Date.now() || body.expiresAt > Date.now() + 600_000) return result(400, 'Invalid notification');
        if (!pushConfigured(this.env)) return result(503, 'Push signing not configured');
        this.ctx.storage.sql.exec('DELETE FROM pushes WHERE expires<=?', Date.now());
        if (this.ctx.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM pushes').one().n >= 100) return result(429, 'Notification limit');
        this.ctx.storage.sql.exec('INSERT OR IGNORE INTO pushes(id,expires,next) VALUES(?,?,?)', body.requestID, body.expiresAt, Date.now() + 10);
        await this.schedule(); return Response.json({ queued: true });
      }
      return result(404, 'Not found');
    } catch { return result(400, 'Invalid request'); }
  }
  webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
    try {
      const a = ws.deserializeAttachment() as Attachment;
      if (a.expires < Date.now() || (typeof message === 'string' ? new TextEncoder().encode(message).length : message.byteLength) > MAX_FRAME) { ws.close(1009, 'Expired or too large'); return; }
      if (!a.window || Date.now() - a.window > 60_000) { a.window = Date.now(); a.count = 0; }
      if (++a.count > 240) { ws.close(1008, 'Rate limited'); return; }
      ws.serializeAttachment(a);
      const frame = JSON.parse(typeof message === 'string' ? message : new TextDecoder().decode(message));
      if (a.role === 'host') {
        if (ws !== this.host() || !['challenge', 'response', 'error'].includes(frame.type) || !UUID.test(frame.channel)) throw new Error('frame');
        const phone = this.phones().find(p => (p.deserializeAttachment() as Attachment).channel === frame.channel);
        if (!phone) return;
        const p = phone.deserializeAttachment() as Attachment;
        if (!this.device(p.pairing!) || p.expires < Date.now()) { phone.close(4001, 'Expired'); return; }
        if (frame.type === 'challenge' && p.phase === 'opening' && typeof frame.payload === 'string' && frame.payload.length === 44) p.phase = 'challenge';
        else if (frame.type === 'response' && p.phase === 'request' && typeof frame.payload === 'string') p.phase = 'complete';
        else if (frame.type === 'error') { phone.send(JSON.stringify({ type: 'error', error: 'Mac unavailable or pairing invalid' })); phone.close(4001, 'Unavailable'); return; }
        else throw new Error('phase');
        phone.serializeAttachment(p); phone.send(JSON.stringify({ type: frame.type, payload: frame.payload }));
      } else {
        if (frame.type !== 'request' || a.phase !== 'challenge' || typeof frame.payload !== 'string' || !this.device(a.pairing!)) throw new Error('phase');
        const host = this.host(); if (!host) { ws.close(1012, 'Mac offline'); return; }
        a.phase = 'request'; ws.serializeAttachment(a);
        host.send(JSON.stringify({ type: 'request', channel: a.channel, pairingID: a.pairing, payload: frame.payload }));
      }
    } catch { ws.close(1008, 'Invalid frame'); }
  }
  webSocketClose(ws: WebSocket) {
    const a = ws.deserializeAttachment() as Attachment;
    if (a?.role === 'host' && !this.host()) this.closePhones();
    ws.close(1000, 'Closed');
  }
  webSocketError(ws: WebSocket) { ws.close(1011, 'Connection failed'); }
  async alarm() {
    this.ctx.storage.sql.exec('DELETE FROM devices WHERE expires<=?', Date.now());
    this.ctx.storage.sql.exec('DELETE FROM pushes WHERE expires<=?', Date.now());
    for (const ws of this.ctx.getWebSockets()) { const a = ws.deserializeAttachment() as Attachment; if (a.expires <= Date.now()) ws.close(4001, 'Expired'); }
    const pending = this.ctx.storage.sql.exec<{ id: string; expires: number; attempts: number }>('SELECT * FROM pushes WHERE next<=? LIMIT 10', Date.now()).toArray();
    for (const request of pending) {
      let retry = false;
      for (const device of this.ctx.storage.sql.exec<Device>('SELECT * FROM devices WHERE push IS NOT NULL AND expires>?', Date.now()).toArray()) {
        // Recheck revocation after any awaited send. No secret payload is logged.
        if (!this.device(device.id)) continue;
        try {
          const status = await deliverAlert(this.env, JSON.parse(device.push!), device.id, request.id, request.expires);
          if (status === 410 || status === 400) this.ctx.storage.sql.exec('UPDATE devices SET push=NULL WHERE id=? AND push=?', device.id, device.push);
          else if (status === 429 || status >= 500) retry = true;
        } catch { retry = true; }
      }
      if (retry && request.attempts < 2) this.ctx.storage.sql.exec('UPDATE pushes SET attempts=attempts+1,next=? WHERE id=?', Date.now() + 15_000 * (request.attempts + 1), request.id);
      else this.ctx.storage.sql.exec('DELETE FROM pushes WHERE id=?', request.id);
    }
    if (!this.host() && this.ctx.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM devices').one().n === 0) {
      await this.ctx.storage.deleteAll(); await this.ctx.storage.deleteAlarm(); return;
    }
    await this.schedule();
  }
}
