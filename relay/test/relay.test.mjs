import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import WebSocket from 'ws';
const base = process.env.RELAY_URL || 'http://127.0.0.1:8798';
const token = () => randomBytes(32).toString('hex');
const sockets = [];
function socket(path, auth) {
  const ws = new WebSocket(base.replace(/^http/, 'ws') + path, { headers: { Authorization: `Bearer ${auth}` } }); sockets.push(ws);
  const queue = [], readers = [];
  ws.on('message', data => { const value = JSON.parse(data); const reader = readers.shift(); if (reader) reader(value); else queue.push(value); });
  ws.next = () => queue.length ? Promise.resolve(queue.shift()) : new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Relay response timeout')), 5000); readers.push(value => { clearTimeout(timer); resolve(value); }); });
  ws.opened = new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  return ws;
}
async function http(path, auth, method = 'GET', body) {
  return fetch(base + path, { method, headers: { Authorization: `Bearer ${auth}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
}
test('relay isolates rooms and devices, preserves opaque frames, rejects replay and revocation', async () => {
  const room = `/v1/rooms/${randomUUID()}`, root = token(), device = randomUUID(), phoneToken = token();
  try {
    assert.equal((await http(room, root, 'PUT')).status, 200);
    assert.equal((await http(room, token(), 'PUT')).status, 403);
    assert.equal((await http(`${room}/devices/${device}`, phoneToken, 'PUT', { token: phoneToken, expiresAt: Date.now() + 600000 })).status, 403);
    assert.equal((await http(`${room}/devices/${device}`, root, 'PUT', { token: phoneToken, expiresAt: Date.now() + 600000 })).status, 200);
    assert.equal((await http(`${room}/phone/${device}`, token())).status, 403);
    assert.equal((await http(`${room}/phone/${device}`, phoneToken)).status, 426);
    const offlineStatus = await new Promise((resolve, reject) => {
      const offline = new WebSocket(base.replace(/^http/, 'ws') + `${room}/phone/${device}`, { headers: { Authorization: `Bearer ${phoneToken}` } });
      sockets.push(offline);
      offline.on('unexpected-response', (request, response) => { resolve(response.statusCode); response.destroy(); request.destroy(); });
      offline.on('error', reject);
    });
    assert.equal(offlineStatus, 503);
    const host = socket(`${room}/host`, root); await host.opened;
    const phone = socket(`${room}/phone/${device}`, phoneToken); await phone.opened;
    const opened = await host.next(); assert.equal(opened.type, 'open'); assert.equal(opened.pairingID, device);
    const challenge = randomBytes(32).toString('base64');
    host.send(JSON.stringify({ type: 'challenge', channel: opened.channel, payload: challenge }));
    assert.deepEqual(await phone.next(), { type: 'challenge', payload: challenge });
    const ciphertext = randomBytes(512).toString('base64');
    phone.send(JSON.stringify({ type: 'request', payload: ciphertext }));
    assert.deepEqual(await host.next(), { type: 'request', channel: opened.channel, pairingID: device, payload: ciphertext });
    host.send(JSON.stringify({ type: 'response', channel: opened.channel, payload: ciphertext }));
    assert.deepEqual(await phone.next(), { type: 'response', payload: ciphertext });
    const closed = new Promise(resolve => phone.once('close', resolve));
    phone.send(JSON.stringify({ type: 'request', payload: ciphertext }));
    assert.equal(await closed, 1008);
    assert.equal((await http(`${room}/devices/${randomUUID()}`, root, 'PUT', { token: token(), expiresAt: Date.now() - 1 })).status, 400);
    assert.equal((await http(`${room}/push/${device}`, root, 'PUT', { token: 'ab'.repeat(32), environment: 'sandbox' })).status, 200);
    const notify = await http(`${room}/notify`, root, 'POST', { requestID: randomUUID(), expiresAt: Date.now() + 10000 });
    assert.ok([200, 503].includes(notify.status));
    assert.equal((await http(`${room}/devices/${device}`, root, 'DELETE')).status, 200);
    assert.equal((await http(`${room}/phone/${device}`, phoneToken)).status, 403);
    const otherRoom = `/v1/rooms/${randomUUID()}`;
    assert.equal((await http(`${otherRoom}/phone/${device}`, phoneToken)).status, 403);
  } finally {
    for (const ws of sockets) ws.terminate();
    await http(room, root, 'DELETE');
  }
});
