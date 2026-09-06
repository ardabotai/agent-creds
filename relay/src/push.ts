import type { Env } from './index';
export const pushConfigured = (env: Env) => !!(env.APNS_TEAM_ID && env.APNS_KEY_ID && env.APNS_PRIVATE_KEY);
function base64(bytes: Uint8Array) { return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
export async function deliverAlert(env: Env, device: { token: string; environment: string }, pairingID: string, requestID: string, expires: number) {
  if (!pushConfigured(env)) return 503;
  const pem = env.APNS_PRIVATE_KEY!.replace(/-----[^-]+-----|\s/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const encode = (object: unknown) => base64(new TextEncoder().encode(JSON.stringify(object)));
  const input = `${encode({ alg: 'ES256', kid: env.APNS_KEY_ID })}.${encode({ iss: env.APNS_TEAM_ID, iat: Math.floor(Date.now() / 1000) })}`;
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(input));
  const host = device.environment === 'sandbox' ? 'api.sandbox.push.apple.com' : 'api.push.apple.com';
  const response = await fetch(`https://${host}/3/device/${device.token}`, {
    method: 'POST', signal: AbortSignal.timeout(15_000),
    headers: { authorization: `bearer ${input}.${base64(new Uint8Array(signature))}`, 'apns-topic': 'ai.ardabot.agentcreds.companion',
      'apns-push-type': 'alert', 'apns-priority': '10', 'apns-expiration': String(Math.floor(expires / 1000)), 'apns-collapse-id': requestID, 'content-type': 'application/json' },
    body: JSON.stringify({ aps: { alert: { title: 'Approval needed', body: 'An agent is requesting credential access. Open AgentCreds to review.' }, sound: 'default', category: 'CREDENTIAL_APPROVAL' }, request_id: requestID, pairing_id: pairingID })
  });
  await response.body?.cancel();
  return response.status;
}
