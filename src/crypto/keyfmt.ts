import { fromB64, os2ip, toB64, type Bytes } from '../lib/bytes';

export function pem(label: string, der: Bytes): string {
  const b = toB64(der).replace(/(.{64})/g, '$1\n').trim();
  return `-----BEGIN ${label}-----\n${b}\n-----END ${label}-----`;
}

export const json = (o: unknown) => JSON.stringify(o, null, 2);

/** JWK avec les champs très longs abrégés pour l'affichage. */
export function jwkShort(jwk: JsonWebKey): string {
  const o: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(jwk)) {
    if (k === 'key_ops' || k === 'ext') continue;
    o[k] = typeof v === 'string' && v.length > 60 ? `${v.slice(0, 28)}…${v.slice(-12)}  (${v.length} car.)` : v;
  }
  return json(o);
}

export const b64uToBytes = (s: string) => fromB64(s);
export const b64uToBig = (s: string) => os2ip(fromB64(s));
