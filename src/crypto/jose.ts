// JWS (RFC 7515) : la signature ne porte pas sur le message brut mais sur
// l'entrée de signature ASCII  BASE64URL(en-tête protégé) "." BASE64URL(charge utile).
import { concat, toB64url, utf8, type Bytes } from '../lib/bytes';
import type { SigAlgo } from './sig';

export interface Jws {
  header: Record<string, string>;
  h: string;
  p: string;
  s: string;
  signingInput: string;
  sig: Bytes;
  ok: boolean;
  compact: string;
  flattened: { protected: string; payload: string; signature: string };
  general: { payload: string; signatures: { protected: string; signature: string }[] };
  note: string;
}

export async function joseSign<K>(A: SigAlgo<K>, keys: K, payload: Bytes): Promise<Jws | null> {
  if (!A.jose) return null;
  const { alg, note } = A.jose(keys);
  const header = { alg, typ: 'JOSE' };
  const h = toB64url(utf8(JSON.stringify(header)));
  const p = toB64url(payload);
  const signingInput = `${h}.${p}`;
  const r = await A.sign(keys, utf8(signingInput));
  const sig = concat(...r.sig.map((x) => x.bytes));
  const s = toB64url(sig);
  const ok = (await A.verify(keys, utf8(signingInput), sig)).ok;
  return {
    header, h, p, s, signingInput, sig, ok, note,
    compact: `${h}.${p}.${s}`,
    flattened: { protected: h, payload: p, signature: s },
    general: { payload: p, signatures: [{ protected: h, signature: s }] },
  };
}
