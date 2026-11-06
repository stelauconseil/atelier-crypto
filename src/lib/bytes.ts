// Petits utilitaires d'octets, volontairement explicites (support de cours).

export type Bytes = Uint8Array;

export const enc = new TextEncoder();
export const dec = new TextDecoder();

export const utf8 = (s: string): Bytes => enc.encode(s);
export const fromUtf8 = (b: Bytes): string => dec.decode(b);

export function toHex(b: Bytes, sep = ''): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(sep);
}

export function fromHex(h: string): Bytes {
  const s = h.replace(/[^0-9a-fA-F]/g, '');
  if (s.length % 2) throw new Error('Hexadécimal de longueur impaire');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toB64(b: Bytes): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

export function fromB64(s: string): Bytes {
  const t = atob(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''));
  return Uint8Array.from(t, (c) => c.charCodeAt(0));
}

export const toB64url = (b: Bytes) => toB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function concat(...parts: Bytes[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function rand(n: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function xor(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i % b.length];
  return out;
}

export function equal(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function u32be(n: number): Bytes {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

export function i2osp(x: bigint, len: number): Bytes {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error('Entier trop grand pour la longueur demandée');
  return out;
}

export function os2ip(b: Bytes): bigint {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}

export function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

/** Copie avec un bit inversé à la position donnée (démonstration d'altération). */
export function flipByte(b: Bytes, index?: number): { out: Bytes; index: number } {
  const out = new Uint8Array(b);
  const i = index ?? Math.floor(Math.random() * b.length);
  out[i] ^= 0x01;
  return { out, index: i };
}

export const ab = (b: Bytes): ArrayBuffer => b.slice().buffer as ArrayBuffer;
