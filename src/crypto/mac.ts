// SHA-256 écrit à la main (Merkle-Damgård explicite) pour démontrer l'extension de longueur,
// et comparaison avec HMAC-SHA-256 qui y résiste.
import { hmac } from '@noble/hashes/hmac.js';
import { concat, type Bytes } from '../lib/bytes';
import { sha256 } from './kdf';

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
export const IV = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

/** Fonction de compression f : état (8 mots) × bloc (64 octets) → nouvel état. `rounds` < 64 : version affaiblie, pour l'expérience. */
export function compress(state: Uint32Array, block: Bytes, rounds = 64): Uint32Array {
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) w[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) | (block[4 * i + 2] << 8) | block[4 * i + 3];
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
    const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  let [a, b, c, d, e, f, g, h] = state;
  for (let i = 0; i < rounds; i++) {
    const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
    const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  const out = new Uint32Array(8);
  [a, b, c, d, e, f, g, h].forEach((v, i) => (out[i] = (state[i] + v) | 0));
  return out;
}

/** Bourrage SHA-256 pour un message de `len` octets : 0x80, zéros, longueur en bits sur 64 bits. */
export function mdPadding(len: number): Bytes {
  const z = (55 - (len % 64) + 64) % 64;
  const p = new Uint8Array(1 + z + 8);
  p[0] = 0x80;
  const bits = BigInt(len) * 8n;
  for (let i = 0; i < 8; i++) p[p.length - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);
  return p;
}

const stateBytes = (s: Uint32Array) => {
  const b = new Uint8Array(32);
  s.forEach((v, i) => {
    b[4 * i] = v >>> 24; b[4 * i + 1] = (v >>> 16) & 255; b[4 * i + 2] = (v >>> 8) & 255; b[4 * i + 3] = v & 255;
  });
  return b;
};
const bytesState = (b: Bytes) => {
  const s = new Uint32Array(8);
  for (let i = 0; i < 8; i++) s[i] = (b[4 * i] << 24) | (b[4 * i + 1] << 16) | (b[4 * i + 2] << 8) | b[4 * i + 3];
  return s;
};

/** SHA-256 en reprenant un état et une longueur déjà traitée (cœur de l'attaque). */
export function sha256From(state: Uint32Array, processed: number, data: Bytes): Bytes {
  const msg = concat(data, mdPadding(processed + data.length));
  let s = state;
  for (let i = 0; i < msg.length; i += 64) s = compress(s, msg.slice(i, i + 64));
  return stateBytes(s);
}

export const mySha256 = (m: Bytes) => sha256From(IV, 0, m);

/** SHA-256 réduit à `rounds` tours par bloc (1 à 64) : sert à voir l'avalanche s'installer. */
export function sha256Rounds(m: Bytes, rounds: number): Bytes {
  const msg = concat(m, mdPadding(m.length));
  let s: Uint32Array = IV;
  for (let i = 0; i < msg.length; i += 64) s = compress(s, msg.slice(i, i + 64), rounds);
  return stateBytes(s);
}

/** MAC naïf : SHA-256(K ‖ M). */
export const naiveMac = (key: Bytes, m: Bytes) => sha256(concat(key, m));
export const hmacSha256 = (key: Bytes, m: Bytes) => hmac(sha256, key, m);

/**
 * L'attaquant connaît tag = SHA-256(K ‖ M), M et |K|, mais pas K.
 * Il fabrique M′ = M ‖ bourrage ‖ suite et le tag valide correspondant.
 */
export function lengthExtend(tag: Bytes, keyLen: number, m: Bytes, suffix: Bytes) {
  const glue = mdPadding(keyLen + m.length);
  const forgedMsg = concat(m, glue, suffix);
  const forgedTag = sha256From(bytesState(tag), keyLen + m.length + glue.length, suffix);
  return { glue, forgedMsg, forgedTag };
}
