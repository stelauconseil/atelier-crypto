import { sha256 } from '@noble/hashes/sha2.js';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { concat, u32be, type Bytes } from '../lib/bytes';

export { sha256 };

/** MGF1 (PKCS#1) : masque de longueur arbitraire à partir d'un haché. */
export function mgf1(seed: Bytes, len: number): Bytes {
  const out: Bytes[] = [];
  for (let c = 0; out.length * 32 < len; c++) out.push(sha256(concat(seed, u32be(c))));
  return concat(...out).slice(0, len);
}

/** KDF ANSI X9.63 (= KDF2 de l'ISO 18033-2) : compteur à partir de 1. */
export function x963kdf(z: Bytes, sharedInfo: Bytes, len: number): Bytes {
  const out: Bytes[] = [];
  for (let c = 1; out.length * 32 < len; c++) out.push(sha256(concat(z, u32be(c), sharedInfo)));
  return concat(...out).slice(0, len);
}

export const hkdfExtract = (salt: Bytes, ikm: Bytes) => extract(sha256, ikm, salt);
export const hkdfExpand = (prk: Bytes, info: Bytes, len: number) => expand(sha256, prk, info, len);
export const hkdf = (ikm: Bytes, salt: Bytes, info: Bytes, len: number) => hkdfExpand(hkdfExtract(salt, ikm), info, len);
