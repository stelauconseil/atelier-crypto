// Hachage, MAC et dérivation : SHA-2, SHA-3, BLAKE2/BLAKE3, HMAC détaillé, HKDF pas à pas,
// dérivation de clé à partir d'un mot de passe (PBKDF2, scrypt, Argon2id).
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { blake2b, blake2s } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { keccak_256, sha3_256, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { concat, equal, xor, type Bytes } from '../lib/bytes';
import { mdPadding, sha256Rounds } from './mac';

// ================================================================ fonctions de hachage
export interface HashDef {
  id: string;
  label: string;
  /** Construction : Merkle-Damgård, éponge, HAIFA (BLAKE2), arbre de Merkle (BLAKE3). */
  build: string;
  /** Taille du bloc traité (octets) ; pour une éponge : le débit r. */
  block: number;
  out: number;
  xof?: boolean;
  keyed?: boolean;
  h: (m: Bytes, opts?: { dkLen?: number; key?: Bytes }) => Bytes;
}

export const HASHES: Record<string, HashDef> = {
  sha256: { id: 'sha256', label: 'SHA-256', build: 'Merkle-Damgård', block: 64, out: 32, h: (m) => sha256(m) },
  sha512: { id: 'sha512', label: 'SHA-512', build: 'Merkle-Damgård', block: 128, out: 64, h: (m) => sha512(m) },
  sha3_256: { id: 'sha3_256', label: 'SHA3-256', build: 'éponge (r = 136 o, c = 64 o)', block: 136, out: 32, h: (m) => sha3_256(m) },
  sha3_512: { id: 'sha3_512', label: 'SHA3-512', build: 'éponge (r = 72 o, c = 128 o)', block: 72, out: 64, h: (m) => sha3_512(m) },
  keccak256: { id: 'keccak256', label: 'Keccak-256 (Ethereum)', build: 'éponge, bourrage d\'origine', block: 136, out: 32, h: (m) => keccak_256(m) },
  shake128: { id: 'shake128', label: 'SHAKE128 (XOF)', build: 'éponge (r = 168 o)', block: 168, out: 32, xof: true, h: (m, o) => shake128(m, { dkLen: o?.dkLen ?? 32 }) },
  shake256: { id: 'shake256', label: 'SHAKE256 (XOF)', build: 'éponge (r = 136 o)', block: 136, out: 64, xof: true, h: (m, o) => shake256(m, { dkLen: o?.dkLen ?? 64 }) },
  blake2s: { id: 'blake2s', label: 'BLAKE2s-256', build: 'HAIFA, 10 tours, mots de 32 bits', block: 64, out: 32, keyed: true, h: (m, o) => blake2s(m, { key: o?.key?.length ? o.key : undefined }) },
  blake2b: { id: 'blake2b', label: 'BLAKE2b-512', build: 'HAIFA, 12 tours, mots de 64 bits', block: 128, out: 64, keyed: true, h: (m, o) => blake2b(m, { key: o?.key?.length ? o.key : undefined }) },
  blake3: { id: 'blake3', label: 'BLAKE3', build: 'arbre de Merkle de blocs de 1 Kio, 7 tours', block: 64, out: 32, xof: true, keyed: true, h: (m, o) => blake3(m, { dkLen: o?.dkLen ?? 32, key: o?.key?.length === 32 ? o.key : undefined }) },
};

/** Le message tel que SHA-256 le traite : message, 0x80, zéros, longueur en bits sur 8 octets, en blocs de 64 octets. */
export function sha256Padded(m: Bytes) {
  const pad = mdPadding(m.length);
  const full = concat(m, pad);
  return { m, mark: pad.slice(0, 1), zeros: pad.slice(1, pad.length - 8), len: pad.slice(pad.length - 8), blocks: full.length / 64 };
}

/** Nombre de bits qui diffèrent entre deux chaînes de même longueur. */
export function bitDiff(a: Bytes, b: Bytes): number {
  let n = 0;
  for (let i = 0; i < a.length; i++) for (let x = a[i] ^ b[i]; x; x &= x - 1) n++;
  return n;
}

export function flipBit(m: Bytes, bit: number): Bytes {
  const c = m.slice();
  if (c.length) c[(bit >> 3) % c.length] ^= 1 << (bit & 7);
  return c;
}

/**
 * Avalanche de SHA-256 réduit, pour 1 à 64 tours : bits de sortie modifiés quand on bascule un bit de l'octet `at`
 * (moyenne sur ses 8 bits). Le message est ramené à 55 octets (un seul bloc) : l'octet 0 entre dans le mot w₀,
 * dès le premier tour ; l'octet 54 dans w₁₃, au quatorzième seulement.
 */
export function avalancheByRounds(m: Bytes, at: number): number[] {
  const base = new Uint8Array(55).fill(0x20);
  base.set(m.slice(0, 55));
  const out: number[] = [];
  for (let r = 1; r <= 64; r++) {
    const h0 = sha256Rounds(base, r);
    let sum = 0;
    for (let t = 0; t < 8; t++) sum += bitDiff(h0, sha256Rounds(flipBit(base, at * 8 + t), r));
    out.push(sum / 8);
  }
  return out;
}

/** Premier nombre de tours où l'avalanche atteint `seuil` bits (sur 256). */
export const roundsToAvalanche = (curve: number[], seuil = 110) => curve.findIndex((v) => v >= seuil) + 1;

// ================================================================ « Too Much Crypto » (Aumasson, 2019)
export const TOO_MUCH = [
  { algo: 'AES-128', std: 10, proposed: 9, note: 'meilleure attaque pratique : 6 tours' },
  { algo: 'BLAKE2b', std: 12, proposed: 8, note: 'aucune attaque pratique non triviale sur les versions réduites' },
  { algo: 'BLAKE2s', std: 10, proposed: 7, note: 'BLAKE3 (2020) adopte 7 tours' },
  { algo: 'ChaCha20', std: 20, proposed: 8, note: 'ChaCha8 : aucune attaque publiée' },
  { algo: 'SHA-3', std: 24, proposed: 10, note: 'meilleure attaque pratique : 5 tours ; KangarooTwelve en a 12' },
];

// ================================================================ HMAC détaillé (RFC 2104, SHA-256)
export function hmacParts(key: Bytes, m: Bytes) {
  const B = 64;
  const k0 = new Uint8Array(B);
  k0.set(key.length > B ? sha256(key) : key);
  const ipadKey = xor(k0, new Uint8Array(B).fill(0x36));
  const opadKey = xor(k0, new Uint8Array(B).fill(0x5c));
  const inner = sha256(concat(ipadKey, m));
  const tag = sha256(concat(opadKey, inner));
  return { k0, hashedKey: key.length > B, ipadKey, opadKey, inner, tag, ok: equal(tag, hmac(sha256, key, m)) };
}

// ================================================================ HKDF pas à pas (RFC 5869, SHA-256)
export function hkdfSteps(ikm: Bytes, salt: Bytes, info: Bytes, L: number) {
  if (L > 255 * 32) throw new Error('L dépasse 255 × 32 octets.');
  const prk = hmac(sha256, salt.length ? salt : new Uint8Array(32), ikm);
  const T: Bytes[] = [];
  let prev = new Uint8Array(0);
  for (let i = 1; T.length * 32 < L; i++) {
    prev = hmac(sha256, prk, concat(prev, info, new Uint8Array([i])));
    T.push(prev);
  }
  return { prk, T, okm: concat(...T).slice(0, L) };
}

// ================================================================ mots de passe
export type PwAlg = 'pbkdf2' | 'scrypt' | 'argon2id';

export interface PwParams {
  iterations: number; // PBKDF2
  logN: number; // scrypt : N = 2^logN
  r: number;
  mKiB: number; // Argon2id
  t: number;
  p: number;
}

export const PW_DEFAULTS: PwParams = { iterations: 600_000, logN: 15, r: 8, mKiB: 19_456, t: 2, p: 1 };

/** Mémoire utilisée par une évaluation (octets) : c'est elle qui coûte cher aux attaquants sur GPU ou ASIC. */
export function pwMemory(alg: PwAlg, P: PwParams): number {
  if (alg === 'pbkdf2') return 64 * 2; // deux blocs SHA-256 : rien
  if (alg === 'scrypt') return 128 * P.r * 2 ** P.logN;
  return P.mKiB * 1024;
}

export async function pwHash(alg: PwAlg, password: Bytes, salt: Bytes, P: PwParams, dkLen = 32): Promise<Bytes> {
  if (alg === 'pbkdf2') return pbkdf2Async(sha256, password, salt, { c: P.iterations, dkLen });
  if (alg === 'scrypt') return scryptAsync(password, salt, { N: 2 ** P.logN, r: P.r, p: P.p, dkLen, maxmem: 2 ** 31 });
  return argon2idAsync(password, salt, { m: P.mKiB, t: P.t, p: P.p, dkLen });
}
