import { describe, expect, it } from 'vite-plus/test';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, fromHex, toHex, utf8 } from '../lib/bytes';
import { HASHES, avalancheByRounds, roundsToAvalanche, bitDiff, flipBit, hkdfSteps, hmacParts, pwHash, sha256Padded, PW_DEFAULTS } from './hash';
import { mySha256, sha256Rounds } from './mac';

describe('fonctions de hachage', () => {
  it('vecteurs : SHA-256, SHA3-256, Keccak-256, BLAKE2s, BLAKE2b de la chaîne vide', () => {
    const e = new Uint8Array(0);
    expect(toHex(HASHES.sha256.h(e))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(toHex(HASHES.sha3_256.h(e))).toBe('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
    expect(toHex(HASHES.keccak256.h(e))).toBe('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    expect(toHex(HASHES.blake2s.h(e))).toBe('69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9');
    expect(toHex(HASHES.blake2b.h(e))).toBe('786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce');
    expect(toHex(HASHES.blake3.h(e))).toBe('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262');
  });
  it('bourrage SHA-256 : 0x80, zéros, longueur ; 55 octets tiennent dans un bloc, 56 en demandent deux', () => {
    const p = sha256Padded(utf8('abc'));
    expect(p.mark[0]).toBe(0x80);
    expect(toHex(p.len)).toBe('0000000000000018');
    expect(sha256Padded(new Uint8Array(55)).blocks).toBe(1);
    expect(sha256Padded(new Uint8Array(56)).blocks).toBe(2);
  });
  it('SHA-256 réduit : 64 tours = SHA-256 ; l\'avalanche s\'installe en une vingtaine de tours', () => {
    const m = utf8('Rendez-vous à 14 h');
    expect(toHex(sha256Rounds(m, 64))).toBe(toHex(sha256(m)));
    expect(toHex(mySha256(m))).toBe(toHex(sha256(m)));
    const early = avalancheByRounds(m, 0);
    const late = avalancheByRounds(m, 54);
    expect(early[0]).toBeLessThan(40);
    expect(roundsToAvalanche(early)).toBeLessThan(8);
    expect(roundsToAvalanche(late)).toBeGreaterThan(14);
    expect(roundsToAvalanche(late)).toBeLessThan(24);
    expect(late[12]).toBe(0); // w₁₃ n'est pas encore entré au 13e tour
    expect(bitDiff(sha256(m), sha256(flipBit(m, 0)))).toBeGreaterThan(90);
  });
  it('BLAKE2 avec clé = MAC ; XOF de longueur choisie', () => {
    const k = new Uint8Array(32).fill(1);
    expect(toHex(HASHES.blake2s.h(utf8('x'), { key: k }))).not.toBe(toHex(HASHES.blake2s.h(utf8('x'))));
    expect(HASHES.shake128.h(utf8('x'), { dkLen: 100 })).toHaveLength(100);
    expect(HASHES.blake3.h(utf8('x'), { dkLen: 64 })).toHaveLength(64);
  });
});

describe('HMAC et HKDF', () => {
  it('HMAC détaillé = HMAC de la bibliothèque, clé courte et clé longue (hachée)', () => {
    for (const k of [utf8('clé'), new Uint8Array(100).fill(7)]) {
      const r = hmacParts(k, utf8('message'));
      expect(r.ok).toBe(true);
      expect(toHex(r.tag)).toBe(toHex(hmac(sha256, k, utf8('message'))));
    }
  });
  it('HKDF : vecteur de test 1 de RFC 5869', () => {
    const r = hkdfSteps(fromHex('0b'.repeat(22)), fromHex('000102030405060708090a0b0c'), fromHex('f0f1f2f3f4f5f6f7f8f9'), 42);
    expect(toHex(r.prk)).toBe('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
    expect(toHex(r.okm)).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
    expect(r.T).toHaveLength(2);
    expect(toHex(concat(...r.T)).startsWith(toHex(r.okm))).toBe(true);
  });
});

describe('mots de passe', () => {
  it('PBKDF2, scrypt, Argon2id : déterministes à sel égal, différents à sel différent', async () => {
    const P = { ...PW_DEFAULTS, iterations: 1000, logN: 10, mKiB: 256, t: 1 };
    for (const alg of ['pbkdf2', 'scrypt', 'argon2id'] as const) {
      const a = await pwHash(alg, utf8('motdepasse'), utf8('sel-0001'), P);
      expect(toHex(a)).toBe(toHex(await pwHash(alg, utf8('motdepasse'), utf8('sel-0001'), P)));
      expect(toHex(a)).not.toBe(toHex(await pwHash(alg, utf8('motdepasse'), utf8('sel-0002'), P)));
    }
  });
  it('PBKDF2-HMAC-SHA256 : vecteur connu (1 itération, « password », « salt »)', async () => {
    const r = await pwHash('pbkdf2', utf8('password'), utf8('salt'), { ...PW_DEFAULTS, iterations: 1 }, 32);
    expect(toHex(r)).toBe('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
  });
});
