import { describe, expect, it } from 'vite-plus/test';
import { p256 } from '@noble/curves/nist.js';
import { fromHex, toHex, utf8 } from '../lib/bytes';
import {
  JavaRandom, crackJavaRandom, drbgGenerate, drbgInstantiate, drbgReseed, dualEcAttack, dualEcSetup, dualEcStep,
  rfc6979, sourceBytes, stats, verdict, weakKey, crackWeakKey,
} from './rng';

describe('sources et tests statistiques', () => {
  it('getRandomValues passe les trois tests ; le compteur et RANDU ratent le χ²', () => {
    const v = verdict(stats(sourceBytes('crypto', 65536)));
    expect(v.monobit && v.chi2).toBe(true);
    expect(verdict(stats(sourceBytes('counter', 65536))).chi2).toBe(false); // trop parfait
    expect(verdict(stats(sourceBytes('randu', 65536))).chi2).toBe(false); // l'octet de poids faible a une période de 64
  });
});

describe('java.util.Random', () => {
  it('suite connue pour la graine 42 (nextInt)', () => {
    const r = new JavaRandom(42n);
    expect([r.nextInt(), r.nextInt(), r.nextInt()]).toEqual([-1170105035, 234785527, -1360544799]);
  });
  it('deux sorties suffisent à prédire toutes les suivantes', () => {
    const r = new JavaRandom(BigInt(Date.now()));
    const a = r.nextInt(), b = r.nextInt();
    const c = crackJavaRandom(a, b)!;
    const clone = JavaRandom.fromState(c.state);
    for (let i = 0; i < 10; i++) expect(clone.nextInt()).toBe(r.nextInt());
    expect(c.tries).toBeLessThanOrEqual(65536);
  });
});

describe('HMAC-DRBG et RFC 6979', () => {
  it('RFC 6979 A.2.5 : P-256, SHA-256, « sample » → k attendu, et même k que @noble/curves', () => {
    const x = fromHex('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721');
    const r = rfc6979(x, utf8('sample'));
    expect(r.k.toString(16).toUpperCase()).toBe('A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60');
    const sig = p256.sign(utf8('sample'), x, { format: 'compact' });
    const R = p256.Point.BASE.multiply(r.k).toAffine().x % p256.Point.CURVE().n;
    expect(toHex(sig.slice(0, 32))).toBe(R.toString(16).padStart(64, '0'));
  });
  it('DRBG : déterministe à graine égale, différent après reseed ou avec une entrée additionnelle', () => {
    const e = new Uint8Array(32).fill(5), n = new Uint8Array(16).fill(6);
    const a = drbgGenerate(drbgInstantiate(e, n, new Uint8Array(0)), 64);
    const b = drbgGenerate(drbgInstantiate(e, n, new Uint8Array(0)), 64);
    expect(toHex(a.out)).toBe(toHex(b.out));
    expect(a.state.counter).toBe(2);
    const c = drbgGenerate(a.state, 64);
    expect(toHex(c.out)).not.toBe(toHex(a.out));
    expect(toHex(drbgGenerate(drbgReseed(a.state, new Uint8Array(32).fill(9)), 64).out)).not.toBe(toHex(c.out));
    expect(toHex(drbgGenerate(a.state, 64, utf8('x')).out)).not.toBe(toHex(c.out));
  });
});

describe('Dual_EC_DRBG', () => {
  it('avec d, deux sorties tronquées d\'un octet donnent l\'état, puis toutes les sorties suivantes', () => {
    const D = dualEcSetup();
    let s = 123456789n;
    const outs = [];
    for (let i = 0; i < 4; i++) { const r = dualEcStep(D, s, 1); s = r.s; outs.push(r.out); }
    const atk = dualEcAttack(D, outs[0], outs[1], 1)!;
    expect(atk).not.toBeNull();
    const p3 = dualEcStep(D, atk.state, 1);
    expect(toHex(p3.out)).toBe(toHex(outs[2]));
    expect(toHex(dualEcStep(D, p3.s, 1).out)).toBe(toHex(outs[3]));
  });
});

describe('Debian 2008', () => {
  it('une clé tirée d\'un PID se retrouve par recherche exhaustive', async () => {
    const pid = 1234;
    expect(await crackWeakKey(weakKey(pid).pub)).toBe(pid);
  }, 60000);
});
