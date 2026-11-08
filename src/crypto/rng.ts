// Aléa et générateurs : générateur du système, tests statistiques, java.util.Random et sa prédiction,
// HMAC-DRBG (SP 800-90A) et nonces RFC 6979, Dual_EC_DRBG et sa porte dérobée, l'entropie manquante (Debian 2008).
import { x25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, i2osp, os2ip, utf8, type Bytes } from '../lib/bytes';

// ================================================================ sources d'octets
export type SourceId = 'crypto' | 'math' | 'randu' | 'counter';

export const SOURCES: Record<SourceId, { label: string; note: string }> = {
  crypto: { label: 'crypto.getRandomValues', note: 'générateur cryptographique du système, alimenté par l\'entropie du noyau' },
  math: { label: 'Math.random', note: 'xorshift128+ dans V8 : statistiquement correct, mais prévisible à partir de quelques sorties' },
  randu: { label: 'RANDU (IBM, 1968)', note: 'xₙ₊₁ = 65 539 · xₙ mod 2³¹ : on garde l\'octet de poids faible' },
  counter: { label: 'Compteur', note: '0, 1, 2, 3… : parfaitement équilibré, totalement prévisible' },
};

export function sourceBytes(id: SourceId, n: number, seed = 1): Bytes {
  const out = new Uint8Array(n);
  if (id === 'crypto') {
    for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  } else if (id === 'math') {
    for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  } else if (id === 'randu') {
    let x = (seed | 1) >>> 0;
    for (let i = 0; i < n; i++) {
      x = Number((BigInt(x) * 65539n) % 2147483648n);
      out[i] = x & 255;
    }
  } else {
    for (let i = 0; i < n; i++) out[i] = i & 255;
  }
  return out;
}

// ================================================================ tests statistiques (SP 800-22, simplifiés)
export interface Stats {
  ones: number;
  bits: number;
  monobitZ: number;
  runs: number;
  runsExpected: number;
  chi2: number;
  histogram: number[];
}

export function stats(b: Bytes): Stats {
  let ones = 0;
  let runs = 1;
  let prev = -1;
  const histogram = new Array(256).fill(0);
  for (let i = 0; i < b.length; i++) {
    histogram[b[i]]++;
    for (let j = 7; j >= 0; j--) {
      const bit = (b[i] >> j) & 1;
      ones += bit;
      if (prev !== -1 && bit !== prev) runs++;
      prev = bit;
    }
  }
  const bits = b.length * 8;
  const p = ones / bits;
  const exp = b.length / 256;
  const chi2 = histogram.reduce((s, o) => s + (o - exp) ** 2 / exp, 0);
  return { ones, bits, monobitZ: (ones - bits / 2) / Math.sqrt(bits / 4), runs, runsExpected: 2 * bits * p * (1 - p) + 1, chi2, histogram };
}

/** Verdicts grossiers : |z| < 3 pour la fréquence ; χ² à 255 degrés de liberté entre 190 et 330 (≈ 0,1 % de chaque côté). */
export const verdict = (s: Stats) => ({
  monobit: Math.abs(s.monobitZ) < 3,
  runs: Math.abs(s.runs - s.runsExpected) < 3 * Math.sqrt(s.runsExpected / 2),
  chi2: s.chi2 > 190 && s.chi2 < 330,
});

// ================================================================ java.util.Random (LCG de 48 bits)
const MULT = 0x5deece66dn;
const ADD = 0xbn;
const MASK = (1n << 48n) - 1n;

export class JavaRandom {
  seed: bigint;
  constructor(seed: bigint) {
    this.seed = (seed ^ MULT) & MASK;
  }
  static fromState(state: bigint) {
    const r = new JavaRandom(0n);
    r.seed = state & MASK;
    return r;
  }
  next(bits: number): number {
    this.seed = (this.seed * MULT + ADD) & MASK;
    return Number(BigInt.asIntN(32, this.seed >> BigInt(48 - bits)));
  }
  nextInt(): number {
    return this.next(32);
  }
}

/**
 * Deux sorties consécutives de nextInt() suffisent : la première donne les 32 bits hauts de l'état,
 * il reste 16 bits à deviner, que la seconde sortie départage. Renvoie l'état après la seconde sortie.
 */
export function crackJavaRandom(i1: number, i2: number): { state: bigint; tries: number } | null {
  const hi = BigInt(i1 >>> 0) << 16n;
  for (let low = 0; low < 65536; low++) {
    const s = hi | BigInt(low);
    const s2 = (s * MULT + ADD) & MASK;
    if (Number(BigInt.asIntN(32, s2 >> 16n)) === i2) return { state: s2, tries: low + 1 };
  }
  return null;
}

// ================================================================ HMAC-DRBG (SP 800-90A, SHA-256)
export interface DrbgState {
  K: Bytes;
  V: Bytes;
  counter: number;
}

const H = (k: Bytes, ...m: Bytes[]) => hmac(sha256, k, concat(...m));

export function drbgUpdate(s: DrbgState, data?: Bytes): DrbgState {
  const d = data ?? new Uint8Array(0);
  let K = H(s.K, s.V, new Uint8Array([0]), d);
  let V = H(K, s.V);
  if (d.length) {
    K = H(K, V, new Uint8Array([1]), d);
    V = H(K, V);
  }
  return { ...s, K, V };
}

export function drbgInstantiate(entropy: Bytes, nonce: Bytes, perso: Bytes): DrbgState {
  return drbgUpdate({ K: new Uint8Array(32), V: new Uint8Array(32).fill(1), counter: 1 }, concat(entropy, nonce, perso));
}

export function drbgGenerate(s0: DrbgState, n: number, addl?: Bytes): { out: Bytes; state: DrbgState; blocks: Bytes[] } {
  let s = addl?.length ? drbgUpdate(s0, addl) : s0;
  const blocks: Bytes[] = [];
  let V = s.V;
  while (blocks.length * 32 < n) {
    V = H(s.K, V);
    blocks.push(V);
  }
  s = drbgUpdate({ ...s, V }, addl);
  return { out: concat(...blocks).slice(0, n), state: { ...s, counter: s0.counter + 1 }, blocks };
}

export function drbgReseed(s: DrbgState, entropy: Bytes, addl?: Bytes): DrbgState {
  return { ...drbgUpdate(s, concat(entropy, addl ?? new Uint8Array(0))), counter: 1 };
}

// ================================================================ RFC 6979 : le nonce ECDSA tiré d'un HMAC-DRBG
const N = p256.Point.CURVE().n;

export function rfc6979(priv: Bytes, msg: Bytes) {
  const h1 = sha256(msg);
  const h1mod = i2osp(os2ip(h1) % N, 32);
  const s = drbgUpdate({ K: new Uint8Array(32), V: new Uint8Array(32).fill(1), counter: 1 }, concat(priv, h1mod));
  const seed = { K: s.K, V: s.V };
  let { K, V } = s;
  for (let tries = 1; ; tries++) {
    V = H(K, V);
    const k = os2ip(V);
    if (k >= 1n && k < N) return { h1, h1mod, seed, k, tries };
    K = H(K, V, new Uint8Array([0]));
    V = H(K, V);
  }
}

// ================================================================ Dual_EC_DRBG (simplifié, sur P-256)
export interface DualEc {
  /** Q : point public de la norme ; P = d·Q, publié lui aussi. d ne l'est pas. */
  P: Bytes;
  Q: Bytes;
  d: bigint;
}

const Point = p256.Point;
const xOf = (pt: InstanceType<typeof Point>) => pt.toAffine().x;
const rndScalar = () => 1n + (os2ip(crypto.getRandomValues(new Uint8Array(40))) % (N - 1n));

/** Le concepteur choisit d au hasard et publie P = d·Q : rien, dans P et Q, ne trahit d. */
export function dualEcSetup(): DualEc {
  const q = rndScalar();
  const d = rndScalar();
  const Q = Point.BASE.multiply(q);
  return { P: Q.multiply(d).toBytes(false), Q: Q.toBytes(false), d };
}

/** Une étape : s ← x(s·P) ; sortie = x(s·Q) privée de ses `drop` premiers octets (2 dans la norme). */
export function dualEcStep(D: DualEc, s: bigint, drop: number): { s: bigint; out: Bytes } {
  const s1 = xOf(Point.fromBytes(D.P).multiply(s));
  const r = xOf(Point.fromBytes(D.Q).multiply(s1));
  return { s: s1, out: i2osp(r, 32).slice(drop) };
}

/**
 * L'attaque : pour chaque préfixe possible, on relève la sortie en un point R = s·Q, puis d·R = s·P,
 * dont l'abscisse est l'état suivant. La sortie suivante départage les candidats.
 */
export function dualEcAttack(D: DualEc, out1: Bytes, out2: Bytes, drop: number) {
  let tried = 0;
  let onCurve = 0;
  for (let pre = 0; pre < 256 ** drop; pre++) {
    tried++;
    const x = concat(i2osp(BigInt(pre), drop), out1);
    let R;
    try {
      R = Point.fromBytes(concat(new Uint8Array([2]), x));
    } catch {
      continue;
    }
    onCurve++;
    const sNext = xOf(R.multiply(D.d)); // = x(s·P) : l'état qui produira la sortie suivante
    const guess = i2osp(xOf(Point.fromBytes(D.Q).multiply(sNext)), 32).slice(drop);
    if (guess.every((v, i) => v === out2[i])) return { state: sNext, tried, onCurve };
  }
  return null;
}

// ================================================================ Debian OpenSSL (2006-2008) : 15 bits d'entropie
/** La clé ne dépend que du PID du processus (1 à 32 768) : on la recalcule à partir de lui. */
export function weakKey(pid: number) {
  const priv = sha256(utf8(`openssl-debian-pid-${pid}`));
  return { priv, pub: x25519.getPublicKey(priv) };
}

/** Recherche exhaustive par tranches (pour laisser respirer l'interface). */
export async function crackWeakKey(target: Bytes, onProgress?: (done: number) => void): Promise<number | null> {
  const t = target.join(',');
  for (let pid = 1; pid <= 32768; pid++) {
    if (weakKey(pid).pub.join(',') === t) return pid;
    if (pid % 1024 === 0) {
      onProgress?.(pid);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  return null;
}
