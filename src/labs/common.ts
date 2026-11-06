import type { Seg } from '../crypto/types';
import { CryptoRejected } from '../crypto/types';

/** Inverse un bit d'un octet choisi dans le premier segment du ton préféré (chiffré, signature…). */
export function tamper(segs: Seg[], prefer: string[] = ['ct', 'sig', 'enc', 'tag']): { segs: Seg[]; where: string } {
  let idx = segs.findIndex((s) => prefer.includes(s.tone) && s.bytes.length > 0);
  if (idx < 0) idx = 0;
  const s = segs[idx];
  const pos = Math.floor(Math.random() * s.bytes.length);
  const b = new Uint8Array(s.bytes);
  const before = b[pos];
  b[pos] ^= 0x01;
  const out = segs.map((x, i) => (i === idx ? { ...x, bytes: b, note: 'altéré' } : x));
  return { segs: out, where: `${s.label}, octet n° ${pos + 1} : 0x${before.toString(16).padStart(2, '0')} → 0x${b[pos].toString(16).padStart(2, '0')}` };
}

export function errText(e: unknown): string {
  if (e instanceof CryptoRejected) return e.message;
  if (e instanceof Error) return `Erreur : ${e.message}`;
  return String(e);
}
