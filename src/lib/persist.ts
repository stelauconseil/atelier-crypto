// État des pages conservé dans le navigateur (localStorage), validé par zod.
//
// Chaque page a une entrée `atelier/v1/<page>` : { v: 1, data: { champ: valeur codée } }.
// Les valeurs sont codées en JSON avec des marqueurs pour ce que JSON ne sait pas porter :
// octets {$b: hex}, entiers longs {$n: décimal}, clés WebCrypto {$k: JWK, alg, usages}.
// Une valeur illisible ou d'un autre format est ignorée : la page repart de ses valeurs par défaut.
import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react';
import { z } from 'zod';
import { fromHex, toHex } from './bytes';

const PREFIX = 'atelier/v1/';
const Envelope = z.object({ v: z.literal(1), data: z.record(z.string(), z.unknown()) });

const store = {
  read(page: string): Record<string, unknown> {
    try {
      const raw = localStorage.getItem(PREFIX + page);
      if (!raw) return {};
      const r = Envelope.safeParse(JSON.parse(raw));
      return r.success ? r.data.data : {};
    } catch {
      return {};
    }
  },
  write(page: string, field: string, value: unknown) {
    try {
      const data = store.read(page);
      if (value === undefined) delete data[field];
      else data[field] = value;
      localStorage.setItem(PREFIX + page, JSON.stringify({ v: 1, data }));
    } catch { /* stockage plein ou indisponible : la page fonctionne sans mémoire */ }
  },
};

// ---------------------------------------------------------------- codage
const Bytes = z.object({ $b: z.string().regex(/^[0-9a-f]*$/) });
const Big = z.object({ $n: z.string().regex(/^-?\d+$/) });
const Key = z.object({ $k: z.record(z.string(), z.unknown()), alg: z.record(z.string(), z.unknown()), usages: z.array(z.string()) });

const isKey = (v: unknown): v is CryptoKey => typeof CryptoKey !== 'undefined' && v instanceof CryptoKey;

/** Code une valeur (octets, bigint, objets, tableaux, clés WebCrypto exportables) en JSON. */
export async function encode(v: unknown): Promise<unknown> {
  if (v instanceof Uint8Array) return { $b: toHex(v) };
  if (typeof v === 'bigint') return { $n: v.toString() };
  if (isKey(v)) {
    const jwk = await crypto.subtle.exportKey('jwk', v);
    const a = v.algorithm as { name: string; namedCurve?: string; hash?: { name: string } };
    return { $k: jwk, alg: { name: a.name, ...(a.namedCurve ? { namedCurve: a.namedCurve } : {}), ...(a.hash ? { hash: a.hash.name } : {}) }, usages: v.usages };
  }
  if (Array.isArray(v)) return Promise.all(v.map(encode));
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) if (typeof x !== 'function' && x !== undefined) o[k] = await encode(x);
    return o;
  }
  return v;
}

/** Inverse d'`encode`. Lève une erreur si une clé WebCrypto ne peut pas être réimportée. */
export async function decode(v: unknown): Promise<unknown> {
  if (Array.isArray(v)) return Promise.all(v.map(decode));
  if (v && typeof v === 'object') {
    const b = Bytes.safeParse(v);
    if (b.success && Object.keys(v).length === 1) return fromHex(b.data.$b);
    const n = Big.safeParse(v);
    if (n.success && Object.keys(v).length === 1) return BigInt(n.data.$n);
    const k = Key.safeParse(v);
    if (k.success) return crypto.subtle.importKey('jwk', k.data.$k as JsonWebKey, k.data.alg as unknown as AlgorithmIdentifier, true, k.data.usages as KeyUsage[]);
    const o: Record<string, unknown> = {};
    for (const [key, x] of Object.entries(v)) o[key] = await decode(x);
    return o;
  }
  return v;
}

/** Version synchrone (sans clés WebCrypto), pour les valeurs simples. */
export function encodeSync(v: unknown): unknown {
  if (v instanceof Uint8Array) return { $b: toHex(v) };
  if (typeof v === 'bigint') return { $n: v.toString() };
  if (Array.isArray(v)) return v.map(encodeSync);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([, x]) => typeof x !== 'function' && x !== undefined).map(([k, x]) => [k, encodeSync(x)]));
  return v;
}

export function decodeSync(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(decodeSync);
  if (v && typeof v === 'object') {
    const b = Bytes.safeParse(v);
    if (b.success && Object.keys(v).length === 1) return fromHex(b.data.$b);
    const n = Big.safeParse(v);
    if (n.success && Object.keys(v).length === 1) return BigInt(n.data.$n);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, decodeSync(x)]));
  }
  return v;
}

// ---------------------------------------------------------------- hooks
/**
 * Comme useState, mais la valeur est conservée par page dans le navigateur.
 * `schema` (zod) vérifie la valeur relue : si elle ne correspond pas (ancien format, valeur
 * altérée à la main), on garde la valeur initiale.
 */
export function usePersisted<T>(page: string, field: string, initial: T | (() => T), schema: z.ZodType<T>): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => {
    const stored = store.read(page)[field];
    if (stored !== undefined) {
      const r = schema.safeParse(decodeSync(stored));
      if (r.success) return r.data;
    }
    return typeof initial === 'function' ? (initial as () => T)() : initial;
  });
  useEffect(() => { store.write(page, field, encodeSync(value)); }, [page, field, value]);
  return [value, setValue];
}

/**
 * État asynchrone (biclés comprenant des clés WebCrypto) : relit l'état enregistré, sinon appelle
 * `make`. Renvoie [valeur, définir (et enregistrer), prêt].
 */
export function usePersistedAsync<T>(page: string, field: string, make: () => Promise<T>, check: (v: unknown) => v is T): [T | null, (v: T) => void, boolean] {
  const [value, setValue] = useState<T | null>(null);
  const [ready, setReady] = useState(false);
  const live = useRef(true);
  useEffect(() => {
    live.current = true;
    setReady(false);
    (async () => {
      let v: T | null = null;
      const stored = store.read(page)[field];
      if (stored !== undefined) {
        try {
          const d = await decode(stored);
          if (check(d)) v = d;
        } catch { /* clé illisible : on régénère */ }
      }
      if (!v) {
        v = await make();
        store.write(page, field, await encode(v));
      }
      if (live.current) { setValue(v); setReady(true); }
    })();
    return () => { live.current = false; };
  }, [page, field]); // eslint-disable-line react-hooks/exhaustive-deps
  const set = useCallback((v: T) => {
    setValue(v);
    void encode(v).then((e) => store.write(page, field, e));
  }, [page, field]);
  return [value, set, ready];
}

/** Lecture impérative d'une valeur enregistrée (clés WebCrypto comprises) ; undefined si absente ou illisible. */
export async function loadValue(page: string, field: string): Promise<unknown> {
  const stored = store.read(page)[field];
  if (stored === undefined) return undefined;
  try {
    return await decode(stored);
  } catch {
    return undefined;
  }
}

export function saveValue(page: string, field: string, v: unknown) {
  void encode(v).then((e) => store.write(page, field, e)).catch(() => { /* valeur non enregistrable */ });
}

/** Une biclé et ses vues, telles que renvoyées par les `keygen()` de l'atelier. */
export function isKeyPair(v: unknown): v is { keys: unknown; pub: unknown[]; priv: unknown[] } {
  return !!v && typeof v === 'object' && 'keys' in v && Array.isArray((v as { pub?: unknown }).pub) && Array.isArray((v as { priv?: unknown }).priv);
}

// ---------------------------------------------------------------- réinitialisation
const RESET = 'atelier-reset';

/** Pages qui ont un état enregistré. */
export function savedPages(): string[] {
  try {
    return Object.keys(localStorage).filter((k) => k.startsWith(PREFIX)).map((k) => k.slice(PREFIX.length));
  } catch {
    return [];
  }
}

export function hasSaved(page: string): boolean {
  return Object.keys(store.read(page)).length > 0;
}

/** Efface l'état d'une page (ou de toutes avec '*') et prévient les pages affichées. */
export function resetState(page: string | '*') {
  try {
    for (const p of page === '*' ? savedPages() : [page]) localStorage.removeItem(PREFIX + p);
  } catch { /* rien à effacer */ }
  window.dispatchEvent(new CustomEvent(RESET, { detail: page }));
}

/** Compteur qui change quand l'état de `page` est effacé : à utiliser comme `key` pour remonter la page. */
export function useResetNonce(page: string): number {
  const [n, setN] = useState(0);
  useEffect(() => {
    const on = (e: Event) => {
      const p = (e as CustomEvent<string>).detail;
      if (p === '*' || p === page) setN((x) => x + 1);
    };
    window.addEventListener(RESET, on);
    return () => window.removeEventListener(RESET, on);
  }, [page]);
  return n;
}

// Schémas réutilisables.
export const zBytes = z.instanceof(Uint8Array);
export const zBig = z.bigint();
export { z };
