// Signatures : RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA P-256, Ed25519, ML-DSA-65, SLH-DSA.
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128f, slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { ab, concat, fromHex, i2osp, modPow, os2ip, xor, type Bytes } from '../lib/bytes';
import { mgf1, sha256 } from './kdf';
import { b64uToBig, b64uToBytes, jwkShort, pem } from './keyfmt';
import { seg, type Seg, type View } from './types';
import type { KeyPairViews } from './pke';

const subtle = () => globalThis.crypto.subtle;

export interface SigAlgo<K = any> {
  pipelineSign: string[];
  pipelineVerify: string[];
  variants?: { id: string; label: string }[];
  /** Identifiant JOSE (RFC 7518, RFC 8037, projets IETF pour le post-quantique). */
  jose?: (keys: K) => { alg: string; note: string };
  keygen(variant?: string): Promise<KeyPairViews<K>>;
  sign(keys: K, msg: Bytes): Promise<{ sig: Seg[]; inside: View[] }>;
  verify(keys: K, msg: Bytes, sig: Bytes): Promise<{ ok: boolean; inside: View[] }>;
}

// ================================================================ RSA
interface RsaSigKeys {
  priv: CryptoKey;
  pub: CryptoKey;
  n: bigint;
  e: bigint;
  name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS';
}

async function rsaSigKeygen(name: RsaSigKeys['name']): Promise<KeyPairViews<RsaSigKeys>> {
  const kp = await subtle().generateKey({ name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = await subtle().exportKey('jwk', kp.privateKey);
  const pjwk = await subtle().exportKey('jwk', kp.publicKey);
  const spki = new Uint8Array(await subtle().exportKey('spki', kp.publicKey));
  const n = b64uToBig(jwk.n!);
  return {
    keys: { priv: kp.privateKey, pub: kp.publicKey, n, e: b64uToBig(jwk.e!), name },
    pub: [
      { title: 'Clé publique (n, e)', segs: [seg('n', i2osp(n, 256), 'pub', '2048 bits'), seg('e', b64uToBytes(jwk.e!), 'hdr')] },
      { title: 'JWK', text: jwkShort(pjwk) },
      { title: 'SPKI → PEM', text: pem('PUBLIC KEY', spki) },
    ],
    priv: [
      { title: 'Exposant privé d', segs: [seg('d', i2osp(b64uToBig(jwk.d!), 256), 'priv')] },
      { title: 'JWK privé', text: jwkShort(jwk) },
    ],
  };
}

/** σᵉ mod n : ce que le vérificateur reconstruit (EM). */
const openSig = (K: RsaSigKeys, sig: Bytes) => i2osp(modPow(os2ip(sig), K.e, K.n), 256);

export const DIGESTINFO_SHA256 = fromHex('3031300d060960864801650304020105000420');

export const RSA_PKCS1_SIG: SigAlgo<RsaSigKeys> = {
  jose: () => ({ alg: 'RS256', note: 'RFC 7518 : RSASSA-PKCS1-v1_5 avec SHA-256' }),
  pipelineSign: ['H = SHA-256(M)', 'EM = 00 01 FF…FF 00 ‖ DigestInfo ‖ H', 'σ = EMᵈ mod n'],
  pipelineVerify: ['EM′ = σᵉ mod n', 'Réencoder l\'EM attendu', 'Comparer octet à octet'],
  keygen: () => rsaSigKeygen('RSASSA-PKCS1-v1_5'),
  async sign(K, msg) {
    const sig = new Uint8Array(await subtle().sign({ name: K.name }, K.priv, ab(msg)));
    const em = openSig(K, sig);
    const ffEnd = em.indexOf(0, 2);
    return {
      sig: [seg('σ', sig, 'sig', '256 octets, déterministe : resigner donne la même σ')],
      inside: [
        {
          title: 'EM signé (block type 1), retrouvé par σᵉ mod n',
          caption: 'DigestInfo = SEQUENCE { OID sha256 2.16.840.1.101.3.4.2.1, NULL } ‖ OCTET STRING H, encodé en DER.',
          segs: [seg('00 01', em.slice(0, 2), 'hdr'), seg('FF … FF', em.slice(2, ffEnd), 'pad'), seg('00', em.slice(ffEnd, ffEnd + 1), 'hdr'), seg('DigestInfo (OID SHA-256)', em.slice(ffEnd + 1, ffEnd + 20), 'hdr'), seg('H = SHA-256(M)', em.slice(ffEnd + 20), 'hash')],
        },
      ],
    };
  },
  async verify(K, msg, sig) {
    const ok = await subtle().verify({ name: K.name }, K.pub, ab(sig), ab(msg));
    const expected = sha256(msg);
    return {
      ok,
      inside: [{ title: 'Comparaison du haché', segs: [seg('H(M) recalculé', expected, 'hash'), seg('fin de σᵉ mod n', openSig(K, sig).slice(-32), ok ? 'hash' : 'ct')] }],
    };
  },
};

export const RSA_PSS: SigAlgo<RsaSigKeys> = {
  jose: () => ({ alg: 'PS256', note: 'RFC 7518 : RSASSA-PSS, SHA-256, MGF1-SHA-256, sel de 32 octets' }),
  pipelineSign: ['mHash = SHA-256(M)', 'sel aléatoire', 'H = SHA-256(0⁸ ‖ mHash ‖ sel)', 'EM = (PS ‖ 01 ‖ sel) ⊕ MGF1(H) ‖ H ‖ BC', 'σ = EMᵈ mod n'],
  pipelineVerify: ['EM = σᵉ mod n', 'Démasquer DB, extraire le sel', 'Recalculer H', 'Comparer'],
  keygen: () => rsaSigKeygen('RSA-PSS'),
  async sign(K, msg) {
    const sig = new Uint8Array(await subtle().sign({ name: 'RSA-PSS', saltLength: 32 }, K.priv, ab(msg)));
    return { sig: [seg('σ', sig, 'sig', 'probabiliste : resigner donne une autre σ')], inside: pssDecode(K, sig, msg) };
  },
  async verify(K, msg, sig) {
    const ok = await subtle().verify({ name: 'RSA-PSS', saltLength: 32 }, K.pub, ab(sig), ab(msg));
    return { ok, inside: pssDecode(K, sig, msg) };
  },
};

function pssDecode(K: RsaSigKeys, sig: Bytes, msg: Bytes): View[] {
  const em = openSig(K, sig);
  const maskedDB = em.slice(0, 223);
  const H = em.slice(223, 255);
  const db = xor(maskedDB, mgf1(H, 223));
  db[0] &= 0x7f;
  const salt = db.slice(191);
  const H2 = sha256(concat(new Uint8Array(8), sha256(msg), salt));
  return [
    { title: 'EM = σᵉ mod n', segs: [seg('maskedDB', maskedDB, 'mask'), seg('H', H, 'hash'), seg('BC', em.slice(255), 'hdr', 'octet final 0xBC')] },
    { title: 'DB démasqué = maskedDB ⊕ MGF1(H)', segs: [seg('PS (zéros)', db.slice(0, 190), 'pad'), seg('01', db.slice(190, 191), 'hdr'), seg('sel', salt, 'salt', '32 octets aléatoires')] },
    { title: 'Contrôle : H = SHA-256(0⁸ ‖ mHash ‖ sel)', segs: [seg('H recalculé', H2, 'hash')] },
  ];
}

// ================================================================ ECDSA P-256
interface EcKeys {
  priv: CryptoKey;
  pub: CryptoKey;
  d: Bytes;
  pubRaw: Bytes;
}

export function derFromRaw(raw: Bytes): Bytes {
  const int = (b: Bytes) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v: Bytes = b.slice(i);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

export const ECDSA: SigAlgo<EcKeys> = {
  jose: () => ({ alg: 'ES256', note: 'RFC 7518 : ECDSA P-256 + SHA-256, signature au format brut r ‖ s (64 octets), pas en DER' }),
  pipelineSign: ['h = SHA-256(M)', 'k aléatoire secret', 'r = x(k·G) mod q', 's = k⁻¹(h + d·r) mod q', 'σ = r ‖ s'],
  pipelineVerify: ['u₁ = h·s⁻¹, u₂ = r·s⁻¹', 'R = u₁·G + u₂·Q', 'x(R) mod q = r ?'],
  async keygen() {
    const kp = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const raw = new Uint8Array(await subtle().exportKey('raw', kp.publicKey));
    const jwk = await subtle().exportKey('jwk', kp.privateKey);
    const pjwk = await subtle().exportKey('jwk', kp.publicKey);
    const spki = new Uint8Array(await subtle().exportKey('spki', kp.publicKey));
    const d = b64uToBytes(jwk.d!);
    return {
      keys: { priv: kp.privateKey, pub: kp.publicKey, d, pubRaw: raw },
      pub: [
        { title: 'Q = d·G, non compressé', segs: [seg('04', raw.slice(0, 1), 'hdr'), seg('X', raw.slice(1, 33), 'pub'), seg('Y', raw.slice(33), 'pub')] },
        { title: 'Forme compressée (33 octets)', caption: '02 si Y est pair, 03 sinon : Y se recalcule à partir de X.', segs: [seg(raw[64] & 1 ? '03' : '02', new Uint8Array([raw[64] & 1 ? 3 : 2]), 'hdr'), seg('X', raw.slice(1, 33), 'pub')] },
        { title: 'JWK (ES256)', text: jwkShort(pjwk) },
        { title: 'SPKI → PEM', text: pem('PUBLIC KEY', spki) },
      ],
      priv: [{ title: 'Scalaire privé d', segs: [seg('d', d, 'priv', '32 octets')] }, { title: 'JWK privé', text: jwkShort(jwk) }],
    };
  },
  async sign(K, msg) {
    const raw = new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, K.priv, ab(msg)));
    const der = derFromRaw(raw);
    return {
      sig: [seg('r', raw.slice(0, 32), 'sig'), seg('s', raw.slice(32), 'sig')],
      inside: [
        { title: 'Format brut IEEE P1363 (JOSE, WebCrypto) : r ‖ s, 64 octets', segs: [seg('r', raw.slice(0, 32), 'sig'), seg('s', raw.slice(32), 'sig')] },
        { title: `Format DER (X.509, CMS, OpenSSL) : ${der.length} octets`, caption: 'SEQUENCE { INTEGER r, INTEGER s } ; un 00 est ajouté si le bit de poids fort vaut 1.', segs: [seg('30 len', der.slice(0, 2), 'hdr'), seg('DER r, s', der.slice(2), 'sig')] },
        { title: 'Haché signé', segs: [seg('h = SHA-256(M)', sha256(msg), 'hash')] },
      ],
    };
  },
  async verify(K, msg, sig) {
    return { ok: await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, K.pub, ab(sig), ab(msg)), inside: [] };
  },
};

// ---- Démonstration « PS3 » : deux signatures ECDSA avec le même k révèlent d.
const Fn = p256.Point.Fn;
const q = Fn.ORDER;
const mod = (a: bigint) => ((a % q) + q) % q;
const inv = (a: bigint) => Fn.inv(mod(a));

export function ecdsaWithK(d: bigint, k: bigint, msg: Bytes) {
  const h = mod(os2ip(sha256(msg)));
  const r = mod(p256.Point.BASE.multiply(k).toAffine().x);
  const s = mod(inv(k) * (h + d * r));
  return { h, r, s };
}

export function recoverFromReusedK(a: { h: bigint; r: bigint; s: bigint }, b: { h: bigint; s: bigint }) {
  const k = mod((a.h - b.h) * inv(a.s - b.s));
  const d = mod((a.s * k - a.h) * inv(a.r));
  return { k, d };
}

// ================================================================ Ed25519
interface EdKeys {
  sk: Bytes;
  pk: Bytes;
}

export const ED25519: SigAlgo<EdKeys> = {
  jose: () => ({ alg: 'EdDSA', note: 'RFC 8037 (avec une JWK « OKP », crv Ed25519) ; la RFC 9864 ajoute l\'identifiant explicite « Ed25519 »' }),
  pipelineSign: ['(a, préfixe) = SHA-512(seed)', 'r = H(préfixe ‖ M)', 'R = r·B', 'S = r + H(R ‖ A ‖ M)·a', 'σ = R ‖ S'],
  pipelineVerify: ['S·B = R + H(R ‖ A ‖ M)·A ?'],
  async keygen() {
    const { secretKey: sk, publicKey: pk } = ed25519.keygen();
    return {
      keys: { sk, pk },
      pub: [{ title: 'Clé publique A (RFC 8032)', caption: '32 octets : y en petit-boutiste, le bit de poids fort porte le signe de x.', segs: [seg('A', pk, 'pub')] }],
      priv: [{ title: 'Graine privée', caption: 'La vraie clé a et le préfixe de nonce sont dérivés par SHA-512(graine).', segs: [seg('graine', sk, 'priv', '32 octets')] }],
    };
  },
  async sign(K, msg) {
    const sig = ed25519.sign(msg, K.sk);
    return {
      sig: [seg('R', sig.slice(0, 32), 'sig', 'point r·B'), seg('S', sig.slice(32), 'sig', 'scalaire')],
      inside: [{ title: 'Déterministe par construction', caption: 'r dépend de la clé et du message : resigner donne la même signature, sans risque de nonce répété.', segs: [seg('σ', sig, 'sig', '64 octets')] }],
    };
  },
  async verify(K, msg, sig) {
    let ok = false;
    try {
      ok = ed25519.verify(sig, msg, K.pk);
    } catch {
      ok = false;
    }
    return { ok, inside: [] };
  },
};

// ================================================================ ML-DSA-65
interface PqKeys {
  sk: Bytes;
  pk: Bytes;
  variant?: string;
}

export const MLDSA: SigAlgo<PqKeys> = {
  jose: () => ({ alg: 'ML-DSA-65', note: 'identifiant du projet IETF draft-ietf-cose-dilithium (non encore une RFC)' }),
  pipelineSign: ['μ = H(tr ‖ M)', 'y aléatoire (masque)', 'w = A·y, w₁ = bits hauts', 'c̃ = H(μ ‖ w₁)', 'z = y + c·s₁', 'Rejet si z fuit ? recommencer', 'σ = c̃ ‖ z ‖ h'],
  pipelineVerify: ['w₁′ = UseHint(h, A·z − c·t₁·2ᵈ)', 'c̃ = H(μ ‖ w₁′) ?', '‖z‖∞ borné ?'],
  async keygen() {
    const { publicKey: pk, secretKey: sk } = ml_dsa65.keygen();
    return {
      keys: { pk, sk },
      pub: [{ title: 'Clé publique (FIPS 204)', segs: [seg('ρ', pk.slice(0, 32), 'salt', 'graine de A'), seg('t₁ (6 × 320 octets)', pk.slice(32), 'pub')] }],
      priv: [{ title: 'Clé privée', segs: [seg('ρ', sk.slice(0, 32), 'salt'), seg('K', sk.slice(32, 64), 'priv'), seg('tr = H(pk)', sk.slice(64, 128), 'hash'), seg('s₁', sk.slice(128, 768), 'priv'), seg('s₂', sk.slice(768, 1536), 'priv'), seg('t₀', sk.slice(1536), 'priv')] }],
    };
  },
  async sign(K, msg) {
    const t = performance.now();
    const sig = ml_dsa65.sign(msg, K.sk);
    const ms = performance.now() - t;
    return {
      sig: [seg('c̃', sig.slice(0, 48), 'hash', 'défi'), seg('z (5 polynômes)', sig.slice(48, 3248), 'sig'), seg('h (indices)', sig.slice(3248), 'hdr')],
      inside: [{ title: `Signature ML-DSA-65 : ${sig.length} octets, ${ms.toFixed(0)} ms`, caption: 'Version « hedged » : aléa mélangé au déterminisme, resigner donne une autre σ.', segs: [seg('σ', sig, 'sig')] }],
    };
  },
  async verify(K, msg, sig) {
    return { ok: ml_dsa65.verify(sig, msg, K.pk), inside: [] };
  },
};

// ================================================================ SLH-DSA
const SLH = {
  '128f': { impl: slh_dsa_sha2_128f, n: 16, k: 33, a: 6, d: 22, hp: 3, len: 35 },
  '128s': { impl: slh_dsa_sha2_128s, n: 16, k: 14, a: 12, d: 7, hp: 9, len: 35 },
} as const;

export const SLHDSA: SigAlgo<PqKeys> = {
  jose: (K) => ({ alg: `SLH-DSA-SHA2-${K.variant ?? '128f'}`, note: 'identifiant du projet IETF draft-ietf-cose-sphincs-plus (non encore une RFC)' }),
  variants: [
    { id: '128f', label: 'SLH-DSA-SHA2-128f (rapide, 17 Ko)' },
    { id: '128s', label: 'SLH-DSA-SHA2-128s (compacte, 7,8 Ko, lente)' },
  ],
  pipelineSign: ['R = PRF(SK.prf, opt, M)', 'Indice d\'arbre et de feuille = H(R, PK, M)', 'Signature FORS du condensé', 'Hyper-arbre : d couches WOTS+ + chemins de Merkle', 'σ = R ‖ FORS ‖ HT'],
  pipelineVerify: ['Recalcul de la clé FORS', 'Remontée des d couches', 'Racine = PK.root ?'],
  async keygen(variant = '128f') {
    const P = SLH[variant as keyof typeof SLH];
    const { publicKey: pk, secretKey: sk } = P.impl.keygen();
    return {
      keys: { pk, sk, variant },
      pub: [{ title: 'Clé publique (FIPS 205) : 32 octets seulement', segs: [seg('PK.seed', pk.slice(0, 16), 'salt'), seg('PK.root', pk.slice(16), 'pub', 'racine de l\'hyper-arbre')] }],
      priv: [{ title: 'Clé privée', segs: [seg('SK.seed', sk.slice(0, 16), 'priv'), seg('SK.prf', sk.slice(16, 32), 'priv'), seg('PK.seed', sk.slice(32, 48), 'salt'), seg('PK.root', sk.slice(48), 'pub')] }],
    };
  },
  async sign(K, msg) {
    const P = SLH[(K.variant ?? '128f') as keyof typeof SLH];
    const t = performance.now();
    const sig = P.impl.sign(msg, K.sk);
    const ms = performance.now() - t;
    const fors = P.k * (P.a + 1) * P.n;
    return {
      sig: [seg('R', sig.slice(0, P.n), 'salt'), seg(`FORS (${P.k} arbres)`, sig.slice(P.n, P.n + fors), 'sig'), seg(`Hyper-arbre (${P.d} couches WOTS+)`, sig.slice(P.n + fors), 'sig')],
      inside: [{ title: `${sig.length} octets en ${ms.toFixed(0)} ms`, caption: 'Sécurité fondée uniquement sur la fonction de hachage : le choix conservateur, au prix de la taille et du temps.', segs: [seg('σ', sig, 'sig')] }],
    };
  },
  async verify(K, msg, sig) {
    const P = SLH[(K.variant ?? '128f') as keyof typeof SLH];
    let ok = false;
    try {
      ok = P.impl.verify(sig, msg, K.pk);
    } catch {
      ok = false;
    }
    return { ok, inside: [] };
  },
};

export const SIG: Record<string, SigAlgo> = {
  'rsa-pkcs1-sig': RSA_PKCS1_SIG,
  'rsa-pss': RSA_PSS,
  ecdsa: ECDSA,
  ed25519: ED25519,
  mldsa: MLDSA,
  slhdsa: SLHDSA,
};
