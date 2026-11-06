// Chiffrement à clé publique : RSA (textbook, PKCS#1 v1.5, OAEP, KEM), ECIES, HPKE, ML-KEM, hybride.
import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ab, concat, equal, i2osp, modPow, os2ip, rand, utf8, xor, type Bytes } from '../lib/bytes';
import { hkdf, hkdfExpand, hkdfExtract, mgf1, sha256, x963kdf } from './kdf';
import { b64uToBig, b64uToBytes, jwkShort, pem } from './keyfmt';
import { CryptoRejected, seg, type Seg, type View } from './types';

const subtle = () => globalThis.crypto.subtle;

export interface KeyPairViews<K> {
  keys: K;
  pub: View[];
  priv: View[];
}

export interface PkeAlgo<K = any> {
  pipelineEnc: string[];
  pipelineDec: string[];
  /** Taille maximale du clair en octets (schémas qui chiffrent directement avec RSA). */
  maxPt?: (keys: K) => number;
  keygen(): Promise<KeyPairViews<K>>;
  encrypt(keys: K, pt: Bytes): Promise<{ wire: Seg[]; inside: View[] }>;
  decrypt(keys: K, wire: Bytes): Promise<{ pt: Bytes; inside: View[] }>;
}

// ================================================================ RSA
export interface RsaKeys {
  n: bigint;
  e: bigint;
  d: bigint;
  k: number; // taille du module en octets
  oaepPriv: CryptoKey;
}

export async function rsaKeygen(): Promise<KeyPairViews<RsaKeys>> {
  const kp = await subtle().generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
  const jwk = await subtle().exportKey('jwk', kp.privateKey);
  const pubJwk = await subtle().exportKey('jwk', kp.publicKey);
  const spki = new Uint8Array(await subtle().exportKey('spki', kp.publicKey));
  const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', kp.privateKey));
  const n = b64uToBig(jwk.n!);
  const e = b64uToBig(jwk.e!);
  const d = b64uToBig(jwk.d!);
  const k = 256;
  return {
    keys: { n, e, d, k, oaepPriv: kp.privateKey },
    pub: [
      {
        title: 'Clé publique brute (n, e)',
        caption: 'n = p·q, module de 2048 bits ; e = 65537 (0x010001).',
        segs: [seg('Module n', i2osp(n, k), 'pub', '256 octets'), seg('Exposant public e', i2osp(e, 3), 'hdr')],
      },
      { title: 'JWK (RFC 7517)', text: jwkShort(pubJwk) },
      { title: 'SubjectPublicKeyInfo DER → PEM', caption: `${spki.length} octets : en-tête ASN.1 + RSAPublicKey (n, e)`, text: pem('PUBLIC KEY', spki) },
    ],
    priv: [
      {
        title: 'Exposant privé d',
        caption: 'e·d ≡ 1 mod λ(n). Le JWK et le PKCS#8 contiennent aussi p, q, dp, dq, qi (accélération CRT).',
        segs: [seg('d', i2osp(d, k), 'priv')],
      },
      { title: 'JWK privé', text: jwkShort(jwk) },
      { title: 'PKCS#8 DER → PEM', caption: `${pkcs8.length} octets`, text: pem('PRIVATE KEY', pkcs8) },
    ],
  };
}

const rsaPub = (K: RsaKeys, m: bigint) => modPow(m, K.e, K.n);
const rsaPriv = (K: RsaKeys, c: bigint) => modPow(c, K.d, K.n);

export const RSA_TEXTBOOK: PkeAlgo<RsaKeys> = {
  pipelineEnc: ['m = entier(M)', 'c = mᵉ mod n'],
  pipelineDec: ['m = cᵈ mod n', 'M = octets(m)'],
  maxPt: (K) => K.k - 1,
  keygen: rsaKeygen,
  async encrypt(K, pt) {
    const m = os2ip(pt);
    const c = rsaPub(K, m);
    return {
      wire: [seg('c = mᵉ mod n', i2osp(c, K.k), 'ct', 'déterministe : rechiffrer donne le même c')],
      inside: [
        {
          title: 'Le clair vu comme un entier',
          caption: 'Aucun aléa, aucun remplissage : c est déterministe (on peut tester des clairs candidats) et malléable : (c·sᵉ) déchiffre en m·s.',
          segs: [seg('m', pt, 'pt', `${pt.length} octets, m < n`)],
        },
      ],
    };
  },
  async decrypt(K, wire) {
    const m = rsaPriv(K, os2ip(wire));
    let b = i2osp(m, K.k);
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    return { pt: b, inside: [{ title: 'm = cᵈ mod n', segs: [seg('m', b, 'pt')] }] };
  },
};

function pkcs1v15Encode(K: RsaKeys, M: Bytes): { em: Bytes; ps: Bytes } {
  const psLen = K.k - M.length - 3;
  if (psLen < 8) throw new CryptoRejected(`Message trop long : ${K.k - 11} octets au plus pour RSA-2048.`);
  const ps = new Uint8Array(psLen);
  for (let i = 0; i < psLen; i++) {
    let x = 0;
    while (x === 0) x = rand(1)[0];
    ps[i] = x;
  }
  return { em: concat(new Uint8Array([0, 2]), ps, new Uint8Array([0]), M), ps };
}

export const RSA_PKCS1V15: PkeAlgo<RsaKeys> = {
  pipelineEnc: ['EM = 00 ‖ 02 ‖ PS ‖ 00 ‖ M', 'c = EMᵉ mod n'],
  pipelineDec: ['EM = cᵈ mod n', 'EM commence par 00 02 ?', 'Chercher le 00 séparateur', 'M'],
  maxPt: (K) => K.k - 11,
  keygen: rsaKeygen,
  async encrypt(K, pt) {
    const { em, ps } = pkcs1v15Encode(K, pt);
    const c = rsaPub(K, os2ip(em));
    return {
      wire: [seg('c = EMᵉ mod n', i2osp(c, K.k), 'ct')],
      inside: [
        {
          title: 'EM : message encodé (block type 2)',
          caption: `PS = ${ps.length} octets aléatoires tous ≠ 00 ; le 00 qui suit marque le début de M.`,
          segs: [seg('00', new Uint8Array([0]), 'hdr'), seg('02', new Uint8Array([2]), 'hdr', 'block type 2 : chiffrement'), seg('PS', ps, 'pad', 'bourrage ≥ 8 octets non nuls'), seg('00', new Uint8Array([0]), 'hdr', 'séparateur'), seg('M', pt, 'pt')],
        },
      ],
    };
  },
  async decrypt(K, wire) {
    const em = i2osp(rsaPriv(K, os2ip(wire)), K.k);
    const view: View = { title: 'EM = cᵈ mod n, tel que le voit le destinataire', segs: [seg('EM', em, em[0] === 0 && em[1] === 2 ? 'pad' : 'ct')] };
    if (em[0] !== 0 || em[1] !== 2)
      throw new CryptoRejected(`EM commence par ${em[0].toString(16).padStart(2, '0')} ${em[1].toString(16).padStart(2, '0')} au lieu de 00 02 : remplissage invalide. Répondre cela à l'attaquant, c'est l'oracle de Bleichenbacher.`);
    let i = 2;
    while (i < em.length && em[i] !== 0) i++;
    if (i === em.length || i < 10) throw new CryptoRejected('Séparateur 00 absent ou PS trop court : remplissage invalide (oracle).');
    const M = em.slice(i + 1);
    view.segs = [seg('00 02', em.slice(0, 2), 'hdr'), seg('PS', em.slice(2, i), 'pad'), seg('00', em.slice(i, i + 1), 'hdr'), seg('M', M, 'pt')];
    return { pt: M, inside: [view] };
  },
};

const LHASH = sha256(new Uint8Array(0));

export function oaepEncode(k: number, M: Bytes, seed = rand(32)) {
  const hLen = 32;
  const psLen = k - M.length - 2 * hLen - 2;
  if (psLen < 0) throw new CryptoRejected(`Message trop long : ${k - 2 * hLen - 2} octets au plus (RSA-2048, SHA-256).`);
  const ps = new Uint8Array(psLen);
  const db = concat(LHASH, ps, new Uint8Array([1]), M);
  const maskedDB = xor(db, mgf1(seed, k - hLen - 1));
  const maskedSeed = xor(seed, mgf1(maskedDB, hLen));
  return { em: concat(new Uint8Array([0]), maskedSeed, maskedDB), seed, db, ps, maskedDB, maskedSeed };
}

export const RSA_OAEP: PkeAlgo<RsaKeys> = {
  pipelineEnc: ['DB = lHash ‖ PS ‖ 01 ‖ M', 'seed aléatoire', 'maskedDB = DB ⊕ MGF1(seed)', 'maskedSeed = seed ⊕ MGF1(maskedDB)', 'c = EMᵉ mod n'],
  pipelineDec: ['EM = cᵈ mod n', 'seed = maskedSeed ⊕ MGF1(maskedDB)', 'DB = maskedDB ⊕ MGF1(seed)', 'Vérifier lHash et 01', 'M'],
  maxPt: (K) => K.k - 66,
  keygen: rsaKeygen,
  async encrypt(K, pt) {
    const o = oaepEncode(K.k, pt);
    const c = rsaPub(K, os2ip(o.em));
    return {
      wire: [seg('c = EMᵉ mod n', i2osp(c, K.k), 'ct', 'probabiliste : chaque chiffrement diffère')],
      inside: [
        {
          title: 'Avant masquage : DB et seed',
          segs: [seg('lHash = SHA-256("")', LHASH, 'hash'), seg('PS (zéros)', o.ps, 'pad'), seg('01', new Uint8Array([1]), 'hdr'), seg('M', pt, 'pt')],
        },
        { title: 'Graine aléatoire', segs: [seg('seed', o.seed, 'salt', '32 octets')] },
        {
          title: 'EM = 00 ‖ maskedSeed ‖ maskedDB (réseau de Feistel à deux tours)',
          caption: 'Tout EM ressemble à de l\'aléa : sans clé privée, impossible de vérifier un format, donc pas d\'oracle simple.',
          segs: [seg('00', new Uint8Array([0]), 'hdr'), seg('maskedSeed', o.maskedSeed, 'mask'), seg('maskedDB', o.maskedDB, 'mask')],
        },
      ],
    };
  },
  async decrypt(K, wire) {
    // Déchiffrement par l'implémentation WebCrypto du navigateur (preuve d'interopérabilité)…
    let pt: Bytes;
    try {
      pt = new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, K.oaepPriv, ab(wire)));
    } catch {
      throw new CryptoRejected('⊥ — décodage OAEP invalide (lHash, séparateur 01 ou octet de tête).');
    }
    // … puis décodage pas à pas pour l'affichage.
    const em = i2osp(rsaPriv(K, os2ip(wire)), K.k);
    const maskedSeed = em.slice(1, 33);
    const maskedDB = em.slice(33);
    const seed = xor(maskedSeed, mgf1(maskedDB, 32));
    const db = xor(maskedDB, mgf1(seed, K.k - 33));
    const one = db.indexOf(1, 32);
    return {
      pt,
      inside: [
        { title: 'EM = cᵈ mod n', segs: [seg('00', em.slice(0, 1), 'hdr'), seg('maskedSeed', maskedSeed, 'mask'), seg('maskedDB', maskedDB, 'mask')] },
        { title: 'Démasqué', caption: 'Déchiffré par WebCrypto (RSA-OAEP, SHA-256), puis redécodé ici à la main.', segs: [seg('seed', seed, 'salt'), seg('lHash', db.slice(0, 32), 'hash'), seg('PS', db.slice(32, one), 'pad'), seg('01', db.slice(one, one + 1), 'hdr'), seg('M', db.slice(one + 1), 'pt')] },
      ],
    };
  },
};

export const RSA_KEM: PkeAlgo<RsaKeys> = {
  pipelineEnc: ['r aléatoire dans [0, n)', 'enc = rᵉ mod n', 'K ‖ nonce = KDF2(r)', 'AES-256-GCM', 'enc ‖ C ‖ tag'],
  pipelineDec: ['r = encᵈ mod n', 'K ‖ nonce = KDF2(r)', 'AES-GCM.Open', 'Clair ou ⊥'],
  keygen: rsaKeygen,
  async encrypt(K, pt) {
    const r = os2ip(rand(K.k)) % K.n;
    const enc = i2osp(rsaPub(K, r), K.k);
    const z = i2osp(r, K.k);
    const km = x963kdf(z, new Uint8Array(0), 44);
    const out = gcm(km.slice(0, 32), km.slice(32)).encrypt(pt);
    return {
      wire: [seg('enc = rᵉ mod n', enc, 'enc'), seg('C', out.slice(0, -16), 'ct'), seg('tag', out.slice(-16), 'tag')],
      inside: [
        { title: 'Le secret encapsulé : un entier aléatoire r', caption: 'Aucun remplissage : r est uniforme, la clé est K = KDF(r).', segs: [seg('r', z, 'secret')] },
        { title: 'Dérivation (KDF2 / X9.63, SHA-256)', segs: [seg('Clé AES-256', km.slice(0, 32), 'key'), seg('Nonce', km.slice(32), 'nonce')] },
      ],
    };
  },
  async decrypt(K, wire) {
    const enc = wire.slice(0, K.k);
    const z = i2osp(rsaPriv(K, os2ip(enc)), K.k);
    const km = x963kdf(z, new Uint8Array(0), 44);
    try {
      return { pt: gcm(km.slice(0, 32), km.slice(32)).decrypt(wire.slice(K.k)), inside: [{ title: 'r retrouvé', segs: [seg('r', z, 'secret')] }] };
    } catch {
      throw new CryptoRejected('⊥ — tag invalide : enc ou C altéré (la clé dérivée diffère).');
    }
  },
};

// ================================================================ ECIES (variante Apple)
export interface EcKeys {
  priv: CryptoKey;
  pubRaw: Bytes;
}

export const ECIES: PkeAlgo<EcKeys> = {
  pipelineEnc: ['Biclé éphémère (e, E = e·G)', 'Z = x(e·Q_B)', 'K ‖ IV = X9.63-KDF(Z, E)', 'AES-128-GCM', 'E ‖ C ‖ tag'],
  pipelineDec: ['Z = x(d_B·E)', 'K ‖ IV = X9.63-KDF(Z, E)', 'AES-GCM.Open', 'Clair ou ⊥'],
  async keygen() {
    const kp = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const raw = new Uint8Array(await subtle().exportKey('raw', kp.publicKey));
    const jwk = await subtle().exportKey('jwk', kp.privateKey);
    const pjwk = await subtle().exportKey('jwk', kp.publicKey);
    const spki = new Uint8Array(await subtle().exportKey('spki', kp.publicKey));
    return {
      keys: { priv: kp.privateKey, pubRaw: raw },
      pub: [
        { title: 'Point public Q_B, non compressé (SEC 1)', segs: [seg('04', raw.slice(0, 1), 'hdr', 'non compressé'), seg('X', raw.slice(1, 33), 'pub'), seg('Y', raw.slice(33), 'pub')] },
        { title: 'JWK', text: jwkShort(pjwk) },
        { title: 'SPKI → PEM', text: pem('PUBLIC KEY', spki) },
      ],
      priv: [
        { title: 'Scalaire privé d_B', caption: 'Dans la Secure Enclave, ces 32 octets ne sortiraient jamais.', segs: [seg('d', b64uToBytes(jwk.d!), 'priv')] },
        { title: 'JWK privé', text: jwkShort(jwk) },
      ],
    };
  },
  async encrypt(K, pt) {
    const pub = await subtle().importKey('raw', ab(K.pubRaw), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    const eph = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const E = new Uint8Array(await subtle().exportKey('raw', eph.publicKey));
    const Z = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256));
    const km = x963kdf(Z, E, 32);
    const out = gcm(km.slice(0, 16), km.slice(16)).encrypt(pt);
    return {
      wire: [seg('E = e·G', E, 'enc', 'point éphémère, 65 octets'), seg('C', out.slice(0, -16), 'ct'), seg('tag', out.slice(-16), 'tag')],
      inside: [
        { title: 'Secret ECDH', caption: 'Z n\'est jamais utilisé tel quel : il passe par le KDF, avec E en sharedInfo.', segs: [seg('Z = x(e·Q_B)', Z, 'secret')] },
        { title: 'X9.63-KDF(Z, sharedInfo = E) → 32 octets', segs: [seg('Clé AES-128', km.slice(0, 16), 'key'), seg('IV GCM (16 octets)', km.slice(16), 'nonce')] },
      ],
    };
  },
  async decrypt(K, wire) {
    const E = wire.slice(0, 65);
    let epub: CryptoKey;
    try {
      epub = await subtle().importKey('raw', ab(E), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    } catch {
      throw new CryptoRejected('⊥ — E n\'est pas un point valide de P-256.');
    }
    const Z = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: epub }, K.priv, 256));
    const km = x963kdf(Z, E, 32);
    try {
      return { pt: gcm(km.slice(0, 16), km.slice(16)).decrypt(wire.slice(65)), inside: [{ title: 'Z recalculé avec d_B', segs: [seg('Z', Z, 'secret')] }] };
    } catch {
      throw new CryptoRejected('⊥ — tag invalide.');
    }
  },
};

// ================================================================ HPKE (RFC 9180, mode Base)
// DHKEM(X25519, HKDF-SHA256) = 0x0020, HKDF-SHA256 = 0x0001, AES-128-GCM = 0x0001
const I2 = (n: number) => new Uint8Array([n >> 8, n & 255]);
const SUITE_KEM = concat(utf8('KEM'), I2(0x0020));
const SUITE_HPKE = concat(utf8('HPKE'), I2(0x0020), I2(0x0001), I2(0x0001));
const V1 = utf8('HPKE-v1');
const lExtract = (suite: Bytes, salt: Bytes, label: string, ikm: Bytes) => hkdfExtract(salt, concat(V1, suite, utf8(label), ikm));
const lExpand = (suite: Bytes, prk: Bytes, label: string, info: Bytes, L: number) => hkdfExpand(prk, concat(I2(L), V1, suite, utf8(label), info), L);
export const HPKE_INFO = utf8('atelier-crypto HPKE');
const EMPTY = new Uint8Array(0);

export function hpkeSchedule(dh: Bytes, enc: Bytes, pkR: Bytes, info = HPKE_INFO) {
  const kemContext = concat(enc, pkR);
  const eaePrk = lExtract(SUITE_KEM, EMPTY, 'eae_prk', dh);
  const shared = lExpand(SUITE_KEM, eaePrk, 'shared_secret', kemContext, 32);
  const pskIdHash = lExtract(SUITE_HPKE, EMPTY, 'psk_id_hash', EMPTY);
  const infoHash = lExtract(SUITE_HPKE, EMPTY, 'info_hash', info);
  const ksc = concat(new Uint8Array([0]), pskIdHash, infoHash);
  const secret = lExtract(SUITE_HPKE, shared, 'secret', EMPTY);
  return {
    shared,
    key: lExpand(SUITE_HPKE, secret, 'key', ksc, 16),
    baseNonce: lExpand(SUITE_HPKE, secret, 'base_nonce', ksc, 12),
    exporter: lExpand(SUITE_HPKE, secret, 'exp', ksc, 32),
  };
}

export interface XKeys {
  sk: Bytes;
  pk: Bytes;
}

export function hpkeSeal(pkR: Bytes, pt: Bytes, aad = EMPTY, info = HPKE_INFO, skE = x25519.utils.randomSecretKey()) {
  const enc = x25519.getPublicKey(skE);
  const dh = x25519.getSharedSecret(skE, pkR);
  const ks = hpkeSchedule(dh, enc, pkR, info);
  return { enc, ct: gcm(ks.key, ks.baseNonce, aad).encrypt(pt), dh, ks };
}

export const HPKE: PkeAlgo<XKeys> = {
  pipelineEnc: ['Encap : skE, enc = pkE', 'dh = X25519(skE, pkR)', 'shared = ExtractAndExpand(dh, enc ‖ pkR)', 'KeySchedule → key, base_nonce', 'AES-128-GCM', 'enc ‖ C ‖ tag'],
  pipelineDec: ['dh = X25519(skR, enc)', 'shared_secret', 'KeySchedule', 'AES-GCM.Open', 'Clair ou ⊥'],
  async keygen() {
    const sk = x25519.utils.randomSecretKey();
    const pk = x25519.getPublicKey(sk);
    return {
      keys: { sk, pk },
      pub: [{ title: 'pkR : clé publique X25519 (RFC 7748)', caption: '32 octets : la coordonnée u du point sur Curve25519.', segs: [seg('pkR', pk, 'pub')] }],
      priv: [{ title: 'skR', segs: [seg('skR', sk, 'priv', '32 octets')] }],
    };
  },
  async encrypt(K, pt) {
    const { enc, ct, dh, ks } = hpkeSeal(K.pk, pt);
    return {
      wire: [seg('enc = pkE', enc, 'enc', '32 octets'), seg('C', ct.slice(0, -16), 'ct'), seg('tag', ct.slice(-16), 'tag')],
      inside: [
        { title: 'Suite : DHKEM(X25519, HKDF-SHA256) · HKDF-SHA256 · AES-128-GCM · mode Base', caption: 'suite_id = "HPKE" ‖ 0020 ‖ 0001 ‖ 0001 ; info = "atelier-crypto HPKE".', segs: [seg('dh = X25519(skE, pkR)', dh, 'secret'), seg('shared_secret', ks.shared, 'secret')] },
        { title: 'Key schedule', caption: 'LabeledExtract / LabeledExpand : chaque dérivation porte un label et l\'identifiant de suite.', segs: [seg('key', ks.key, 'key'), seg('base_nonce', ks.baseNonce, 'nonce'), seg('exporter_secret', ks.exporter, 'secret')] },
      ],
    };
  },
  async decrypt(K, wire) {
    const enc = wire.slice(0, 32);
    const dh = x25519.getSharedSecret(K.sk, enc);
    const ks = hpkeSchedule(dh, enc, K.pk);
    try {
      return { pt: gcm(ks.key, ks.baseNonce).decrypt(wire.slice(32)), inside: [{ title: 'Recalculé par le destinataire', segs: [seg('shared_secret', ks.shared, 'secret'), seg('key', ks.key, 'key')] }] };
    } catch {
      throw new CryptoRejected('⊥ — Open échoue : enc, C ou tag altéré.');
    }
  },
};

// ================================================================ ML-KEM-768
export interface MlKemKeys {
  pk: Bytes;
  sk: Bytes;
}

const DEM_INFO = utf8('atelier-crypto DEM');

export const MLKEM: PkeAlgo<MlKemKeys> = {
  pipelineEnc: ['Encaps(pk) → (ct, ss)', 'K ‖ nonce = HKDF(ss)', 'AES-256-GCM', 'ct ‖ C ‖ tag'],
  pipelineDec: ['Decaps(sk, ct) → ss', 'K ‖ nonce = HKDF(ss)', 'AES-GCM.Open', 'Clair ou ⊥'],
  async keygen() {
    const { publicKey: pk, secretKey: sk } = ml_kem768.keygen();
    return {
      keys: { pk, sk },
      pub: [{ title: 'Clé d\'encapsulation ek (FIPS 203)', caption: 'k = 3 polynômes compressés sur 12 bits (t̂) puis la graine ρ de la matrice A.', segs: [seg('t̂ (3 × 384 octets)', pk.slice(0, 1152), 'pub'), seg('ρ', pk.slice(1152), 'salt', 'graine publique de A')] }],
      priv: [{ title: 'Clé de décapsulation dk', caption: 'ŝ ‖ ek ‖ H(ek) ‖ z (z : aléa du rejet implicite).', segs: [seg('ŝ', sk.slice(0, 1152), 'priv'), seg('ek', sk.slice(1152, 2336), 'pub'), seg('H(ek)', sk.slice(2336, 2368), 'hash'), seg('z', sk.slice(2368), 'salt')] }],
    };
  },
  async encrypt(K, pt) {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(K.pk);
    const km = hkdf(sharedSecret, EMPTY, DEM_INFO, 44);
    const out = gcm(km.slice(0, 32), km.slice(32)).encrypt(pt);
    return {
      wire: [seg('ct (encapsulation)', cipherText, 'enc', '1 088 octets : u (960) ‖ v (128)'), seg('C', out.slice(0, -16), 'ct'), seg('tag', out.slice(-16), 'tag')],
      inside: [{ title: 'Secret partagé produit par Encaps', caption: 'Personne ne le « choisit » : il naît de l\'encapsulation.', segs: [seg('ss', sharedSecret, 'secret'), seg('Clé AES-256', km.slice(0, 32), 'key'), seg('Nonce', km.slice(32), 'nonce')] }],
    };
  },
  async decrypt(K, wire) {
    const ss = ml_kem768.decapsulate(wire.slice(0, 1088), K.sk);
    const km = hkdf(ss, EMPTY, DEM_INFO, 44);
    try {
      return { pt: gcm(km.slice(0, 32), km.slice(32)).decrypt(wire.slice(1088)), inside: [{ title: 'ss retrouvé par Decaps', segs: [seg('ss', ss, 'secret')] }] };
    } catch {
      throw new CryptoRejected('⊥ — ct altéré : Decaps rend un secret pseudo-aléatoire (rejet implicite, aucune erreur), donc l\'AEAD échoue.');
    }
  },
};

// ================================================================ Hybride X25519MLKEM768
export interface HybKeys {
  mk: MlKemKeys;
  x: XKeys;
}

export const HYBRID: PkeAlgo<HybKeys> = {
  pipelineEnc: ['ML-KEM.Encaps(pk_mlkem)', 'X25519 éphémère', 'ss = ss_mlkem ‖ ss_x25519', 'HKDF → K ‖ nonce', 'AES-256-GCM'],
  pipelineDec: ['ML-KEM.Decaps', 'X25519(sk, E)', 'ss = ss_mlkem ‖ ss_x25519', 'HKDF', 'Clair ou ⊥'],
  async keygen() {
    const mk = ml_kem768.keygen();
    const sk = x25519.utils.randomSecretKey();
    const x = { sk, pk: x25519.getPublicKey(sk) };
    return {
      keys: { mk: { pk: mk.publicKey, sk: mk.secretKey }, x },
      pub: [{ title: 'Partage de clé X25519MLKEM768 (TLS 1.3)', caption: 'Ordre normalisé : la partie ML-KEM d\'abord, puis X25519 (1 216 octets).', segs: [seg('ek ML-KEM-768', mk.publicKey, 'pub'), seg('X25519', x.pk, 'pub')] }],
      priv: [{ title: 'Deux clés privées', segs: [seg('dk ML-KEM', mk.secretKey, 'priv'), seg('sk X25519', sk, 'priv')] }],
    };
  },
  async encrypt(K, pt) {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(K.mk.pk);
    const e = x25519.utils.randomSecretKey();
    const E = x25519.getPublicKey(e);
    const xs = x25519.getSharedSecret(e, K.x.pk);
    const ss = concat(sharedSecret, xs);
    const km = hkdf(ss, EMPTY, DEM_INFO, 44);
    const out = gcm(km.slice(0, 32), km.slice(32)).encrypt(pt);
    return {
      wire: [seg('ct ML-KEM', cipherText, 'enc'), seg('E X25519', E, 'enc'), seg('C', out.slice(0, -16), 'ct'), seg('tag', out.slice(-16), 'tag')],
      inside: [{ title: 'Secret combiné (concaténation, comme dans TLS)', caption: 'Sûr tant que l\'un des deux composants résiste. X-Wing combine autrement (SHA3-256 avec étiquette).', segs: [seg('ss ML-KEM', sharedSecret, 'secret'), seg('ss X25519', xs, 'secret')] }],
    };
  },
  async decrypt(K, wire) {
    const ss1 = ml_kem768.decapsulate(wire.slice(0, 1088), K.mk.sk);
    const xs = x25519.getSharedSecret(K.x.sk, wire.slice(1088, 1120));
    const km = hkdf(concat(ss1, xs), EMPTY, DEM_INFO, 44);
    try {
      return { pt: gcm(km.slice(0, 32), km.slice(32)).decrypt(wire.slice(1120)), inside: [] };
    } catch {
      throw new CryptoRejected('⊥ — échec de l\'AEAD : une des deux encapsulations a été altérée.');
    }
  },
};

export const PKE: Record<string, PkeAlgo> = {
  'rsa-textbook': RSA_TEXTBOOK,
  'rsa-pkcs1': RSA_PKCS1V15,
  'rsa-oaep': RSA_OAEP,
  'rsa-kem': RSA_KEM,
  ecies: ECIES,
  hpke: HPKE,
  mlkem: MLKEM,
  hybrid: HYBRID,
};

export { equal };
