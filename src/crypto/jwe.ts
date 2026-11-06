// JWE (RFC 7516) : les formats JOSE des chiffrements de l'atelier.
// Structure commune : BASE64URL(en-tête protégé) . clé chiffrée . IV . chiffré . tag
// Le contenu est chiffré en AES-256-GCM (« enc » : A256GCM) avec pour AAD l'en-tête protégé encodé (ASCII).
import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { ab, concat, fromB64, i2osp, modPow, os2ip, rand, toB64url, u32be, utf8, type Bytes } from '../lib/bytes';
import { sha256 } from './kdf';
import { hpkeSchedule, oaepEncode, pkcs1v15Encode, type EcKeys, type RsaKeys, type XKeys } from './pke';
import { CryptoRejected } from './types';

const subtle = () => globalThis.crypto.subtle;

export interface Jwe {
  header: Record<string, unknown>;
  b: { ek: Bytes; iv: Bytes; ct: Bytes; tag: Bytes };
  s: { h: string; ek: string; iv: string; ct: string; tag: string };
  compact: string;
  flattened: Record<string, string>;
  general: Record<string, unknown>;
  note: string;
}

export interface JweAlgo<K> {
  alg: string;
  enc: string;
  note: string;
  encrypt(keys: K, pt: Bytes): Promise<Jwe>;
  decrypt(keys: K, compact: string): Promise<Bytes>;
}

function assemble(header: Record<string, unknown>, ek: Bytes, iv: Bytes, ct: Bytes, tag: Bytes, note: string, hB64?: string): Jwe {
  const h = hB64 ?? toB64url(utf8(JSON.stringify(header)));
  const s = { h, ek: toB64url(ek), iv: toB64url(iv), ct: toB64url(ct), tag: toB64url(tag) };
  return {
    header, b: { ek, iv, ct, tag }, s, note,
    compact: `${s.h}.${s.ek}.${s.iv}.${s.ct}.${s.tag}`,
    flattened: { protected: s.h, encrypted_key: s.ek, iv: s.iv, ciphertext: s.ct, tag: s.tag },
    general: { protected: s.h, recipients: [{ encrypted_key: s.ek }], iv: s.iv, ciphertext: s.ct, tag: s.tag },
  };
}

function parse(compact: string) {
  const p = compact.split('.');
  if (p.length !== 5) throw new CryptoRejected('Un JWE compact a exactement 5 parties.');
  const header = JSON.parse(new TextDecoder().decode(fromB64(p[0])));
  return { h: p[0], header, ek: fromB64(p[1]), iv: fromB64(p[2]), ct: fromB64(p[3]), tag: fromB64(p[4]) };
}

/** Chiffrement du contenu, commun à RSA-OAEP-256, RSA1_5 et ECDH-ES : AES-256-GCM, AAD = en-tête encodé. */
function sealContent(cek: Bytes, header: Record<string, unknown>, pt: Bytes) {
  const h = toB64url(utf8(JSON.stringify(header)));
  const iv = rand(12);
  const out = gcm(cek, iv, utf8(h)).encrypt(pt);
  return { h, iv, ct: out.slice(0, -16), tag: out.slice(-16) };
}

function openContent(cek: Bytes, j: ReturnType<typeof parse>) {
  try {
    return gcm(cek, j.iv, utf8(j.h)).decrypt(concat(j.ct, j.tag));
  } catch {
    throw new CryptoRejected('⊥ — tag A256GCM invalide.');
  }
}

// ---------------------------------------------------------------- RSA-OAEP-256
export const JWE_RSA_OAEP: JweAlgo<RsaKeys> = {
  alg: 'RSA-OAEP-256',
  enc: 'A256GCM',
  note: 'RFC 7518 §4.3 : la clé de contenu (CEK, 32 octets aléatoires) est chiffrée par RSAES-OAEP avec SHA-256 et MGF1-SHA-256',
  async encrypt(K, pt) {
    const header = { alg: this.alg, enc: this.enc };
    const cek = rand(32);
    const ek = i2osp(modPow(os2ip(oaepEncode(K.k, cek).em), K.e, K.n), K.k);
    const { h, iv, ct, tag } = sealContent(cek, header, pt);
    return assemble(header, ek, iv, ct, tag, this.note, h);
  },
  async decrypt(K, compact) {
    const j = parse(compact);
    let cek: Bytes;
    try {
      cek = new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, K.oaepPriv, ab(j.ek)));
    } catch {
      throw new CryptoRejected('⊥ — clé chiffrée OAEP invalide.');
    }
    return openContent(cek, j);
  },
};

// ---------------------------------------------------------------- RSA1_5 (à proscrire)
export const JWE_RSA1_5: JweAlgo<RsaKeys> = {
  alg: 'RSA1_5',
  enc: 'A256GCM',
  note: 'RFC 7518 §4.2, désormais déconseillé (RFC 8725) : la CEK est chiffrée en RSAES-PKCS1-v1_5, exposée à l\'oracle de Bleichenbacher',
  async encrypt(K, pt) {
    const header = { alg: this.alg, enc: this.enc };
    const cek = rand(32);
    const ek = i2osp(modPow(os2ip(pkcs1v15Encode(K, cek).em), K.e, K.n), K.k);
    const { h, iv, ct, tag } = sealContent(cek, header, pt);
    return assemble(header, ek, iv, ct, tag, this.note, h);
  },
  async decrypt(K, compact) {
    const j = parse(compact);
    const em = i2osp(modPow(os2ip(j.ek), K.d, K.n), K.k);
    const sep = em.indexOf(0, 2);
    if (em[0] !== 0 || em[1] !== 2 || sep < 10) throw new CryptoRejected('⊥ — remplissage PKCS#1 v1.5 invalide.');
    return openContent(em.slice(sep + 1), j);
  },
};

// ---------------------------------------------------------------- ECDH-ES (accord direct)
/** Concat KDF de NIST SP 800-56A, profilé par RFC 7518 §4.6.2 (un seul tour de SHA-256 pour 256 bits). */
export function concatKdf(z: Bytes, enc: string, apu = new Uint8Array(0), apv = new Uint8Array(0)): Bytes {
  const lv = (b: Bytes) => concat(u32be(b.length), b);
  const otherInfo = concat(lv(utf8(enc)), lv(apu), lv(apv), u32be(256));
  return sha256(concat(u32be(1), z, otherInfo));
}

export const JWE_ECDH_ES: JweAlgo<EcKeys> = {
  alg: 'ECDH-ES',
  enc: 'A256GCM',
  note: 'RFC 7518 §4.6 : accord de clé direct, pas de clé chiffrée ; la CEK = Concat KDF(Z, "A256GCM"), le point éphémère voyage dans l\'en-tête (« epk »)',
  async encrypt(K, pt) {
    const pub = await subtle().importKey('raw', ab(K.pubRaw), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    const eph = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const ej = await subtle().exportKey('jwk', eph.publicKey);
    const z = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256));
    const header = { alg: this.alg, enc: this.enc, epk: { kty: 'EC', crv: 'P-256', x: ej.x, y: ej.y } };
    const cek = concatKdf(z, this.enc);
    const { h, iv, ct, tag } = sealContent(cek, header, pt);
    return assemble(header, new Uint8Array(0), iv, ct, tag, this.note, h);
  },
  async decrypt(K, compact) {
    const j = parse(compact);
    const epk = await subtle().importKey('jwk', { ...j.header.epk, ext: true }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const z = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: epk }, K.priv, 256));
    return openContent(concatKdf(z, j.header.enc), j);
  },
};

// ---------------------------------------------------------------- HPKE intégré (projet IETF)
export const JWE_HPKE: JweAlgo<XKeys> = {
  alg: 'HPKE-3',
  enc: 'int',
  note: 'projet IETF draft-ietf-jose-hpke-encrypt (révision -14) : HPKE-3 = DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, chiffrement intégré ; la clé « chiffrée » est l\'encapsulation, IV et tag restent vides. Identifiants et règles encore susceptibles d\'évoluer',
  async encrypt(K, pt) {
    const header = { alg: this.alg, enc: this.enc };
    const h = toB64url(utf8(JSON.stringify(header)));
    const skE = x25519.utils.randomSecretKey();
    const enc = x25519.getPublicKey(skE);
    const ks = hpkeSchedule(x25519.getSharedSecret(skE, K.pk), enc, K.pk, new Uint8Array(0));
    const ct = gcm(ks.key, ks.baseNonce, utf8(h)).encrypt(pt);
    return assemble(header, enc, new Uint8Array(0), ct, new Uint8Array(0), this.note, h);
  },
  async decrypt(K, compact) {
    const j = parse(compact);
    const ks = hpkeSchedule(x25519.getSharedSecret(K.sk, j.ek), j.ek, K.pk, new Uint8Array(0));
    try {
      return gcm(ks.key, ks.baseNonce, utf8(j.h)).decrypt(j.ct);
    } catch {
      throw new CryptoRejected('⊥ — Open HPKE échoue.');
    }
  },
};

export const JWE: Record<string, JweAlgo<any>> = {
  'rsa-oaep': JWE_RSA_OAEP,
  'rsa-pkcs1': JWE_RSA1_5,
  ecies: JWE_ECDH_ES,
  hpke: JWE_HPKE,
};
