// Établissement de clé : accord Diffie-Hellman (corps fini, P-256, X25519), grille statique / éphémère,
// échange authentifié (SIGMA), Chip Authentication (ICAO 9303-11) et Double Ratchet (Signal).
import { cbc, cmac, gcm } from '@noble/ciphers/aes.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { hmac } from '@noble/hashes/hmac.js';
import { concat, equal, i2osp, modPow, os2ip, rand, u32be, utf8, type Bytes } from '../lib/bytes';
import { hkdf, sha256 } from './kdf';
import { CryptoRejected } from './types';

// ================================================================ DH en corps fini
export interface DhGroup {
  id: string;
  label: string;
  p: bigint;
  g: bigint;
  /** Ordre du sous-groupe engendré par g : q = (p − 1) / 2 premier (g d'ordre q), ou p − 1 (racine primitive). */
  q: bigint;
  /** g est une racine primitive : il engendre tout le groupe (ℤ/pℤ)*, sous-groupes d'ordre 2 compris. */
  primitive?: boolean;
  bytes: number;
}

/** ffdhe2048 (RFC 7919) : nombre premier sûr de 2048 bits, g = 2. */
const FFDHE2048_P = BigInt('0x' +
  'FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF');

export const DH_GROUPS: Record<string, DhGroup> = {
  toy: { id: 'toy', label: 'Jouet : p = 23, g = 2 (ordre 11)', p: 23n, g: 2n, q: 11n, bytes: 1 },
  dhwar: { id: 'dhwar', label: 'DH War : p = 47, g = 26 (racine primitive)', p: 47n, g: 26n, q: 46n, primitive: true, bytes: 1 },
  ffdhe2048: { id: 'ffdhe2048', label: 'ffdhe2048 (RFC 7919)', p: FFDHE2048_P, g: 2n, q: (FFDHE2048_P - 1n) / 2n, bytes: 256 },
};

/** Exposant secret : uniforme dans [1, q − 1] (dans [2, q − 1] pour le groupe jouet, pour éviter le cas trivial). */
export function dhSecret(G: DhGroup): bigint {
  if (G.q < 1n << 16n) return 2n + BigInt(Math.floor(Math.random() * Number(G.q - 2n)));
  return 1n + (os2ip(rand(G.bytes + 8)) % (G.q - 1n));
}

export const dhPublic = (G: DhGroup, x: bigint) => modPow(G.g, x, G.p);

/** Critère d'Euler : Y^((p−1)/2) mod p vaut 1 si Y est un carré modulo p, p − 1 sinon. */
export const isSquare = (G: DhGroup, Y: bigint) => modPow(Y, (G.p - 1n) / 2n, G.p) === 1n;

/** Table des puissances g^x mod p, x = 1 … ordre de g (petits groupes seulement). */
export function powerTable(G: DhGroup): bigint[] {
  const t: bigint[] = [];
  let y = 1n;
  for (let x = 1n; x <= G.q; x++) t.push((y = (y * G.g) % G.p));
  return t;
}

/** Validation d'une valeur publique reçue (SP 800-56A §5.6.2.3.1) : 1 < Y < p − 1 et Y^q = 1. */
export function dhCheck(G: DhGroup, Y: bigint): string | null {
  if (Y <= 1n || Y >= G.p - 1n) return `Y = ${Y <= 1n ? Y : 'p − 1'} : valeur dégénérée, elle force Z dans {1, p − 1}.`;
  if (Y >= G.p) return 'Y ≥ p : valeur hors du groupe.';
  if (modPow(Y, G.q, G.p) !== 1n) return 'Y n\'est pas dans le sous-groupe d\'ordre q : attaque par petit sous-groupe possible.';
  return null;
}

export function dhShared(G: DhGroup, x: bigint, Y: bigint, validate = true): bigint {
  if (validate) {
    const err = dhCheck(G, Y);
    if (err) throw new CryptoRejected(err);
  }
  return modPow(Y, x, G.p);
}

// ================================================================ ECDH P-256
export interface EcPair {
  priv: Bytes;
  pub: Bytes; // point non compressé 04 ‖ X ‖ Y
}

export function p256Pair(): EcPair {
  const priv = p256.utils.randomSecretKey();
  return { priv, pub: p256.getPublicKey(priv, false) };
}

/** Z = abscisse x de d·Q (SEC 1, §3.3.1). Le point reçu est validé : sur la courbe, différent de l'infini. */
export function ecdhP256(priv: Bytes, peerPub: Bytes): Bytes {
  try {
    return p256.getSharedSecret(priv, peerPub).slice(1);
  } catch (e) {
    throw new CryptoRejected(`Point refusé : ${(e as Error).message}.`);
  }
}

export const compressP256 = (pub: Bytes) => p256.Point.fromBytes(pub).toBytes(true);

// ================================================================ X25519
/** « Clamping » RFC 7748 : 3 bits de poids faible à 0 (multiple du cofacteur 8), bit 255 à 0, bit 254 à 1. */
export function clamp(k: Bytes): Bytes {
  const c = k.slice();
  c[0] &= 248;
  c[31] &= 127;
  c[31] |= 64;
  return c;
}

export function xPair() {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

/** X25519(k, u). Un résultat tout à zéro (point d'ordre faible) est refusé, comme le recommande RFC 7748 §6.1. */
export function xdh(priv: Bytes, peerPub: Bytes): Bytes {
  try {
    return x25519.getSharedSecret(priv, peerPub);
  } catch {
    throw new CryptoRejected('Secret partagé nul : la clé publique reçue est un point d\'ordre faible.');
  }
}

/** Points d'ordre faible de Curve25519 (encodages u sur 32 octets, petit-boutiste). */
export const LOW_ORDER = {
  zero: new Uint8Array(32),
  one: (() => { const u = new Uint8Array(32); u[0] = 1; return u; })(),
};

// ================================================================ Grille statique / éphémère
export type Mode = 's' | 'e';

export interface Party {
  name: string;
  static: { priv: Bytes; pub: Bytes };
}

export interface GridSession {
  n: number;
  modeA: Mode;
  modeB: Mode;
  /** Clés publiques utilisées (celles qu'un observateur enregistre). */
  pubA: Bytes;
  pubB: Bytes;
  z: Bytes;
  key: Bytes;
  nonces?: { a: Bytes; b: Bytes };
}

/** Une session : une seule opération DH entre la clé choisie par A (statique ou éphémère) et celle de B. */
export function gridSession(n: number, A: Party, B: Party, modeA: Mode, modeB: Mode, withNonces: boolean): GridSession {
  const a = modeA === 's' ? A.static : xPair();
  const b = modeB === 's' ? B.static : xPair();
  const z = xdh(a.priv, b.pub);
  const nonces = withNonces ? { a: rand(16), b: rand(16) } : undefined;
  const salt = nonces ? concat(nonces.a, nonces.b) : new Uint8Array(0);
  const key = hkdf(z, salt, utf8('atelier grille'), 16);
  return { n, modeA, modeB, pubA: a.pub, pubB: b.pub, z, key, nonces };
}

/** Un attaquant qui a enregistré la session puis vole la clé statique de X peut-il recalculer Z ? */
export function recoverable(s: GridSession, leaked: 'A' | 'B' | 'none'): boolean {
  if (leaked === 'A') return s.modeA === 's';
  if (leaked === 'B') return s.modeB === 's';
  return false;
}

// ================================================================ SIGMA (DH éphémère authentifié par signatures)
export interface SigmaParty {
  name: string;
  sign: { priv: Bytes; pub: Bytes }; // Ed25519, clé d'identité certifiée
}

export const edPair = () => {
  const priv = ed25519.utils.randomSecretKey();
  return { priv, pub: ed25519.getPublicKey(priv) };
};

export interface SigmaRun {
  /** Ce que chacun a envoyé et ce que l'autre a reçu (différent si Mallory s'interpose). */
  ea: { priv: Bytes; pub: Bytes };
  eb: { priv: Bytes; pub: Bytes };
  aSees: Bytes; // éphémère reçue par A (en principe eb.pub)
  bSees: Bytes; // éphémère reçue par B (en principe ea.pub)
  mallory?: { ma: { priv: Bytes; pub: Bytes }; mb: { priv: Bytes; pub: Bytes } };
  zA: Bytes;
  zB: Bytes;
  /** Signatures : chacun signe (son éphémère ‖ celle qu'il a reçue). */
  sigA?: Bytes;
  sigB?: Bytes;
  aAccepts: boolean;
  bAccepts: boolean;
  /** Mallory connaît-elle les secrets de A et de B ? */
  malloryKnows: boolean;
}

export function sigmaRun(A: SigmaParty, B: SigmaParty, authenticated: boolean, mitm: boolean): SigmaRun {
  const ea = xPair();
  const eb = xPair();
  let bSees: Bytes = ea.pub;
  let aSees: Bytes = eb.pub;
  let mallory: SigmaRun['mallory'];
  if (mitm) {
    mallory = { ma: xPair(), mb: xPair() };
    bSees = mallory.ma.pub; // B croit recevoir l'éphémère de A
    aSees = mallory.mb.pub; // A croit recevoir celle de B
  }
  const zA = xdh(ea.priv, aSees);
  const zB = xdh(eb.priv, bSees);
  let aAccepts = true;
  let bAccepts = true;
  let sigA: Bytes | undefined;
  let sigB: Bytes | undefined;
  if (authenticated) {
    // B signe (eB ‖ éphémère reçue) ; A vérifie avec la clé publique certifiée de B, sur ce qu'elle a vu, elle.
    sigB = ed25519.sign(concat(eb.pub, bSees), B.sign.priv);
    sigA = ed25519.sign(concat(ea.pub, aSees), A.sign.priv);
    // Mallory ne peut que relayer les signatures (elle n'a pas les clés d'identité).
    aAccepts = ed25519.verify(sigB, concat(aSees, ea.pub), B.sign.pub);
    bAccepts = ed25519.verify(sigA, concat(bSees, eb.pub), A.sign.pub);
  }
  return { ea, eb, aSees, bSees, mallory, zA, zB, sigA, sigB, aAccepts, bAccepts, malloryKnows: mitm };
}

// ================================================================ Chip Authentication (ICAO 9303-11, simplifiée)
export interface Chip {
  /** Clé privée de Chip Authentication : générée et injectée à la personnalisation, jamais lisible. */
  caPriv: Bytes;
  dg14: Bytes;
  sod: { dg14Hash: Bytes; sig: Bytes };
}

export interface Issuer {
  dsPriv: Bytes;
  dsPub: Bytes;
}

export const issuerNew = (): Issuer => {
  const dsPriv = p256.utils.randomSecretKey();
  return { dsPriv, dsPub: p256.getPublicKey(dsPriv, false) };
};

/** OID id-CA-ECDH-AES-CBC-CMAC-256 (BSI TR-03110) : 0.4.0.127.0.7.2.2.3.2.4 */
const OID_CA_AES256 = new Uint8Array([0x06, 0x0a, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x04]);

/** DG14 simplifié : l'OID du protocole suivi du point public de la puce (le vrai DG14 est un SET ASN.1 de SecurityInfos). */
export function dg14Of(caPub: Bytes): Bytes {
  return concat(new Uint8Array([0x6e]), OID_CA_AES256, new Uint8Array([0x04, caPub.length]), caPub);
}

export const dg14Pub = (dg14: Bytes) => dg14.slice(dg14.length - 65);

/** Personnalisation : la puce reçoit sa biclé ; le Document Signer signe le haché du DG14 dans le SOD. */
export function personalize(I: Issuer): Chip {
  const caPriv = p256.utils.randomSecretKey();
  const dg14 = dg14Of(p256.getPublicKey(caPriv, false));
  const dg14Hash = sha256(dg14);
  return { caPriv, dg14, sod: { dg14Hash, sig: p256.sign(dg14Hash, I.dsPriv, { prehash: false }) } };
}

/** Clone : copie tout ce qui est lisible (DG14, SOD), mais pas la clé privée, qu'il remplace par la sienne. */
export const cloneChip = (c: Chip): Chip => ({ ...c, caPriv: p256.utils.randomSecretKey() });

/** KDF de 9303-11 §9.7.1 pour AES-256 : SHA-256(Z ‖ compteur), compteur 1 pour K_Enc, 2 pour K_MAC. */
export function icaoKdf(z: Bytes) {
  return { kEnc: sha256(concat(z, u32be(1))), kMac: sha256(concat(z, u32be(2))) };
}

/** Bourrage ISO/IEC 9797-1 méthode 2 : 0x80 puis des zéros jusqu'au multiple de 16. */
export function iso9797(b: Bytes): Bytes {
  const n = 16 - ((b.length + 1) % 16 === 0 ? 0 : (b.length + 1) % 16);
  return concat(b, new Uint8Array([0x80]), new Uint8Array(n % 16));
}

export interface SmResponse {
  ssc: Bytes;
  iv: Bytes;
  ct: Bytes;
  mac: Bytes;
}

/** Réponse en Secure Messaging (simplifiée) : IV = E(K_Enc, SSC), AES-CBC, puis CMAC tronqué à 8 octets sur SSC ‖ chiffré. */
export function smWrap(kEnc: Bytes, kMac: Bytes, ssc: Bytes, data: Bytes): SmResponse {
  const iv = cbc(kEnc, new Uint8Array(16), { disablePadding: true }).encrypt(ssc);
  const ct = cbc(kEnc, iv, { disablePadding: true }).encrypt(iso9797(data));
  const mac = cmac(iso9797(concat(ssc, ct)), kMac).slice(0, 8);
  return { ssc, iv, ct, mac };
}

export function smUnwrap(kEnc: Bytes, kMac: Bytes, r: SmResponse): Bytes {
  const mac = cmac(iso9797(concat(r.ssc, r.ct)), kMac).slice(0, 8);
  if (!equal(mac, r.mac)) throw new CryptoRejected('MAC de Secure Messaging invalide : la puce ne détient pas la clé privée attendue (clone ?).');
  const iv = cbc(kEnc, new Uint8Array(16), { disablePadding: true }).encrypt(r.ssc);
  const p = cbc(kEnc, iv, { disablePadding: true }).decrypt(r.ct);
  return p.slice(0, p.lastIndexOf(0x80));
}

export interface PassiveAuth {
  hashOk: boolean;
  sigOk: boolean;
}

/** Authentification passive du DG14 : son haché est-il celui que le Document Signer a signé ? */
export function passiveAuth(c: Chip, dsPub: Bytes): PassiveAuth {
  const hashOk = equal(sha256(c.dg14), c.sod.dg14Hash);
  const sigOk = p256.verify(c.sod.sig, c.sod.dg14Hash, dsPub, { prehash: false });
  return { hashOk, sigOk };
}

export interface CaRun {
  pa: PassiveAuth;
  eph: EcPair;
  zIS: Bytes;
  zChip: Bytes;
  isKeys: ReturnType<typeof icaoKdf>;
  chipKeys: ReturnType<typeof icaoKdf>;
  resp: SmResponse;
  read: Bytes | null;
  error: string | null;
}

/** Une lecture complète : authentification passive, Chip Authentication, puis une réponse protégée de la puce. */
export function chipAuthenticate(c: Chip, dsPub: Bytes, data: Bytes): CaRun {
  const pa = passiveAuth(c, dsPub);
  const eph = p256Pair(); // biclé éphémère du système d'inspection
  const chipPub = dg14Pub(c.dg14);
  const zIS = ecdhP256(eph.priv, chipPub); // côté IS : sk éphémère × clé publique du DG14
  const zChip = ecdhP256(c.caPriv, eph.pub); // côté puce : sa clé privée × l'éphémère reçue
  const isKeys = icaoKdf(zIS);
  const chipKeys = icaoKdf(zChip);
  const ssc = new Uint8Array(16); // le compteur repart de zéro après Chip Authentication
  ssc[15] = 1;
  const resp = smWrap(chipKeys.kEnc, chipKeys.kMac, ssc, data);
  let read: Bytes | null = null;
  let error: string | null = null;
  if (!pa.hashOk || !pa.sigOk) error = 'Authentification passive en échec : le DG14 n\'est pas celui signé par l\'État émetteur.';
  else {
    try {
      read = smUnwrap(isKeys.kEnc, isKeys.kMac, resp);
    } catch (e) {
      error = (e as Error).message;
    }
  }
  return { pa, eph, zIS, zChip, isKeys, chipKeys, resp, read, error };
}

// ================================================================ Double Ratchet (Signal, simplifié)
export interface RatchetState {
  name: string;
  dhs: { priv: Bytes; pub: Bytes };
  dhr: Bytes | null;
  rk: Bytes;
  cks: Bytes | null;
  ckr: Bytes | null;
  ns: number;
  nr: number;
  pn: number;
}

export interface RatchetHeader {
  dh: Bytes;
  pn: number;
  n: number;
}

export interface RatchetMsg {
  from: string;
  header: RatchetHeader;
  ct: Bytes;
  /** Pour l'affichage pédagogique uniquement. */
  mk: Bytes;
  /** Premier message d'une nouvelle chaîne d'envoi : il porte une nouvelle clé publique de ratchet. */
  dhStep: boolean;
}

const INFO_RK = utf8('Atelier Double Ratchet');

/** KDF_RK : HKDF(sel = RK, ikm = sortie DH) → (nouvelle RK, clé de chaîne). */
export function kdfRk(rk: Bytes, dhOut: Bytes): [Bytes, Bytes] {
  const out = hkdf(dhOut, rk, INFO_RK, 64);
  return [out.slice(0, 32), out.slice(32)];
}

/** KDF_CK : HMAC(CK, 0x01) = clé de message, HMAC(CK, 0x02) = clé de chaîne suivante. */
export function kdfCk(ck: Bytes): [Bytes, Bytes] {
  return [hmac(sha256, ck, new Uint8Array([1])), hmac(sha256, ck, new Uint8Array([2]))];
}

const encodeHeader = (h: RatchetHeader) => concat(h.dh, u32be(h.pn), u32be(h.n));

function aead(mk: Bytes) {
  const k = hkdf(mk, new Uint8Array(32), utf8('Atelier message keys'), 44);
  return { key: k.slice(0, 32), nonce: k.slice(32) };
}

/** Initialisation après l'accord initial (X3DH dans Signal) : SK partagé, B publie sa clé de ratchet. */
export function ratchetInit(sk: Bytes): { alice: RatchetState; bob: RatchetState } {
  const bobDh = xPair();
  const aliceDh = xPair();
  const [rk, cks] = kdfRk(sk, xdh(aliceDh.priv, bobDh.pub));
  return {
    alice: { name: 'Alice', dhs: aliceDh, dhr: bobDh.pub, rk, cks, ckr: null, ns: 0, nr: 0, pn: 0 },
    bob: { name: 'Bob', dhs: bobDh, dhr: null, rk: sk, cks: null, ckr: null, ns: 0, nr: 0, pn: 0 },
  };
}

export const cloneState = (s: RatchetState): RatchetState => ({ ...s, dhs: { ...s.dhs } });

export function ratchetEncrypt(s: RatchetState, pt: Bytes): RatchetMsg {
  if (!s.cks) throw new CryptoRejected(`${s.name} n'a pas encore de chaîne d'envoi : il doit d'abord recevoir un message.`);
  const [mk, ck] = kdfCk(s.cks);
  s.cks = ck;
  const header = { dh: s.dhs.pub, pn: s.pn, n: s.ns };
  s.ns++;
  const { key, nonce } = aead(mk);
  return { from: s.name, header, ct: gcm(key, nonce, encodeHeader(header)).encrypt(pt), mk, dhStep: header.n === 0 };
}

/** Étape DH du ratchet : à la réception d'une nouvelle clé publique de l'autre partie. */
function dhRatchet(s: RatchetState, h: RatchetHeader) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = h.dh;
  [s.rk, s.ckr] = kdfRk(s.rk, xdh(s.dhs.priv, s.dhr));
  s.dhs = xPair();
  [s.rk, s.cks] = kdfRk(s.rk, xdh(s.dhs.priv, s.dhr));
}

/** Réception dans l'ordre (les clés de messages sautés ne sont pas gérées ici). Renvoie aussi si un pas DH a eu lieu. */
export function ratchetDecrypt(s: RatchetState, m: RatchetMsg): { pt: Bytes; dhStep: boolean } {
  let dhStep = false;
  if (!s.dhr || !equal(m.header.dh, s.dhr)) {
    dhRatchet(s, m.header);
    dhStep = true;
  }
  if (!s.ckr) throw new CryptoRejected('Pas de chaîne de réception.');
  while (s.nr < m.header.n) {
    s.ckr = kdfCk(s.ckr)[1];
    s.nr++;
  }
  const [mk, ck] = kdfCk(s.ckr);
  s.ckr = ck;
  s.nr++;
  const { key, nonce } = aead(mk);
  try {
    return { pt: gcm(key, nonce, encodeHeader(m.header)).decrypt(m.ct), dhStep };
  } catch {
    throw new CryptoRejected('Clé de message incorrecte : déchiffrement impossible.');
  }
}

/**
 * Ève a copié l'état de Bob à un instant donné (ses clés privées de ratchet comprises). Elle écoute ensuite
 * passivement : elle suit la chaîne de réception de Bob et, tant que Bob n'a pas renouvelé sa clé DH,
 * sa chaîne d'envoi. Renvoie le clair si elle y parvient.
 */
export function eveTry(eve: Eve, m: RatchetMsg): Bytes | null {
  try {
    if (m.from === 'Bob') {
      if (!eve.sendCk || !equal(m.header.dh, eve.sendDh)) return null;
      while (eve.sendN < m.header.n) {
        eve.sendCk = kdfCk(eve.sendCk)[1];
        eve.sendN++;
      }
      const [mk, ck] = kdfCk(eve.sendCk);
      eve.sendCk = ck;
      eve.sendN++;
      const { key, nonce } = aead(mk);
      return gcm(key, nonce, encodeHeader(m.header)).decrypt(m.ct);
    }
    const { pt, dhStep } = ratchetDecrypt(eve.state, m);
    // Après un pas DH, Ève a tiré sa propre clé : ce n'est pas celle que Bob utilisera pour envoyer.
    if (dhStep) eve.sendCk = null;
    return pt;
  } catch {
    return null;
  }
}

/** Petit utilitaire d'affichage : un entier en octets (grand-boutiste) de la taille du groupe. */
export const bigBytes = (x: bigint, len: number) => i2osp(x, len);

export interface Eve {
  state: RatchetState;
  sendCk: Bytes | null;
  sendDh: Bytes;
  sendN: number;
}

/** Ève copie l'état complet de Bob (compromission de l'appareil). */
export const eveSteal = (bob: RatchetState): Eve => ({ state: cloneState(bob), sendCk: bob.cks, sendDh: bob.dhs.pub, sendN: bob.ns });
