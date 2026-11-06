// Icônes Font Awesome Pro Duotone, importées une à une depuis le Kit :
// seules les icônes réellement utilisées entrent dans le build (tree-shaking).
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { config, type IconDefinition } from '@fortawesome/fontawesome-svg-core';
import '@fortawesome/fontawesome-svg-core/styles.css';
import {
  faAppleWhole, faBolt, faBomb, faBook, faBoxOpen, faCapsules, faCircle1, faCircle2, faCircle3, faCircle4, faCircle5,
  faCircle6, faCircle7, faCircle8, faCircle9, faCircleCheck, faCircleInfo, faCircleXmark, faClone, faCodeMerge, faDice,
  faFeather, faGift, faHouse, faKey, faKeySkeleton, faLightbulbOn, faLink, faLock, faLockOpen, faMusic, faPenNib,
  faRepeat, faSaltShaker, faShieldCheck, faShuffle, faSignature, faSkullCrossbones, faStopwatch,
  faSun, faMoon, faSwatchbook, faTableCells, faTimeline, faTrees, faCube, faUserSecret, faDiceThree, faStar,
  faChevronUp, faChevronDown, faPaperPlane, faInbox, faLayerGroup, faFingerprint, faWandMagicSparkles,
  faBinaryLock, faArrowLeft, faArrowRight, faGlobe, faCode, faBookOpenReader, faFlaskVial, faHandPointer, faEye,
  faCalendarRange, faFilter, faFileCode, faGraduationCap,
  faHandshake, faSquareRootVariable, faBezierCurve, faWaveSine, faGrid2, faUserCheck, faPassport, faArrowsSpin,
  faUserNinja, faBandage, faMicrochip, faIdCard, faMessages, faEquals, faArrowsRotate,
} from '@awesome.me/kit-c549591fa3/icons/duotone/solid';

config.autoAddCss = false;

export type Icon = IconDefinition;

export const IC = {
  lock: faLock, unlock: faLockOpen, bolt: faBolt, sign: faPenNib, verify: faShieldCheck, key: faKey, keypair: faKeySkeleton,
  dice: faDiceThree, ok: faCircleCheck, ko: faCircleXmark, info: faCircleInfo, home: faHouse, history: faTimeline,
  notions: faLightbulbOn, palette: faSwatchbook, sun: faSun, moon: faMoon, attack: faSkullCrossbones, forge: faUserSecret,
  star: faStar, more: faChevronDown, less: faChevronUp, send: faPaperPlane, receive: faInbox, sym: faLock, pke: faKeySkeleton,
  sigFamily: faSignature, layers: faLayerGroup, fingerprint: faFingerprint, magic: faWandMagicSparkles,
  logo: faBinaryLock, prev: faArrowLeft, next: faArrowRight, public: faGlobe, private: faUserSecret, code: faCode,
  deeper: faBookOpenReader, lab: faFlaskVial, pointer: faHandPointer, eye: faEye, period: faCalendarRange,
  filter: faFilter, file: faFileCode, learn: faGraduationCap,
  kex: faHandshake, attacker: faUserNinja, heal: faBandage, chip: faMicrochip, idcard: faIdCard, chat: faMessages,
  equal: faEquals, again: faArrowsRotate, clone: faClone,
} satisfies Record<string, IconDefinition>;

/** Une icône par algorithme : clin d'œil à ce qui le caractérise. */
export const ALGO_ICON: Record<string, IconDefinition> = {
  ecb: faClone, // les blocs répétés
  cbc: faLink, // le chaînage
  ctr: faStopwatch, // le compteur
  gcm: faShieldCheck, // l'AEAD de référence
  gcmsiv: faRepeat, // le nonce qu'on peut répéter
  chacha: faMusic, // la danse
  kw: faGift, // l'emballage
  'rsa-textbook': faBook, // textbook
  'rsa-pkcs1': faBomb, // l'oracle de Bleichenbacher
  'rsa-oaep': faShuffle, // le masquage
  'rsa-kem': faCapsules, // l'encapsulation
  ecies: faAppleWhole, // la variante Apple
  hpke: faBoxOpen, // l'enveloppe moderne
  mlkem: faTableCells, // le réseau euclidien
  hybrid: faCodeMerge, // deux secrets fusionnés
  'rsa-pkcs1-sig': faSignature,
  'rsa-pss': faSaltShaker, // le sel
  ecdsa: faDice, // le nonce k
  ed25519: faFeather, // légèreté, déterminisme
  mldsa: faCube, // le module
  slhdsa: faTrees, // la forêt de Merkle
  dh: faSquareRootVariable, // l'arithmétique modulaire
  ecdh: faBezierCurve, // la courbe
  x25519: faWaveSine, // la courbe de Montgomery
  'kex-grid': faGrid2, // les quatre cases
  sigma: faUserCheck, // l'identité signée
  'chip-auth': faPassport,
  ratchet: faArrowsSpin, // le cliquet
};

const NUMS = [faCircle1, faCircle2, faCircle3, faCircle4, faCircle5, faCircle6, faCircle7, faCircle8, faCircle9];

export function Fad({ icon, className = '', title }: { icon: IconDefinition; className?: string; title?: string }) {
  return <FontAwesomeIcon icon={icon} className={`fad-i ${className}`} title={title} />;
}

/** Pastille numérotée des sections (circle-1, circle-2… en duotone). */
export function Num({ n }: { n: number }) {
  const icon = NUMS[n - 1];
  return icon ? <Fad icon={icon} className="num" /> : <span className="n">{n}</span>;
}
