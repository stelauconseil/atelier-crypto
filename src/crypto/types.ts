import type { Bytes } from '../lib/bytes';

/** Rôle d'un segment d'octets : détermine sa couleur et sa légende dans l'interface. */
export type Tone =
  | 'key' // clé symétrique
  | 'priv' // clé privée
  | 'pub' // clé publique
  | 'nonce' // IV / nonce
  | 'pt' // clair
  | 'ct' // chiffré
  | 'tag' // tag d'authentification
  | 'aad' // données associées
  | 'pad' // remplissage / bourrage
  | 'hdr' // octets fixes de format (00 02, 0x04, BC…)
  | 'enc' // encapsulation transmise
  | 'sig' // signature
  | 'hash' // haché
  | 'salt' // sel / aléa
  | 'mask' // masque, flux de clé
  | 'secret'; // secret partagé, clé dérivée

export interface Seg {
  label: string;
  bytes: Bytes;
  tone: Tone;
  note?: string;
}

/** Une vue affichable : soit une suite de segments d'octets, soit un texte (JWK, PEM…). */
export interface View {
  title: string;
  caption?: string;
  segs?: Seg[];
  text?: string;
  /** Afficher les octets par blocs de N (ex. 16 pour AES) et signaler les blocs répétés. */
  block?: number;
  repeats?: boolean;
}

export const seg = (label: string, bytes: Bytes, tone: Tone, note?: string): Seg => ({ label, bytes, tone, note });

/** Erreur « pédagogique » : son message est affiché tel quel à l'utilisateur. */
export class CryptoRejected extends Error {}
