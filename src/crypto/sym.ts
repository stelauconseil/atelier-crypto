// Chiffrement symétrique : AES (ECB, CBC, CTR, GCM, GCM-SIV, KW) et ChaCha20-Poly1305.
// WebCrypto quand le navigateur le fournit, @noble/ciphers sinon.
import { ecb, gcmsiv, aeskw } from '@noble/ciphers/aes.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ab, concat, xor, type Bytes } from '../lib/bytes';
import { CryptoRejected, seg, type Seg, type View } from './types';

export interface SymOut {
  wire: Seg[];
  inside: View[];
}
export interface SymIn {
  pt: Bytes;
  inside: View[];
}

export interface SymAlgo {
  keyLens: number[];
  nonceLen: number; // 0 : pas de nonce
  nonceName: string;
  tagLen: number;
  aead: boolean;
  /** Le clair est saisi en hexadécimal (clé à envelopper) plutôt qu'en texte. */
  hexPlaintext?: boolean;
  pipelineEnc: string[];
  pipelineDec: string[];
  encrypt(key: Bytes, nonce: Bytes, pt: Bytes, aad: Bytes): Promise<SymOut>;
  decrypt(key: Bytes, wire: Bytes, aad: Bytes): Promise<SymIn>;
}

const subtle = () => globalThis.crypto.subtle;

export function pkcs7(pt: Bytes, bs = 16): Bytes {
  const n = bs - (pt.length % bs);
  return concat(pt, new Uint8Array(n).fill(n));
}

export function unpkcs7(p: Bytes, bs = 16): Bytes {
  const n = p[p.length - 1];
  if (n < 1 || n > bs || p.length < n) throw new CryptoRejected(`Remplissage invalide (dernier octet 0x${n.toString(16).padStart(2, '0')})`);
  for (let i = p.length - n; i < p.length; i++)
    if (p[i] !== n) throw new CryptoRejected('Remplissage invalide : octets de bourrage incohérents');
  return p.slice(0, p.length - n);
}

/** Vue « clair découpé en blocs de 16 octets, remplissage PKCS#7 en évidence ». */
function paddedView(pt: Bytes, title = 'Clair remplissé (PKCS#7), par blocs de 16 octets'): View {
  const n = 16 - (pt.length % 16);
  return {
    title,
    caption: `${pt.length} octets de clair + ${n} octet(s) de bourrage valant 0x${n.toString(16).padStart(2, '0')}`,
    segs: [seg('Clair', pt, 'pt'), seg('Bourrage PKCS#7', new Uint8Array(n).fill(n), 'pad')],
    block: 16,
  };
}

async function importAes(key: Bytes, name: string) {
  return subtle().importKey('raw', ab(key), { name }, false, ['encrypt', 'decrypt']);
}

/** E_K(0¹²⁸) : la clé de hachage H de GHASH. */
export function aesBlock(key: Bytes, block: Bytes): Bytes {
  return ecb(key, { disablePadding: true }).encrypt(block);
}

// ---------------------------------------------------------------- ECB
export const ECB: SymAlgo = {
  keyLens: [16, 24, 32],
  nonceLen: 0,
  nonceName: '—',
  tagLen: 0,
  aead: false,
  pipelineEnc: ['Remplissage PKCS#7', 'Découpe en blocs', 'E_K bloc par bloc', 'C₁ ‖ C₂ ‖ …'],
  pipelineDec: ['D_K bloc par bloc', 'Contrôle du remplissage', 'Clair'],
  async encrypt(key, _n, pt) {
    const padded = pkcs7(pt);
    const ct = ecb(key, { disablePadding: true }).encrypt(padded);
    return {
      wire: [seg('Chiffré', ct, 'ct', 'aucun IV : le même clair donne toujours le même chiffré')],
      inside: [
        paddedView(pt),
        { title: 'Chiffré par blocs : les blocs identiques sont signalés', segs: [seg('C', ct, 'ct')], block: 16, repeats: true },
      ],
    };
  },
  async decrypt(key, wire) {
    if (wire.length % 16) throw new CryptoRejected('Longueur non multiple de 16 octets');
    const padded = ecb(key, { disablePadding: true }).decrypt(wire);
    return { pt: unpkcs7(padded), inside: [{ title: 'Après D_K, avant retrait du remplissage', segs: [seg('Clair remplissé', padded, 'pt')], block: 16 }] };
  },
};

// ---------------------------------------------------------------- CBC
export const CBC: SymAlgo = {
  keyLens: [16, 24, 32],
  nonceLen: 16,
  nonceName: 'IV',
  tagLen: 0,
  aead: false,
  pipelineEnc: ['Remplissage PKCS#7', 'Pᵢ ⊕ Cᵢ₋₁ (C₀ = IV)', 'E_K', 'IV ‖ C'],
  pipelineDec: ['D_K', '⊕ Cᵢ₋₁', 'Contrôle du remplissage', 'Clair'],
  async encrypt(key, iv, pt) {
    const k = await importAes(key, 'AES-CBC');
    const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-CBC', iv: ab(iv) }, k, ab(pt)));
    return {
      wire: [seg('IV', iv, 'nonce', 'imprévisible, transmis en clair'), seg('Chiffré', ct, 'ct', 'aucune intégrité')],
      inside: [paddedView(pt), { title: 'Chiffré par blocs : plus de répétition, grâce au chaînage', segs: [seg('C', ct, 'ct')], block: 16, repeats: true }],
    };
  },
  async decrypt(key, wire) {
    const iv = wire.slice(0, 16);
    const ct = wire.slice(16);
    const k = await importAes(key, 'AES-CBC');
    try {
      const pt = new Uint8Array(await subtle().decrypt({ name: 'AES-CBC', iv: ab(iv) }, k, ab(ct)));
      return {
        pt,
        inside: [
          {
            title: 'Déchiffrement accepté',
            caption: "CBC n'a aucune intégrité : un chiffré altéré peut être « accepté » avec un clair modifié. Seul le remplissage est contrôlé.",
            segs: [seg('Clair', pt, 'pt')],
            block: 16,
          },
        ],
      };
    } catch {
      throw new CryptoRejected('Remplissage invalide. Si le serveur laisse voir cette erreur, c\'est un oracle de remplissage (Vaudenay 2002).');
    }
  },
};

// ---------------------------------------------------------------- CTR
export const CTR: SymAlgo = {
  keyLens: [16, 24, 32],
  nonceLen: 16,
  nonceName: 'Compteur initial',
  tagLen: 0,
  aead: false,
  pipelineEnc: ['E_K(compteur), E_K(compteur+1)…', 'Flux de clé', 'C = P ⊕ flux', 'nonce ‖ C'],
  pipelineDec: ['Même flux E_K(compteur…)', 'P = C ⊕ flux'],
  async encrypt(key, ctr, pt) {
    const k = await importAes(key, 'AES-CTR');
    const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-CTR', counter: ab(ctr), length: 64 }, k, ab(pt)));
    return {
      wire: [seg('Compteur initial', ctr, 'nonce', 'unique par message et par clé'), seg('Chiffré', ct, 'ct', '|C| = |P|, aucun remplissage')],
      inside: [
        {
          title: 'Flux de clé = C ⊕ P',
          caption: 'AES ne chiffre pas le message : il produit un flux pseudo-aléatoire, combiné au clair par XOR (malléable).',
          segs: [seg('Flux E_K(compteur…)', xor(ct, pt), 'mask')],
          block: 16,
        },
      ],
    };
  },
  async decrypt(key, wire) {
    const ctr = wire.slice(0, 16);
    const ct = wire.slice(16);
    const k = await importAes(key, 'AES-CTR');
    const pt = new Uint8Array(await subtle().decrypt({ name: 'AES-CTR', counter: ab(ctr), length: 64 }, k, ab(ct)));
    return {
      pt,
      inside: [{ title: 'Toujours « accepté »', caption: 'CTR ne détecte rien : un bit inversé dans C inverse le même bit du clair.', segs: [seg('Clair', pt, 'pt')] }],
    };
  },
};

// ---------------------------------------------------------------- GCM
export const GCM: SymAlgo = {
  keyLens: [16, 24, 32],
  nonceLen: 12,
  nonceName: 'Nonce (96 bits)',
  tagLen: 16,
  aead: true,
  pipelineEnc: ['H = E_K(0)', 'CTR à partir de J₀ + 1', 'GHASH(AAD, C)', 'tag = GHASH ⊕ E_K(J₀)', 'nonce ‖ C ‖ tag'],
  pipelineDec: ['Recalcul du tag', 'Comparaison', 'Déchiffrement CTR', 'Clair ou ⊥'],
  async encrypt(key, nonce, pt, aad) {
    const k = await importAes(key, 'AES-GCM');
    const out = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: ab(nonce), additionalData: ab(aad), tagLength: 128 }, k, ab(pt)));
    const ct = out.slice(0, out.length - 16);
    const tag = out.slice(out.length - 16);
    const H = aesBlock(key, new Uint8Array(16));
    const J0 = concat(nonce, new Uint8Array([0, 0, 0, 1]));
    return {
      wire: [seg('Nonce', nonce, 'nonce', 'jamais deux fois avec la même clé'), seg('Chiffré', ct, 'ct'), seg('Tag', tag, 'tag', '128 bits')],
      inside: [
        {
          title: 'Valeurs internes de GCM',
          caption: 'H est la clé du MAC polynomial GHASH ; E_K(J₀) masque le résultat. Nonce réutilisé ⇒ même masque ⇒ H calculable ⇒ falsifications.',
          segs: [seg('H = E_K(0¹²⁸)', H, 'secret'), seg('J₀ = nonce ‖ 00000001', J0, 'nonce'), seg('E_K(J₀)', aesBlock(key, J0), 'mask')],
        },
        { title: 'Données associées (authentifiées, non chiffrées)', segs: [seg('AAD', aad, 'aad')] },
      ],
    };
  },
  async decrypt(key, wire, aad) {
    const k = await importAes(key, 'AES-GCM');
    try {
      const pt = new Uint8Array(
        await subtle().decrypt({ name: 'AES-GCM', iv: ab(wire.slice(0, 12)), additionalData: ab(aad), tagLength: 128 }, k, ab(wire.slice(12))),
      );
      return { pt, inside: [] };
    } catch {
      throw new CryptoRejected('⊥ — tag invalide : chiffré, nonce ou AAD altéré. Aucun octet de clair n\'est rendu.');
    }
  },
};

// ---------------------------------------------------------------- AES-GCM-SIV
export const GCMSIV: SymAlgo = {
  keyLens: [16, 32],
  nonceLen: 12,
  nonceName: 'Nonce (96 bits)',
  tagLen: 16,
  aead: true,
  pipelineEnc: ['Clés dérivées du nonce', 'POLYVAL(AAD, P)', 'tag (sert d\'IV synthétique)', 'CTR depuis le tag', 'nonce ‖ C ‖ tag'],
  pipelineDec: ['CTR depuis le tag', 'POLYVAL(AAD, P)', 'Comparaison du tag', 'Clair ou ⊥'],
  async encrypt(key, nonce, pt, aad) {
    const out = gcmsiv(key, nonce, aad).encrypt(pt);
    return {
      wire: [seg('Nonce', nonce, 'nonce', 'sa réutilisation ne révèle que l\'égalité des messages'), seg('Chiffré', out.slice(0, -16), 'ct'), seg('Tag (IV synthétique)', out.slice(-16), 'tag')],
      inside: [
        {
          title: 'Résistance à la réutilisation de nonce',
          caption: 'Le tag est calculé sur le clair puis sert d\'IV au chiffrement : même (clé, nonce, AAD, clair) ⇒ même sortie, rien de plus ne fuit.',
          segs: [seg('Tag', out.slice(-16), 'tag')],
        },
      ],
    };
  },
  async decrypt(key, wire, aad) {
    try {
      return { pt: gcmsiv(key, wire.slice(0, 12), aad).decrypt(wire.slice(12)), inside: [] };
    } catch {
      throw new CryptoRejected('⊥ — tag invalide.');
    }
  },
};

// ---------------------------------------------------------------- ChaCha20-Poly1305
export const CHACHA: SymAlgo = {
  keyLens: [32],
  nonceLen: 12,
  nonceName: 'Nonce (96 bits)',
  tagLen: 16,
  aead: true,
  pipelineEnc: ['Bloc 0 → clé Poly1305 (r, s)', 'Flux ChaCha20 dès le bloc 1', 'C = P ⊕ flux', 'Poly1305(AAD, C)', 'nonce ‖ C ‖ tag'],
  pipelineDec: ['Recalcul Poly1305', 'Comparaison', 'Déchiffrement', 'Clair ou ⊥'],
  async encrypt(key, nonce, pt, aad) {
    const out = chacha20poly1305(key, nonce, aad).encrypt(pt);
    return {
      wire: [seg('Nonce', nonce, 'nonce'), seg('Chiffré', out.slice(0, -16), 'ct'), seg('Tag Poly1305', out.slice(-16), 'tag')],
      inside: [{ title: 'Données associées', segs: [seg('AAD', aad, 'aad')] }],
    };
  },
  async decrypt(key, wire, aad) {
    try {
      return { pt: chacha20poly1305(key, wire.slice(0, 12), aad).decrypt(wire.slice(12)), inside: [] };
    } catch {
      throw new CryptoRejected('⊥ — tag Poly1305 invalide.');
    }
  },
};

// ---------------------------------------------------------------- AES-KW
export const KW: SymAlgo = {
  keyLens: [16, 24, 32],
  nonceLen: 0,
  nonceName: '—',
  tagLen: 0,
  aead: false,
  hexPlaintext: true,
  pipelineEnc: ['A = A6A6A6A6A6A6A6A6', '6 × n tours de E_K', 'A ‖ R₁ ‖ … ‖ Rₙ'],
  pipelineDec: ['6 × n tours de D_K', 'A = A6A6… ?', 'Clé ou ⊥'],
  async encrypt(kek, _n, pt) {
    if (pt.length < 16 || pt.length % 8) throw new CryptoRejected('AES-KW enveloppe une clé de 16, 24 ou 32 octets (multiple de 8, ≥ 16).');
    const out = aeskw(kek).encrypt(pt);
    return {
      wire: [seg('Clé enveloppée', out, 'ct', '8 octets de plus que la clé : l\'intégrité est intégrée')],
      inside: [{ title: 'Valeur d\'intégrité initiale (RFC 3394)', caption: 'Au déchiffrement, A doit redevenir A6A6A6A6A6A6A6A6, sinon rejet.', segs: [seg('A (IV par défaut)', new Uint8Array(8).fill(0xa6), 'hdr')] }],
    };
  },
  async decrypt(kek, wire) {
    try {
      return { pt: aeskw(kek).decrypt(wire), inside: [] };
    } catch {
      throw new CryptoRejected('⊥ — la valeur d\'intégrité A ne vaut pas A6A6A6A6A6A6A6A6.');
    }
  },
};

export const SYM: Record<string, SymAlgo> = { ecb: ECB, cbc: CBC, ctr: CTR, gcm: GCM, gcmsiv: GCMSIV, chacha: CHACHA, kw: KW };
