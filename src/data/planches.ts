// Planches A4 du cours, en PDF, proposées au téléchargement.
// Dans l'artefact claude.ai (VITE_HISTORY=memory), les fichiers ne sont pas embarqués : on pointe vers le site public.
const BASE = import.meta.env.VITE_HISTORY === 'memory' ? 'https://stelauconseil.github.io/atelier-crypto/' : import.meta.env.BASE_URL;
export const planchesUrl = (f: string) => `${BASE}planches/${f}`;

export interface PlanchePage {
  n: number;
  label: string;
  title: string;
  sections: string;
  thumb: string;
}

export interface Planche {
  id: string;
  file: string;
  title: string;
  sub: string;
  version: string;
  size: string;
  pages: PlanchePage[];
}

export const PLANCHES: Planche[] = [
  {
    id: 'f1f2',
    file: 'planches-chiffrement-signature-v3.pdf',
    title: 'Chiffrer, transmettre une clé, signer',
    sub: 'Feuilles F1 et F2 : symétrique, asymétrique, signatures et notions du cours',
    version: 'v3 · novembre 2026',
    size: '515 Ko',
    pages: [
      { n: 1, label: 'F1 recto', title: 'Chiffrer des données : de PKCS#1 v1.5 à HPKE', sections: '§ 1 à 3 : hybride KEM/DEM, le symétrique en 25 ans, modes d\'AES, règles d\'or', thumb: 'v3-1.webp' },
      { n: 2, label: 'F1 verso', title: 'Transmettre une clé : du transport au KEM', sections: '§ 4 à 7 : frise, transport / accord / KEM, comparatif, glossaire', thumb: 'v3-2.webp' },
      { n: 3, label: 'F2 recto', title: 'Signer : de PKCS#1 v1.5 à SLH-DSA', sections: '§ 8 à 11 : signature et MAC, frise, trois familles, comparatif', thumb: 'v3-3.webp' },
      { n: 4, label: 'F2 verso', title: 'Comprendre : les notions derrière les planches', sections: '§ 12 à 17 : AEAD, MAC et hachage, jeux de sécurité, preuves, PKCS#1', thumb: 'v3-4.webp' },
    ],
  },
  {
    id: 'f3',
    file: 'planche-aes-permutations-v2.pdf',
    title: 'AES, permutations et pseudo-aléa',
    sub: 'Feuille F3 : ce que veut dire « AES est une permutation », masque jetable, anniversaires',
    version: 'v2 stabilisée · 8 novembre 2026',
    size: '485 Ko',
    pages: [
      { n: 1, label: 'F3 · 1/4', title: 'AES est une permutation : de quoi parle-t-on ?', sections: '§ 1 à 4 : fonctions et permutations, (2¹²⁸)!, le catalogue des clés', thumb: 'f3-1.webp' },
      { n: 2, label: 'F3 · 2/4', title: 'Dans AES : quatre bijections, aucun marquage', sections: '§ 5 à 8 : anatomie d\'un tour, S-box, wide trail', thumb: 'f3-2.webp' },
      { n: 3, label: 'F3 · 3/4', title: '128 bits de clé, un téraoctet de données', sections: '§ 9 à 12 : primitive et mode, masque jetable contre AES-CTR, jeu PRP', thumb: 'f3-3.webp' },
      { n: 4, label: 'F3 · 4/4', title: 'Anniversaires et catalogue en miniature', sections: '§ 13 à 16 : anniversaires, données par clé, exemple sur 3 bits', thumb: 'f3-4.webp' },
    ],
  },
];

/** Pages de planche à recommander depuis chaque algorithme (onglet « Pour aller plus loin »). */
export const PLANCHE_FOR: Record<string, [string, number][]> = {
  ecb: [['f1f2', 1], ['f3', 3]],
  cbc: [['f1f2', 1], ['f3', 3]],
  ctr: [['f1f2', 1], ['f3', 3], ['f3', 4]],
  gcm: [['f1f2', 1], ['f1f2', 4], ['f3', 4]],
  gcmsiv: [['f1f2', 1], ['f3', 4]],
  chacha: [['f1f2', 1], ['f1f2', 4]],
  kw: [['f1f2', 1]],
  sha256: [['f1f2', 4]],
  hmac: [['f1f2', 4]],
  hkdf: [['f1f2', 2]],
  dh: [['f1f2', 2]],
  ecdh: [['f1f2', 2]],
  x25519: [['f1f2', 2]],
  'rsa-textbook': [['f1f2', 2], ['f1f2', 4]],
  'rsa-pkcs1': [['f1f2', 2], ['f1f2', 4]],
  'rsa-oaep': [['f1f2', 2]],
  'rsa-kem': [['f1f2', 2]],
  ecies: [['f1f2', 2]],
  hpke: [['f1f2', 1], ['f1f2', 2]],
  mlkem: [['f1f2', 2]],
  hybrid: [['f1f2', 1], ['f1f2', 2]],
  'rsa-pkcs1-sig': [['f1f2', 3], ['f1f2', 4]],
  'rsa-pss': [['f1f2', 3]],
  ecdsa: [['f1f2', 3]],
  ed25519: [['f1f2', 3]],
  mldsa: [['f1f2', 3]],
  slhdsa: [['f1f2', 3]],
};
