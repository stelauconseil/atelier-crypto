export type Lane = 'sym' | 'rsa' | 'ec' | 'sig' | 'pq';

export const LANES: { id: Lane; label: string; color: string }[] = [
  { id: 'sym', label: 'Symétrique', color: 'var(--teal)' },
  { id: 'rsa', label: 'RSA', color: 'var(--navy)' },
  { id: 'ec', label: 'DH / courbes', color: 'var(--orange)' },
  { id: 'sig', label: 'Signatures', color: 'var(--plum)' },
  { id: 'pq', label: 'Post-quantique', color: 'var(--violet)' },
];

export interface Ev {
  year: number;
  lane: Lane;
  title: string;
  detail: string;
  algo?: string;
  bad?: boolean;
}

export const EVENTS: Ev[] = [
  { year: 1977, lane: 'sym', title: 'DES', detail: 'FIPS 46 : bloc 64 bits, clé 56 bits ; cassé par force brute en 1998.' },
  { year: 1981, lane: 'sym', title: 'Modes ECB, CBC, CFB, OFB', detail: 'FIPS 81.', algo: 'ecb' },
  { year: 2001, lane: 'sym', title: 'AES et CTR', detail: 'FIPS 197 (Rijndael) ; CTR normalisé (SP 800-38A).', algo: 'ctr' },
  { year: 2002, lane: 'sym', title: 'Oracle de remplissage', detail: 'Vaudenay sur CBC, puis Lucky13 et POODLE (2013-14).', algo: 'cbc', bad: true },
  { year: 2002, lane: 'sym', title: 'AES-KW', detail: 'RFC 3394 : enveloppement de clés.', algo: 'kw' },
  { year: 2007, lane: 'sym', title: 'GCM', detail: 'SP 800-38D : l\'AEAD de référence (CCM en 2004).', algo: 'gcm' },
  { year: 2015, lane: 'sym', title: 'ChaCha20-Poly1305', detail: 'RFC 7539, puis RFC 8439.', algo: 'chacha' },
  { year: 2016, lane: 'sym', title: 'Sweet32', detail: 'Collisions d\'anniversaire sur 3DES (blocs de 64 bits).', bad: true },
  { year: 2018, lane: 'sym', title: 'TLS 1.3', detail: 'RFC 8446 : AEAD uniquement, CBC et RC4 supprimés.' },
  { year: 2019, lane: 'sym', title: 'AES-GCM-SIV', detail: 'RFC 8452 : tolère la réutilisation de nonce.', algo: 'gcmsiv' },

  { year: 1977, lane: 'rsa', title: 'RSA', detail: 'Rivest, Shamir, Adleman.', algo: 'rsa-textbook' },
  { year: 1993, lane: 'rsa', title: 'PKCS#1 v1.5', detail: 'Remplissage 00 02 PS 00 M.', algo: 'rsa-pkcs1' },
  { year: 1994, lane: 'rsa', title: 'OAEP', detail: 'Bellare et Rogaway ; adopté par PKCS#1 v2.0 en 1998.', algo: 'rsa-oaep' },
  { year: 1998, lane: 'rsa', title: 'Bleichenbacher', detail: '« Attaque du million de messages » sur PKCS#1 v1.5.', algo: 'rsa-pkcs1', bad: true },
  { year: 2001, lane: 'rsa', title: 'RSA-KEM', detail: 'Shoup ; ISO/IEC 18033-2 en 2006.', algo: 'rsa-kem' },
  { year: 2017, lane: 'rsa', title: 'ROBOT', detail: 'Bleichenbacher toujours exploitable dans des serveurs TLS.', bad: true },
  { year: 2018, lane: 'rsa', title: 'Fin du transport RSA', detail: 'TLS 1.3 le supprime.' },
  { year: 2023, lane: 'rsa', title: 'Marvin', detail: 'Variante temporelle dans de nombreuses bibliothèques ; v1.5 interdit pour les clés.', bad: true },

  { year: 1976, lane: 'ec', title: 'Diffie-Hellman', detail: '« New Directions in Cryptography ».' },
  { year: 1985, lane: 'ec', title: 'Courbes elliptiques', detail: 'Koblitz et Miller.' },
  { year: 1998, lane: 'ec', title: 'DHAES / DHIES', detail: 'Abdalla, Bellare, Rogaway.', algo: 'ecies' },
  { year: 2000, lane: 'ec', title: 'ECIES normalisé', detail: 'SEC 1, ANSI X9.63, IEEE 1363a.', algo: 'ecies' },
  { year: 2006, lane: 'ec', title: 'Curve25519', detail: 'Bernstein ; X25519 normalisé en 2016 (RFC 7748).' },
  { year: 2010, lane: 'ec', title: 'HKDF', detail: 'RFC 5869 : extract puis expand.' },
  { year: 2022, lane: 'ec', title: 'HPKE', detail: 'RFC 9180 ; MLS en 2023.', algo: 'hpke' },

  { year: 1993, lane: 'sig', title: 'Signature PKCS#1 v1.5', detail: '00 01 FF…FF 00 ‖ DigestInfo.', algo: 'rsa-pkcs1-sig' },
  { year: 1992, lane: 'sig', title: 'ECDSA', detail: 'Vanstone ; normalisé en 1999-2000 (X9.62, FIPS 186-2).', algo: 'ecdsa' },
  { year: 2002, lane: 'sig', title: 'RSASSA-PSS', detail: 'PKCS#1 v2.1.', algo: 'rsa-pss' },
  { year: 2006, lane: 'sig', title: 'Falsification e = 3', detail: 'Bleichenbacher : vérificateurs laxistes ; BERserk en 2014.', bad: true },
  { year: 2010, lane: 'sig', title: 'Sony PS3', detail: 'Nonce ECDSA fixe : clé privée retrouvée.', algo: 'ecdsa', bad: true },
  { year: 2011, lane: 'sig', title: 'Ed25519', detail: 'Bernstein et al. ; RFC 8032 en 2017.', algo: 'ed25519' },
  { year: 2017, lane: 'sig', title: 'SHAttered', detail: 'Première collision SHA-1.', bad: true },
  { year: 2023, lane: 'sig', title: 'FIPS 186-5', detail: 'EdDSA approuvé, DSA retiré.' },

  { year: 1994, lane: 'pq', title: 'Algorithme de Shor', detail: 'Factorisation et logarithme discret en temps polynomial sur ordinateur quantique.' },
  { year: 2016, lane: 'pq', title: 'Appel du NIST', detail: 'Concours de normalisation post-quantique.' },
  { year: 2022, lane: 'pq', title: 'Sélection', detail: 'Kyber, Dilithium, Falcon, SPHINCS+ retenus.' },
  { year: 2024, lane: 'pq', title: 'FIPS 203 / 204 / 205', detail: 'ML-KEM, ML-DSA, SLH-DSA ; TLS hybride par défaut dans les navigateurs.', algo: 'mlkem' },
  { year: 2030, lane: 'pq', title: 'Dépréciation (projet)', detail: 'RSA et ECC de 112 bits dépréciés (NIST IR 8547).' },
  { year: 2035, lane: 'pq', title: 'Interdiction (projet)', detail: 'RSA et ECC interdits (NIST IR 8547).' },
];
