// Où trouve-t-on Diffie-Hellman ? Chaque usage est rangé dans la grille statique / éphémère.
// ee : éphémère × éphémère · es : éphémère × statique · ss : statique × statique · mix : plusieurs DH combinés.
export type Cell = 'ee' | 'es' | 'ss' | 'mix';

export interface DhUse {
  name: string;
  domain: string;
  cell: Cell;
  dh: string;
  auth: string;
}

export const CELL_LABEL: Record<Cell, string> = {
  ee: 'éphémère × éphémère',
  es: 'éphémère × statique',
  ss: 'statique × statique',
  mix: 'plusieurs DH combinés',
};

export const DH_USES: DhUse[] = [
  // ---------------------------------------------------------------- éphémère × éphémère, authentifié à part
  { name: 'TLS 1.3', domain: 'Web, API', cell: 'ee', dh: '(EC)DHE seul autorisé : X25519, P-256, ffdhe ; X25519MLKEM768 en hybride', auth: 'Signature du serveur sur la transcription (CertificateVerify) : un SIGMA' },
  { name: 'TLS 1.2 (ECDHE_*)', domain: 'Web, API', cell: 'ee', dh: 'ECDHE ou DHE ; les suites DH/ECDH statiques et le transport RSA existent encore', auth: 'Signature du serveur sur les paramètres DH (ServerKeyExchange)' },
  { name: 'SSH', domain: 'Administration', cell: 'ee', dh: 'curve25519-sha256, ecdh-sha2-nistp256 ; mlkem768x25519-sha256 et sntrup761x25519 en hybride', auth: 'Signature de la clé d\'hôte sur le haché d\'échange H' },
  { name: 'IKEv2 / IPsec', domain: 'VPN', cell: 'ee', dh: 'Groupes DH (14, 19, 31…), ML-KEM ajouté par échanges intermédiaires (RFC 9370)', auth: 'Signatures ou PSK : SIGMA est né pour IKE' },
  { name: 'DTLS-SRTP, WebRTC', domain: 'Visioconférence', cell: 'ee', dh: 'ECDHE dans DTLS', auth: 'Empreintes de certificats échangées par la signalisation' },
  { name: 'ZRTP', domain: 'Téléphonie chiffrée', cell: 'ee', dh: 'DH éphémère, avec mise en cache du secret précédent', auth: 'Short Authentication String lue à voix haute' },
  { name: 'Bluetooth LE Secure Connections', domain: 'Objets connectés', cell: 'ee', dh: 'ECDH P-256', auth: 'Comparaison numérique, passkey ou OOB ; « Just Works » ne protège pas de l\'homme du milieu' },
  { name: 'Wi-Fi WPA3 (SAE, Dragonfly)', domain: 'Réseau local', cell: 'ee', dh: 'DH éphémère dont le générateur est dérivé du mot de passe', auth: 'PAKE : le mot de passe, sans attaque hors ligne' },
  { name: 'PACE (passeport, CNIe)', domain: 'Documents d\'identité', cell: 'ee', dh: 'Deux DH : le premier crée un générateur à partir du nonce chiffré par le CAN ou la MRZ, le second établit la clé', auth: 'PAKE : le mot de passe imprimé (CAN, MRZ) ; jetons MAC croisés' },
  { name: 'ISO 18013-5 (mDL, mdoc)', domain: 'Identité numérique', cell: 'ee', dh: 'Clé éphémère du lecteur × clé éphémère du porteur → clés de session (SessionEstablishment)', auth: 'Authentification du document par signature ou par MAC (voir ci-dessous)' },
  { name: 'FIDO2 CTAP2 (clientPIN)', domain: 'Authentification', cell: 'ee', dh: 'ECDH P-256 entre la plateforme et l\'authentificateur pour protéger le PIN', auth: 'Aucune : protection contre l\'écoute du canal USB/NFC seulement' },
  { name: 'Signal : Double Ratchet', domain: 'Messagerie', cell: 'ee', dh: 'Nouvelle paire X25519 à chaque changement de sens de la conversation ; une KDF symétrique dérive une clé par message', auth: 'Héritée de l\'accord initial X3DH / PQXDH' },
  // ---------------------------------------------------------------- éphémère × statique (une passe, le statique est authentifié)
  { name: 'ECIES', domain: 'Chiffrement de fichiers, Apple', cell: 'es', dh: 'Éphémère de l\'émetteur × clé statique du destinataire', auth: 'Implicite côté destinataire ; l\'émetteur est anonyme' },
  { name: 'HPKE (mode Base)', domain: 'MLS, ECH, OHTTP, COSE', cell: 'es', dh: 'DHKEM : éphémère × statique du destinataire', auth: 'Implicite côté destinataire' },
  { name: 'JWE ECDH-ES, CMS (RFC 5753), OpenPGP (RFC 6637)', domain: 'Formats', cell: 'es', dh: 'Éphémère de l\'émetteur × statique du destinataire, puis KDF', auth: 'Implicite côté destinataire' },
  { name: 'age (X25519)', domain: 'Chiffrement de fichiers', cell: 'es', dh: 'Éphémère × clé du destinataire, une fois par destinataire', auth: 'Implicite côté destinataire' },
  { name: 'Chip Authentication (EAC)', domain: 'Passeports', cell: 'es', dh: 'Éphémère du système d\'inspection × clé statique de la puce (DG14)', auth: 'Implicite : seule la vraie puce calcule les bons MAC (anti-clonage)' },
  { name: 'mdoc : authentification par MAC', domain: 'Identité numérique', cell: 'es', dh: 'Clé statique du document (attestée dans le MSO) × éphémère du lecteur → EMacKey', auth: 'Implicite et non transférable, contrairement à une signature' },
  { name: 'Tor (ntor)', domain: 'Anonymat', cell: 'mix', dh: 'ntor : éphémère × éphémère et éphémère × clé statique du relais', auth: 'Implicite côté relais ; le client reste anonyme' },
  { name: 'Noise N, X, K', domain: 'Protocoles', cell: 'es', dh: 'Motifs à sens unique : e × s du destinataire', auth: 'Implicite côté destinataire' },
  // ---------------------------------------------------------------- statique × statique
  { name: 'TLS 1.2 ECDH statique (supprimé)', domain: 'Web', cell: 'ss', dh: 'Clé ECDH du certificat serveur, parfois du client', auth: 'Certificats ; pas de confidentialité persistante' },
  { name: 'Noise KK (partie ss)', domain: 'Protocoles', cell: 'ss', dh: 's × s, toujours accompagné d\'éphémères', auth: 'Mutuelle et implicite' },
  { name: 'JWE ECDH-1PU, HPKE Auth', domain: 'Formats', cell: 'ss', dh: 'Ajoute s_émetteur × s_destinataire à l\'éphémère', auth: 'Authentifie l\'émetteur sans signature' },
  // ---------------------------------------------------------------- combinaisons
  { name: 'Signal X3DH, puis PQXDH', domain: 'Messagerie', cell: 'mix', dh: 'IK_A × SPK_B, EK_A × IK_B, EK_A × SPK_B, EK_A × OPK_B (+ ML-KEM depuis 2023)', auth: 'Mutuelle et implicite, hors ligne grâce aux prékeys signées' },
  { name: 'WireGuard (Noise IKpsk2)', domain: 'VPN', cell: 'mix', dh: 'e×s, s×s, e×e, s×e : les quatre cases', auth: 'Clés statiques connues à l\'avance ; PSK optionnelle (résistance post-quantique)' },
  { name: 'MQV, HMQV', domain: 'Normes ANSI, IEEE', cell: 'mix', dh: 'Statique et éphémère combinés dans un seul calcul', auth: 'Mutuelle et implicite' },
  { name: 'MLS (RFC 9420)', domain: 'Messagerie de groupe', cell: 'mix', dh: 'TreeKEM : arbre de HPKE (DHKEM) rafraîchi par chaque membre', auth: 'Signatures des membres' },
  { name: 'Kerberos PKINIT (mode DH)', domain: 'Annuaire', cell: 'mix', dh: 'DH entre client et KDC', auth: 'Signatures et certificats' },
];
