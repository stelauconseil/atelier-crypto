export type Family = 'sym' | 'kex' | 'pke' | 'sig';
export type PillTone = 'ok' | 'mid' | 'ko' | 'pq' | 'nt';

export interface AlgoInfo {
  id: string;
  family: Family;
  name: string;
  short: string;
  year: string;
  status: [string, PillTone][];
  lead: string;
  points: string[];
  formula?: string;
  pitfalls?: string[];
  where?: string;
  refs?: string;
  defaultText?: string;
}

export const FAMILIES: { id: Family; label: string; sub: string }[] = [
  { id: 'sym', label: 'Chiffrement symétrique', sub: 'AES et ses modes, AEAD' },
  { id: 'kex', label: 'Établissement de clé', sub: 'Diffie-Hellman, statique ou éphémère' },
  { id: 'pke', label: 'Chiffrement asymétrique', sub: 'Du transport de clé au KEM' },
  { id: 'sig', label: 'Signatures', sub: 'De PKCS#1 v1.5 à SLH-DSA' },
];

export const ALGOS: AlgoInfo[] = [
  // ------------------------------------------------------------------ symétrique
  {
    id: 'ecb', family: 'sym', name: 'AES-ECB', short: 'ECB', year: '1981 (mode) · 2001 (AES)', status: [['à bannir', 'ko']],
    lead: 'Chaque bloc de 16 octets est chiffré indépendamment par E_K. C\'est le mode « sans mode » : AES pur, appliqué bloc par bloc.',
    points: ['Blocs clairs égaux ⇒ blocs chiffrés égaux : la structure du message reste visible (le « pingouin »).', 'Déterministe : le même message donne toujours le même chiffré, donc aucune sécurité IND-CPA.', 'Remplissage PKCS#7 : on complète jusqu\'au multiple de 16, chaque octet de bourrage vaut le nombre d\'octets ajoutés.'],
    formula: 'Cᵢ = E_K(Pᵢ)',
    pitfalls: ['Tapez un message qui répète 16 caractères identiques (ex. « AAAAAAAAAAAAAAAA » deux fois) : les blocs chiffrés répétés s\'allument.'],
    where: 'Jamais, sauf pour chiffrer un unique bloc aléatoire (ex. dériver H dans GCM).', refs: 'FIPS 81 · SP 800-38A',
    defaultText: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA — mêmes blocs, mêmes chiffrés',
  },
  {
    id: 'cbc', family: 'sym', name: 'AES-CBC', short: 'CBC', year: '1981', status: [['legacy', 'mid']],
    lead: 'Chaque bloc clair est combiné par XOR au chiffré précédent avant E_K ; un IV imprévisible amorce la chaîne.',
    points: ['Plus de répétition visible : le chaînage diffuse chaque bloc dans les suivants.', 'Aucune intégrité : un bit inversé dans Cᵢ inverse le même bit de Pᵢ₊₁ (et brouille Pᵢ).', 'Seul le remplissage est contrôlé : l\'erreur « remplissage invalide », si elle est observable, est un oracle (Vaudenay 2002, POODLE, Lucky13).'],
    formula: 'Cᵢ = E_K(Pᵢ ⊕ Cᵢ₋₁),  C₀ = IV',
    pitfalls: ['Altérez un octet du chiffré, puis déchiffrez : soit le clair est modifié sans alerte, soit le remplissage est rejeté.'],
    where: 'TLS ≤ 1.2, anciens CMS et fichiers chiffrés. À composer en encrypt-then-MAC.', refs: 'SP 800-38A',
  },
  {
    id: 'ctr', family: 'sym', name: 'AES-CTR', short: 'CTR', year: '2001', status: [['brique', 'nt']],
    lead: 'AES devient un générateur de flux : on chiffre un compteur, et le résultat est combiné au clair par XOR.',
    points: ['Parallélisable, pas de remplissage : |C| = |P|.', 'Malléable : inverser un bit du chiffré inverse exactement le même bit du clair.', 'Compteur unique impératif : C₁ ⊕ C₂ = P₁ ⊕ P₂ si le flux est réutilisé.'],
    formula: 'Cᵢ = Pᵢ ⊕ E_K(compteur + i)',
    where: 'Brique de GCM et CCM, SRTP.', refs: 'SP 800-38A',
  },
  {
    id: 'gcm', family: 'sym', name: 'AES-GCM', short: 'GCM', year: '2004 · 2007', status: [['AEAD de référence', 'ok']],
    lead: 'CTR pour la confidentialité, plus GHASH, un MAC polynomial dans GF(2¹²⁸), pour l\'intégrité du chiffré et des données associées.',
    points: ['Chiffre et authentifie : tout bit altéré (C, nonce, AAD ou tag) donne ⊥, aucun clair n\'est rendu.', 'AAD : authentifiées mais transmises en clair (en-têtes, identifiants).', 'Nonce de 96 bits, jamais réutilisé sous une même clé : sinon le masque E_K(J₀) se répète, H se calcule et les falsifications deviennent possibles.'],
    formula: 'tag = GHASH_H(AAD, C) ⊕ E_K(J₀),  H = E_K(0¹²⁸)',
    where: 'TLS 1.2/1.3, IPsec, JWE (A256GCM), CryptoKit, HPKE.', refs: 'SP 800-38D · RFC 5116',
  },
  {
    id: 'gcmsiv', family: 'sym', name: 'AES-GCM-SIV', short: 'GCM-SIV', year: '2019', status: [['robuste', 'ok']],
    lead: 'Le tag est calculé d\'abord, sur le clair, puis sert d\'IV synthétique au chiffrement CTR.',
    points: ['Réutiliser un nonce ne révèle que l\'égalité de deux messages identiques.', 'Deux passes sur les données : un peu plus lent que GCM.', 'Clés de chiffrement et de MAC dérivées du nonce à chaque message.'],
    formula: 'tag = AES(POLYVAL(AAD, P)) ;  C = CTR_tag(P)',
    where: 'Systèmes où l\'unicité des nonces est difficile à garantir (KMS cloud).', refs: 'RFC 8452',
  },
  {
    id: 'chacha', family: 'sym', name: 'ChaCha20-Poly1305', short: 'ChaCha20', year: '2015', status: [['AEAD de référence', 'ok']],
    lead: 'Chiffrement par flot ARX (additions, rotations, XOR) sans AES, avec le MAC Poly1305. Rapide en logiciel et en temps constant par construction.',
    points: ['Clé de 256 bits, nonce de 96 bits, tag de 128 bits.', 'Le premier bloc de flux fournit la clé Poly1305 (r, s), à usage unique par message.', 'Pas une permutation : aucune limite d\'anniversaire liée à la taille de bloc.'],
    formula: 'tag = Poly1305_(r,s)(AAD, C)',
    where: 'TLS 1.3, WireGuard, SSH, HPKE.', refs: 'RFC 8439',
  },
  {
    id: 'kw', family: 'sym', name: 'AES-KW (key wrap)', short: 'AES-KW', year: '2002', status: [['clés', 'ok']],
    lead: 'Chiffrement déterministe réservé à l\'enveloppement de clés : 6 × n tours d\'AES et une valeur d\'intégrité A = A6A6A6A6A6A6A6A6.',
    points: ['Pas de nonce : le déterminisme est acceptable parce que le contenu (une clé) est aléatoire.', 'Intégrité intégrée : la sortie fait 8 octets de plus que la clé enveloppée.', 'La KEK (key encryption key) protège une DEK (data encryption key).'],
    formula: 'Wrap_KEK(DEK) = A ‖ R₁ ‖ … ‖ Rₙ',
    where: 'HSM, PKCS#11, CMS, JWE A256KW.', refs: 'RFC 3394 · RFC 5649 · SP 800-38F',
  },
  // ------------------------------------------------------------------ asymétrique
  {
    id: 'rsa-textbook', family: 'pke', name: 'RSA « textbook »', short: 'RSA brut', year: '1977', status: [['jamais tel quel', 'ko']],
    lead: 'La primitive nue : le message est un entier m < n, et c = mᵉ mod n. Indispensable pour comprendre, inutilisable en pratique.',
    points: ['Déterministe : chiffrer deux fois le même message donne le même c ; on peut tester des clairs candidats.', 'Malléable : c·sᵉ se déchiffre en m·s mod n, sans connaître la clé.', 'C\'est cette malléabilité qu\'exploite l\'attaque de Bleichenbacher.'],
    formula: 'c = mᵉ mod n ;  m = cᵈ mod n',
    refs: 'Rivest, Shamir, Adleman 1977',
  },
  {
    id: 'rsa-pkcs1', family: 'pke', name: 'RSAES-PKCS1-v1_5', short: 'PKCS#1 v1.5', year: '1993', status: [['interdit pour les clés', 'ko']],
    lead: 'Remplissage aléatoire simple : EM = 00 ‖ 02 ‖ PS ‖ 00 ‖ M, puis c = EMᵉ mod n. Le « vieux » transport de clé de TLS ≤ 1.2.',
    points: ['PS : au moins 8 octets aléatoires non nuls ; le premier 00 qui suit marque le début de M.', 'Un destinataire qui laisse voir (erreur, délai) si EM commence par 00 02 offre un oracle : ~10⁴ à 10⁶ requêtes suffisent à retrouver M.', 'Interdit après 2023 pour le transport de clés (SP 800-131A), absent de TLS 1.3.'],
    formula: 'EM = 00 ‖ 02 ‖ PS ‖ 00 ‖ M ;  c = EMᵉ mod n',
    pitfalls: ['Altérez un octet du chiffré : le message d\'erreur qui s\'affiche est exactement l\'information que l\'attaquant exploite.'],
    where: 'TLS ≤ 1.2 (échange RSA), vieux CMS / S/MIME.', refs: 'RFC 8017 · Bleichenbacher 1998 · ROBOT 2017 · Marvin 2023',
  },
  {
    id: 'rsa-oaep', family: 'pke', name: 'RSAES-OAEP', short: 'RSA-OAEP', year: '1994 · 1998', status: [['OK', 'ok'], ['en sursis', 'pq']],
    lead: 'Remplissage randomisé par un réseau de Feistel à deux tours (MGF1) : IND-CCA2 dans le modèle de l\'oracle aléatoire.',
    points: ['Chiffrement probabiliste : une graine aléatoire masque tout l\'EM.', 'Sans clé privée, EM ressemble à de l\'aléa : pas de format vérifiable de l\'extérieur.', 'Ici, l\'encodage est fait à la main et le déchiffrement par WebCrypto : preuve d\'interopérabilité octet pour octet.'],
    formula: 'DB = lHash ‖ PS ‖ 01 ‖ M ;  EM = 00 ‖ seed ⊕ MGF1(maskedDB) ‖ DB ⊕ MGF1(seed)',
    where: 'CMS, JWE RSA-OAEP-256, PKCS#11, Apple OAEPSHA256AESGCM.', refs: 'RFC 8017 · Bellare-Rogaway 1994',
  },
  {
    id: 'rsa-kem', family: 'pke', name: 'RSA-KEM', short: 'RSA-KEM', year: '2001', status: [['OK, rare', 'ok'], ['en sursis', 'pq']],
    lead: 'Pas de remplissage : on chiffre un entier r uniforme, et la clé de session est K = KDF(r). Réduction IND-CCA2 serrée.',
    points: ['Le secret n\'est pas « choisi » par l\'émetteur : c\'est l\'aléa encapsulé qui fait naître K.', 'Ici : KDF2 (X9.63, SHA-256) → clé AES-256 et nonce, puis AES-GCM (KEM/DEM).', 'Même structure que HPKE et ML-KEM : enc ‖ C ‖ tag.'],
    formula: 'enc = rᵉ mod n ;  K = KDF(r)',
    where: 'CMS (RFC 5990, RFC 9690).', refs: 'ISO/IEC 18033-2 · Shoup 2001',
  },
  {
    id: 'ecies', family: 'pke', name: 'ECIES (P-256, variante Apple)', short: 'ECIES', year: '1998 · 2000', status: [['OK', 'ok'], ['peu interopérable', 'mid']],
    lead: 'ECDH éphémère-statique, puis KDF, puis AEAD. Ici la variante de Apple SecKey : X9.63-KDF(SHA-256) avec E en sharedInfo, puis AES-128-GCM et un IV de 16 octets dérivé.',
    points: ['Aucune authentification de l\'émetteur : n\'importe qui peut chiffrer pour B.', 'Pas de confidentialité persistante côté destinataire : compromettre d_B révèle tous les messages passés.', '« ECIES » désigne une famille : KDF, sharedInfo, encodage du point, DEM et cofacteur varient d\'une implémentation à l\'autre.'],
    formula: 'E = e·G ;  Z = x(e·Q_B) ;  K ‖ IV = X9.63-KDF(Z, E)',
    where: 'Apple Secure Enclave (SecKeyCreateEncryptedData), cartes, eID.', refs: 'SEC 1 v2 · ANSI X9.63 · IEEE 1363a',
  },
  {
    id: 'hpke', family: 'pke', name: 'HPKE (RFC 9180)', short: 'HPKE', year: '2022', status: [['standard moderne', 'ok']],
    lead: 'ECIES rigoureusement spécifié : une suite KEM + KDF + AEAD, un key schedule étiqueté, quatre modes (Base, PSK, Auth, AuthPSK).',
    points: ['Ici : mode Base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.', 'Implémenté à la main dans l\'atelier et vérifié contre la bibliothèque de référence @hpke/core.', 'Le mode Auth authentifie l\'émetteur ; l\'exporter_secret dérive d\'autres clés.'],
    formula: '(shared, enc) = Encap(pkR) ;  KeySchedule(mode, shared, info, psk)',
    where: 'MLS, TLS ECH, Oblivious HTTP, CryptoKit.', refs: 'RFC 9180',
  },
  {
    id: 'mlkem', family: 'pke', name: 'ML-KEM-768 (ex-Kyber)', short: 'ML-KEM', year: '2024', status: [['post-quantique', 'pq']],
    lead: 'KEM fondé sur les réseaux euclidiens (Module-LWE), rendu IND-CCA2 par la transformation de Fujisaki-Okamoto.',
    points: ['Clé publique 1 184 octets, encapsulation 1 088 octets, secret 32 octets.', 'Rejet implicite : un ct altéré ne provoque pas d\'erreur, Decaps rend un secret pseudo-aléatoire, donc pas d\'oracle.', 'Ici combiné à AES-256-GCM via HKDF : chiffrement hybride KEM/DEM.'],
    formula: '(ct, ss) = Encaps(ek) ;  ss = Decaps(dk, ct)',
    where: 'TLS 1.3 (hybride), CryptoKit et Secure Enclave (macOS 26).', refs: 'FIPS 203',
  },
  {
    id: 'hybrid', family: 'pke', name: 'X25519MLKEM768 (hybride)', short: 'Hybride PQ', year: '2024', status: [['transition', 'pq']],
    lead: 'KEM hybride : classique et post-quantique en parallèle, secrets concaténés. Sûr tant que l\'un des deux résiste.',
    points: ['Ordre normalisé pour TLS : la partie ML-KEM d\'abord, puis X25519.', 'Protège dès aujourd\'hui contre « harvest now, decrypt later ».', 'X-Wing (projet IETF) combine autrement, avec SHA3-256 et une étiquette.'],
    formula: 'ss = ss_ML-KEM ‖ ss_X25519',
    where: 'TLS 1.3 par défaut dans les navigateurs.', refs: 'draft-ietf-tls-ecdhe-mlkem',
  },
  // ------------------------------------------------------------------ établissement de clé
  {
    id: 'dh', family: 'kex', name: 'Diffie-Hellman (corps fini)', short: 'DH', year: '1976', status: [['ffdhe ≥ 3072 bits', 'mid'], ['en sursis', 'pq']],
    lead: 'Deux parties publient gᵃ et gᵇ ; chacune élève la valeur de l\'autre à son propre exposant secret et obtient le même gᵃᵇ, sans jamais l\'avoir transmis.',
    points: ['Ni chiffrement ni signature : un accord de clé, non interactif et symétrique dans les rôles. Le troisième service de la cryptographie asymétrique.', 'La sécurité repose sur le logarithme discret (et sur l\'hypothèse CDH / DDH) : retrouver a à partir de gᵃ mod p.', 'Z n\'est jamais utilisé tel quel : il passe dans une KDF (HKDF, X9.63, Concat KDF) qui en tire des clés uniformes.', 'Il faut valider la valeur reçue : 1 < Y < p − 1 et Y appartient au sous-groupe d\'ordre q.'],
    formula: 'A = gᵃ mod p,  B = gᵇ mod p,  Z = Bᵃ = Aᵇ = gᵃᵇ mod p',
    pitfalls: ['Choisissez le groupe jouet (p = 23) pour suivre les calculs à la main, puis remplacez la valeur publique de Bob par p − 1 et désactivez la validation.'],
    where: 'TLS (DHE), IKEv2, SSH, OpenPGP ; remplacé presque partout par ECDH et X25519.', refs: 'RFC 7919 · SP 800-56A · RFC 2631',
  },
  {
    id: 'ecdh', family: 'kex', name: 'ECDH P-256', short: 'ECDH', year: '1985 · 2000', status: [['OK', 'ok'], ['en sursis', 'pq']],
    lead: 'Diffie-Hellman dans le groupe des points d\'une courbe elliptique : Z est l\'abscisse de a·B = b·A = ab·G.',
    points: ['256 bits sur courbe ≈ 3 072 bits en corps fini (~128 bits de sécurité).', 'Clé publique : point (X, Y), non compressé 04 ‖ X ‖ Y (65 octets) ou compressé 02/03 ‖ X (33 octets).', 'Le point reçu doit être sur la courbe : sinon, attaque par point invalide (Jager, Schwenk, Somorovsky 2015).'],
    formula: 'Z = x(a · B) = x(b · A) = x(ab · G)',
    pitfalls: ['Altérez un octet de la clé publique de Bob : le point sort de la courbe et il est refusé.'],
    where: 'TLS, ECIES, JWE ECDH-ES, passeports (Chip Authentication, PACE), mdoc, Bluetooth LE, FIDO2.', refs: 'SP 800-56A · SEC 1 · FIPS 186-5',
  },
  {
    id: 'x25519', family: 'kex', name: 'X25519 (Curve25519)', short: 'X25519', year: '2006 · 2016', status: [['référence moderne', 'ok'], ['en sursis', 'pq']],
    lead: 'ECDH sur Curve25519 avec l\'échelle de Montgomery : uniquement la coordonnée u, 32 octets, calcul à temps constant, sans cas particulier.',
    points: ['Toute chaîne de 32 octets est une clé privée valide après « clamping » : 3 bits bas à 0 (cofacteur 8), bit 255 à 0, bit 254 à 1.', 'Toute chaîne de 32 octets est acceptée comme clé publique : les points d\'ordre faible donnent Z = 0, à refuser.', 'Conçue pour être difficile à mal implémenter (Bernstein, 2006).'],
    formula: 'Z = X25519(a, u_B) = X25519(b, u_A)',
    pitfalls: ['Envoyez le point u = 0 à la place de la clé publique de Bob : le secret serait nul.'],
    where: 'TLS 1.3, SSH, Signal, WireGuard, HPKE, age, Tor, X25519MLKEM768.', refs: 'RFC 7748',
  },
  {
    id: 'kex-grid', family: 'kex', name: 'Statique ou éphémère ?', short: 'Statique / éph.', year: '2006 · SP 800-56A', status: [['notion clé', 'nt']],
    lead: 'Chaque côté utilise soit une clé statique (longue durée, souvent certifiée), soit une clé éphémère tirée pour la session. Ce choix décide de tout : fraîcheur, confidentialité persistante, authentification.',
    points: ['Statique : authentifie implicitement son détenteur (lui seul peut calculer Z), mais sa fuite rouvre toutes les sessions où elle a servi.', 'Éphémère : rend Z neuf et, effacée après usage, protège le passé (forward secrecy), mais n\'authentifie personne.', 'Éphémère × éphémère : il faut authentifier autrement, par signatures (SIGMA, TLS 1.3) ou par un mot de passe (PACE, SAE).'],
    formula: 'C(2e, 0s) · C(1e, 1s) · C(0e, 2s) · C(2e, 2s)  (SP 800-56A)',
    pitfalls: ['Lancez trois sessions statique × statique : Z ne change jamais. Passez Alice en éphémère, puis faites fuir la clé statique de Bob.'],
    where: 'Voir le catalogue sous l\'atelier : de TLS au passeport, chaque protocole occupe une case.', refs: 'SP 800-56A Rev. 3 · Noise',
  },
  {
    id: 'sigma', family: 'kex', name: 'DH authentifié (STS, SIGMA)', short: 'SIGMA', year: '1992 · 2003', status: [['schéma de TLS 1.3', 'ok']],
    lead: 'DH éphémère des deux côtés pour la confidentialité persistante, puis chacun signe les deux valeurs éphémères avec sa clé d\'identité : l\'homme du milieu est démasqué.',
    points: ['DH « nu » ne protège que contre l\'écoute passive : Mallory peut faire deux échanges et relayer.', 'Station-to-Station (Diffie, van Oorschot, Wiener 1992), puis SIGMA (Krawczyk 2003), base d\'IKEv2 et de TLS 1.3.', 'SIGMA ajoute un MAC sur l\'identité pour lier l\'identité à la clé de session.'],
    formula: 'σ_B = Sign_B(g^b ‖ g^a),  σ_A = Sign_A(g^a ‖ g^b)',
    pitfalls: ['Activez Mallory sans signatures : Alice et Bob acceptent, mais avec deux secrets différents, tous deux connus de Mallory.'],
    where: 'TLS 1.3 (CertificateVerify), IKEv2, SSH (signature de l\'hôte sur H).', refs: 'Krawczyk 2003 · RFC 8446 §4.4.3',
  },
  {
    id: 'chip-auth', family: 'kex', name: 'Chip Authentication (passeport)', short: 'Chip Auth.', year: '2006 · 2009', status: [['ICAO 9303-11', 'ok']],
    lead: 'Le système d\'inspection fait un ECDH entre une biclé éphémère et la clé statique de la puce, lue dans le DG14 et garantie par la signature de l\'État émetteur. Seule la vraie puce peut ensuite produire des MAC corrects : c\'est l\'anti-clonage.',
    points: ['La biclé de la puce est propre à chaque document, injectée à la personnalisation ; sa clé publique (DG14) est couverte par le SOD signé par le Document Signer (authentification passive).', 'Authentification implicite : aucune signature, donc aucune preuve transférable, contrairement à l\'Active Authentication.', 'Les clés de session K_Enc et K_MAC remplacent celles de BAC/PACE : le Secure Messaging redémarre.'],
    formula: 'Z = x(sk_puce · PK_IS) ;  K_Enc = H(Z ‖ 1),  K_MAC = H(Z ‖ 2)',
    pitfalls: ['Lisez une puce clonée : DG14 et SOD sont parfaitement authentiques, mais le MAC de la première réponse est faux.'],
    where: 'Passeports européens depuis 2009 (EAC), cartes d\'identité, titres de séjour.', refs: 'ICAO Doc 9303-11 · BSI TR-03110',
  },
  {
    id: 'ratchet', family: 'kex', name: 'Double Ratchet (Signal)', short: 'Double Ratchet', year: '2013 · 2016', status: [['messagerie', 'ok']],
    lead: 'Deux cliquets : un cliquet DH (nouvelle paire X25519 à chaque changement de sens) et un cliquet symétrique (une KDF dérive une clé par message). Chaque message a sa propre clé.',
    points: ['Confidentialité persistante : une clé de message volée ne permet pas de remonter aux précédentes.', 'Auto-guérison (post-compromise security) : après le vol de l\'état, le prochain pas DH, tiré sans que l\'attaquant le voie, le remet dehors.', 'Initialisé par X3DH (puis PQXDH avec ML-KEM) ; le DH n\'a lieu qu\'au changement de sens, pas à chaque message.'],
    formula: '(RK, CK) = KDF_RK(RK, DH(…)) ;  (CK, MK) = KDF_CK(CK)',
    pitfalls: ['Échangez quelques messages, faites voler l\'état de Bob, puis continuez : Ève lit les premiers messages, puis plus rien.'],
    where: 'Signal, WhatsApp, Google Messages (RCS), Facebook Messenger ; MLS pour les groupes.', refs: 'Signal Double Ratchet spec (2016)',
  },
  // ------------------------------------------------------------------ signatures
  {
    id: 'rsa-pkcs1-sig', family: 'sig', name: 'RSASSA-PKCS1-v1_5', short: 'PKCS#1 v1.5', year: '1993', status: [['accepté, legacy', 'mid'], ['en sursis', 'pq']],
    lead: 'EM = 00 ‖ 01 ‖ FF…FF ‖ 00 ‖ DigestInfo ‖ H(M), puis σ = EMᵈ mod n. Déterministe.',
    points: ['Pas d\'oracle de déchiffrement ici : ce « v1.5 »-là reste accepté, contrairement au chiffrement.', 'Danger : un vérificateur laxiste qui n\'analyse pas tout l\'EM (e = 3 : falsifications 2006, BERserk 2014). Bonne pratique : réencoder l\'EM attendu et comparer.', 'L\'atelier calcule σᵉ mod n pour montrer l\'EM signé.'],
    formula: 'σ = (00 01 FF…FF 00 ‖ DigestInfo ‖ H(M))ᵈ mod n',
    where: 'Certificats X.509, CMS, CAdES/PAdES, JWS RS256.', refs: 'RFC 8017',
  },
  {
    id: 'rsa-pss', family: 'sig', name: 'RSASSA-PSS', short: 'RSA-PSS', year: '1996 · 2002', status: [['recommandé', 'ok'], ['en sursis', 'pq']],
    lead: 'Signature RSA probabiliste : un sel aléatoire, un haché H et un masque MGF1. Preuve serrée dans le modèle de l\'oracle aléatoire.',
    points: ['Signer deux fois le même message donne deux σ différentes.', 'EM = maskedDB ‖ H ‖ BC ; le vérificateur démasque DB pour retrouver le sel, puis recalcule H.', 'Imposé par TLS 1.3 pour les signatures de la poignée de main.'],
    formula: 'H = SHA-256(0⁸ ‖ H(M) ‖ sel) ;  EM = (PS ‖ 01 ‖ sel) ⊕ MGF1(H) ‖ H ‖ BC',
    where: 'TLS 1.3, JWS PS256, signature qualifiée.', refs: 'RFC 8017 · Bellare-Rogaway 1996',
  },
  {
    id: 'ecdsa', family: 'sig', name: 'ECDSA P-256', short: 'ECDSA', year: '1992 · 1999', status: [['OK', 'ok'], ['en sursis', 'pq']],
    lead: 'Signature sur courbe elliptique : tout repose sur un nonce k secret, unique et uniforme pour chaque signature.',
    points: ['Deux formats pour la même signature : brut r ‖ s (64 octets, JOSE et WebCrypto) ou DER (X.509, OpenSSL).', 'k réutilisé pour deux messages ⇒ deux équations, deux inconnues ⇒ clé privée retrouvée (Sony PS3, 2010). Démonstration ci-dessous.', '(r, −s) est aussi valide : ECDSA est malléable (pas SUF-CMA).'],
    formula: 'r = x(k·G) mod q ;  s = k⁻¹(h + d·r) mod q',
    where: 'Secure Enclave, passkeys/WebAuthn, mdoc ISO 18013-5, wallets EUDI, JWS ES256.', refs: 'FIPS 186-5 · RFC 6979',
  },
  {
    id: 'ed25519', family: 'sig', name: 'Ed25519', short: 'Ed25519', year: '2011', status: [['OK', 'ok'], ['en sursis', 'pq']],
    lead: 'Schnorr sur Curve25519 (forme d\'Edwards) : nonce déterministe par construction, formules complètes, temps constant.',
    points: ['Clé publique 32 octets, signature 64 octets (R ‖ S).', 'r = H(préfixe ‖ M) : resigner donne la même signature, aucun risque de nonce répété.', 'Approuvé par le NIST dans FIPS 186-5 (2023).'],
    formula: 'R = r·B ;  S = r + H(R ‖ A ‖ M)·a',
    where: 'SSH, Signal, DNSSEC, Git, FIPS 186-5.', refs: 'RFC 8032',
  },
  {
    id: 'mldsa', family: 'sig', name: 'ML-DSA-65 (ex-Dilithium)', short: 'ML-DSA', year: '2024', status: [['post-quantique', 'pq']],
    lead: 'Signature sur réseaux euclidiens (Module-LWE/SIS), paradigme « Fiat-Shamir with aborts » : on recommence tant que la signature pourrait fuir s₁.',
    points: ['Clé publique 1 952 octets, signature 3 309 octets (c̃ ‖ z ‖ h).', 'Rapide à signer et à vérifier ; version « hedged » par défaut.', 'Disponible dans CryptoKit et la Secure Enclave depuis macOS 26.'],
    formula: 'z = y + c·s₁,  rejet si ‖z‖∞ trop grand',
    where: 'X.509 et TLS en cours, CryptoKit.', refs: 'FIPS 204',
  },
  {
    id: 'slhdsa', family: 'sig', name: 'SLH-DSA (ex-SPHINCS+)', short: 'SLH-DSA', year: '2024', status: [['post-quantique', 'pq'], ['conservateur', 'ok']],
    lead: 'Signature fondée uniquement sur une fonction de hachage : hyper-arbre d\'arbres de Merkle de signatures WOTS+, feuilles FORS. Sans état.',
    points: ['Clé publique de 32 octets seulement, mais signatures de 8 à 17 Ko (et jusqu\'à 50 Ko).', 'Le choix conservateur : aucune hypothèse algébrique, seulement la sécurité de SHA-256 ou SHAKE.', 'Comparez les variantes 128f (rapide, grande) et 128s (compacte, lente).'],
    formula: 'σ = R ‖ SIG_FORS ‖ SIG_HT',
    where: 'Racines de confiance, archivage long terme, firmware.', refs: 'FIPS 205',
  },
];

export const byId = (id: string) => ALGOS.find((a) => a.id === id);
