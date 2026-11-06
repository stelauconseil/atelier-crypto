// « Pour aller plus loin » : l'explication détaillée de chaque élément affiché par l'atelier.
// Mise en forme minimale : paragraphes séparés par une ligne vide, listes en « - », `code`, **gras**.

export interface AdvSection {
  h: string;
  t: string;
}

export const ADVANCED: Record<string, AdvSection[]> = {
  ecb: [
    { h: 'Ce que montre la vue « par blocs »', t: `Le clair est complété par **PKCS#7** jusqu'au multiple de 16 octets : s'il manque n octets, on ajoute n octets valant n (de \`01\` à \`10\`). Un clair déjà aligné reçoit un bloc entier de \`10\` : sans cela, impossible de distinguer un dernier octet \`01\` légitime d'un bourrage.

Chaque bloc est ensuite chiffré seul : \`Cᵢ = E_K(Pᵢ)\`. La fonction étant une permutation fixe pour une clé donnée, deux blocs clairs égaux donnent deux blocs chiffrés égaux. C'est ce que l'atelier encadre en rouge.` },
    { h: 'Pourquoi c\'est rédhibitoire', t: `- ECB est **déterministe** : aucune sécurité IND-CPA, un observateur reconnaît un message déjà vu.
- La structure du clair fuit (le célèbre « pingouin » chiffré en ECB reste lisible).
- Un attaquant peut **réordonner, dupliquer ou supprimer** des blocs sans être détecté.

ECB n'est acceptable que pour chiffrer un unique bloc aléatoire : c'est d'ailleurs ainsi que GCM calcule \`H = E_K(0¹²⁸)\` (voir l'atelier GCM).` },
    { h: 'À essayer', t: `Gardez le message par défaut (32 « A »), chiffrez : les blocs 1 et 2 sont identiques. Ajoutez un caractère : le bourrage passe de 16 à 15 octets valant \`0f\`, et le dernier bloc change entièrement.` },
  ],
  cbc: [
    { h: 'Le chaînage', t: `\`Cᵢ = E_K(Pᵢ ⊕ Cᵢ₋₁)\` avec \`C₀ = IV\`. L'IV fait 16 octets, il est **public** (transmis en tête) mais doit être **imprévisible** : un IV prévisible a permis l'attaque BEAST contre TLS 1.0, où l'IV d'un enregistrement était le dernier bloc chiffré du précédent.

Au déchiffrement, \`Pᵢ = D_K(Cᵢ) ⊕ Cᵢ₋₁\` : c'est ce XOR avec le bloc chiffré précédent qui rend CBC malléable.` },
    { h: 'Ce que fait le bouton « Altérer un bit »', t: `- Inverser un bit de \`Cᵢ\` **brouille entièrement** \`Pᵢ\` (D_K est une permutation pseudo-aléatoire)…
- … et **inverse exactement le même bit** de \`Pᵢ₊₁\`, puisque \`Cᵢ\` y entre par XOR.

Si l'altération touche le dernier bloc, le bourrage devient le plus souvent invalide : le déchiffrement échoue avec « remplissage invalide ».` },
    { h: 'L\'oracle de remplissage (Vaudenay, 2002)', t: `Si un serveur répond différemment selon que le bourrage est valide ou non (message d'erreur, code HTTP, temps de réponse), l'attaquant modifie octet par octet le bloc précédent jusqu'à obtenir un bourrage valide. Il en déduit \`D_K(Cᵢ)\` octet par octet, en au plus 256 essais par octet, **sans jamais connaître la clé**. Lucky13 et POODLE en sont des variantes contre TLS.

Parade : ne jamais utiliser CBC sans MAC, et composer en **encrypt-then-MAC** (vérifier le MAC avant de toucher au bourrage) ; mieux, utiliser un AEAD.` },
  ],
  ctr: [
    { h: 'AES comme générateur de flux', t: `Le bloc de 16 octets « Compteur initial » est chiffré, puis incrémenté (ici sur ses 64 bits de poids faible) : \`E_K(ctr), E_K(ctr+1), …\`. Ces blocs forment le **flux de clé**, combiné au clair par XOR. AES n'est jamais appliqué au message lui-même, et D_K n'est jamais utilisé.

La vue « Flux de clé = C ⊕ P » le prouve : connaître un clair et son chiffré révèle le flux, donc tout message chiffré avec le même compteur.` },
    { h: 'Les deux règles', t: `- **Compteur unique** par clé : réutiliser un flux donne \`C₁ ⊕ C₂ = P₁ ⊕ P₂\`, ce que l'atelier signale si vous chiffrez deux messages différents sans changer le compteur.
- **Aucune intégrité** : un bit inversé dans C inverse le même bit du clair, et le déchiffrement « réussit ». CTR doit toujours être associé à un MAC ; c'est exactement ce que font GCM et CCM.` },
  ],
  gcm: [
    { h: 'Les valeurs internes affichées', t: `- \`H = E_K(0¹²⁸)\` : la clé du MAC polynomial **GHASH**, propre à la clé K.
- \`J₀ = nonce ‖ 00000001\` : le bloc compteur initial quand le nonce fait 96 bits. Le chiffrement CTR démarre à \`J₀ + 1\`.
- \`E_K(J₀)\` : le masque appliqué au résultat de GHASH pour former le tag.

\`tag = GHASH_H(AAD ‖ C ‖ longueurs) ⊕ E_K(J₀)\`, où GHASH évalue un polynôme en H dans le corps GF(2¹²⁸) dont les coefficients sont les blocs d'AAD et de C.` },
    { h: 'Pourquoi le nonce ne doit jamais se répéter', t: `Deux messages sous la même clé et le même nonce partagent le même flux CTR (donc \`C₁ ⊕ C₂ = P₁ ⊕ P₂\`) **et** le même masque \`E_K(J₀)\`. En combinant les deux tags, le masque disparaît et il reste une équation polynomiale dont H est racine : l'attaquant retrouve H et peut **forger des tags valides** pour n'importe quel message (attaque « forbidden » de Joux).

Avec des nonces aléatoires de 96 bits, la probabilité de collision impose de ne pas dépasser **2³² messages par clé** (SP 800-38D).` },
    { h: 'Ce que vérifie Open', t: `Le destinataire recalcule le tag sur AAD et C **avant** de déchiffrer quoi que ce soit, puis compare en temps constant. Un seul bit différent dans le nonce, l'AAD, C ou le tag donne ⊥, sans aucun octet de clair : c'est la propriété INT-CTXT qui, avec IND-CPA, donne IND-CCA2.` },
  ],
  gcmsiv: [
    { h: 'Un IV synthétique', t: `AES-GCM-SIV inverse l'ordre de GCM : il calcule d'abord un MAC (**POLYVAL**, cousin de GHASH) sur l'AAD **et le clair**, en tire le tag, puis utilise ce tag comme compteur initial du chiffrement CTR. Des clés de chiffrement et d'authentification sont dérivées du nonce à chaque message.` },
    { h: 'Ce que cela change', t: `- Si le nonce se répète, seule l'égalité de deux messages **identiques** fuit : chiffrez deux fois le même message avec le même nonce, la sortie est identique ; changez une lettre, tout change.
- Le prix : deux passes sur les données, et le chiffrement ne peut pas commencer avant d'avoir lu tout le clair.

Utile quand l'unicité des nonces est difficile à garantir (systèmes distribués, KMS).` },
  ],
  chacha: [
    { h: 'ChaCha20', t: `Un chiffrement par flot de Bernstein, construit uniquement avec des **additions modulo 2³², des rotations et des XOR** (ARX) sur un état de 16 mots de 32 bits (constantes, clé de 256 bits, compteur, nonce de 96 bits). Pas de table de substitution : le temps de calcul ne dépend pas des données, d'où une résistance naturelle aux attaques par canaux auxiliaires.` },
    { h: 'Poly1305 et la construction AEAD (RFC 8439)', t: `Le **bloc 0** du flux ChaCha20 fournit une clé Poly1305 à usage unique \`(r, s)\` ; le chiffrement utilise les blocs suivants. Le tag est un polynôme en r modulo 2¹³⁰ − 5, évalué sur l'AAD et C, auquel on ajoute s. Comme pour GCM, réutiliser un nonce réutilise \`(r, s)\` et permet de forger.

ChaCha20 n'est pas une permutation de blocs : il n'a pas la limite d'anniversaire des chiffrements par bloc de 128 bits.` },
  ],
  kw: [
    { h: 'Envelopper une clé', t: `AES-KW (RFC 3394) chiffre une clé de 16, 24 ou 32 octets (la DEK) sous une clé d'enveloppement (la KEK). La sortie fait **8 octets de plus** : la valeur d'intégrité initiale \`A = A6A6A6A6A6A6A6A6\` est mélangée au contenu par 6 × n tours d'AES.

Au déchiffrement, si A ne redevient pas \`A6A6…\`, la clé est rejetée : l'intégrité est intégrée, sans tag séparé.` },
    { h: 'Pourquoi déterministe, et pourquoi c\'est acceptable', t: `Il n'y a ni nonce ni aléa : la même clé enveloppée deux fois donne la même sortie. C'est acceptable parce que le contenu est lui-même une clé aléatoire, jamais un message structuré ou répété. On retrouve AES-KW dans les HSM (PKCS#11), CMS et JWE (\`A256KW\`). La variante KWP (RFC 5649) accepte des longueurs quelconques.` },
  ],
  'rsa-textbook': [
    { h: 'Les éléments de la biclé', t: `- **n = p·q**, le module de 2 048 bits (256 octets) ; p et q sont deux grands nombres premiers secrets.
- **e = 65537** (\`01 00 01\`) : l'exposant public, choisi petit et creux (deux bits à 1) pour accélérer le chiffrement.
- **d** : l'exposant privé, tel que \`e·d ≡ 1 mod λ(n)\`.

Le JWK (\`n\`, \`e\`, \`d\`, \`p\`, \`q\`, \`dp\`, \`dq\`, \`qi\`) et le PKCS#8 contiennent aussi les valeurs du CRT, qui accélèrent le déchiffrement d'un facteur 4 environ. Le SPKI en PEM, lui, encode \`SEQUENCE { AlgorithmIdentifier rsaEncryption, BIT STRING { SEQUENCE { n, e } } }\` en DER.` },
    { h: 'Pourquoi on ne l\'utilise jamais tel quel', t: `- **Déterministe** : rechiffrez le même message, le chiffré est identique. Un attaquant qui soupçonne « OUI » ou « NON » chiffre les deux et compare.
- **Malléable** : \`(c · sᵉ) mod n\` se déchiffre en \`m · s mod n\`. On transforme le clair sans le connaître : c'est le cœur de l'attaque de Bleichenbacher.
- **Petits messages** : si \`mᵉ < n\` (petit m, e = 3), c est un entier ordinaire et une racine cubique suffit à retrouver m.` },
  ],
  'rsa-pkcs1': [
    { h: 'Lecture de l\'EM', t: `\`EM = 00 ‖ 02 ‖ PS ‖ 00 ‖ M\`, de la taille exacte de n (256 octets) :
- \`00\` en tête garantit \`EM < n\` ;
- \`02\` est le **block type** du chiffrement (\`01\` est celui de la signature) ;
- \`PS\` : au moins 8 octets aléatoires **tous non nuls**, ce qui rend le chiffrement probabiliste ;
- le premier \`00\` après PS marque le début de M, d'où l'interdiction des octets nuls dans PS.

M fait donc au plus k − 11 = 245 octets.` },
    { h: 'L\'attaque de Bleichenbacher (1998)', t: `Un EM valide commence par \`00 02\`, donc le clair m appartient à \`[2B, 3B[\` avec \`B = 2^(8(k−2))\`. L'attaquant envoie \`c · sᵉ mod n\` pour des s bien choisis ; chaque fois que le serveur révèle (par un message, une alerte TLS ou un **délai**) que le remplissage est valide, il apprend que \`m·s mod n\` est dans cet intervalle, et resserre l'ensemble des valeurs possibles de m. Après 10⁴ à 10⁶ requêtes, il ne reste qu'une valeur : m, donc la clé de session, **sans jamais connaître d**.

Le message d'erreur affiché par l'atelier quand vous altérez le chiffré est exactement l'information exploitée.` },
    { h: 'Pourquoi les parades ont échoué', t: `TLS 1.2 demande de remplacer, en cas d'erreur, la clé par une valeur aléatoire et de continuer comme si de rien n'était. Mais tenir un comportement **en temps strictement constant** à travers tout le code (décodage, comparaison, allocation) s'est révélé presque impossible : ROBOT (2017) a retrouvé l'oracle chez de nombreux équipementiers, Marvin (2023) dans de nombreuses bibliothèques. D'où le retrait : SP 800-131A interdit ce chiffrement pour le transport de clés après 2023, et TLS 1.3 a supprimé le transport RSA.` },
  ],
  'rsa-oaep': [
    { h: 'Les étapes de l\'encodage (fait à la main ici)', t: `Avec SHA-256 (hLen = 32) et k = 256 :
- \`DB = lHash ‖ PS ‖ 01 ‖ M\` sur k − hLen − 1 = 223 octets, où \`lHash = SHA-256(label)\` (label vide ici) et PS des zéros ;
- une **graine** aléatoire de 32 octets ;
- \`maskedDB = DB ⊕ MGF1(seed, 223)\` ;
- \`maskedSeed = seed ⊕ MGF1(maskedDB, 32)\` ;
- \`EM = 00 ‖ maskedSeed ‖ maskedDB\`, puis \`c = EMᵉ mod n\`.

C'est un réseau de **Feistel à deux tours** : la graine masque DB, puis DB masqué masque la graine. Sans clé privée, EM est indiscernable de l'aléa.` },
    { h: 'MGF1', t: `\`MGF1(Z, L) = H(Z ‖ 00000000) ‖ H(Z ‖ 00000001) ‖ …\`, tronqué à L octets : un haché étiré en masque de longueur quelconque.` },
    { h: 'La preuve d\'interopérabilité', t: `L'atelier encode à la main puis demande au **navigateur** (WebCrypto, RSA-OAEP SHA-256) de déchiffrer. Si un seul octet de l'encodage était faux, le navigateur refuserait. Le décodage est ensuite refait à la main pour afficher la graine et DB.

OAEP est IND-CCA2 dans le modèle de l'oracle aléatoire, mais avec une réduction **lâche** ; une implémentation qui distingue ses cas d'erreur reste attaquable (Manger, 2001).` },
  ],
  'rsa-kem': [
    { h: 'Encapsuler plutôt que chiffrer', t: `Au lieu de mettre en forme une clé choisie, on tire un entier **r uniforme dans [0, n)** et on transmet \`enc = rᵉ mod n\`. Aucun remplissage, aucun format à vérifier : il n'y a pas d'oracle possible. La clé naît du KDF : \`K ‖ nonce = KDF2(r)\` (ici X9.63 avec SHA-256, 44 octets), puis AES-256-GCM chiffre le message.` },
    { h: 'Pourquoi c\'est plus propre qu\'OAEP', t: `La preuve IND-CCA2 de RSA-KEM est **serrée** : casser le schéma est presque exactement aussi dur que résoudre le problème RSA. Le paradigme **KEM/DEM** sépare proprement l'encapsulation (RSA) et le chiffrement des données (AEAD) : chaque étage peut être changé sans toucher à l'autre. C'est le modèle qu'adoptent HPKE et ML-KEM.` },
  ],
  ecies: [
    { h: 'Les formats affichés', t: `- **Point public non compressé** (SEC 1) : \`04 ‖ X ‖ Y\`, 65 octets. Le point éphémère E transmis a le même format.
- **Scalaire privé d** : 32 octets. Dans la Secure Enclave d'Apple, il ne sortirait jamais de la puce.
- **Z = x(e·Q_B)** : la coordonnée x du point commun, 32 octets.` },
    { h: 'La variante d\'Apple pas à pas', t: `\`kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM\` :
- KDF **X9.63** avec SHA-256 : \`SHA-256(Z ‖ compteur ‖ sharedInfo)\`, avec \`sharedInfo = E\` (le point éphémère) ;
- 32 octets dérivés : 16 pour la clé AES-128, 16 pour l'IV de GCM (« VariableIV ») ;
- envoi de \`E ‖ C ‖ tag\`.

Lier E dans le KDF empêche de rejouer le même secret avec un autre point. Le code de l'atelier suit cette variante ; l'interopérabilité avec \`SecKeyCreateDecryptedData\` reste à confirmer sur un Mac (c'est l'exercice proposé avec la Secure Enclave).` },
    { h: 'Limites', t: `ECIES n'authentifie pas l'émetteur, et ne donne aucune confidentialité persistante côté destinataire : compromettre d_B révèle tous les messages passés. « ECIES » désigne en outre une famille de variantes (KDF, sharedInfo, encodage du point, DEM), d'où son interopérabilité fragile. HPKE en est la version rigoureusement spécifiée.` },
  ],
  hpke: [
    { h: 'Les identifiants de suite', t: `HPKE (RFC 9180) nomme précisément chaque brique : **KEM** \`0x0020\` = DHKEM(X25519, HKDF-SHA256), **KDF** \`0x0001\` = HKDF-SHA256, **AEAD** \`0x0001\` = AES-128-GCM. Ces identifiants entrent dans chaque dérivation (\`suite_id\`), ce qui interdit de mélanger les contextes.` },
    { h: 'Le key schedule', t: `- **Encap** : \`skE\` aléatoire, \`enc = pkE\` (32 octets), \`dh = X25519(skE, pkR)\`, puis \`shared_secret = ExtractAndExpand(dh, enc ‖ pkR)\`.
- **KeySchedule** : \`key\`, \`base_nonce\` et \`exporter_secret\` sont dérivés de shared_secret, du mode (\`00\` = Base), de \`info\` (« atelier-crypto HPKE ») et d'un éventuel PSK.
- Chaque étape utilise **LabeledExtract** / **LabeledExpand** : le préfixe \`"HPKE-v1"\`, le suite_id et une étiquette (\`"eae_prk"\`, \`"shared_secret"\`, \`"key"\`…) sont ajoutés aux entrées de HKDF.

Le nonce du n-ième message vaut \`base_nonce ⊕ n\` : ici, un seul message, donc \`base_nonce\`.` },
    { h: 'Vérifié contre la référence', t: `L'implémentation de l'atelier, écrite à la main, est testée contre la bibliothèque **@hpke/core** : un message scellé ici est ouvert par la bibliothèque de référence. Les modes **Auth** (l'émetteur prouve son identité avec sa clé statique) et **PSK** ne changent que le key schedule.` },
  ],
  mlkem: [
    { h: 'Les formats FIPS 203 (ML-KEM-768)', t: `- **Clé d'encapsulation** (1 184 octets) : \`t̂\`, 3 polynômes de 256 coefficients sur 12 bits (3 × 384 octets), puis la graine \`ρ\` (32 octets) qui régénère la matrice publique A.
- **Clé de décapsulation** (2 400 octets) : \`ŝ\` (secret), une copie de la clé publique, \`H(ek)\` et \`z\`, l'aléa du rejet implicite.
- **Encapsulation** (1 088 octets) : \`u\` (960 octets) et \`v\` (128 octets), compressés.` },
    { h: 'Module-LWE en une phrase', t: `La clé publique est \`t = A·s + e\` : un produit matrice-vecteur de polynômes, bruité par une petite erreur e. Retrouver s à partir de (A, t) est le problème **Module Learning With Errors**, que l'on croit difficile même pour un ordinateur quantique.` },
    { h: 'Fujisaki-Okamoto et rejet implicite', t: `Le schéma de base n'est qu'IND-CPA. La transformation de Fujisaki-Okamoto le rend IND-CCA2 : à la décapsulation, on **rechiffre** ce qu'on vient de déchiffrer et on vérifie qu'on retrouve exactement le ct reçu. Si ce n'est pas le cas, on ne renvoie pas d'erreur : on renvoie \`K = J(z ‖ ct)\`, un secret pseudo-aléatoire. Altérez l'encapsulation : aucun message d'erreur côté KEM, c'est l'AEAD qui échoue ensuite.` },
  ],
  hybrid: [
    { h: 'Pourquoi hybrider', t: `ML-KEM est récent ; X25519 est éprouvé mais vulnérable à un futur ordinateur quantique. En combinant les deux, la clé reste sûre **tant que l'un des deux tient**. C'est la défense contre « harvest now, decrypt later » : un trafic enregistré aujourd'hui reste protégé demain.` },
    { h: 'Le format TLS 1.3', t: `X25519MLKEM768 (groupe \`0x11EC\`) : la part publique est \`ek ML-KEM (1 184 o) ‖ X25519 (32 o)\`, la réponse \`ct ML-KEM (1 088 o) ‖ X25519 éphémère (32 o)\`, et le secret \`ss_ML-KEM ‖ ss_X25519\` (64 octets) entre dans le key schedule de TLS.

X-Wing, proposé à l'IETF pour HPKE, combine différemment : \`SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ étiquette)\`, pour lier aussi les valeurs publiques.` },
  ],
  'rsa-pkcs1-sig': [
    { h: 'Lecture de l\'EM signé', t: `L'atelier calcule \`σᵉ mod n\` pour montrer ce qui a été signé :
- \`00 01\` : block type 1, réservé à la signature ;
- \`FF … FF\` : bourrage constant (au moins 8 octets) — c'est un schéma **déterministe** ;
- \`00\` : séparateur ;
- **DigestInfo** : \`30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20\`, soit en DER \`SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1 (sha256), NULL }, OCTET STRING (32 octets) }\` ;
- **H(M)** : les 32 octets du haché.` },
    { h: 'Le vrai danger : la vérification laxiste', t: `Contrairement au chiffrement v1.5, la signature n'offre **aucun oracle** : elle reste acceptée. Mais en 2006, Bleichenbacher a montré qu'un vérificateur qui se contente de chercher le haché sans contrôler qu'il termine exactement l'EM accepte des signatures forgées quand e = 3 (on fabrique une racine cubique approchée avec des octets « poubelle » à la fin). BERserk (2014) a retrouvé la faille dans NSS (Firefox).

La bonne pratique : **réencoder l'EM attendu** à partir de H(M) et comparer octet par octet, comme le fait l'atelier dans la vue de vérification.` },
  ],
  'rsa-pss': [
    { h: 'L\'EM d\'une signature PSS', t: `\`EM = maskedDB ‖ H ‖ BC\` (256 octets) :
- \`mHash = SHA-256(M)\`, un **sel** aléatoire de 32 octets ;
- \`H = SHA-256(0x00 × 8 ‖ mHash ‖ sel)\` ;
- \`DB = PS (zéros) ‖ 01 ‖ sel\`, masqué par \`MGF1(H)\` ;
- \`BC\` : octet final fixe ; le bit de poids fort de maskedDB est forcé à 0 pour que \`EM < n\`.

Le vérificateur démasque DB, lit le sel, recalcule H et compare : l'atelier affiche ces trois étapes.` },
    { h: 'Ce que le sel apporte', t: `Signez deux fois le même message : les deux σ diffèrent. La preuve de sécurité de PSS est **serrée** dans le modèle de l'oracle aléatoire (Bellare-Rogaway 1996), alors que PKCS#1 v1.5 n'a pas de preuve comparable. TLS 1.3 impose PSS pour les signatures de la poignée de main (les certificats peuvent rester en v1.5).` },
  ],
  ecdsa: [
    { h: 'Deux formats pour la même signature', t: `- **Brut (IEEE P1363)** : \`r ‖ s\`, 64 octets pour P-256. C'est le format de WebCrypto, de JOSE (\`ES256\`) et de COSE.
- **DER** : \`30 len 02 len r 02 len s\`, environ 70 à 72 octets. C'est le format de X.509, CMS et OpenSSL. Un octet \`00\` est ajouté devant r ou s quand son bit de poids fort vaut 1, pour qu'il ne soit pas lu comme négatif.

Confondre les deux est une source classique de bugs d'interopérabilité (signature JWT refusée par une bibliothèque Java, par exemple).` },
    { h: 'Le nonce k et l\'attaque PS3', t: `\`r = x(k·G) mod q\`, \`s = k⁻¹(h + d·r) mod q\`. Si le même k sert pour deux messages, r est identique, et les deux équations en s se résolvent : \`k = (h₁ − h₂)/(s₁ − s₂)\`, puis \`d = (s₁·k − h₁)/r\`. Sony a ainsi perdu la clé de signature de la PlayStation 3 en 2010 ; la démonstration en bas de l'atelier refait le calcul. Il suffit même de quelques bits de k biaisés ou fuyant par le temps de calcul (Minerva, TPM-Fail) pour retrouver d par réduction de réseau.

Parade : k **déterministe** (RFC 6979), dérivé de d et de h par HMAC-DRBG ; c'est le choix d'EdDSA par construction.` },
    { h: 'Malléabilité', t: `Si \`(r, s)\` est valide, \`(r, q − s)\` l'est aussi : ECDSA n'est pas SUF-CMA. Bitcoin impose pour cette raison un s « bas » (low-s).` },
  ],
  ed25519: [
    { h: 'Les formats RFC 8032', t: `- **Clé publique A** (32 octets) : la coordonnée y du point en petit-boutiste, le bit de poids fort portant le signe de x.
- **Clé privée** : une graine de 32 octets. \`SHA-512(graine)\` donne 64 octets : la première moitié, « clampée » (bits forcés), est le scalaire secret a ; la seconde est le **préfixe** du nonce.
- **Signature** (64 octets) : \`R ‖ S\`.` },
    { h: 'Nonce déterministe et Schnorr', t: `\`r = SHA-512(préfixe ‖ M)\`, \`R = r·B\`, \`S = r + SHA-512(R ‖ A ‖ M)·a mod ℓ\`. Le nonce dépend de la clé et du message : resigner donne la même signature, et deux messages différents ne partagent jamais r. La vérification teste \`S·B = R + H(R ‖ A ‖ M)·A\`. Les formules d'addition de la courbe d'Edwards sont **complètes** (pas de cas particulier), ce qui facilite une implémentation en temps constant.` },
  ],
  mldsa: [
    { h: 'Les formats FIPS 204 (ML-DSA-65)', t: `- **Clé publique** (1 952 octets) : \`ρ\` (32 octets, graine de A) ‖ \`t₁\` (6 polynômes, bits de poids fort de t).
- **Clé privée** (4 032 octets) : \`ρ ‖ K ‖ tr ‖ s₁ ‖ s₂ ‖ t₀\`, où \`tr = H(pk)\` et K sert au nonce déterministe.
- **Signature** (3 309 octets) : \`c̃\` (48 octets, le défi haché) ‖ \`z\` (5 polynômes) ‖ \`h\` (indices de correction).` },
    { h: 'Fiat-Shamir avec rejets', t: `Le signataire tire un masque y, calcule \`w = A·y\`, en garde les bits hauts \`w₁\`, dérive le défi \`c = H(μ ‖ w₁)\` et répond \`z = y + c·s₁\`. Si z (ou la correction) risque de révéler quelque chose de s₁, la signature est **rejetée et recommencée** avec un nouveau y : en moyenne quelques tentatives. Le vérificateur reconstruit w₁ à partir de z, c et t₁ grâce aux indices h, et vérifie que c̃ correspond.

Version « hedged » par défaut : un aléa est mélangé au calcul déterministe du masque, ce qui protège contre les attaques par fautes.` },
  ],
  slhdsa: [
    { h: 'Les formats FIPS 205', t: `- **Clé publique** (32 octets seulement) : \`PK.seed ‖ PK.root\`, la racine de l'hyper-arbre.
- **Clé privée** : \`SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root\`.
- **Signature** : \`R\` (aléa) ‖ signature **FORS** (k arbres de hauteur a) ‖ signature de l'**hyper-arbre** (d couches de signatures WOTS+ et de chemins d'authentification de Merkle).

Pour 128f : k = 33, a = 6, d = 22 ⇒ 17 088 octets. Pour 128s : k = 14, a = 12, d = 7 ⇒ 7 856 octets, mais une signature bien plus lente : comparez les temps affichés.` },
    { h: 'Sécurité fondée sur le seul hachage', t: `Aucune structure algébrique : la sécurité repose uniquement sur les propriétés de la fonction de hachage (SHA-256 ou SHAKE). C'est le choix **conservateur** du post-quantique, au prix de signatures volumineuses.

« Sans état » : contrairement à LMS et XMSS, aucun compteur à tenir. L'indice de la feuille est tiré pseudo-aléatoirement du message, et l'hyper-arbre est assez grand pour que les collisions restent négligeables. C'est le descendant normalisé de SPHINCS+.` },
  ],
  // ------------------------------------------------------------------ établissement de clé
  dh: [
    { h: 'Une famille à part entière', t: `Le NIST range DH dans l'**établissement de clé**, aux côtés de deux autres sous-familles :

- **l'accord de clé** : DH, ECDH, X25519 (SP 800-56A). Les deux parties contribuent, aucune ne choisit seule le secret ;
- **le transport de clé** : une partie choisit la clé et la chiffre pour l'autre, avec RSA-OAEP (SP 800-56B) ;
- **l'encapsulation (KEM)** : RSA-KEM, ML-KEM (SP 800-227), et DHKEM, qui n'est qu'un DH éphémère-statique mis en forme de KEM.

DH est aussi un **composant** : ECIES et HPKE (pages du chiffrement asymétrique) sont des assemblages « accord de clé + KDF + AEAD », et presque tous les protocoles sécurisés en contiennent au moins un (voir le catalogue de la page « Statique ou éphémère ? »).` },
    { h: 'Ce que montre l\'atelier', t: `- **Groupe jouet** (p = 23, g = 2, q = 11) : 2 engendre le sous-groupe d'ordre 11 des carrés. Les exposants sont petits : on refait les calculs à la main.
- **ffdhe2048** (RFC 7919) : p est un nombre premier **sûr** (q = (p − 1)/2 est premier), ses chiffres viennent de e, ce qui écarte tout soupçon de porte dérobée. Les groupes ffdhe3072 et au-delà sont ceux à retenir aujourd'hui.

Les valeurs sont affichées en octets grand-boutistes, sur la taille de p : c'est ainsi que TLS et IKE les transportent, zéros de tête compris (leur suppression en TLS ≤ 1.2 est la cause de l'attaque Raccoon).` },
    { h: 'Petit sous-groupe et validation', t: `Si Alice élève à sa puissance a une valeur Y choisie par Mallory sans la vérifier :

- Y = 1 ou Y = p − 1 (ordres 1 et 2) : Z vaut 1 ou ±1, Mallory le devine sans rien connaître ;
- Y d'ordre petit r : Z tombe dans un ensemble de r valeurs, ce qui révèle a mod r. Avec plusieurs petits ordres et le théorème des restes chinois, une clé **statique** fuit entièrement (Lim et Lee, 1997).

Parade (SP 800-56A §5.6.2.3) : vérifier 1 < Y < p − 1 et Yᵠ = 1 mod p, utiliser un nombre premier sûr, et préférer des clés éphémères.` },
    { h: 'Logjam et la taille des groupes', t: `Le calcul du logarithme discret par crible algébrique se fait en deux temps : un énorme **précalcul** qui ne dépend que de p, puis une résolution rapide pour chaque échange. Logjam (2015) a montré qu'un serveur pouvait être forcé vers le DH « export » de 512 bits, et qu'un précalcul sur quelques groupes de 1024 bits très répandus suffisait à écouter une grande part du trafic VPN et HTTPS. D'où : pas de groupe de moins de 2048 bits, et des groupes nommés plutôt que générés à la volée.` },
  ],
  ecdh: [
    { h: 'Les formats du point', t: `- **Non compressé** : \`04 ‖ X ‖ Y\`, 65 octets (SEC 1). C'est le format de WebCrypto (« raw »), de TLS et du DG14 des passeports.
- **Compressé** : \`02 ‖ X\` ou \`03 ‖ X\` selon la parité de Y, 33 octets. Y se retrouve en résolvant y² = x³ − 3x + b.
- **JWK** : \`x\` et \`y\` en base64url ; **SPKI** (DER) dans les certificats.

Le secret Z est l'**abscisse** de a·B, sur 32 octets : l'ordonnée n'apporte rien et n'est pas utilisée.` },
    { h: 'L\'attaque par point invalide', t: `Les formules d'addition sur une courbe y² = x³ + ax + b n'utilisent pas b. Si l'implémentation ne vérifie pas que le point reçu est sur **la** courbe, Mallory envoie un point d'une autre courbe (même a, autre b) dont l'ordre est petit : comme pour le petit sous-groupe, le résultat révèle d mod r. Avec quelques dizaines de requêtes, une clé ECDH **statique** de serveur TLS a ainsi été extraite (Jager, Schwenk, Somorovsky, 2015).

Parade : vérifier que le point est sur la courbe et n'est pas l'infini (SP 800-56A §5.6.2.3.3). L'atelier le fait : altérez Y et le point est refusé.` },
    { h: 'P-256, brainpool et compagnie', t: `Les passeports utilisent souvent **brainpoolP256r1** (BSI), aux paramètres générés de façon vérifiable ; les courbes NIST ont des graines inexpliquées, ce qui nourrit une méfiance ancienne mais sans attaque connue. Le principe d'ECDH est identique sur toutes ces courbes de Weierstrass.` },
  ],
  x25519: [
    { h: 'Pourquoi X25519 est plus difficile à mal utiliser', t: `- Seule la coordonnée **u** circule : pas de point à valider ni de format à choisir. Toute chaîne de 32 octets est acceptée.
- L'**échelle de Montgomery** fait le même calcul quel que soit le bit du scalaire : temps constant naturel.
- Le « clamping » rend le scalaire multiple de 8 (le cofacteur) : les composantes de petit ordre sont annulées, et le bit 254 fixé empêche les implémentations de prendre un raccourci dépendant du secret.
- Une clé publique mal formée tombe sur la **tordue** de la courbe, elle aussi choisie sûre.` },
    { h: 'Le test du secret nul', t: `Les points d'ordre 1, 2, 4 ou 8 donnent Z = 0 après clamping. RFC 7748 §6.1 recommande de rejeter un Z tout à zéro : un attaquant qui envoie u = 0 forcerait un secret connu de tous. Cette vérification a de l'importance dans les protocoles où le secret doit « engager » les deux parties (contributory behaviour), comme certaines constructions de messagerie.` },
    { h: 'Petit-boutiste', t: `Contrairement à SEC 1, X25519 encode tout en **petit-boutiste** : l'octet 0 est le moins significatif. C'est pourquoi le clamping touche \`k[0]\` (bits bas) et \`k[31]\` (bits hauts). Vecteur de test vérifié par l'atelier : RFC 7748 §6.1.` },
  ],
  'kex-grid': [
    { h: 'La nomenclature SP 800-56A', t: `Le NIST classe les schémas d'accord par le nombre de clés éphémères (e) et statiques (s) utilisées en tout :

- **C(2e, 2s)** : les deux côtés ont une éphémère et une statique (Full Unified Model, MQV) ;
- **C(2e, 0s)** : éphémère × éphémère, il faut authentifier à part (TLS 1.3) ;
- **C(1e, 2s)** et **C(1e, 1s)** : une seule passe, l'initiateur éphémère, le répondeur statique (ECIES, HPKE, Chip Authentication) ;
- **C(0e, 2s)** : statique × statique, sans fraîcheur sans nonces.

Le cadre **Noise** utilise des lettres : \`e\` et \`s\` pour chaque partie, et des motifs (N, K, X, IK, XX…) qui disent quels DH sont faits et dans quel ordre.` },
    { h: 'Trois propriétés à ne pas confondre', t: `- **Fraîcheur** : le secret change à chaque session. Il suffit d'une éphémère d'un côté, ou de nonces dans la KDF.
- **Confidentialité persistante** (forward secrecy) : la fuite ultérieure des clés de longue durée ne rouvre pas les sessions passées. Il faut que chaque DH de la session implique au moins une éphémère **effacée**, et en pratique une éphémère de chaque côté.
- **Authentification implicite** : seul le détenteur de la clé statique peut calculer Z. Elle n'est confirmée que lorsqu'il **utilise** la clé (MAC, chiffré correct), d'où les « key confirmation » des protocoles.

Un piège : en éphémère × statique, la fuite de la clé statique du destinataire rouvre tous les messages passés. C'est le cas d'ECIES et de HPKE en mode Base, et la raison pour laquelle Signal ne s'en contente pas.` },
    { h: 'Et le post-quantique ?', t: `Un KEM comme ML-KEM ne fait que le cas « éphémère de l'émetteur × statique du destinataire », en une passe interactive : il n'existe pas de « ML-KEM statique × statique » non interactif. Pour remplacer un protocole qui combine plusieurs DH (Noise, X3DH, WireGuard), il faut plusieurs encapsulations (PQ-Noise, KEMTLS) ou une hybridation qui garde X25519 (PQXDH). Les isogénies (CSIDH) offrent un vrai DH post-quantique, mais lent et encore à l'étude depuis la chute de SIDH en 2022.` },
  ],
  sigma: [
    { h: 'L\'homme du milieu', t: `DH protège contre un attaquant **passif**. Un attaquant **actif** fait deux échanges : avec Alice, il se fait passer pour Bob ; avec Bob, pour Alice. Chacun obtient un secret valide, partagé avec Mallory, qui déchiffre, lit, modifie et rechiffre. Rien dans DH seul ne lie la valeur reçue à une identité.` },
    { h: 'Station-to-Station, puis SIGMA', t: `**STS** (1992) : chacun signe les deux valeurs éphémères (et chiffre sa signature avec la clé de session). Mallory peut relayer les signatures mais pas en fabriquer : Alice vérifie que la signature de Bob porte sur **l'éphémère qu'elle a reçue** et sur la sienne ; avec Mallory au milieu, ce n'est pas le cas.

**SIGMA** (« SIGn-and-MAc », Krawczyk 2003) corrige une faiblesse de STS (attaque par mauvaise attribution d'identité) en ajoutant un **MAC sur l'identité** avec une clé dérivée du secret. IKEv2 en dérive directement ; TLS 1.3 aussi : CertificateVerify signe le haché de toute la transcription, Finished en est le MAC.` },
    { h: 'Ce que simplifie l\'atelier', t: `Les signatures Ed25519 portent sur \`éphémère propre ‖ éphémère reçue\` ; il n'y a ni certificats ni MAC final. La dérivation de clé et le MAC d'identité de SIGMA-I ne sont pas représentés : l'essentiel, voir pourquoi la signature casse l'attaque, est conservé.` },
  ],
  'chip-auth': [
    { h: 'Trois mécanismes à distinguer', t: `- **Authentification passive** : le SOD contient les hachés des groupes de données (DG1 la MRZ, DG2 la photo, DG14…), signés par le **Document Signer** de l'État émetteur. Elle prouve que les données sont authentiques, pas que la puce l'est : on peut copier DG et SOD sur une autre puce.
- **Active Authentication** (DG15) : la puce signe un défi du lecteur avec une clé privée. Elle prouve la puce, mais la signature est une **preuve transférable** qu'un document donné a été lu à un instant donné.
- **Chip Authentication** (DG14) : un ECDH entre la clé statique de la puce et une éphémère du système d'inspection. Elle prouve la puce **implicitement** (seule elle peut calculer les bons MAC) et ne laisse aucune preuve transférable. Elle établit en plus des clés de Secure Messaging fortes.` },
    { h: 'Le déroulé', t: `1. Le système d'inspection (IS) lit DG14 et SOD, vérifie la signature du SOD (chaîne CSCA → DS) puis le haché du DG14 : la clé publique de la puce est authentique.
2. Il tire une biclé éphémère sur les mêmes paramètres de domaine et envoie sa clé publique (MSE:Set AT puis General Authenticate).
3. Chacun calcule Z ; \`K_Enc = H(Z ‖ 00000001)\` et \`K_MAC = H(Z ‖ 00000002)\` (SHA-1 tronqué pour 3DES et AES-128, SHA-256 pour AES-192/256).
4. Le Secure Messaging redémarre avec ces clés et un compteur SSC remis à zéro. La première réponse dont le MAC se vérifie prouve la puce.

En Chip Authentication v2 (eID, TR-03110), la puce renvoie en plus un nonce et un jeton \`T = MAC(K_MAC, PK_IS)\`. Avec PACE-CAM, l'authentification de la puce est intégrée directement à PACE.` },
    { h: 'Les simplifications de l\'atelier', t: `- P-256 au lieu de brainpoolP256r1 ou d'autres courbes (le calcul est le même) ;
- un DG14 réduit à l'OID et au point public, au lieu d'un SET ASN.1 de SecurityInfos ;
- un SOD réduit au haché et à une signature ECDSA brute, au lieu d'un SignedData CMS ;
- une seule réponse protégée (DO87, DO8E), sans en-tête de commande ni DO99.

Le DG1 affiché est le spécimen fictif de l'ICAO (Utopie, Anna Maria Eriksson).` },
    { h: 'Et le statique côté puce ?', t: `C'est la case « éphémère × statique » de la grille : la puce est authentifiée, l'IS ne l'est pas (c'est le rôle de la **Terminal Authentication**, par signature et certificats CV, pour accéder aux empreintes). Si la clé privée de la puce fuyait, les sessions enregistrées seraient lisibles : elle ne quitte jamais la puce, qui la protège matériellement.` },
  ],
  ratchet: [
    { h: 'Les deux cliquets', t: `- **Cliquet symétrique** : chaque chaîne (envoi, réception) avance d'un cran par message. \`MK = HMAC(CK, 01)\` chiffre le message, \`CK′ = HMAC(CK, 02)\` remplace la clé de chaîne. Une fonction à sens unique : voler CK ne permet pas de remonter aux messages précédents.
- **Cliquet DH** : à chaque changement de sens, l'émetteur tire une nouvelle paire X25519 et la met dans l'en-tête. Le destinataire fait un pas DH : \`(RK, CKr) = KDF_RK(RK, DH(sa clé, nouvelle clé reçue))\`, puis tire lui-même une nouvelle paire pour sa prochaine chaîne d'envoi.

Le DH n'a donc **pas** lieu à chaque message : une rafale de messages dans le même sens utilise la même clé DH, avec des clés de message différentes tirées de la chaîne symétrique.` },
    { h: 'Confidentialité persistante et auto-guérison', t: `- **Vers le passé** : une clé de message ou de chaîne volée ne donne rien sur les messages antérieurs (sens unique des KDF, éphémères effacées).
- **Vers le futur** (post-compromise security) : si tout l'état d'un appareil est copié, l'attaquant suit la conversation tant qu'elle reste sur des clés qu'il possède. Au premier pas DH tiré **après** le vol, avec une clé privée qu'il n'a pas vue, il perd la piste. Un attaquant **actif** qui garde l'appareil compromis échappe à cette guérison : elle ne vaut que contre une copie ponctuelle.` },
    { h: 'L\'en-tête et les messages désordonnés', t: `L'en-tête porte la clé publique de ratchet, **PN** (longueur de la chaîne d'envoi précédente) et **N** (rang dans la chaîne actuelle). Avec PN, le destinataire sait combien de clés de l'ancienne chaîne il doit dériver et garder en réserve pour des messages arrivés en retard. L'atelier livre tout dans l'ordre et ne gère pas ces clés sautées.

Dans Signal, l'en-tête est lui-même chiffré (header encryption) et le secret initial vient de **X3DH** (quatre DH : IK_A×SPK_B, EK_A×IK_B, EK_A×SPK_B, EK_A×OPK_B), remplacé en 2023 par **PQXDH**, qui ajoute une encapsulation ML-KEM. En octobre 2025, Signal a ajouté un cliquet post-quantique, SPQR (fondé sur ML-KEM-768), dont la sortie est mélangée à celle du Double Ratchet par une KDF : c'est le « Triple Ratchet ».` },
  ],
};
