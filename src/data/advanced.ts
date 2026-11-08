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
    { h: 'Le choix du générateur', t: `Dans (ℤ/pℤ)*, l'ordre de tout élément divise p − 1. Avec un nombre premier **sûr** p = 2q + 1 (q premier), il n'y a que quatre ordres possibles : 1, 2, q et 2q.

- Une **racine primitive** (ordre 2q = p − 1) engendre tout le groupe. Pour p = 47, il y en a φ(46) = 22, dont 26, 23 et 31 : la table gˣ du jeu **DH War** parcourt alors les 46 valeurs une fois chacune. Une racine primitive n'est jamais un carré.
- Un **générateur du sous-groupe d'ordre q** n'engendre que les carrés. Il y en a φ(23) = 22 pour p = 47 (2, 3, 4, 6…), dont le carré de toute racine primitive : 26² = 18, 23² = 12, 31² = 21.

L'atelier propose ces six générateurs pour p = 47 : on voit la fuite de parité apparaître avec les trois premiers et disparaître avec leurs carrés.

Pour DH, on préfère le second : avec une racine primitive, le symbole de Legendre de A (critère d'Euler, A^((p−1)/2) mod p = ±1) révèle la **parité** de a à quiconque observe l'échange, et l'hypothèse DDH tombe. Avec g d'ordre q premier, toutes les valeurs publiques sont des carrés et rien ne fuit. C'est le choix de ffdhe (g = 2, d'ordre q) et du groupe jouet p = 23.` },
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
  // ------------------------------------------------------------------ hachage, MAC et dérivation
  sha256: [
    { h: 'Trois résistances, trois coûts', t: `- **Préimage** : retrouver un M de haché donné, ≈ 2²⁵⁶ essais.
- **Seconde préimage** : trouver M′ ≠ M de même haché qu'un M imposé, ≈ 2²⁵⁶.
- **Collision** : trouver deux messages quelconques de même haché, ≈ 2¹²⁸ seulement, par le paradoxe des anniversaires (voir « Notions »).

C'est la collision qui a fait tomber MD5 (2004) et SHA-1 (2017) : deux documents de même empreinte, l'un anodin, l'autre signé à sa place.` },
    { h: 'Merkle-Damgård et ses conséquences', t: `Le message est bourré (\`0x80\`, des zéros, la longueur sur 64 bits), découpé en blocs de 64 octets, puis une **fonction de compression** f enchaîne : \`Hᵢ = f(Hᵢ₋₁, Mᵢ)\`. La longueur dans le bourrage (« renforcement de Merkle-Damgård ») garantit qu'une collision sur le haché donne une collision sur f.

Le revers : le haché publié **est** l'état interne. Qui connaît \`SHA-256(K ‖ M)\` et la longueur de K peut continuer le calcul : c'est l'**extension de longueur** (page HMAC). SHA-512/256, tronqué, et SHA-3 n'ont pas ce défaut.` },
    { h: 'L\'expérience des tours', t: `L'atelier exécute une fonction de compression écrite à la main, ce qui permet de l'arrêter après r tours. On voit l'avalanche s'installer, et sa vitesse dépend de l'endroit du bit modifié : un bit du premier mot de message (w₀) est diffusé en quelques tours, alors qu'un bit du mot w₁₃ n'entre dans le calcul qu'au quatorzième tour, et l'avalanche n'est complète qu'au-delà. SHA-256 en fait 64. Les meilleures attaques sur SHA-256 réduit atteignent environ 31 tours pour les collisions (pratiques en dessous), ce qui laisse une marge confortable, mais c'est bien de **marge** qu'il s'agit : l'avalanche visible ne prouve rien à elle seule.` },
  ],
  sha3: [
    { h: 'L\'éponge', t: `Keccak manipule un état de 1 600 bits (5 × 5 mots de 64 bits), séparé en deux : le **débit** r, où l'on absorbe le message par blocs puis d'où l'on essore la sortie, et la **capacité** c, jamais exposée. La sécurité générique est de c/2 bits : SHA3-256 prend c = 512, d'où 256 bits de résistance aux préimages et 128 aux collisions.

Chaque absorption est suivie de **Keccak-f**, 24 tours de cinq étapes (θ, ρ, π, χ, ι), une permutation publique : pas de clé, pas de fonction de compression.` },
    { h: 'XOF, KMAC et famille', t: `- **SHAKE128 / SHAKE256** : longueur de sortie libre (XOF). ML-KEM et ML-DSA s'en servent pour dériver matrices et aléas.
- **cSHAKE, KMAC, TupleHash, ParallelHash** (SP 800-185) : variantes à personnalisation ; KMAC est un MAC direct, sans la construction HMAC.
- **KangarooTwelve** : les concepteurs eux-mêmes ramènent Keccak à 12 tours pour la vitesse.` },
    { h: 'Keccak-256 n\'est pas SHA3-256', t: `Le NIST a modifié le bourrage entre la soumission (2011) et la norme (2015) pour séparer les usages : l'octet de domaine vaut \`0x06\` pour SHA-3, \`0x1F\` pour SHAKE, \`0x01\` dans le Keccak d'origine. Ethereum, lancé entre les deux, a gardé l'original : sa fonction \`keccak256\` ne donne pas SHA3-256. Un seul octet d'écart suffit à rendre les deux sorties sans rapport.` },
  ],
  blake: [
    { h: 'Une famille, trois générations', t: `- **BLAKE** (2008) : Jean-Philippe Aumasson, Luca Henzen, Willi Meier et Raphael Phan le soumettent à la compétition SHA-3 (51 candidats). Il atteint la finale, que Keccak remporte en 2012.
- **BLAKE2** (2012) : Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn et Christian Winnerlein le simplifient et l'allègent (BLAKE2b : 12 tours au lieu de 16, BLAKE2s : 10 au lieu de 14). Il devient le hachage rapide de référence hors du NIST (RFC 7693).
- **BLAKE3** (2020) : Jack O'Connor, Aumasson, Neves et Wilcox-O'Hearn. 7 tours, un arbre de Merkle de blocs de 1 Kio (parallélisme, vérification en flux), XOF, modes « clé » et « dérivation » intégrés.` },
    { h: 'La coquille devenue constante', t: `Le cœur de BLAKE est le quart de tour de **ChaCha** (Bernstein) : additions, rotations, XOR. Deux différences : les mots du message y sont injectés, et le sens des rotations est inversé. On a parfois cherché à cette inversion une raison savante ; Aumasson raconte dans son *Crypto Dictionary* (2021) qu'elle vient tout simplement d'une **coquille** dans la spécification d'origine de BLAKE, conservée ensuite dans BLAKE2 et BLAKE3.` },
    { h: '« Too Much Crypto »', t: `Dans cet article de 2019, présenté à Real World Crypto 2020, Aumasson soutient que la plupart des primitives symétriques font **plus de tours que nécessaire** : la cryptanalyse progresse peu depuis des décennies, les marges sont incohérentes d'une primitive à l'autre, et ces tours inutiles coûtent du temps et de l'énergie. Il propose : AES-128 à 9 tours (au lieu de 10), BLAKE2b à 8 (12), BLAKE2s à 7 (10), ChaCha à 8 (20), SHA-3 à 10 (24).

Son bilan de 2025 : aucune de ces versions réduites n'a été cassée ; la meilleure attaque pratique sur AES plafonne à 6 tours, sur SHA-3 à 5. BLAKE3 applique l'idée avec 7 tours. Les organismes de normalisation, eux, n'ont rien changé, et l'idée reste discutée : Bernstein, par exemple, juge ChaCha8 trop risqué.` },
    { h: 'Avant d\'avoir cassé AES par force brute', t: `L'argument repose sur une distinction : la sécurité ne se joue pas contre la recherche exhaustive, qui est hors de portée, mais contre la cryptanalyse. Un ordre de grandeur : 2¹²⁸ ≈ 3,4 × 10³⁸ clés pour AES-128. À 10¹⁸ clés testées par seconde (bien au-delà de toute machine existante), il faut en moyenne 1,7 × 10²⁰ secondes, soit environ 5 × 10¹² ans, quelque 400 fois l'âge de l'Univers. Le Soleil sera éteint bien avant.

D'où la boutade qu'on prête volontiers à Aumasson : l'espèce humaine aura disparu avant que quiconque ne déchiffre de l'AES par force brute. La vraie question est donc la marge face aux attaques structurelles, et c'est elle que « Too Much Crypto » propose de recalibrer.` },
  ],
  hmac: [
    { h: 'La construction', t: `\`HMAC(K, M) = H((K₀ ⊕ opad) ‖ H((K₀ ⊕ ipad) ‖ M))\`, où K₀ est la clé complétée par des zéros jusqu'à la taille de bloc B (64 octets pour SHA-256), ou d'abord hachée si elle dépasse B. \`ipad\` est l'octet 0x36 répété, \`opad\` l'octet 0x5c.

Les deux constantes diffèrent pour que les clés intérieure et extérieure soient distinctes. Les deux premiers blocs (K₀ ⊕ ipad et K₀ ⊕ opad) ne dépendent que de la clé : les implémentations les précalculent une fois.` },
    { h: 'Ce que dit la preuve', t: `Bellare, Canetti et Krawczyk (1996) montrent que HMAC est une fonction pseudo-aléatoire si la compression l'est. Bellare (2006) affaiblit l'hypothèse : il suffit que la compression soit une PRF, la **résistance aux collisions n'est pas requise**. C'est pourquoi HMAC-MD5 et HMAC-SHA-1 ne sont pas cassés en tant que MAC, même si l'on n'a plus de raison de les choisir.` },
    { h: 'Bien s\'en servir', t: `- **Comparer en temps constant** : un \`==\` qui s'arrête au premier octet différent laisse mesurer combien d'octets sont justes, et forger le tag octet par octet.
- **Tronquer avec prudence** : 128 bits au moins en général ; TLS 1.2 n'en garde que 96 dans le message Finished, protégé par le reste du protocole.
- **Une clé par usage** : dérivez-les avec HKDF plutôt que de réutiliser la même clé pour chiffrer et authentifier.
- Avec SHA-3 ou BLAKE2, HMAC n'est plus nécessaire : KMAC et le mode à clé de BLAKE2 font un MAC directement.` },
  ],
  hkdf: [
    { h: 'Pourquoi deux étapes', t: `Un secret d'échange de clés (Z d'un ECDH, sortie de ML-KEM) n'est pas uniforme : c'est l'abscisse d'un point, une valeur structurée. **Extract** concentre son entropie en une clé pseudo-aléatoire PRK de 32 octets. **Expand** en tire autant d'octets que voulu, en les liant à \`info\` : version du protocole, rôle, usage. Quand l'IKM est déjà uniforme (une clé maître aléatoire), on peut ne faire qu'Expand.` },
    { h: 'Le sel', t: `Le sel est public et facultatif ; il renforce l'extraction quand l'IKM a peu d'entropie ou peut être influencé par un attaquant, et sépare les instances. Sans sel, HKDF utilise 32 octets nuls. Dans TLS 1.3, le sel de chaque étape est la clé dérivée de l'étape précédente : la planification des clés est une chaîne d'Extract et d'Expand (Derive-Secret, HKDF-Expand-Label).` },
    { h: 'Où on la retrouve dans l\'atelier', t: `HPKE (KeySchedule), le Double Ratchet (KDF_RK), les clés de session de la grille statique / éphémère, la dérivation d'ECIES « propre ». À l'inverse, la Concat KDF de JOSE et la KDF X9.63 d'Apple sont des cousines plus simples, à un seul étage, fondées sur un haché plutôt que sur HMAC.` },
  ],
  pwhash: [
    { h: 'Ralentir l\'attaquant, pas l\'utilisateur', t: `Un mot de passe humain a peu d'entropie : 20 à 40 bits pour la plupart. Si sa base de hachés fuit, l'attaquant essaie des dictionnaires hors ligne, à la vitesse de son matériel. On ne peut pas augmenter l'entropie ; on augmente le **coût de chaque essai**. Une connexion légitime paie ce coût une fois ; l'attaquant, des milliards de fois.

Le **sel**, unique par compte, empêche les tables précalculées (arc-en-ciel) et oblige à attaquer chaque compte séparément.` },
    { h: 'Temps ou mémoire', t: `- **PBKDF2** répète HMAC. Il ne demande presque pas de mémoire : un GPU fait des millions d'essais par seconde, en parallèle. OWASP recommande 600 000 itérations avec SHA-256.
- **scrypt** (Percival 2009) remplit un grand tableau puis le relit dans un ordre qui dépend des données : la mémoire devient le facteur limitant.
- **Argon2id** (Biryukov, Dinu, Khovratovich), lauréat de la Password Hashing Competition en 2015, normalisé en 2021 (RFC 9106) : paramètres séparés pour la mémoire, le temps et le parallélisme ; la variante « id » combine la résistance aux canaux auxiliaires et aux compromis temps-mémoire. Il utilise BLAKE2b en interne.` },
    { h: 'Choisir ses paramètres', t: `Partir du temps acceptable côté serveur (quelques centaines de millisecondes), puis monter la mémoire aussi haut que le serveur le permet. Point de départ OWASP pour Argon2id : 19 Mio, 2 passes, 1 fil. Les paramètres sont stockés avec le haché (format \`$argon2id$v=19$m=19456,t=2,p=1$sel$haché\`) : on peut les relever plus tard et re-hacher à la connexion suivante.` },
  ],
  // ------------------------------------------------------------------ aléa
  csprng: [
    { h: 'Ce qu\'on attend d\'un générateur cryptographique', t: `Statistiquement uniforme ne suffit pas. Il faut l'**imprévisibilité** : sans l'état interne, aucune sortie ne doit se deviner à partir des précédentes (mieux qu'avec une chance sur 2ⁿ), et la compromission de l'état présent ne doit pas révéler les sorties passées (**résistance au retour en arrière**). Après un réensemencement avec assez d'entropie, l'attaquant qui connaissait l'ancien état doit aussi perdre la trace (**rétablissement**).

Math.random (xorshift128+ dans V8), Mersenne Twister ou le LCG de Java satisfont les tests statistiques et échouent tous à la première exigence.` },
    { h: 'D\'où vient l\'aléa du système', t: `Le noyau collecte des événements imprévisibles (horodatages d'interruptions, disque, réseau, instruction RDRAND/RDSEED du processeur), les **mélange** dans un pool par une fonction de hachage (BLAKE2s sous Linux depuis 2022), puis les **étire** avec un générateur déterministe (ChaCha20). Les applications le lisent par \`getrandom()\`, \`/dev/urandom\`, \`BCryptGenRandom\`, ou, dans un navigateur, \`crypto.getRandomValues\` (au plus 65 536 octets par appel), que l'atelier utilise partout.

Le seul moment délicat est le **démarrage** : une machine virtuelle clonée ou un routeur sans disque peut générer ses clés avant d'avoir accumulé de l'entropie. C'est l'origine des facteurs RSA partagés trouvés par Heninger et al. (2012).` },
    { h: 'Les tests statistiques', t: `- **Fréquence** : sur n bits, le nombre de 1 suit une loi binomiale ; z = (uns − n/2) / √(n/4) doit rester petit.
- **Séries** : le nombre de changements 0 ↔ 1 doit être proche de n/2 ; un générateur qui alterne trop ou pas assez se trahit.
- **χ²** des octets : chacune des 256 valeurs doit apparaître à peu près n/256 fois ; à 255 degrés de liberté, le χ² vaut environ 255, ni beaucoup plus (biais), ni beaucoup moins (trop régulier, comme le compteur).

Les batteries complètes (NIST SP 800-22, Dieharder, TestU01) en alignent des dizaines. Elles écartent les mauvais générateurs ; elles ne certifient jamais les bons.` },
    { h: 'À essayer', t: `Passez sur « compteur » : l'image montre des bandes régulières, la fréquence et les séries sont parfaites, mais le χ² est très en dessous de 255. Passez sur RANDU : seules 64 valeurs d'octet apparaissent (sans terme additif, les k bits de poids faible d'un LCG modulo une puissance de 2 ont une période d'au plus 2ᵏ⁻² : 64 pour un octet).` },
  ],
  javarandom: [
    { h: 'Le générateur', t: `\`java.util.Random\` est un générateur congruentiel linéaire : état de **48 bits**, \`s ← (s × 0x5DEECE66D + 0xB) mod 2⁴⁸\`, et \`nextInt()\` renvoie les **32 bits de poids fort**. Le constructeur combine la graine par XOR avec la même constante 0x5DEECE66D ; sans graine, il prend un compteur et \`System.nanoTime()\`.

Il ne cache que 16 bits : le premier entier observé donne les 32 bits hauts de l'état, il reste 2¹⁶ = 65 536 possibilités pour les bits bas, et le deuxième entier départage. Quelques millisecondes suffisent.` },
    { h: 'Le même problème partout', t: `- **Mersenne Twister** (Python \`random\`, PHP \`mt_rand\`, Ruby) : 624 sorties de 32 bits donnent l'état complet par simple inversion du « tempering ».
- **xorshift128+** (Math.random de V8, Firefox, Safari) : quelques sorties et un solveur SMT suffisent.
- Codes de réinitialisation, jetons de session, identifiants de partie de poker en ligne : dès qu'ils proviennent d'un tel générateur, l'attaquant qui en voit quelques-uns prédit les autres.` },
    { h: 'Ce qu\'il faut utiliser', t: `\`java.security.SecureRandom\`, \`secrets\` en Python, \`random_bytes\` en PHP, \`crypto.getRandomValues\` ou \`crypto.randomUUID\` en JavaScript. Ils s'appuient sur le générateur du système. Ils sont plus lents, ce qui ne compte que pour la simulation numérique : c'est là que Mersenne Twister reste pertinent.` },
  ],
  hmacdrbg: [
    { h: 'Les trois opérations de SP 800-90A', t: `- **Instantiate** : K = 00…00, V = 01…01, puis \`Update(entropie ‖ nonce ‖ personnalisation)\`.
- **Update(data)** : \`K = HMAC(K, V ‖ 00 ‖ data)\`, \`V = HMAC(K, V)\`, puis, si data n'est pas vide, une seconde fois avec \`01\`.
- **Generate** : \`V = HMAC(K, V)\` autant de fois que nécessaire, on concatène les V, puis **Update** (avec l'entrée additionnelle). Ce dernier Update remplace K et V : c'est lui qui empêche de revenir en arrière.

La norme borne une requête à 2¹⁹ bits et impose un **Reseed** au plus tard après 2⁴⁸ requêtes. Le compteur de l'atelier montre le nombre de requêtes depuis le dernier ensemencement.` },
    { h: 'Entropie, nonce, personnalisation', t: `L'entropie est le seul ingrédient secret : sans elle, le générateur est entièrement déterminé. Le nonce et la chaîne de personnalisation ne sont pas secrets ; ils distinguent deux instances qui auraient reçu, par malchance ou par clonage de machine virtuelle, la même entropie (identifiant de l'appareil, numéro de série, horodatage). L'entrée additionnelle de Generate joue le même rôle à chaque requête.` },
    { h: 'RFC 6979 : un DRBG détourné', t: `Une signature ECDSA exige un k secret, unique et uniforme : un k répété (Sony PS3, 2010) ou légèrement biaisé (attaques par réseau euclidien, quelques bits suffisent) livre la clé privée. RFC 6979 (Pornin, 2013) supprime le besoin d'aléa : on instancie un HMAC-DRBG avec \`x ‖ H(m) mod n\` comme entropie, et on tire k. Même clé et même message donnent le même k, donc la même signature ; un autre message donne un k sans rapport.

Ed25519 fait la même chose plus simplement : \`r = H(préfixe secret ‖ m)\`. Les versions récentes mêlent un peu d'aléa à cette dérivation (signatures « hedged ») pour résister aux attaques par fautes.` },
  ],
  dualec: [
    { h: 'Le générateur', t: `Deux points publics P et Q de la courbe P-256. À chaque étape : \`s ← x(s·P)\` puis la sortie est \`x(s·Q)\` privée de ses 16 premiers bits (30 octets sur 32). Il est **lent** (deux multiplications scalaires pour 30 octets, des centaines de fois plus lent que HMAC-DRBG) et légèrement **biaisé** (Gjøsteen 2006, Schoenmakers et Sidorenko 2006) : deux raisons de ne pas l'utiliser, avant même la porte dérobée.` },
    { h: 'La porte dérobée', t: `Si quelqu'un connaît d tel que P = d·Q, alors pour une sortie r = x(s·Q) : il essaie les 2¹⁶ préfixes, relève chaque candidat en un point R de la courbe (environ la moitié des abscisses conviennent), et calcule x(d·R) = x(d·s·Q) = x(s·P) : c'est l'**état suivant**. La sortie d'après lui permet de choisir le bon candidat. Une trentaine d'octets observés suffit, par exemple le nonce aléatoire du ClientHello ou du ServerHello de TLS.

Shumow et Ferguson l'ont montré en 2007. La norme ne disait pas d'où venaient P et Q ; elle permettait de choisir ses propres points, mais la validation FIPS exigeait les points officiels.` },
    { h: 'Ce qui s\'est passé ensuite', t: `- **2013** : les documents Snowden (programme Bullrun) indiquent que la NSA a œuvré à l'adoption de Dual_EC ; RSA Security, qui l'avait mis par défaut dans BSAFE, recommande de cesser de l'utiliser. Reuters rapporte un contrat de 10 millions de dollars.
- **2014** : Checkoway et al. exploitent concrètement Dual_EC dans plusieurs bibliothèques TLS, en quelques secondes à quelques heures selon les cas.
- **2015** : SP 800-90A révision 1 le retire. Juniper découvre que le Q de ScreenOS a été remplacé à son insu ; un défaut faisait sortir Dual_EC sans post-traitement.

La leçon dépasse le cas : une constante inexpliquée dans une norme est une dette de confiance. D'où les constantes « rien dans les manches » (chiffres de π, racines carrées des premiers nombres premiers dans SHA-2).` },
  ],
  debian: [
    { h: 'Deux lignes en trop', t: `En septembre 2006, un mainteneur Debian commente deux appels \`MD_Update\` dans \`md_rand.c\` d'OpenSSL : Valgrind signalait la lecture de mémoire non initialisée, utilisée volontairement comme source d'entropie d'appoint. L'une des deux lignes était la seule qui ajoutait réellement l'entropie au pool. Restait le **numéro de processus**, au plus 32 768 sous Linux.

Découvert par Luciano Bello en mai 2008 (DSA-1571, CVE-2008-0166) : toutes les clés SSH, SSL et OpenVPN générées en deux ans sur Debian et Ubuntu appartenaient à un ensemble de quelques dizaines de milliers par type et par taille. Les listes ont été publiées en quelques jours.` },
    { h: 'Plus grave encore : DSA', t: `Une clé solide utilisée pour signer **DSA** sur une machine touchée était aussi compromise : le nonce k de chaque signature venait du même générateur appauvri. Une seule signature et 32 768 essais livraient la clé privée. C'est le même mécanisme que la PS3 et la raison d'être de RFC 6979.` },
    { h: 'Ce qui l\'aurait évité', t: `- Ne pas modifier du code cryptographique sans relecture par ses auteurs (la question avait été posée sur une liste, mal comprise).
- Des tests de bout en bout qui vérifient que deux générations successives diffèrent, même après redémarrage.
- S'appuyer sur le générateur du système plutôt que sur un pool en espace utilisateur : c'est la recommandation actuelle d'OpenSSL et de la plupart des bibliothèques.` },
  ],
};
