# Atelier crypto

Atelier interactif du cours **Introduction à la cryptographie moderne** (EPITA, EGE, ESG) :
chiffrer, déchiffrer, signer et vérifier avec du vrai code, et voir le **format exact** des clés,
des clairs, des chiffrés et des signatures, segment par segment.

Benoit LEGER-DERVILLE · Stelau · iDAKTO

**En ligne : <https://stelauconseil.github.io/atelier-crypto/>**

## Contenu

| Famille | Algorithmes |
|---|---|
| Symétrique | AES-ECB, AES-CBC, AES-CTR, AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, AES-KW |
| Hachage, MAC et dérivation | SHA-256 (bourrage, avalanche, version réduite tour par tour), SHA-3 / SHAKE / Keccak-256, BLAKE2 et BLAKE3 (« Too Much Crypto »), HMAC pas à pas et extension de longueur, HKDF (Extract / Expand), PBKDF2, scrypt et Argon2id |
| Établissement de clé | Diffie-Hellman (corps fini, jouet et ffdhe2048), ECDH P-256, X25519, grille statique / éphémère avec le catalogue des protocoles qui utilisent DH, DH authentifié (SIGMA, homme du milieu), Chip Authentication des passeports (anti-clonage), Double Ratchet de Signal (vol d'état, auto-guérison) |
| Chiffrement asymétrique | RSA brut, RSAES-PKCS1-v1_5, RSAES-OAEP, RSA-KEM, ECIES (P-256, variante Apple), HPKE (RFC 9180), ML-KEM-768, X25519MLKEM768 |
| Signatures | RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA P-256 (+ attaque « PS3 » du nonce réutilisé), Ed25519, ML-DSA-65, SLH-DSA (128f / 128s) |
| Pages transverses | Carrousel d'exemples par famille sur l'accueil, planches du cours en PDF (page dédiée et renvois depuis « Pour aller plus loin »), frise historique filtrable, Notions (extension de longueur SHA-256(K ‖ M) contre HMAC, paradoxe des anniversaires), glossaire |

Pour chaque algorithme : une fiche de rappel (issue des planches), de vrais champs et boutons
(générer, chiffrer, altérer un bit, déchiffrer, signer, vérifier), la chaîne d'opérations animée
(GSAP) et l'anatomie des octets : `00 02 PS 00 M`, `enc ‖ C ‖ tag`, `r ‖ s` et DER, JWK, PEM…

## D'où vient le code crypto

- **WebCrypto** du navigateur : AES-CBC/CTR/GCM, RSA-OAEP (déchiffrement), RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA, ECDH.
- **@noble** (ciphers, curves, hashes, post-quantum) : ECB, GCM-SIV, ChaCha20-Poly1305, AES-KW, X25519, Ed25519, ML-KEM, ML-DSA, SLH-DSA.
- **Écrit à la main** (`src/crypto/`), pour que tout se voie : DH et sa validation, grille statique / éphémère, SIGMA, Chip Authentication (KDF ICAO, Secure Messaging AES-CBC + CMAC), Double Ratchet, RSA brut (BigInt), PKCS#1 v1.5, encodage OAEP
  (déchiffré ensuite par WebCrypto, preuve d'interopérabilité), RSA-KEM, ECIES, HPKE mode Base
  (vérifié contre `@hpke/core`), SHA-256 en Merkle-Damgård explicite, ECDSA à nonce fixé.

## Installation

Les icônes viennent d'un **Kit Font Awesome Pro** (paquet npm privé `@awesome.me/kit-…`).
Le fichier `.npmrc` du dépôt lit le jeton dans une variable d'environnement, jamais en clair :

```bash
export FONTAWESOME_PACKAGE_TOKEN=…   # dans ~/.zshrc ; jeton du Kit, compte Font Awesome Pro
```

Sans ce jeton, `npm install` échoue sur `@awesome.me/kit-…` : il faut un abonnement Pro
ou remplacer `src/lib/icons.tsx` par des icônes libres (`@fortawesome/free-solid-svg-icons`).

## Commandes (Vite+)

```bash
vp install          # dépendances
vp dev              # serveur de développement
vp test             # 80 tests : allers-retours, altérations, interopérabilité, attaques
vp build            # build statique dans dist/
SINGLE=1 vp build   # un seul fichier HTML autonome dans dist-single/
vp run test:e2e     # tests Playwright (script du package.json ; aussi : npm run test:e2e)
```

`vp test` est la commande intégrée (Vitest) ; `vp run <script>` (ou `vpr <script>`) lance un script du `package.json`.

### Tests de robustesse de l'interface (Playwright)

`tests/e2e/robustesse.spec.ts` parcourt les ateliers avec des saisies extrêmes (300 caractères sans espace,
émoji, message vide, hexadécimal invalide, message trop long pour RSA), à 1 440 et 1 100 pixels de large.
Il vérifie qu'aucun élément ne déborde horizontalement, qu'aucune erreur JavaScript n'apparaît et que
chaque atelier affiche le bon verdict (⊥ après altération, JWS vérifié, oracle de remplissage…).

```bash
npx playwright install chromium   # une fois
npm run test:e2e                  # build + vp preview, puis les 66 tests
ATELIER_URL=file://$PWD/dist-single/index.html npm run test:e2e   # sur un build en fichier unique
```

Le routage utilise le fragment d'URL (`#/algo/gcm`) : le build fonctionne hébergé n'importe où
(GitHub Pages, Netlify) ou ouvert directement depuis le disque.

## Arborescence

```
src/
  crypto/     sym.ts · pke.ts · sig.ts · mac.ts · kdf.ts · keyfmt.ts · crypto.test.ts
  data/       algos.ts (fiches) · history.ts (frise)
  labs/       SymLab · PkeLab · SigLab (bancs d'essai)
  components/ ByteView (anatomie des octets) · ui (pipeline animé, onglets de formats…)
  pages/      Layout · HomePage · AlgoPage · HistoryPage · NotionsPage
```

Stack : Vite+ (Vite 8, Vitest 5), React 19, TanStack Router, GSAP. Police à chasse fixe : Monaspace Argon (OFL).

## Palette des octets

`src/palette.css` : douze familles de rôles, une encre par famille (clair et sombre), validées par calcul
sur les juxtapositions réelles de l'app (pire écart daltonien entre voisins ΔE 7,3 / 9,8, vision normale ≥ 15,1).
La couleur n'est jamais seule : légende nommée, espace entre segments, hachures (bourrage, masques),
pointillés (octets de format). La page `#/palette` montre la palette en situation et permet de revenir
à celle des planches PDF.

## Publication

À chaque `push` sur `main`, `.github/workflows/pages.yml` installe, lance les tests unitaires,
construit, lance les tests Playwright puis publie `dist/` sur GitHub Pages. Les pull requests
sont testées sans être publiées. Le jeton Font Awesome est fourni par le secret d'Actions
`FONTAWESOME_PACKAGE_TOKEN`.

## Licence

Code sous licence [MIT](LICENSE). Les icônes Font Awesome Pro ne sont **pas** couvertes par cette
licence : elles relèvent de la licence Font Awesome Pro de leur titulaire et ne sont pas incluses
dans le dépôt (seulement dans le site construit).

## État conservé dans le navigateur

Chaque page garde ses réglages, ses textes et ses biclés dans le `localStorage` (`atelier/v1/<page>`),
validés par zod à la relecture (`src/lib/persist.ts`). Les octets, les entiers longs et les clés WebCrypto
(exportées en JWK) sont codés en JSON ; une valeur illisible est ignorée et la page repart de ses valeurs
par défaut. « Réinitialiser la page » efface l'état d'une page, « Effacer l'état de toutes les pages »
(menu) efface tout. Ce sont des clés de démonstration : elles sont stockées en clair.

## Planches PDF

Les planches A4 du cours sont dans `public/planches/` (PDF et vignettes WebP), servies telles quelles par
Vite. Leurs sources HTML et le script de rendu sont tenus à part (projet du cours). Dans l'artefact
claude.ai, les liens pointent vers le site public.
