# Atelier crypto

Atelier interactif du cours **Introduction à la cryptographie moderne** (EPITA, EGE, ESG) :
chiffrer, déchiffrer, signer et vérifier avec du vrai code, et voir le **format exact** des clés,
des clairs, des chiffrés et des signatures, segment par segment.

Benoit LEGER-DERVILLE · Stelau · iDAKTO

## Contenu

| Famille | Algorithmes |
|---|---|
| Symétrique | AES-ECB, AES-CBC, AES-CTR, AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, AES-KW |
| Chiffrement asymétrique | RSA brut, RSAES-PKCS1-v1_5, RSAES-OAEP, RSA-KEM, ECIES (P-256, variante Apple), HPKE (RFC 9180), ML-KEM-768, X25519MLKEM768 |
| Signatures | RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA P-256 (+ attaque « PS3 » du nonce réutilisé), Ed25519, ML-DSA-65, SLH-DSA (128f / 128s) |
| Pages transverses | Frise historique filtrable, Notions (extension de longueur SHA-256(K ‖ M) contre HMAC, paradoxe des anniversaires), glossaire |

Pour chaque algorithme : une fiche de rappel (issue des planches), de vrais champs et boutons
(générer, chiffrer, altérer un bit, déchiffrer, signer, vérifier), la chaîne d'opérations animée
(GSAP) et l'anatomie des octets : `00 02 PS 00 M`, `enc ‖ C ‖ tag`, `r ‖ s` et DER, JWK, PEM…

## D'où vient le code crypto

- **WebCrypto** du navigateur : AES-CBC/CTR/GCM, RSA-OAEP (déchiffrement), RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA, ECDH.
- **@noble** (ciphers, curves, hashes, post-quantum) : ECB, GCM-SIV, ChaCha20-Poly1305, AES-KW, X25519, Ed25519, ML-KEM, ML-DSA, SLH-DSA.
- **Écrit à la main** (`src/crypto/`), pour que tout se voie : RSA brut (BigInt), PKCS#1 v1.5, encodage OAEP
  (déchiffré ensuite par WebCrypto, preuve d'interopérabilité), RSA-KEM, ECIES, HPKE mode Base
  (vérifié contre `@hpke/core`), SHA-256 en Merkle-Damgård explicite, ECDSA à nonce fixé.

## Commandes (Vite+)

```bash
vp install          # dépendances
vp dev              # serveur de développement
vp test             # 30 tests : allers-retours, altérations, interopérabilité, attaques
vp build            # build statique dans dist/
SINGLE=1 vp build   # un seul fichier HTML autonome dans dist-single/
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
sur les juxtapositions réelles de l'app (pire écart daltonien entre voisins ΔE 7,3 / 9,8, vision normale ≥ 15,7).
La couleur n'est jamais seule : légende nommée, espace entre segments, hachures (bourrage, masques),
pointillés (octets de format). La page `#/palette` montre la palette en situation et permet de revenir
à celle des planches PDF.
