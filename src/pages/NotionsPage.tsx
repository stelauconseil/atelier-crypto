import { ALGO_ICON, Fad, IC } from '../lib/icons';
import { useState, type ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { equal, rand, toHex, utf8 } from '../lib/bytes';
import { hmacSha256, lengthExtend, naiveMac } from '../crypto/mac';
import { seg } from '../crypto/types';
import { ByteView } from '../components/ByteView';
import { Card, Status } from '../components/ui';

function LengthExtension() {
  const [key] = useState(() => rand(16));
  const [m, setM] = useState('montant=10&dest=alice');
  const [suffix, setSuffix] = useState('&dest=mallory&montant=9999');
  const [out, setOut] = useState<null | ReturnType<typeof lengthExtend> & { tag: Uint8Array; naiveOk: boolean; hmacOk: boolean }>(null);
  const run = () => {
    const mb = utf8(m);
    const tag = naiveMac(key, mb);
    const r = lengthExtend(tag, key.length, mb, utf8(suffix));
    setOut({ ...r, tag, naiveOk: equal(naiveMac(key, r.forgedMsg), r.forgedTag), hmacOk: equal(hmacSha256(key, r.forgedMsg), r.forgedTag) });
  };
  return (
    <Card n={2} title="MAC naïf SHA-256(K ‖ M) : l'attaque par extension de longueur, en direct">
      <p style={{ margin: '0 0 8px' }}>
        Le serveur authentifie ses messages avec <code>tag = SHA-256(K ‖ M)</code>, K secrète de 16 octets. L'attaquant voit M et le tag.
        Comme le haché publié <b>est</b> l'état interne final de Merkle-Damgård, il reprend le calcul à partir du tag et fabrique un tag valide pour
        <code> M ‖ bourrage ‖ suite</code>, sans jamais connaître K. SHA-256 est réimplémenté à la main dans l'atelier pour pouvoir repartir d'un état.
      </p>
      <div className="row">
        <label className="f"><span className="lab">Message légitime M</span><input className="t mono" value={m} onChange={(e) => setM(e.target.value)} /></label>
        <label className="f"><span className="lab">Suite ajoutée par l'attaquant</span><input className="t mono" value={suffix} onChange={(e) => setSuffix(e.target.value)} /></label>
        <button className="btn b-org" onClick={run}><Fad icon={IC.forge} />Forger sans la clé</button>
      </div>
      {out && (
        <>
          <ByteView view={{ title: 'Ce que voit l\'attaquant', segs: [seg('M', utf8(m), 'pt'), seg('tag = SHA-256(K ‖ M)', out.tag, 'tag')] }} />
          <ByteView view={{ title: 'Message forgé M′ = M ‖ bourrage ‖ suite', caption: 'Le bourrage SHA-256 (0x80, zéros, longueur de K ‖ M en bits) devient une partie du message.', segs: [seg('M', utf8(m), 'pt'), seg('bourrage (« colle »)', out.glue, 'pad'), seg('suite', utf8(suffix), 'ct')] }} />
          <ByteView view={{ title: 'Tag forgé, calculé à partir de l\'état h', segs: [seg('tag′', out.forgedTag, 'tag')] }} />
          <Status s={out.naiveOk ? { kind: 'ko', text: 'Le serveur vérifie SHA-256(K ‖ M′) = tag′ : ACCEPTÉ. Falsification réussie sans la clé.' } : { kind: 'info', text: 'Inattendu.' }} />
          <Status s={out.hmacOk ? { kind: 'ko', text: 'HMAC accepte aussi (inattendu).' } : { kind: 'ok', text: 'Avec HMAC-SHA-256 = H((K⊕opad) ‖ H((K⊕ipad) ‖ M)), le même tag′ est REJETÉ : le hachage externe masque l\'état.' }} />
          <p className="meta">Ni SHA-3 (l'éponge ne publie qu'une partie de son état) ni SHA-512/256 ni BLAKE2/3 ne sont vulnérables. Le remède standard : <A id="hmac">HMAC</A>, ou le mode à clé de <A id="blake">BLAKE2</A>.</p>
          <p className="meta">Le serveur lira peut-être « dest=mallory » en dernier : beaucoup d'analyseurs de paramètres retiennent la dernière occurrence. Clé du serveur (secrète) : <code>{toHex(key)}</code>.</p>
        </>
      )}
    </Card>
  );
}

function Birthday() {
  const [perm, setPerm] = useState<number[]>([]);
  const [func, setFunc] = useState<number[]>([]);
  const [stats, setStats] = useState<number[]>([]);
  const first = (s: number[]) => { const v = new Set<number>(); for (let i = 0; i < s.length; i++) { if (v.has(s[i])) return i; v.add(s[i]); } return -1; };
  const run = () => {
    const p = Array.from({ length: 256 }, (_, i) => i);
    for (let i = 255; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [p[i], p[j]] = [p[j], p[i]]; }
    const f = Array.from({ length: 256 }, () => Math.floor(Math.random() * 256));
    setPerm(p); setFunc(f); setStats([...stats, first(f)].slice(-50));
  };
  const cf = first(func);
  const cell = (v: number, i: number, hit: boolean) => (
    <span key={i} className={`by sg ${hit ? 't-priv' : 't-ct'}`} style={{ padding: '1px 3px', marginRight: 2 }}>{v.toString(16).padStart(2, '0')}</span>
  );
  return (
    <Card n={3} title="Permutation ou fonction aléatoire : le paradoxe des anniversaires sur 8 bits">
      <p style={{ margin: '0 0 8px' }}>
        Un flux produit par une <b>permutation</b> (comme AES-CTR) ne répète jamais une valeur avant d'avoir épuisé les 2ⁿ possibles. Un flux vraiment aléatoire en répète une après
        environ √(π·2ⁿ/2) tirages : ≈ 20 pour 8 bits, ≈ 2³² pour un bloc de 64 bits (Sweet32), ≈ 2⁶⁴ pour AES. C'est l'origine des limites de volume par clé.
        Même calcul pour les collisions d'un haché de n bits (2ⁿᐟ² essais : 2¹²⁸ pour <A id="sha256">SHA-256</A>) et pour les nonces aléatoires de 96 bits
        de <A id="gcm">GCM</A> : au-delà de 2³² messages sous une même clé, le risque de répétition n'est plus négligeable.
      </p>
      <button className="btn b-pri" onClick={run}><Fad icon={IC.dice} />Tirer 256 valeurs de chaque</button>
      {func.length > 0 && (
        <div className="grid2" style={{ marginTop: 10 }}>
          <div>
            <div className="who"><Fad icon={IC.layers} />Permutation : 40 premières valeurs</div>
            <div className="bytes">{perm.slice(0, 40).map((v, i) => cell(v, i, false))}</div>
            <Status s={{ kind: 'ok', text: 'Aucune répétition, jamais.' }} />
          </div>
          <div>
            <div className="who"><Fad icon={IC.dice} />Fonction aléatoire : 40 premières valeurs</div>
            <div className="bytes">{func.slice(0, 40).map((v, i) => cell(v, i, cf >= 0 && i <= cf && v === func[cf]))}</div>
            <Status s={{ kind: 'ko', text: `Première répétition au tirage n° ${cf + 1}. Moyenne sur ${stats.length} essai(s) : ${(stats.reduce((a, b) => a + b + 1, 0) / stats.length).toFixed(1)}.` }} />
          </div>
        </div>
      )}
    </Card>
  );
}

/** Lien vers un atelier. */
function A({ id, children }: { id: string; children: ReactNode }) {
  return <Link to="/algo/$id" params={{ id }}>{children}</Link>;
}

/** Ce qu'on cherche à garantir, et quelle famille le fait. */
const GOALS: { goal: string; q: string; tools: [string, string][]; not: string }[] = [
  { goal: 'Confidentialité', q: 'Personne d\'autre ne peut lire.', tools: [['gcm', 'AES-GCM'], ['chacha', 'ChaCha20-Poly1305'], ['hpke', 'HPKE'], ['mlkem', 'ML-KEM']], not: 'Ne dit rien sur la provenance ni l\'intégrité, sauf en AEAD.' },
  { goal: 'Intégrité et authenticité (clé partagée)', q: 'Le message vient bien de quelqu\'un qui a la clé, intact.', tools: [['hmac', 'HMAC'], ['blake', 'BLAKE2 à clé'], ['gcm', 'tag GCM']], not: 'Le destinataire pourrait l\'avoir écrit lui-même : pas de preuve pour un tiers.' },
  { goal: 'Authenticité vérifiable par tous', q: 'Le détenteur de la clé privée l\'a signé ; n\'importe qui peut vérifier.', tools: [['ecdsa', 'ECDSA'], ['ed25519', 'Ed25519'], ['mldsa', 'ML-DSA']], not: 'La « non-répudiation » demande en plus un cadre juridique (horodatage, certificat qualifié…).' },
  { goal: 'Établissement de clé', q: 'Deux parties obtiennent un secret commun sur un canal public.', tools: [['dh', 'DH'], ['x25519', 'X25519'], ['sigma', 'SIGMA'], ['mlkem', 'ML-KEM']], not: 'Sans authentification, rien n\'empêche l\'homme du milieu.' },
  { goal: 'Empreinte et dérivation', q: 'Un résumé court qui engage le contenu ; des clés tirées d\'un secret.', tools: [['sha256', 'SHA-256'], ['sha3', 'SHA-3'], ['hkdf', 'HKDF'], ['pwhash', 'Argon2id']], not: 'Un haché seul n\'authentifie rien : n\'importe qui peut le recalculer.' },
  { goal: 'Aléa', q: 'Des clés, nonces et sels que personne ne peut prédire.', tools: [['csprng', 'générateur du système'], ['hmacdrbg', 'HMAC-DRBG']], not: 'Passer des tests statistiques ne prouve pas l\'imprévisibilité.' },
];

/** Équivalences de sécurité (NIST SP 800-57 partie 1, rév. 5 ; catégories NIST pour le post-quantique). */
const LEVELS: [string, string, string, string, string][] = [
  ['112 bits', '(3DES, retiré)', 'RSA-2048, DH-2048', 'P-224', '—'],
  ['128 bits', 'AES-128', 'RSA-3072, DH-3072', 'P-256, X25519, Ed25519', 'ML-KEM-512, ML-DSA-44 *, SLH-DSA-128'],
  ['192 bits', 'AES-192', 'RSA-7680', 'P-384, X448', 'ML-KEM-768, ML-DSA-65, SLH-DSA-192'],
  ['256 bits', 'AES-256', 'RSA-15360', 'P-521', 'ML-KEM-1024, ML-DSA-87, SLH-DSA-256'],
];

const GLOSSARY: { t: string; d: string; id?: string; fam: string }[] = [
  { fam: 'Chiffrement', t: 'AEAD / AAD', d: 'Chiffrement authentifié ; les données associées sont authentifiées mais pas chiffrées (en-têtes, identifiants).', id: 'gcm' },
  { fam: 'Chiffrement', t: 'IV / nonce', d: 'Valeur publique propre à chaque message : imprévisible (CBC) ou seulement unique (CTR, GCM, ChaCha20).', id: 'cbc' },
  { fam: 'Chiffrement', t: 'Malléabilité', d: 'Modifier un chiffré pour transformer le clair de façon contrôlée (CTR, CBC, RSA brut).', id: 'ctr' },
  { fam: 'Chiffrement', t: 'Oracle', d: 'Tout comportement observable (erreur, délai) qui répond à une question sur un chiffré : remplissage CBC, Bleichenbacher.', id: 'rsa-pkcs1' },
  { fam: 'Chiffrement', t: 'KEM / DEM', d: 'Encapsulation de la clé / des données : une clé de session aléatoire, transportée par l\'asymétrique, chiffre les données en symétrique.', id: 'hybrid' },
  { fam: 'Chiffrement', t: 'Rejet implicite', d: 'Un chiffré invalide donne une clé pseudo-aléatoire plutôt qu\'une erreur, pour ne pas offrir d\'oracle (ML-KEM).', id: 'mlkem' },
  { fam: 'Chiffrement', t: 'IND-CPA / IND-CCA2', d: 'Indistinguabilité face à qui peut faire chiffrer / face à qui peut aussi faire déchiffrer tout sauf le défi.' },
  { fam: 'Hachage', t: 'Préimage, seconde préimage, collision', d: 'Retrouver un message d\'après son haché (2ⁿ) ; un second message de même haché (2ⁿ) ; deux messages quelconques de même haché (2ⁿᐟ²).', id: 'sha256' },
  { fam: 'Hachage', t: 'Merkle-Damgård / éponge', d: 'Deux constructions : itérer une compression (SHA-2, extension de longueur possible) ; absorber puis essorer une permutation (SHA-3).', id: 'sha3' },
  { fam: 'Hachage', t: 'MAC', d: 'Code d\'authentification à clé secrète : infalsifiable sans K. Un haché n\'a pas de clé.', id: 'hmac' },
  { fam: 'Hachage', t: 'KDF', d: 'Dérivation de clé : extraire l\'entropie d\'un secret puis l\'étendre en clés séparées par usage (HKDF, Concat KDF, X9.63).', id: 'hkdf' },
  { fam: 'Hachage', t: 'Sel', d: 'Valeur publique, unique par mot de passe ou par instance : interdit les tables précalculées et sépare les contextes.', id: 'pwhash' },
  { fam: 'Hachage', t: 'PRP / PRF', d: 'Permutation / fonction pseudo-aléatoire : indiscernable d\'une permutation / fonction tirée au hasard (AES / HMAC).' },
  { fam: 'Établissement', t: 'Confidentialité persistante (PFS)', d: 'La compromission ultérieure des clés à long terme ne révèle pas les sessions passées : il faut des clés éphémères.', id: 'kex-grid' },
  { fam: 'Établissement', t: 'Sécurité post-compromission (PCS)', d: 'Après le vol d\'un état, le protocole « guérit » au prochain échange DH (Double Ratchet).', id: 'ratchet' },
  { fam: 'Établissement', t: 'Validation de clé publique', d: 'Vérifier qu\'une valeur reçue appartient au bon groupe ou à la courbe : sans cela, attaques par petit sous-groupe ou courbe invalide.', id: 'dh' },
  { fam: 'Établissement', t: 'Homme du milieu', d: 'Un DH non authentifié s\'établit avec l\'attaquant ; d\'où les signatures (SIGMA, TLS) ou les clés statiques connues.', id: 'sigma' },
  { fam: 'Signature', t: 'EUF-CMA', d: 'Impossible de signer un message nouveau, même après avoir obtenu des signatures de messages choisis.' },
  { fam: 'Signature', t: 'Nonce de signature (k)', d: 'Secret, unique, uniforme : répété ou biaisé, il livre la clé privée (PS3). RFC 6979 le dérive de la clé et du message.', id: 'hmacdrbg' },
  { fam: 'Aléa', t: 'Entropie', d: 'Quantité d\'imprévisibilité, en bits : 128 bits = 2¹²⁸ possibilités équiprobables. Un mot de passe humain en a 20 à 40.', id: 'csprng' },
  { fam: 'Aléa', t: 'PRNG / CSPRNG / DRBG', d: 'Générateur pseudo-aléatoire ; « cryptographique » s\'il est imprévisible ; DRBG est le nom NIST (SP 800-90A).', id: 'hmacdrbg' },
  { fam: 'Aléa', t: 'Graine, réensemencement', d: 'L\'entropie initiale d\'un générateur ; en réinjecter régulièrement permet de se rétablir après une compromission.', id: 'hmacdrbg' },
  { fam: 'Aléa', t: 'Porte dérobée (kleptographie)', d: 'Un algorithme sûr pour tous sauf pour qui détient une clé cachée dans ses constantes : Dual_EC_DRBG.', id: 'dualec' },
  { fam: 'Transverse', t: 'Niveau de sécurité', d: 'Log₂ du nombre d\'opérations de la meilleure attaque connue : 128 bits est le minimum actuel.' },
  { fam: 'Transverse', t: 'Hybride (post-quantique)', d: 'Combiner un algorithme classique et un post-quantique : sûr tant que l\'un des deux tient (X25519MLKEM768 dans TLS).', id: 'hybrid' },
  { fam: 'Transverse', t: 'HNDL', d: 'Harvest now, decrypt later : on migre le chiffrement vers le post-quantique avant la signature.', id: 'mlkem' },
  { fam: 'Transverse', t: 'Principe de Kerckhoffs', d: 'La sécurité ne doit reposer que sur le secret de la clé, jamais sur celui de l\'algorithme.' },
  { fam: 'Transverse', t: 'Séparation des clés', d: 'Une clé, un usage : dériver des clés distinctes pour chiffrer, authentifier, chaque direction.', id: 'hkdf' },
];

export function NotionsPage() {
  return (
    <div className="page">
      <div className="head"><div><div className="fam">Notions</div><h1><Fad icon={IC.notions} className="h-ico" />Comprendre ce qu'on manipule</h1></div></div>
      <Card n={1} title="Six objectifs, six familles">
        <div className="kx-scroll">
          <table className="kx-table nt-goals">
            <thead><tr><th>Objectif</th><th>Ce que ça garantit</th><th>Ateliers</th><th>Ce que ça ne garantit pas</th></tr></thead>
            <tbody>
              {GOALS.map((g) => (
                <tr key={g.goal}>
                  <td><b>{g.goal}</b></td><td>{g.q}</td>
                  <td>{g.tools.map(([id, l], i) => <span key={id + l}>{i > 0 && ', '}<A id={id}>{l}</A></span>)}</td>
                  <td className="mute">{g.not}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <LengthExtension />
      <Birthday />
      <Card n={4} title="Niveaux de sécurité équivalents">
        <div className="kx-scroll">
          <table className="kx-table">
            <thead><tr><th>Sécurité</th><th>Symétrique</th><th>Corps fini (RSA, DH)</th><th>Courbes elliptiques</th><th>Post-quantique</th></tr></thead>
            <tbody>{LEVELS.map((r) => <tr key={r[0]}>{r.map((c, i) => <td key={i}>{i === 0 ? <b>{c}</b> : c}</td>)}</tr>)}</tbody>
          </table>
        </div>
        <p className="meta">
          Un haché de n bits offre n/2 bits contre les collisions : SHA-256 pour 128 bits, SHA-384 pour 192. La taille de RSA croît bien plus vite que celle des courbes,
          d'où leur adoption. Face à un ordinateur quantique, l'algorithme de Shor casse RSA, DH et les courbes à toute taille ; celui de Grover ne fait que réduire la marge
          du symétrique, d'où la préférence pour AES-256 (exigé par CNSA 2.0). * ML-DSA-44 vise la catégorie 2 (collision de SHA-256).
        </p>
      </Card>
      <Card n={5} title="Glossaire">
        {[...new Set(GLOSSARY.map((g) => g.fam))].map((fam) => (
          <div key={fam} className="nt-fam">
            <h4>{fam}</h4>
            <div className="grid2">
              {GLOSSARY.filter((g) => g.fam === fam).map((g) => (
                <div key={g.t}>
                  <b style={{ color: 'var(--navy)' }}>{g.t}</b> — {g.d}
                  {g.id && <> <Link to="/algo/$id" params={{ id: g.id }} className="nt-go" title="Voir l'atelier"><Fad icon={ALGO_ICON[g.id] ?? IC.lab} /></Link></>}
                </div>
              ))}
            </div>
          </div>
        ))}
      </Card>
      <p className="meta">Les démonstrations s'exécutent entièrement dans le navigateur ; aucune donnée ne quitte la page.</p>
    </div>
  );
}
