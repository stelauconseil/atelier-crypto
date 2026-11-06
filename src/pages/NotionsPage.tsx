import { Fad, IC } from '../lib/icons';
import { useState } from 'react';
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
    <Card n={1} title="MAC naïf SHA-256(K ‖ M) : l'attaque par extension de longueur, en direct">
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
    <Card n={2} title="Permutation ou fonction aléatoire : le paradoxe des anniversaires sur 8 bits">
      <p style={{ margin: '0 0 8px' }}>
        Un flux produit par une <b>permutation</b> (comme AES-CTR) ne répète jamais une valeur avant d'avoir épuisé les 2ⁿ possibles. Un flux vraiment aléatoire en répète une après
        environ √(π·2ⁿ/2) tirages : ≈ 20 pour 8 bits, ≈ 2³² pour un bloc de 64 bits (Sweet32), ≈ 2⁶⁴ pour AES. C'est l'origine des limites de volume par clé.
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

const GLOSSARY: [string, string][] = [
  ['AEAD / AAD', 'Chiffrement authentifié ; données associées authentifiées mais non chiffrées.'],
  ['IV / nonce', 'Valeur publique par message : imprévisible (CBC) ou seulement unique (CTR, GCM).'],
  ['MAC', 'Code d\'authentification à clé secrète : infalsifiable sans K. Un hachage n\'a pas de clé.'],
  ['Oracle', 'Tout comportement observable (erreur, délai) qui répond à une question sur un chiffré.'],
  ['Malléabilité', 'Modifier un chiffré pour transformer le clair de façon contrôlée (CTR, RSA brut).'],
  ['KEM / DEM', 'Encapsulation de la clé / encapsulation des données ; composition sûre et interchangeable.'],
  ['KDF', 'Dérivation de clé : X9.63, Concat-KDF, HKDF (extract → expand).'],
  ['IND-CPA / IND-CCA2', 'Indistinguabilité face à qui peut chiffrer / face à qui peut aussi faire déchiffrer (sauf le défi).'],
  ['EUF-CMA', 'Impossible de signer un message nouveau, même après des signatures de messages choisis.'],
  ['PRP / PRF', 'Permutation / fonction pseudo-aléatoire : indiscernable d\'une permutation / fonction tirée au hasard.'],
  ['Rejet implicite', 'Un chiffré invalide donne une clé pseudo-aléatoire plutôt qu\'une erreur (ML-KEM).'],
  ['HNDL', 'Harvest now, decrypt later : pourquoi le chiffrement migre vers le post-quantique avant la signature.'],
];

export function NotionsPage() {
  return (
    <div className="page">
      <div className="head"><div><div className="fam">Notions</div><h1><Fad icon={IC.notions} className="h-ico" />Comprendre ce qu'on manipule</h1></div></div>
      <LengthExtension />
      <Birthday />
      <Card n={3} title="Glossaire">
        <div className="grid2">
          {GLOSSARY.map(([t, d]) => <div key={t}><b style={{ color: 'var(--navy)' }}>{t}</b> — {d}</div>)}
        </div>
      </Card>
      <p className="meta">Les démonstrations s'exécutent entièrement dans le navigateur ; aucune donnée ne quitte la page.</p>
    </div>
  );
}
