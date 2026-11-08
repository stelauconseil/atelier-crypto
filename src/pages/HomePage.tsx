import { ALGO_ICON, Fad, IC, Num } from '../lib/icons';
import { Link } from '@tanstack/react-router';
import { HomeCarousel } from '../components/HomeCarousel';
import { HeroLogo } from '../components/HeroLogo';
import { ALGOS, FAMILIES } from '../data/algos';

const FAM_ICON = { sym: IC.sym, hash: IC.hash, kex: IC.kex, pke: IC.pke, sig: IC.sigFamily, rng: IC.rng } as const;

export function HomePage() {
  return (
    <div className="page">
      <div className="hero">
        <div className="hero-txt">
          <div className="hero-kicker">Introduction à la cryptographie moderne</div>
          <h1>Atelier crypto</h1>
          <p>
            Chiffrer, hacher, échanger une clé, signer, tirer de l'aléa : avec du vrai code et de vrais octets. Chacun des {ALGOS.length} ateliers a sa fiche
            de rappel et son banc d'essai ; vous tapez, vous cliquez, et l'atelier montre le format exact des clés, des clairs, des chiffrés et des signatures,
            segment par segment, puis ce qu'un attaquant en ferait.
          </p>
          <ul className="hero-fams">
            {FAMILIES.map((f) => <li key={f.id}><Fad icon={FAM_ICON[f.id]} />{f.label} <b>{ALGOS.filter((x) => x.family === f.id).length}</b></li>)}
          </ul>
          <p className="hero-small">
            WebCrypto du navigateur quand il sait faire, bibliothèques @noble pour le reste (ChaCha20, ML-KEM, ML-DSA, SLH-DSA, BLAKE3, Argon2…), et du code écrit
            à la main pour ce qui doit se voir (OAEP, ECIES, HPKE, SHA-256 tour par tour, HMAC-DRBG, Dual_EC). Vos clés et réglages restent dans ce navigateur.
          </p>
        </div>
        <HeroLogo />
      </div>
      <HomeCarousel />
      <div className="grid2" style={{ marginTop: 14 }}>
        {FAMILIES.map((f) => (
          <div className="card famcard" key={f.id}>
            <h3><Fad icon={FAM_ICON[f.id]} className="ico-l" />{f.label}</h3>
            <div className="meta" style={{ marginTop: 0 }}>{f.sub}</div>
            <div className="chips">
              {ALGOS.filter((a) => a.family === f.id).map((a) => (
                <Link key={a.id} className="chip" to="/algo/$id" params={{ id: a.id }}><Fad icon={ALGO_ICON[a.id]} />{a.short}</Link>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="grid2" style={{ marginTop: 14 }}>
        <Link to="/histoire" className="card famcard"><h3><Fad icon={IC.history} className="ico-l" />Histoire en frise →</h3><div className="meta">De DES et RSA à ML-KEM : jalons, attaques (Bleichenbacher, PS3, Sweet32…) et normes.</div></Link>
        <Link to="/planches" className="card famcard"><h3><Fad icon={IC.books} className="ico-l" />Planches du cours (PDF) →</h3><div className="meta">Les fiches A4 de synthèse à télécharger : chiffrement, signatures, notions, AES et permutations.</div></Link>
        <Link to="/notions" className="card famcard"><h3><Fad icon={IC.notions} className="ico-l" />Notions →</h3><div className="meta">MAC contre hachage avec l'attaque par extension de longueur en direct, paradoxe des anniversaires, glossaire.</div></Link>
      </div>
      <div className="card" style={{ marginTop: 14 }}>
        <h2><Num n={2} />Mode d'emploi</h2>
        <ul className="howto">
          <li><Fad icon={IC.palette} /><span>Les couleurs sont constantes : <span className="pill t-key">secret</span><span className="pill t-pub">public</span><span className="pill t-nonce">aléa</span><span className="pill t-pt">clair</span><span className="pill t-ct">chiffré</span><span className="pill t-tag">tag</span><span className="pill t-enc">encapsulation</span><span className="pill t-sig">signature</span><span className="pill t-hash">haché</span><span className="pill t-pad">bourrage</span><span className="pill t-hdr">format</span> (détail sur la page Palette).</span></li>
          <li><Fad icon={IC.pointer} /><span>Survolez un segment pour son rôle et sa taille ; basculez hex / base64 ; cliquez « afficher les octets masqués » pour tout voir, puis « replier ».</span></li>
          <li><Fad icon={IC.bolt} /><span>« Altérer un bit » modifie ce qui circule : observez qui détecte (AEAD, signatures) et qui ne voit rien (CBC, CTR, RSA brut).</span></li>
          <li><Fad icon={IC.dice} /><span>Rechiffrez ou resignez le même message : l'atelier dit si le schéma est déterministe ou probabiliste.</span></li>
          <li><Fad icon={IC.code} /><span>Sur chaque algorithme, l'onglet « Pour aller plus loin » détaille chaque élément affiché, et l'onglet « Le code » montre le code TypeScript réellement exécuté.</span></li>
          <li><Fad icon={IC.saved} /><span>Vos réglages, textes et clés sont conservés dans ce navigateur, page par page : « Réinitialiser la page » en haut à droite, ou « Effacer l'état de toutes les pages » dans le menu.</span></li>
        </ul>
      </div>
    </div>
  );
}
