import { Link } from '@tanstack/react-router';
import { useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ALGOS, FAMILIES } from '../data/algos';

function HybridDiagram() {
  const ref = useRef<SVGSVGElement>(null);
  useEffect(() => {
    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ repeat: -1, repeatDelay: 1.2, defaults: { ease: 'power2.inOut' } });
      tl.set(['.k-left', '.k-right', '.pkt', '.step'], { opacity: 0 })
        .to('.s1', { opacity: 1, duration: 0.4 })
        .to('.k-left', { opacity: 1, scale: 1, duration: 0.4 })
        .to('.s2', { opacity: 1, duration: 0.4 })
        .to('.pkt', { opacity: 1, duration: 0.2 })
        .fromTo('.pkt', { x: 0 }, { x: 330, duration: 1.4 })
        .to('.s3', { opacity: 1, duration: 0.4 })
        .to('.k-right', { opacity: 1, duration: 0.4 })
        .to('.s4', { opacity: 1, duration: 0.4 })
        .to({}, { duration: 1.4 });
    }, ref);
    return () => ctx.revert();
  }, []);
  return (
    <svg ref={ref} viewBox="0 0 640 210" width="100%" className="svgdiag" role="img" aria-label="Chiffrement hybride KEM/DEM">
      <rect x="10" y="20" width="170" height="150" rx="12" fill="var(--panel2)" stroke="var(--line)" />
      <rect x="460" y="20" width="170" height="150" rx="12" fill="var(--panel2)" stroke="var(--line)" />
      <text x="95" y="42" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">ÉMETTEUR</text>
      <text x="545" y="42" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">DESTINATAIRE</text>
      <text x="95" y="58" textAnchor="middle" fontSize="11" fill="var(--mute)">connaît pk</text>
      <text x="545" y="58" textAnchor="middle" fontSize="11" fill="var(--mute)">détient sk</text>
      <g className="step s1"><text x="95" y="86" textAnchor="middle" fontSize="12" fill="var(--ink)">① Encaps(pk) → K, enc</text></g>
      <g className="k-left"><rect x="70" y="96" width="50" height="22" rx="6" fill="#e8792b" /><text x="95" y="112" textAnchor="middle" fontWeight="800" fontSize="12" fill="#fff">K</text></g>
      <g className="step s2"><text x="95" y="140" textAnchor="middle" fontSize="12" fill="var(--ink)">② AEAD(K, M) → C ‖ tag</text></g>
      <g className="step s3"><text x="545" y="86" textAnchor="middle" fontSize="12" fill="var(--ink)">④ Decaps(sk, enc) → K</text></g>
      <g className="k-right"><rect x="520" y="96" width="50" height="22" rx="6" fill="#e8792b" /><text x="545" y="112" textAnchor="middle" fontWeight="800" fontSize="12" fill="#fff">K</text></g>
      <g className="step s4"><text x="545" y="140" textAnchor="middle" fontSize="12" fill="var(--ink)">⑤ Open → M ou ⊥</text></g>
      <line x1="180" y1="95" x2="460" y2="95" stroke="var(--line)" strokeWidth="2" strokeDasharray="6 5" />
      <text x="320" y="85" textAnchor="middle" fontSize="11.5" fontWeight="700" fill="var(--red)">✕ K n'est jamais transmise</text>
      <g className="pkt">
        <rect x="120" y="150" width="46" height="22" rx="4" fill="#dff0ff" stroke="#2a6fb8" /><text x="143" y="165" textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="#1b4f86">enc</text>
        <rect x="166" y="150" width="56" height="22" rx="4" fill="#e3f3f2" stroke="#0e8c8c" /><text x="194" y="165" textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="#0a6363">C</text>
        <rect x="222" y="150" width="34" height="22" rx="4" fill="#f9e2ee" stroke="#a3195b" /><text x="239" y="165" textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="#8a1650">tag</text>
      </g>
      <text x="320" y="200" textAnchor="middle" fontSize="12" fill="var(--mute)">③ un seul message, envoyé en une fois : enc ‖ C ‖ tag</text>
    </svg>
  );
}

export function HomePage() {
  return (
    <div className="page">
      <div className="hero">
        <h1>Atelier crypto</h1>
        <p>
          Chiffrer, déchiffrer, signer, vérifier, avec du vrai code et de vrais octets. Chaque algorithme a sa fiche de rappel et son banc d'essai :
          vous tapez, vous cliquez, et l'atelier montre le format exact des clés, des clairs, des chiffrés et des signatures, segment par segment.
        </p>
        <p style={{ fontSize: 13 }}>
          WebCrypto du navigateur quand il sait faire (AES, RSA-OAEP/PSS, ECDSA, ECDH), bibliothèques @noble pour le reste (ChaCha20, GCM-SIV, ML-KEM, ML-DSA, SLH-DSA),
          et du code écrit à la main pour ce qui doit se voir (PKCS#1 v1.5, OAEP, RSA-KEM, ECIES, HPKE, SHA-256).
        </p>
      </div>
      <div className="card">
        <h2><span className="n">★</span>L'idée-force : tout chiffrement réel est hybride (KEM / DEM)</h2>
        <HybridDiagram />
      </div>
      <div className="grid3" style={{ marginTop: 14 }}>
        {FAMILIES.map((f) => (
          <div className="card famcard" key={f.id}>
            <h3>{f.label}</h3>
            <div className="meta" style={{ marginTop: 0 }}>{f.sub}</div>
            <div className="chips">
              {ALGOS.filter((a) => a.family === f.id).map((a) => (
                <Link key={a.id} className="chip" to="/algo/$id" params={{ id: a.id }}>{a.short}</Link>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="grid2" style={{ marginTop: 14 }}>
        <Link to="/histoire" className="card famcard"><h3>Histoire en frise →</h3><div className="meta">De DES et RSA à ML-KEM : jalons, attaques (Bleichenbacher, PS3, Sweet32…) et normes.</div></Link>
        <Link to="/notions" className="card famcard"><h3>Notions →</h3><div className="meta">MAC contre hachage avec l'attaque par extension de longueur en direct, paradoxe des anniversaires, glossaire.</div></Link>
      </div>
      <div className="card" style={{ marginTop: 14 }}>
        <h2>Mode d'emploi</h2>
        <ul style={{ margin: 0, paddingLeft: 18 }}>
          <li>Les couleurs sont constantes : <span className="pill t-key">clé</span><span className="pill t-nonce">nonce</span><span className="pill t-pt">clair</span><span className="pill t-ct">chiffré</span><span className="pill t-tag">tag</span><span className="pill t-enc">encapsulation</span><span className="pill t-sig">signature</span><span className="pill t-pad">bourrage</span><span className="pill t-hdr">octets de format</span>.</li>
          <li>Survolez un segment pour son rôle et sa taille ; basculez hex / base64 ; cliquez « … octets masqués » pour tout afficher.</li>
          <li>« ⚡ Altérer un bit » modifie ce qui circule : observez qui détecte (AEAD, signatures) et qui ne voit rien (CBC, CTR, RSA brut).</li>
          <li>Rechiffrez ou resignez le même message : l'atelier dit si le schéma est déterministe ou probabiliste.</li>
        </ul>
      </div>
    </div>
  );
}
