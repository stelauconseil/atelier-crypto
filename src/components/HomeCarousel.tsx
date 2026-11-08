import { JavaRandom } from '../crypto/rng';
import { Link } from '@tanstack/react-router';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import gsap from 'gsap';
import { sha256 } from '@noble/hashes/sha2.js';
import { Fad, IC, Num } from '../lib/icons';
import { utf8 } from '../lib/bytes';

/** Monte une timeline GSAP en boucle sur le SVG, nettoyée au démontage. */
function useLoop(build: (tl: gsap.core.Timeline) => void) {
  const ref = useRef<SVGSVGElement>(null);
  useEffect(() => {
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ repeat: -1, repeatDelay: 1.2, defaults: { ease: 'power2.inOut' } });
      build(tl);
      if (reduce) tl.progress(0.98).pause();
    }, ref);
    return () => ctx.revert();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return ref;
}

// ---------------------------------------------------------------- 1. chiffrement asymétrique : hybride KEM / DEM
function HybridSlide() {
  const ref = useLoop((tl) => {
    tl.set(['.k-left', '.k-right', '.pkt', '.step'], { opacity: 0 })
      .set(['.pkt', '.p-enc', '.p-ct'], { x: 0, y: 0, opacity: 1 })
      .set('.pkt', { opacity: 0 })
      .to('.s1', { opacity: 1, duration: 0.4 })
      .to('.k-left', { opacity: 1, duration: 0.4 })
      .to('.s2', { opacity: 1, duration: 0.4 })
      .to('.pkt', { opacity: 1, duration: 0.25 })
      .to('.pkt', { x: 357, duration: 1.5 })
      .to('.p-enc', { x: -12, y: -58, opacity: 0, duration: 0.7 }, '+=0.15')
      .to('.s3', { opacity: 1, duration: 0.35 }, '<0.25')
      .to('.k-right', { opacity: 1, duration: 0.4 })
      .to('.p-ct', { x: -22, y: -14, opacity: 0, duration: 0.7 })
      .to('.s4', { opacity: 1, duration: 0.35 }, '<0.3')
      .to({}, { duration: 1.6 });
  });
  return (
    <svg ref={ref} viewBox="0 0 640 214" width="100%" className="svgdiag" role="img" aria-label="Chiffrement hybride KEM/DEM">
      <rect x="10" y="20" width="170" height="162" rx="12" fill="var(--panel2)" stroke="var(--line)" />
      <rect x="460" y="20" width="170" height="162" rx="12" fill="var(--panel2)" stroke="var(--line)" />
      <text x="95" y="42" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">ÉMETTEUR</text>
      <text x="545" y="42" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">DESTINATAIRE</text>
      <text x="95" y="58" textAnchor="middle" fontSize="11" fill="var(--mute)">connaît pk</text>
      <text x="545" y="58" textAnchor="middle" fontSize="11" fill="var(--mute)">détient sk</text>
      <g className="step s1"><text x="95" y="86" textAnchor="middle" fontSize="12" fill="var(--ink)">① Encaps(pk) → K, enc</text></g>
      <g className="k-left"><rect x="70" y="96" width="50" height="22" rx="6" fill="var(--c-secret)" /><text x="95" y="112" textAnchor="middle" fontWeight="800" fontSize="12" fill="var(--panel)">K</text></g>
      <g className="step s2"><text x="95" y="140" textAnchor="middle" fontSize="12" fill="var(--ink)">② AEAD(K, M) → C ‖ tag</text></g>
      <g className="step s3"><text x="545" y="86" textAnchor="middle" fontSize="12" fill="var(--ink)">④ Decaps(sk, enc) → K</text></g>
      <g className="k-right"><rect x="520" y="96" width="50" height="22" rx="6" fill="var(--c-secret)" /><text x="545" y="112" textAnchor="middle" fontWeight="800" fontSize="12" fill="var(--panel)">K</text></g>
      <g className="step s4"><text x="545" y="140" textAnchor="middle" fontSize="12" fill="var(--ink)">⑤ Open → M ou ⊥</text></g>
      <line x1="180" y1="95" x2="460" y2="95" stroke="var(--line)" strokeWidth="2" strokeDasharray="6 5" />
      <text x="320" y="85" textAnchor="middle" fontSize="11.5" fontWeight="700" fill="var(--red)">✕ K n'est jamais transmise</text>
      <g className="pkt">
        <g className="p-enc"><rect x="120" y="152" width="46" height="22" rx="4" fill="var(--panel)" stroke="var(--c-enc)" /><text x="143" y="167" textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="var(--c-enc)">enc</text></g>
        <g className="p-ct">
          <rect x="168" y="152" width="54" height="22" rx="4" fill="var(--panel)" stroke="var(--c-ct)" /><text x="195" y="167" textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="var(--c-ct)">C</text>
          <rect x="224" y="152" width="34" height="22" rx="4" fill="var(--panel)" stroke="var(--c-tag)" /><text x="241" y="167" textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="var(--c-tag)">tag</text>
        </g>
      </g>
      <text x="320" y="204" textAnchor="middle" fontSize="12" fill="var(--mute)">③ un seul message, envoyé en une fois : enc ‖ C ‖ tag</text>
    </svg>
  );
}

// ---------------------------------------------------------------- 2. symétrique : ECB trahit les répétitions, GCM non
function SymSlide() {
  const ref = useLoop((tl) => {
    tl.set(['.ecb-c', '.gcm-c', '.gcm-tag', '.rep', '.verdict'], { opacity: 0 })
      .set('.ecb-c, .gcm-c', { y: -24 })
      .to('.ecb-c', { opacity: 1, y: 0, duration: 0.5, stagger: 0.25 })
      .to('.gcm-c', { opacity: 1, y: 0, duration: 0.5, stagger: 0.25 }, '<')
      .to('.gcm-tag', { opacity: 1, duration: 0.4 })
      .to('.rep', { opacity: 1, duration: 0.4 }, '+=0.3')
      .to('.verdict', { opacity: 1, duration: 0.4, stagger: 0.2 })
      .to({}, { duration: 2.2 });
  });
  const P = ['P₁', 'P₂', 'P₁'];
  const ecb = ['C₁', 'C₂', 'C₁'];
  const gcm = ['7a3f…', 'c21e…', '09b4…'];
  const row = (y: number, label: string, cls: string, vals: string[], color: string, repeat: boolean) => (
    <g>
      <text x="20" y={y + 15} fontSize="13" fontWeight="800" fill="var(--navy)">{label}</text>
      {P.map((p, i) => (
        <g key={`p${i}`}>
          <rect x={110 + i * 120} y={y} width="100" height="22" rx="4" fill="var(--panel)" stroke="var(--c-pt)" />
          <text x={160 + i * 120} y={y + 15} textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="var(--c-pt)">{p}</text>
        </g>
      ))}
      {vals.map((v, i) => (
        <g key={`c${i}`} className={cls}>
          <rect x={110 + i * 120} y={y + 36} width="100" height="22" rx="4" fill="var(--panel)" stroke={repeat && i !== 1 ? 'var(--red)' : color} strokeWidth={repeat && i !== 1 ? 2 : 1} />
          <text x={160 + i * 120} y={y + 51} textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill={color}>{v}</text>
        </g>
      ))}
    </g>
  );
  return (
    <svg ref={ref} viewBox="0 0 640 214" width="100%" className="svgdiag" role="img" aria-label="ECB contre GCM sur des blocs répétés">
      {row(12, 'AES-ECB', 'ecb-c', ecb, 'var(--c-ct)', true)}
      {row(112, 'AES-GCM', 'gcm-c', gcm, 'var(--c-ct)', false)}
      <g className="gcm-tag"><rect x="470" y="148" width="56" height="22" rx="4" fill="var(--panel)" stroke="var(--c-tag)" /><text x="498" y="163" textAnchor="middle" fontSize="11" fontFamily="var(--mono)" fill="var(--c-tag)">tag</text></g>
      <g className="rep"><path d="M160,72 C160,92 400,92 400,72" fill="none" stroke="var(--red)" strokeWidth="1.6" strokeDasharray="4 3" /><text x="280" y="102" textAnchor="middle" fontSize="11.5" fontWeight="700" fill="var(--red)">même clair ⇒ même chiffré</text></g>
      <text className="verdict" x="545" y="64" fontSize="12" fontWeight="700" fill="var(--red)">fuit la structure</text>
      <text className="verdict" x="545" y="164" fontSize="12" fontWeight="700" fill="var(--green)">rien ne se répète</text>
      <text className="verdict" x="545" y="180" fontSize="11" fill="var(--mute)">et toute altération est rejetée</text>
    </svg>
  );
}

// ---------------------------------------------------------------- 3. hachage : l'avalanche
const bitsOf = (b: Uint8Array) => Array.from(b).flatMap((x) => [7, 6, 5, 4, 3, 2, 1, 0].map((j) => (x >> j) & 1));
const H1 = bitsOf(sha256(utf8('Virement de 100 €')));
const H2 = bitsOf(sha256(utf8('Virement de 101 €')));

function HashSlide() {
  const ref = useLoop((tl) => {
    tl.set('.cell', { fill: (i: number) => (H1[i] ? 'var(--c-hash)' : 'var(--panel2)') })
      .set(['.m2', '.changed'], { opacity: 0 })
      .set('.m1', { opacity: 1 })
      .to({}, { duration: 1.2 })
      .to('.m1', { opacity: 0, duration: 0.3 })
      .to('.m2', { opacity: 1, duration: 0.3 }, '<')
      .to('.cell', { fill: (i: number) => (H2[i] ? 'var(--c-hash)' : 'var(--panel2)'), duration: 0.25, stagger: { each: 0.004, from: 'random' } })
      .to('.flip', { stroke: 'var(--red)', strokeWidth: 1.4, duration: 0.3 })
      .to('.changed', { opacity: 1, duration: 0.4 })
      .to({}, { duration: 2.2 })
      .to('.flip', { stroke: 'transparent', duration: 0.2 });
  });
  const diff = H1.filter((b, i) => b !== H2[i]).length;
  return (
    <svg ref={ref} viewBox="0 0 640 214" width="100%" className="svgdiag" role="img" aria-label="Effet avalanche de SHA-256">
      <text x="20" y="28" fontSize="13" fontWeight="800" fill="var(--navy)">M =</text>
      <text className="m1" x="52" y="28" fontSize="13" fontFamily="var(--mono)" fill="var(--c-pt)">« Virement de 100 € »</text>
      <text className="m2" x="52" y="28" fontSize="13" fontFamily="var(--mono)" fill="var(--c-pt)">« Virement de 10<tspan fill="var(--red)" fontWeight="800">1</tspan> € »</text>
      <text x="620" y="28" textAnchor="end" fontSize="13" fontWeight="800" fill="var(--navy)">SHA-256(M) : 256 bits</text>
      {H1.map((_, i) => (
        <rect key={i} className={`cell ${H1[i] !== H2[i] ? 'flip' : ''}`} x={20 + (i % 64) * 9.4} y={44 + Math.floor(i / 64) * 26} width="8" height="22" rx="1.5" stroke="transparent" />
      ))}
      <text className="changed" x="320" y="170" textAnchor="middle" fontSize="13" fontWeight="700" fill="var(--red)">un caractère modifié : {diff} bits sur 256 changent ({Math.round((100 * diff) / 256)} %)</text>
      <text x="320" y="196" textAnchor="middle" fontSize="12" fill="var(--mute)">une bonne fonction de hachage ne laisse voir aucun lien entre deux entrées voisines</text>
    </svg>
  );
}

// ---------------------------------------------------------------- 4. établissement de clé : le mélange de couleurs
function KexSlide() {
  const ref = useLoop((tl) => {
    tl.set(['.mixA', '.mixB', '.sendA', '.sendB', '.finA', '.finB', '.lbl-f', '.eve'], { opacity: 0 })
      .set(['.sendA', '.sendB'], { x: 0 })
      .to(['.mixA', '.mixB'], { opacity: 1, duration: 0.6 })
      .to(['.sendA', '.sendB'], { opacity: 1, duration: 0.2 })
      .to('.sendA', { x: 330, duration: 1.4 })
      .to('.sendB', { x: -330, duration: 1.4 }, '<')
      .to('.eve', { opacity: 1, duration: 0.4 }, '<0.5')
      .to(['.finA', '.finB'], { opacity: 1, duration: 0.6 })
      .to('.lbl-f', { opacity: 1, duration: 0.4 })
      .to({}, { duration: 2.2 });
  });
  const dot = (cx: number, cy: number, c: string, t: string, cls = '') => (
    <g className={cls}><circle cx={cx} cy={cy} r="15" fill={c} stroke="var(--line)" /><text x={cx} y={cy + 32} textAnchor="middle" fontSize="11" fill="var(--ink)">{t}</text></g>
  );
  const G = '#e9c46a', A = '#c0392b', B = '#2e6fb5', GA = '#d4813f', GB = '#7fa07a', S = '#8b5a3c';
  return (
    <svg ref={ref} viewBox="0 0 640 214" width="100%" className="svgdiag" role="img" aria-label="Diffie-Hellman expliqué par le mélange de couleurs">
      <text x="110" y="22" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">ALICE</text>
      <text x="530" y="22" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">BOB</text>
      {dot(320, 44, G, 'couleur publique g')}
      {dot(70, 60, A, 'secret a')}
      {dot(570, 60, B, 'secret b')}
      {dot(150, 60, GA, 'g + a', 'mixA')}
      {dot(490, 60, GB, 'g + b', 'mixB')}
      <g className="sendA"><circle cx="150" cy="128" r="12" fill={GA} stroke="var(--line)" /></g>
      <g className="sendB"><circle cx="490" cy="128" r="12" fill={GB} stroke="var(--line)" /></g>
      <line x1="175" y1="128" x2="465" y2="128" stroke="var(--line)" strokeDasharray="6 5" strokeWidth="2" />
      <text className="eve" x="320" y="112" textAnchor="middle" fontSize="11.5" fill="var(--red)" fontWeight="700">Ève voit g, g + a, g + b… mais ne sait pas « démélanger »</text>
      {dot(110, 168, S, 'g + b + a', 'finA')}
      {dot(530, 168, S, 'g + a + b', 'finB')}
      <text className="lbl-f" x="320" y="174" textAnchor="middle" fontSize="13" fontWeight="700" fill="var(--green)">même couleur des deux côtés : le secret partagé</text>
      <text className="lbl-f" x="320" y="194" textAnchor="middle" fontSize="11.5" fill="var(--mute)">en vrai : A = gᵃ, B = gᵇ, et Bᵃ = Aᵇ = gᵃᵇ</text>
    </svg>
  );
}

// ---------------------------------------------------------------- 5. signatures : signer, vérifier, falsifier
function SigSlide() {
  const ref = useLoop((tl) => {
    tl.set(['.sig', '.ok', '.forge', '.ko', '.m-bad'], { opacity: 0 })
      .set('.m-good', { opacity: 1 })
      .set('.sig', { x: 0 })
      .to('.sig', { opacity: 1, duration: 0.5 }, '+=0.4')
      .to('.sig', { x: 250, duration: 1.1 })
      .to('.ok', { opacity: 1, duration: 0.4 })
      .to({}, { duration: 1.2 })
      .to('.ok', { opacity: 0, duration: 0.3 })
      .to('.forge', { opacity: 1, duration: 0.3 })
      .to('.m-good', { opacity: 0, duration: 0.3 })
      .to('.m-bad', { opacity: 1, duration: 0.3 }, '<')
      .to('.ko', { opacity: 1, duration: 0.4 }, '+=0.3')
      .to({}, { duration: 2 });
  });
  return (
    <svg ref={ref} viewBox="0 0 640 214" width="100%" className="svgdiag" role="img" aria-label="Signer, vérifier, détecter une falsification">
      <text x="100" y="24" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">SIGNATAIRE</text>
      <text x="100" y="40" textAnchor="middle" fontSize="11" fill="var(--mute)">détient sk</text>
      <text x="520" y="24" textAnchor="middle" fontWeight="800" fontSize="13" fill="var(--navy)">TOUT LE MONDE</text>
      <text x="520" y="40" textAnchor="middle" fontSize="11" fill="var(--mute)">connaît pk</text>
      <rect x="160" y="64" width="300" height="34" rx="6" fill="var(--panel)" stroke="var(--c-pt)" />
      <text className="m-good" x="310" y="86" textAnchor="middle" fontSize="13" fontFamily="var(--mono)" fill="var(--c-pt)">« Virement de 100 € à Alice »</text>
      <text className="m-bad" x="310" y="86" textAnchor="middle" fontSize="13" fontFamily="var(--mono)" fill="var(--c-pt)">« Virement de <tspan fill="var(--red)" fontWeight="800">900</tspan> € à Alice »</text>
      <g className="sig"><rect x="80" y="114" width="80" height="26" rx="5" fill="var(--panel)" stroke="var(--c-sig)" strokeWidth="1.6" /><text x="120" y="131" textAnchor="middle" fontSize="12" fontFamily="var(--mono)" fill="var(--c-sig)">σ = Sign(sk)</text></g>
      <text className="forge" x="310" y="58" textAnchor="middle" fontSize="11.5" fontWeight="700" fill="var(--red)">Mallory modifie le montant…</text>
      <g className="ok"><text x="520" y="132" textAnchor="middle" fontSize="13" fontWeight="800" fill="var(--green)">Verify(pk, M, σ) : valide</text></g>
      <g className="ko"><text x="520" y="132" textAnchor="middle" fontSize="13" fontWeight="800" fill="var(--red)">Verify(pk, M′, σ) : invalide</text><text x="520" y="150" textAnchor="middle" fontSize="11" fill="var(--mute)">sans sk, impossible de re-signer</text></g>
      <text x="320" y="196" textAnchor="middle" fontSize="12" fill="var(--mute)">intégrité, authenticité et non-répudiation : on vérifie avec la seule clé publique</text>
    </svg>
  );
}


// ---------------------------------------------------------------- 6. aléa : un générateur non cryptographique se prédit
const JAVA = (() => { const r = new JavaRandom(20261108n); return Array.from({ length: 5 }, () => (r.nextInt() >>> 0).toString().padStart(10, '0')); })();
function RngSlide() {
  const ref = useLoop((tl) => {
    tl.set(['.c-obs', '.c-pred', '.c-real', '.atk', '.ok', '.brace'], { opacity: 0 })
      .set('.c-real', { y: -8 })
      .to('.c-obs', { opacity: 1, duration: 0.4, stagger: 0.5 }, '+=0.3')
      .to('.brace', { opacity: 1, duration: 0.4 })
      .to('.atk', { opacity: 1, duration: 0.5 })
      .to('.c-pred', { opacity: 1, duration: 0.35, stagger: 0.35 }, '+=0.4')
      .to('.c-real', { opacity: 1, y: 0, duration: 0.4, stagger: 0.35 }, '+=0.5')
      .to('.ok', { opacity: 1, duration: 0.4 })
      .to({}, { duration: 2 });
  });
  const X = (i: number) => 22 + i * 122;
  return (
    <svg ref={ref} viewBox="0 0 640 214" width="100%" className="svgdiag" role="img" aria-label="Prédire java.util.Random à partir de deux sorties">
      <text x="320" y="20" textAnchor="middle" fontSize="12" fill="var(--mute)">Le serveur envoie des codes de réinitialisation tirés de <tspan fontFamily="var(--mono)">java.util.Random</tspan></text>
      {JAVA.map((v, i) => (
        <g key={i}>
          <text x={X(i) + 52} y="44" textAnchor="middle" fontSize="11" fill="var(--mute)">code n° {i + 1}</text>
          {i < 2 ? (
            <g className="c-obs"><rect x={X(i)} y="52" width="104" height="28" rx="6" fill="var(--panel)" stroke="var(--orange)" strokeWidth="1.6" /><text x={X(i) + 52} y="71" textAnchor="middle" fontSize="13" fontFamily="var(--mono)" fill="var(--ink)">{v}</text></g>
          ) : (
            <>
              <g className="c-pred"><rect x={X(i)} y="52" width="104" height="28" rx="6" fill="var(--panel)" stroke="var(--red)" strokeWidth="1.6" strokeDasharray="4 3" /><text x={X(i) + 52} y="71" textAnchor="middle" fontSize="13" fontFamily="var(--mono)" fill="var(--red)">{v}</text></g>
              <g className="c-real"><rect x={X(i)} y="122" width="104" height="28" rx="6" fill="var(--panel2)" stroke="var(--line)" /><text x={X(i) + 52} y="141" textAnchor="middle" fontSize="13" fontFamily="var(--mono)" fill="var(--ink)">{v}</text><text x={X(i) + 52} y="166" textAnchor="middle" fontSize="12" fontWeight="800" fill="var(--green)" className="ok">identique</text></g>
            </>
          )}
        </g>
      ))}
      <path className="brace" d={`M${X(0)} 88 Q${X(0)} 96 ${X(0) + 12} 96 L${X(1) + 92} 96 Q${X(1) + 104} 96 ${X(1) + 104} 88`} fill="none" stroke="var(--orange)" strokeWidth="1.4" />
      <g className="atk"><text x={X(0) + 113} y="114" textAnchor="middle" fontSize="12" fontWeight="700" fill="var(--orange)">l'attaquant en observe deux</text><text x={X(0) + 113} y="130" textAnchor="middle" fontSize="11" fill="var(--mute)">→ état de 48 bits en ≤ 2¹⁶ essais</text></g>
      <text x={X(3) + 52} y="104" textAnchor="middle" fontSize="11" fill="var(--red)" className="c-pred">prédits</text>
      <text x={X(3) + 52} y="116" textAnchor="middle" fontSize="11" fill="var(--mute)" className="c-real">… puis envoyés aux autres comptes</text>
      <text x="320" y="200" textAnchor="middle" fontSize="12" fill="var(--mute)">passer les tests statistiques ne suffit pas : une clé exige un générateur imprévisible (SecureRandom, getrandom)</text>
    </svg>
  );
}

interface Slide { fam: string; title: string; to: string; cta: string; node: () => ReactNode }

const SLIDES: Slide[] = [
  { fam: 'Chiffrement asymétrique', title: 'L\'idée-force : tout chiffrement réel est hybride (KEM / DEM)', to: 'hpke', cta: 'Ouvrir HPKE', node: () => <HybridSlide /> },
  { fam: 'Symétrique', title: 'Un mode de chiffrement change tout : ECB trahit les répétitions, GCM non', to: 'ecb', cta: 'Ouvrir AES-ECB', node: () => <SymSlide /> },
  { fam: 'Hachage, MAC et dérivation', title: 'L\'effet avalanche : un caractère change, la moitié de l\'empreinte suit', to: 'sha256', cta: 'Ouvrir SHA-256', node: () => <HashSlide /> },
  { fam: 'Établissement de clé', title: 'Diffie-Hellman : un secret commun sans jamais l\'échanger', to: 'dh', cta: 'Ouvrir Diffie-Hellman', node: () => <KexSlide /> },
  { fam: 'Signatures', title: 'Signer avec la clé privée, vérifier avec la publique', to: 'ecdsa', cta: 'Ouvrir ECDSA', node: () => <SigSlide /> },
  { fam: 'Aléa et générateurs', title: 'Un générateur « statistiquement aléatoire » se prédit en deux sorties', to: 'javarandom', cta: 'Ouvrir java.util.Random', node: () => <RngSlide /> },
];

/** Carrousel de l'accueil : un exemple animé par famille. */
export function HomeCarousel() {
  const [i, setI] = useState(0);
  const [play, setPlay] = useState(() => !window.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
  const [hover, setHover] = useState(false);
  useEffect(() => {
    if (!play || hover) return;
    const t = setTimeout(() => setI((x) => (x + 1) % SLIDES.length), 11000);
    return () => clearTimeout(t);
  }, [i, play, hover]);
  const s = SLIDES[i];
  const go = (d: number) => setI((x) => (x + d + SLIDES.length) % SLIDES.length);
  return (
    <div className="card carousel" onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      onKeyDown={(e) => { if (e.key === 'ArrowRight') go(1); if (e.key === 'ArrowLeft') go(-1); }} tabIndex={0} aria-roledescription="carrousel">
      <div className="split">
        <h2><Num n={1} />{s.title}</h2>
        <span className="ctrls">
          <button className="btn b-ghost b-sm" onClick={() => go(-1)} aria-label="Exemple précédent"><Fad icon={IC.prev} /></button>
          <button className="btn b-ghost b-sm" onClick={() => setPlay(!play)} aria-label={play ? 'Pause' : 'Lecture'}><Fad icon={play ? IC.pause : IC.play} /></button>
          <button className="btn b-ghost b-sm" onClick={() => go(1)} aria-label="Exemple suivant"><Fad icon={IC.next} /></button>
        </span>
      </div>
      <div className="car-stage" key={i}>{s.node()}</div>
      <div className="split car-foot">
        <div className="car-dots" role="tablist">
          {SLIDES.map((x, j) => (
            <button key={x.fam} role="tab" aria-selected={j === i} className={j === i ? 'on' : ''} onClick={() => setI(j)}>{x.fam}</button>
          ))}
        </div>
        <Link className="btn b-pri b-sm" to="/algo/$id" params={{ id: s.to }}>{s.cta}<Fad icon={IC.next} /></Link>
      </div>
      {play && !hover && <div className="car-progress" key={`p${i}`} />}
    </div>
  );
}
