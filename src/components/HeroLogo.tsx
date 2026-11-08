import { useEffect, useRef } from 'react';
import gsap from 'gsap';
import { Fad, IC, type Icon } from '../lib/icons';

/** Les six familles, posées sur l'orbite du logo. */
const RING: { icon: Icon; label: string; color: string }[] = [
  { icon: IC.sym, label: 'Symétrique', color: 'var(--teal)' },
  { icon: IC.hash, label: 'Hachage', color: 'var(--green)' },
  { icon: IC.kex, label: 'Établissement de clé', color: 'var(--orange)' },
  { icon: IC.pke, label: 'Asymétrique', color: '#6d8fd6' },
  { icon: IC.sigFamily, label: 'Signature', color: 'var(--plum)' },
  { icon: IC.rng, label: 'Aléa', color: 'var(--gold)' },
];
const BITS = 14;
const R = 118; // rayon de l'orbite (viewBox 300 × 300, centre 150)

/**
 * Le cadenas binaire au centre ; des bits convergent vers lui et en ressortent chiffrés (hexadécimal) ;
 * les six familles tournent lentement autour.
 */
export function HeroLogo() {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    const ctx = gsap.context(() => {
      const intro = gsap.timeline({ defaults: { ease: 'power3.out' } });
      intro
        .from('.hl-core', { scale: 0.3, opacity: 0, rotate: -40, duration: 0.9, ease: 'back.out(1.8)' })
        .from('.hl-core .fa-primary', { y: -60, opacity: 0, duration: 0.6, ease: 'bounce.out' }, '-=0.35')
        .from('.hl-ring-line', { scale: 0.6, opacity: 0, duration: 0.7 }, '-=0.5')
        .from('.hl-badge', { scale: 0, opacity: 0, duration: 0.45, stagger: 0.09, ease: 'back.out(2.2)' }, '-=0.4');
      if (reduce) { intro.progress(1); return; }

      // l'orbite tourne, les pastilles restent droites
      gsap.to('.hl-orbit', { rotate: 360, duration: 80, ease: 'none', repeat: -1 });
      gsap.to('.hl-badge-in', { rotate: -360, duration: 80, ease: 'none', repeat: -1 });
      // halo qui respire
      gsap.to('.hl-halo', { scale: 1.12, opacity: 0.25, duration: 2.4, ease: 'sine.inOut', yoyo: true, repeat: -1 });
      gsap.to('.hl-core .fa-secondary', { opacity: 0.9, duration: 1.2, ease: 'sine.inOut', yoyo: true, repeat: -1, delay: 1 });

      // bits entrants (0/1) et sortants (hex)
      el.querySelectorAll<SVGTextElement>('.hl-bit').forEach((t, i) => {
        const out = i % 2 === 1;
        const pick = () => {
          const a = Math.random() * Math.PI * 2;
          t.textContent = out ? '0123456789abcdef'[Math.floor(Math.random() * 16)] + '0123456789abcdef'[Math.floor(Math.random() * 16)] : Math.random() < 0.5 ? '0' : '1';
          return a;
        };
        let a = pick();
        const far = { x: 150 + Math.cos(a) * 146, y: 150 + Math.sin(a) * 146 };
        const near = { x: 150 + Math.cos(a) * 46, y: 150 + Math.sin(a) * 46 };
        const tl = gsap.timeline({
          repeat: -1, delay: 1.2 + i * 0.32, repeatDelay: 0.4 + Math.random(),
          onRepeat: () => {
            a = pick();
            far.x = 150 + Math.cos(a) * 146; far.y = 150 + Math.sin(a) * 146;
            near.x = 150 + Math.cos(a) * 46; near.y = 150 + Math.sin(a) * 46;
            tl.invalidate();
          },
        });
        const from = () => (out ? near : far);
        const to = () => (out ? far : near);
        tl.fromTo(t, { attr: { x: () => from().x, y: () => from().y }, opacity: 0 },
          { attr: { x: () => to().x, y: () => to().y }, opacity: 1, duration: 2.2, ease: out ? 'power1.out' : 'power2.in' })
          .to(t, { opacity: 0, duration: 0.4 }, '-=0.45');
      });
    }, el);
    return () => ctx.revert();
  }, []);

  return (
    <div className="hero-logo" ref={root} aria-hidden="true">
      <svg viewBox="0 0 300 300" className="hl-svg">
        <defs>
          <radialGradient id="hl-glow">
            <stop offset="0%" stopColor="#6d8fd6" stopOpacity="0.55" />
            <stop offset="100%" stopColor="#6d8fd6" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle className="hl-halo" cx="150" cy="150" r="78" fill="url(#hl-glow)" style={{ transformOrigin: '150px 150px', opacity: 0.6 }} />
        <circle className="hl-ring-line" cx="150" cy="150" r={R} fill="none" stroke="#ffffff2e" strokeDasharray="3 6" style={{ transformOrigin: '150px 150px' }} />
        <circle className="hl-ring-line" cx="150" cy="150" r="62" fill="none" stroke="#ffffff1c" style={{ transformOrigin: '150px 150px' }} />
        {Array.from({ length: BITS }, (_, i) => (
          <text key={i} className={`hl-bit ${i % 2 ? 'hl-out' : 'hl-in'}`} x="150" y="150" textAnchor="middle" dominantBaseline="middle" opacity="0">0</text>
        ))}
      </svg>
      <div className="hl-orbit">
        {RING.map((f, i) => {
          const a = (i / RING.length) * Math.PI * 2 - Math.PI / 2;
          return (
            <span key={f.label} className="hl-badge" title={f.label}
              style={{ left: `${50 + (R / 3) * Math.cos(a)}%`, top: `${50 + (R / 3) * Math.sin(a)}%`, ['--c' as string]: f.color }}>
              <span className="hl-badge-in"><Fad icon={f.icon} /></span>
            </span>
          );
        })}
      </div>
      <div className="hl-core"><Fad icon={IC.logo} /></div>
    </div>
  );
}
