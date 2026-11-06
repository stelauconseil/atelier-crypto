import { Fad, IC, Num } from '../lib/icons';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import gsap from 'gsap';
import { ByteView, type Encoding } from './ByteView';
import type { View } from '../crypto/types';
import type { AlgoInfo } from '../data/algos';

/** Chaîne d'opérations : s'illumine étape par étape à chaque exécution (animation GSAP). */
export function Pipeline({ label, steps, run }: { label: string; steps: string[]; run: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!run || !ref.current) return;
    const els = ref.current.querySelectorAll('.st');
    const tl = gsap.timeline();
    els.forEach((el) => {
      tl.to(el, { backgroundColor: '#0e8c8c', color: '#fff', borderColor: '#0e8c8c', scale: 1.06, duration: 0.16 })
        .to(el, { scale: 1, duration: 0.12 })
        .to(el, { backgroundColor: 'rgba(14,140,140,0.12)', color: 'inherit', borderColor: 'rgba(14,140,140,0.5)', duration: 0.25 }, '+=0.05');
    });
    return () => {
      tl.kill();
      gsap.set(els, { clearProps: 'all' });
    };
  }, [run]);
  return (
    <div className="pipe" ref={ref}>
      <span className="lbl">{label}</span>
      {steps.map((s, i) => (
        <span key={i} style={{ display: 'contents' }}>
          {i > 0 && <span className="ar">→</span>}
          <span className="st">{s}</span>
        </span>
      ))}
    </div>
  );
}

export function Status({ s }: { s: { kind: 'ok' | 'ko' | 'info'; text: string } | null }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) gsap.fromTo(ref.current, { opacity: 0, y: -4 }, { opacity: 1, y: 0, duration: 0.3 });
  }, [s]);
  if (!s) return null;
  return (
    <div ref={ref} className={`status s-${s.kind}`}>
      <Fad icon={s.kind === 'ok' ? IC.ok : s.kind === 'ko' ? IC.ko : IC.info} />
      <span>{s.text}</span>
    </div>
  );
}

export function Pills({ a }: { a: AlgoInfo }) {
  return (
    <>
      {a.status.map(([t, tone]) => (
        <span key={t} className={`pill p-${tone}`}>{t}</span>
      ))}
    </>
  );
}

export function Recall({ a }: { a: AlgoInfo }) {
  return (
    <div className="card">
      <h2><Num n={1} />Rappel</h2>
      <div className="recall">
        <div>
          <p>{a.lead}</p>
          <ul>{a.points.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
        <div>
          {a.formula && <div className="formula">{a.formula}</div>}
          {a.pitfalls?.map((p) => <div className="tip" key={p}>{p}</div>)}
          <div className="meta">
            {a.where && <div><b>Où :</b> {a.where}</div>}
            {a.refs && <div><b>Références :</b> {a.refs}</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

/** Onglets de formats d'une même clé (brut, JWK, PEM…). */
export function FormatTabs({ views, encoding }: { views: View[]; encoding: Encoding }) {
  const [i, setI] = useState(0);
  if (!views.length) return null;
  const v = views[Math.min(i, views.length - 1)];
  return (
    <div>
      <div className="tabs">
        {views.map((w, j) => (
          <button key={j} className={j === i ? 'on' : ''} onClick={() => setI(j)}>{w.title.split(' (')[0].split(' :')[0]}</button>
        ))}
      </div>
      <ByteView view={v} encoding={encoding} />
    </div>
  );
}

export function Card({ n, title, right, children }: { n?: number; title: string; right?: ReactNode; children: ReactNode }) {
  return (
    <div className="card">
      <div className="split" style={{ marginBottom: 6 }}>
        <h2 style={{ margin: 0 }}>{n !== undefined && <Num n={n} />}{title}</h2>
        {right}
      </div>
      {children}
    </div>
  );
}

export function useBusy() {
  const [busy, setBusy] = useState<string | null>(null);
  const wrap = (name: string, fn: () => Promise<void>) => async () => {
    setBusy(name);
    await new Promise((r) => setTimeout(r, 20)); // laisse le temps d'afficher l'état
    try {
      await fn();
    } finally {
      setBusy(null);
    }
  };
  return { busy, wrap };
}
