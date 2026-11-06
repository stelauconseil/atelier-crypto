import { Link } from '@tanstack/react-router';
import { useLayoutEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import { EVENTS, LANES, type Lane } from '../data/history';

const ERAS = [
  { from: 1976, to: 1997, label: '1976 – 1997 · Fondations' },
  { from: 1998, to: 2009, label: '1998 – 2009 · Attaques et normalisation' },
  { from: 2010, to: 2017, label: '2010 – 2017 · Courbes modernes et AEAD' },
  { from: 2018, to: 2023, label: '2018 – 2023 · Rupture : TLS 1.3, HPKE' },
  { from: 2024, to: 2040, label: '2024 – 2035 · Post-quantique' },
];

export function HistoryPage() {
  const [lanes, setLanes] = useState<Lane[]>(LANES.map((l) => l.id));
  const [era, setEra] = useState<number | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const ctx = gsap.context(() => {
      gsap.from('.tl-ev', { opacity: 0, x: -14, duration: 0.4, stagger: 0.025, ease: 'power2.out' });
    }, ref);
    return () => ctx.revert();
  }, [lanes, era]);
  const toggle = (l: Lane) => setLanes(lanes.includes(l) ? lanes.filter((x) => x !== l) : [...lanes, l]);
  const inEra = (y: number) => era === null || (y >= ERAS[era].from && y <= ERAS[era].to);
  return (
    <div className="page" ref={ref}>
      <div className="head"><div><div className="fam">Histoire</div><h1>Cinquante ans de chiffrement et de signature</h1></div></div>
      <div className="filters">
        {LANES.map((l) => <button key={l.id} className={lanes.includes(l.id) ? 'on' : ''} onClick={() => toggle(l.id)}>{l.label}</button>)}
      </div>
      <div className="filters">
        <button className={era === null ? 'on' : ''} onClick={() => setEra(null)}>Toutes les périodes</button>
        {ERAS.map((e, i) => <button key={i} className={era === i ? 'on' : ''} onClick={() => setEra(i)}>{e.label}</button>)}
      </div>
      <div className="tl">
        {LANES.filter((l) => lanes.includes(l.id)).map((l) => (
          <div className="tl-lane" key={l.id}>
            <div className="ln" style={{ background: l.color }}>{l.label}</div>
            <div className="tl-evs">
              {EVENTS.filter((e) => e.lane === l.id && inEra(e.year)).sort((a, b) => a.year - b.year).map((e, i) => {
                const body = (<><b>{e.year}</b>{e.title}<span className="d">{e.detail}</span></>);
                const style = { ['--c' as string]: e.bad ? 'var(--red)' : l.color };
                return e.algo ? (
                  <Link key={i} to="/algo/$id" params={{ id: e.algo }} className={`tl-ev ${e.bad ? 'bad' : ''}`} style={style}>{body}</Link>
                ) : (
                  <div key={i} className={`tl-ev ${e.bad ? 'bad' : ''}`} style={style}>{body}</div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <p className="meta">En rouge : attaques et accidents. Cliquer un jalon ouvre l'atelier de l'algorithme correspondant. Les dates 2030 et 2035 viennent du projet NIST IR 8547.</p>
    </div>
  );
}
