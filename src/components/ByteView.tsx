import { Fad, IC } from '../lib/icons';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import gsap from 'gsap';
import { concat, toB64, toHex, type Bytes } from '../lib/bytes';
import type { Seg, View } from '../crypto/types';

export type Encoding = 'hex' | 'b64';

const TONE_NAME: Record<string, string> = {
  key: 'clé', priv: 'privé', pub: 'public', nonce: 'nonce / IV', pt: 'clair', ct: 'chiffré', tag: 'tag', aad: 'données associées',
  pad: 'bourrage', hdr: 'octets de format', enc: 'encapsulation', sig: 'signature', hash: 'haché', salt: 'aléa', mask: 'masque / flux', secret: 'secret dérivé',
};

const MAX = 96; // au-delà, les longs segments sont abrégés

function SegBytes({ s, full, onToggle }: { s: Seg; full: boolean; onToggle: () => void }) {
  const b = s.bytes;
  const long = b.length > MAX;
  const render = (arr: Bytes, off = 0) => Array.from(arr, (x, i) => <span className="by" key={off + i}>{x.toString(16).padStart(2, '0')}</span>);
  return (
    <span className={`sg t-${s.tone}`} title={`${s.label} — ${b.length} octet(s)${s.note ? ' — ' + s.note : ''}`}>
      {!long ? render(b) : full ? (
        <>
          {render(b)}
          <button className="fold" onClick={onToggle}><Fad icon={IC.less} /> replier</button>
        </>
      ) : (
        <>
          {render(b.slice(0, 40))}
          <button className="gap" onClick={onToggle}>… afficher les {b.length - 56} octets masqués …</button>
          {render(b.slice(-16), b.length - 16)}
        </>
      )}
    </span>
  );
}

function Blocks({ segs, block, repeats }: { segs: Seg[]; block: number; repeats?: boolean }) {
  const [all_, setAll] = useState(false);
  // Découpe la concaténation des segments en blocs, en conservant la couleur de chaque octet.
  const tones: string[] = [];
  segs.forEach((s) => s.bytes.forEach(() => tones.push(s.tone)));
  const all = concat(...segs.map((s) => s.bytes));
  const blocks: { hex: string; bytes: Bytes; tones: string[] }[] = [];
  for (let i = 0; i < all.length; i += block) {
    const bb = all.slice(i, i + block);
    blocks.push({ hex: toHex(bb), bytes: bb, tones: tones.slice(i, i + block) });
  }
  const count = new Map<string, number>();
  blocks.forEach((b) => count.set(b.hex, (count.get(b.hex) ?? 0) + 1));
  const shown = blocks.length > 24 && !all_ ? [...blocks.slice(0, 16), null, ...blocks.slice(-4)] : blocks;
  return (
    <>
      {shown.map((b, i) =>
        b === null ? (
          <button className="blk gap" key="gap" onClick={() => setAll(true)}>… afficher les {blocks.length - 20} blocs masqués …</button>
        ) : (
          <span className={`blk ${repeats && (count.get(b.hex) ?? 0) > 1 ? 'rep' : ''}`} key={i}>
            <span className="bn">{String(blocks.indexOf(b) + 1).padStart(2, '0')}</span>
            {Array.from(b.bytes, (x, j) => (
              <span className={`by sg t-${b.tones[j]}`} key={j} style={{ marginRight: 0, padding: '1px 3px' }}>
                {x.toString(16).padStart(2, '0')}
              </span>
            ))}
          </span>
        ),
      )}
      {all_ && blocks.length > 24 && <button className="fold" onClick={() => setAll(false)}><Fad icon={IC.less} /> replier</button>}
    </>
  );
}

export function ByteView({ view, encoding = 'hex', animate = true }: { view: View; encoding?: Encoding; animate?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const [full, setFull] = useState<Record<number, boolean>>({});
  const total = useMemo(() => (view.segs ?? []).reduce((n, s) => n + s.bytes.length, 0), [view]);
  const sig = useMemo(() => (view.segs ?? []).map((s) => toHex(s.bytes.slice(0, 8))).join('|') + (view.text ?? ''), [view]);

  useEffect(() => setFull({}), [sig]);

  useLayoutEffect(() => {
    if (!animate || !ref.current) return;
    const ctx = gsap.context(() => {
      gsap.from(ref.current!.querySelectorAll('.lg'), { opacity: 0, x: -8, duration: 0.35, stagger: 0.06, ease: 'power2.out' });
      const bys = ref.current!.querySelectorAll('.by');
      if (bys.length) gsap.from(bys, { opacity: 0, y: 5, duration: 0.25, stagger: { amount: Math.min(0.9, bys.length * 0.012) }, ease: 'power1.out' });
      const t = ref.current!.querySelector('pre.txt');
      if (t) gsap.from(t, { opacity: 0, y: 6, duration: 0.35 });
    }, ref);
    return () => ctx.revert();
  }, [sig, encoding, animate]);

  return (
    <div className="bv" ref={ref}>
      <div className="bv-h">
        <h3>{view.title}</h3>
        {view.segs && <span className="tot">{total} octets · {total * 8} bits</span>}
      </div>
      {view.caption && <div className="cap">{view.caption}</div>}
      {view.segs && (
        <>
          <div className="legend">
            {view.segs.map((s, i) => (
              <span className={`lg t-${s.tone}`} key={i} title={TONE_NAME[s.tone]}>
                {s.label} <i>{s.bytes.length} o</i>
                {s.note && <i>· {s.note}</i>}
              </span>
            ))}
          </div>
          {encoding === 'b64' ? (
            <div className="bytes b64">
              {view.segs.map((s, i) => (
                <span key={i} className={`sg t-${s.tone}`}>{toB64(s.bytes)}</span>
              ))}
            </div>
          ) : (
            <div className="bytes">
              {view.block ? (
                <Blocks segs={view.segs} block={view.block} repeats={view.repeats} />
              ) : (
                view.segs.map((s, i) => <SegBytes key={i} s={s} full={!!full[i]} onToggle={() => setFull({ ...full, [i]: !full[i] })} />)
              )}
            </div>
          )}
        </>
      )}
      {view.text && <pre className="txt">{view.text}</pre>}
    </div>
  );
}

export function EncodingToggle({ value, onChange }: { value: Encoding; onChange: (e: Encoding) => void }) {
  return (
    <span className="enc-toggle">
      <button className={value === 'hex' ? 'on' : ''} onClick={() => onChange('hex')}>hex</button>
      <button className={value === 'b64' ? 'on' : ''} onClick={() => onChange('b64')}>base64</button>
    </span>
  );
}
