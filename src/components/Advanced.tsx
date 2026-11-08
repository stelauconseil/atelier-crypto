import { Fragment, type ReactNode } from 'react';
import { ADVANCED } from '../data/advanced';
import { Fad, IC, Num } from '../lib/icons';
import { PLANCHES, PLANCHE_FOR, planchesUrl } from '../data/planches';

/** Mise en forme minimale : `code`, **gras**. */
function inline(t: string): ReactNode[] {
  return t.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((p, i) =>
    p.startsWith('`') ? <code key={i}>{p.slice(1, -1)}</code> : p.startsWith('**') ? <b key={i}>{p.slice(2, -2)}</b> : <Fragment key={i}>{p}</Fragment>,
  );
}

function Body({ t }: { t: string }) {
  return (
    <>
      {t.split(/\n\s*\n/).map((block, i) => {
        const lines = block.split('\n');
        const items = lines.filter((l) => l.startsWith('- '));
        const intro = lines.filter((l) => !l.startsWith('- ')).join(' ');
        return (
          <Fragment key={i}>
            {intro && <p>{inline(intro)}</p>}
            {items.length > 0 && <ul>{items.map((l, j) => <li key={j}>{inline(l.slice(2))}</li>)}</ul>}
          </Fragment>
        );
      })}
    </>
  );
}

export function Advanced({ id }: { id: string }) {
  const secs = ADVANCED[id] ?? [];
  return (
    <div className="card adv">
      {secs.map((s, i) => (
        <section key={i}>
          <h3><Num n={i + 1} />{s.h}</h3>
          <Body t={s.t} />
        </section>
      ))}
      {(PLANCHE_FOR[id]?.length ?? 0) > 0 && (
        <section className="adv-pdf">
          <h3><Fad icon={IC.books} />Dans les planches du cours</h3>
          <div className="pl-links">
            {PLANCHE_FOR[id].map(([pid, n]) => {
              const p = PLANCHES.find((x) => x.id === pid)!;
              const g = p.pages[n - 1];
              return (
                <a key={`${pid}-${n}`} className="pl-link" href={`${planchesUrl(p.file)}#page=${n}`} target="_blank" rel="noopener">
                  <img src={planchesUrl(g.thumb)} alt="" loading="lazy" />
                  <span><b>{g.label} : {g.title}</b><span className="meta">{g.sections}</span><span className="pl-dl"><Fad icon={IC.pdf} />PDF, page {n}</span></span>
                </a>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}
