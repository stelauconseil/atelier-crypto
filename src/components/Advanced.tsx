import { Fragment, type ReactNode } from 'react';
import { ADVANCED } from '../data/advanced';
import { Num } from '../lib/icons';

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
    </div>
  );
}
