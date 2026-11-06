import { useEffect, useState } from 'react';
import { CODE, extract, type Snippet } from '../lib/source';
import { Fad, IC } from '../lib/icons';

type Highlighter = { codeToHtml: (code: string, o: object) => string };
let hl: Promise<Highlighter> | null = null;

/** Shiki chargé à la demande, avec le seul langage TypeScript et deux thèmes (clair, sombre). */
function getHighlighter() {
  hl ??= (async () => {
    const [{ createHighlighterCore }, { createJavaScriptRegexEngine }, ts, light, dark] = await Promise.all([
      import('shiki/core'),
      import('shiki/engine/javascript'),
      import('@shikijs/langs/typescript'),
      import('@shikijs/themes/github-light'),
      import('@shikijs/themes/github-dark'),
    ]);
    return (await createHighlighterCore({
      langs: [ts.default],
      themes: [light.default, dark.default],
      engine: createJavaScriptRegexEngine(),
    })) as unknown as Highlighter;
  })();
  return hl;
}

function Block({ s }: { s: Snippet }) {
  const [html, setHtml] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    let live = true;
    getHighlighter()
      .then((h) => live && setHtml(h.codeToHtml(s.code, { lang: 'typescript', themes: { light: 'github-light', dark: 'github-dark' } })))
      .catch(() => live && setHtml(null));
    return () => { live = false; };
  }, [s.code]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(s.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* presse-papiers indisponible */ }
  };
  return (
    <div className="code-block">
      <div className="cb-h">
        <span><Fad icon={IC.file} /> {s.file} · ligne {s.line} · <b>{s.name}</b></span>
        <button className="btn b-ghost b-sm" onClick={copy}><Fad icon={IC.layers} />{copied ? 'Copié' : 'Copier'}</button>
      </div>
      {html ? <div dangerouslySetInnerHTML={{ __html: html }} /> : <pre>{s.code}</pre>}
    </div>
  );
}

export function CodeView({ id }: { id: string }) {
  const list = (CODE[id] ?? []).map(([f, n]) => extract(f, n)).filter((x): x is Snippet => !!x);
  return (
    <div className="card">
      <h2><Fad icon={IC.code} className="h2-ico" />Le code exécuté par cette page</h2>
      <p style={{ margin: '0 0 6px' }}>
        Ces extraits sont lus directement dans les fichiers sources de l'atelier au moment du build : ce que vous voyez est exactement ce qui a produit les octets
        de l'onglet Atelier. Les primitives viennent de WebCrypto (<code>crypto.subtle</code>) ou des bibliothèques <code>@noble</code> ; les encodages et les
        dérivations sont écrits ici, en clair.
      </p>
      {list.map((s) => <Block key={s.file + s.name} s={s} />)}
    </div>
  );
}
