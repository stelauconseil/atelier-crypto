import { Fad, IC } from '../lib/icons';
import { PLANCHES, planchesUrl } from '../data/planches';

/** Les planches A4 du cours, à ouvrir ou à télécharger. */
export function PlanchesPage() {
  return (
    <div className="page">
      <div className="head"><div><div className="fam">Compléments</div><h1><Fad icon={IC.books} className="h-ico" />Les planches du cours</h1></div></div>
      <p className="lead">Fiches A4 de synthèse, à imprimer en recto verso. Elles reprennent les ateliers, avec les frises, les comparatifs et les notions qui ne se manipulent pas.</p>
      {PLANCHES.map((p) => (
        <div className="card planche" key={p.id}>
          <div className="split">
            <div>
              <h2 className="pl-title"><Fad icon={IC.pdf} />{p.title}</h2>
              <div className="meta">{p.sub} · {p.version} · {p.pages.length} pages A4 · {p.size}</div>
            </div>
            <span className="ctrls">
              <a className="btn b-ghost" href={planchesUrl(p.file)} target="_blank" rel="noopener"><Fad icon={IC.eye} />Ouvrir</a>
              <a className="btn b-pri" href={planchesUrl(p.file)} download><Fad icon={IC.download} />Télécharger</a>
            </span>
          </div>
          <div className="pl-pages">
            {p.pages.map((g) => (
              <a key={g.n} className="pl-page" href={`${planchesUrl(p.file)}#page=${g.n}`} target="_blank" rel="noopener" title={`Ouvrir à la page ${g.n}`}>
                <img src={planchesUrl(g.thumb)} alt={`${g.label} : ${g.title}`} loading="lazy" />
                <span className="pl-lab">{g.label}</span>
                <b>{g.title}</b>
                <span className="meta">{g.sections}</span>
              </a>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
