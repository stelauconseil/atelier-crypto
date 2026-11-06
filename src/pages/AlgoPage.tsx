import { Link, useParams } from '@tanstack/react-router';
import { ALGOS, FAMILIES, byId } from '../data/algos';
import { Pills, Recall } from '../components/ui';
import { SymLab } from '../labs/SymLab';
import { PkeLab } from '../labs/PkeLab';
import { SigLab } from '../labs/SigLab';

export function AlgoPage() {
  const { id } = useParams({ from: '/algo/$id' });
  const a = byId(id);
  if (!a) return <div className="page"><h1>Algorithme inconnu</h1><Link to="/">Retour</Link></div>;
  const fam = FAMILIES.find((f) => f.id === a.family)!;
  const list = ALGOS.filter((x) => x.family === a.family);
  const i = list.findIndex((x) => x.id === id);
  const prev = list[i - 1];
  const next = list[i + 1];
  return (
    <div className="page">
      <div className="head">
        <div>
          <div className="fam">{fam.label}</div>
          <h1>{a.name}<Pills a={a} /></h1>
        </div>
        <div className="yr">{a.year}</div>
      </div>
      <Recall a={a} />
      <div style={{ height: 14 }} />
      {a.family === 'sym' && <SymLab key={id} id={id} defaultText={a.defaultText} />}
      {a.family === 'pke' && <PkeLab key={id} id={id} />}
      {a.family === 'sig' && <SigLab key={id} id={id} />}
      <div className="split" style={{ marginTop: 18 }}>
        {prev ? <Link className="btn b-ghost" to="/algo/$id" params={{ id: prev.id }}>← {prev.name}</Link> : <span />}
        {next ? <Link className="btn b-ghost" to="/algo/$id" params={{ id: next.id }}>{next.name} →</Link> : <span />}
      </div>
    </div>
  );
}
