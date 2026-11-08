import { Link, useParams } from '@tanstack/react-router';
import { useState } from 'react';
import { Advanced } from '../components/Advanced';
import { CodeView } from '../components/CodeView';
import { ALGO_ICON, Fad, IC } from '../lib/icons';
import { ALGOS, FAMILIES, byId } from '../data/algos';
import { Pills, Recall } from '../components/ui';
import { SymLab } from '../labs/SymLab';
import { PkeLab } from '../labs/PkeLab';
import { SigLab } from '../labs/SigLab';
import { KexLab } from '../labs/KexLab';
import { HashLab } from '../labs/HashLab';
import { RngLab } from '../labs/RngLab';
import { hasSaved, resetState, useResetNonce } from '../lib/persist';

export function AlgoPage() {
  const { id } = useParams({ from: '/algo/$id' });
  const nonce = useResetNonce(id);
  return <AlgoView key={`${id}-${nonce}`} id={id} />;
}

function AlgoView({ id }: { id: string }) {
  const [tab, setTab] = useState<'lab' | 'adv' | 'code'>('lab');
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
          <h1><Fad icon={ALGO_ICON[a.id]} className="h-ico" />{a.name}<Pills a={a} /></h1>
        </div>
        <div className="head-r">
          <div className="yr">{a.year}</div>
          <button className="btn b-ghost b-sm" title={hasSaved(id) ? 'Les réglages, textes et clés de cette page sont conservés dans ce navigateur' : 'Les réglages de cette page seront conservés dans ce navigateur'} onClick={() => resetState(id)}>
            <Fad icon={IC.reset} />Réinitialiser la page
          </button>
        </div>
      </div>
      <div className="tabs main-tabs">
        <button className={tab === 'lab' ? 'on' : ''} onClick={() => setTab('lab')}><Fad icon={IC.lab} />Atelier</button>
        <button className={tab === 'adv' ? 'on' : ''} onClick={() => setTab('adv')}><Fad icon={IC.deeper} />Pour aller plus loin</button>
        <button className={tab === 'code' ? 'on' : ''} onClick={() => setTab('code')}><Fad icon={IC.code} />Le code</button>
      </div>
      {/* l'atelier reste monté quand on change d'onglet : ses clés et résultats sont conservés */}
      <div style={{ display: tab === 'lab' ? 'block' : 'none' }}>
        <Recall a={a} />
        <div style={{ height: 14 }} />
        {a.family === 'sym' && <SymLab id={id} defaultText={a.defaultText} />}
        {a.family === 'hash' && <HashLab id={id} />}
        {a.family === 'rng' && <RngLab id={id} />}
        {a.family === 'kex' && <KexLab id={id} />}
        {a.family === 'pke' && <PkeLab id={id} />}
        {a.family === 'sig' && <SigLab id={id} />}
      </div>
      {tab === 'adv' && <Advanced id={id} />}
      {tab === 'code' && <CodeView id={id} />}
      <div className="split" style={{ marginTop: 18 }}>
        {prev ? <Link className="btn b-ghost" to="/algo/$id" params={{ id: prev.id }}><Fad icon={IC.prev} />{prev.name}</Link> : <span />}
        {next ? <Link className="btn b-ghost" to="/algo/$id" params={{ id: next.id }}>{next.name}<Fad icon={IC.next} /></Link> : <span />}
      </div>
    </div>
  );
}
