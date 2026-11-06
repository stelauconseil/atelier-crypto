import { useEffect, useState } from 'react';
import { concat, fromUtf8, toHex, utf8 } from '../lib/bytes';
import { PKE } from '../crypto/pke';
import type { Seg, View } from '../crypto/types';
import { seg } from '../crypto/types';
import { ByteView, EncodingToggle, type Encoding } from '../components/ByteView';
import { Card, FormatTabs, Pipeline, Status, useBusy } from '../components/ui';
import { errText, tamper } from './common';

type St = { kind: 'ok' | 'ko' | 'info'; text: string } | null;

export function PkeLab({ id }: { id: string }) {
  const A = PKE[id];
  const [keys, setKeys] = useState<any>(null);
  const [pub, setPub] = useState<View[]>([]);
  const [priv, setPriv] = useState<View[]>([]);
  const [pt, setPt] = useState('Clé de session : 7f3a…, à utiliser avant vendredi.');
  const [wire, setWire] = useState<Seg[] | null>(null);
  const [prevWire, setPrevWire] = useState<string | null>(null);
  const [inside, setInside] = useState<View[]>([]);
  const [outInside, setOutInside] = useState<View[]>([]);
  const [result, setResult] = useState<string | null>(null);
  const [st, setSt] = useState<St>(null);
  const [st2, setSt2] = useState<St>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const [runE, setRunE] = useState(0);
  const [runD, setRunD] = useState(0);
  const { busy, wrap } = useBusy();

  const keygen = wrap('keygen', async () => {
    const t = performance.now();
    const r = await A.keygen();
    setKeys(r.keys); setPub(r.pub); setPriv(r.priv);
    setWire(null); setResult(null); setSt2(null); setPrevWire(null);
    setSt({ kind: 'info', text: `Biclé générée en ${(performance.now() - t).toFixed(0)} ms.` });
  });

  useEffect(() => { void keygen(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  const encrypt = wrap('enc', async () => {
    setSt2(null); setResult(null); setOutInside([]);
    try {
      const r = await A.encrypt(keys, utf8(pt));
      const hex = toHex(concat(...r.wire.map((s) => s.bytes)));
      setWire(r.wire); setInside(r.inside); setRunE((x) => x + 1);
      const same = prevWire !== null && prevWire.split('|')[0] === pt;
      setSt(same
        ? prevWire!.split('|')[1] === hex
          ? { kind: 'ko', text: 'Même message, même chiffré : schéma déterministe. Un observateur peut tester des clairs candidats.' }
          : { kind: 'ok', text: 'Même message, chiffré différent : le schéma est probabiliste.' }
        : { kind: 'ok', text: `Chiffré : ${hex.length / 2} octets transmis pour ${utf8(pt).length} octets de clair. Rechiffrez le même message pour comparer.` });
      setPrevWire(pt + '|' + hex);
    } catch (e) {
      setSt({ kind: 'ko', text: errText(e) }); setWire(null);
    }
  });

  const decrypt = wrap('dec', async () => {
    if (!wire) return;
    setRunD((x) => x + 1);
    try {
      const r = await A.decrypt(keys, concat(...wire.map((s) => s.bytes)));
      const txt = fromUtf8(r.pt);
      setResult(txt); setOutInside(r.inside);
      setSt2(txt === pt ? { kind: 'ok', text: 'Déchiffré avec la clé privée.' } : { kind: 'ko', text: 'Accepté, mais le clair a changé : malléabilité, aucune intégrité.' });
    } catch (e) {
      setResult(null); setOutInside([]); setSt2({ kind: 'ko', text: errText(e) });
    }
  });

  const max = keys && A.maxPt ? A.maxPt(keys) : undefined;

  return (
    <>
      <Card n={2} title="Destinataire : sa biclé" right={<span className="row"><EncodingToggle value={enc} onChange={setEnc} /><button className="btn b-ghost b-sm" disabled={!!busy} onClick={keygen}>{busy === 'keygen' ? 'Génération…' : 'Nouvelle biclé'}</button></span>}>
        <div className="grid2">
          <div><div className="who" style={{ color: 'var(--green)' }}>Clé publique, diffusée</div><FormatTabs views={pub} encoding={enc} /></div>
          <div><div className="who" style={{ color: 'var(--red)' }}>Clé privée, gardée secrète</div><FormatTabs views={priv} encoding={enc} /></div>
        </div>
      </Card>

      <Card n={3} title="Émetteur : chiffrer avec la clé publique">
        <Pipeline label="Chiffrer" steps={A.pipelineEnc} run={runE} />
        <label className="f">
          <span className="lab"><span>Clair (UTF-8)</span><span>{utf8(pt).length} octets{max !== undefined ? ` · ${max} au plus` : ''}</span></span>
          <textarea className="t" value={pt} onChange={(e) => setPt(e.target.value)} />
        </label>
        <div className="actions"><button className="btn b-pri" disabled={!keys || !!busy} onClick={encrypt}>🔒 Chiffrer pour le destinataire</button></div>
        <Status s={st} />
        {inside.map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}
      </Card>

      {wire && (
        <Card n={4} title="Message transmis : un seul envoi" right={<button className="btn b-red b-sm" onClick={() => { const t = tamper(wire); setWire(t.segs); setSt2({ kind: 'info', text: `Un bit inversé : ${t.where}.` }); }}>⚡ Altérer un bit</button>}>
          <ByteView view={{ title: 'Ce qui circule', caption: 'La clé de session n\'est jamais transmise : seul ce qui permet au destinataire de la recalculer circule.', segs: wire }} encoding={enc} />
        </Card>
      )}

      {wire && (
        <Card n={5} title="Destinataire : déchiffrer avec la clé privée">
          <Pipeline label="Déchiffrer" steps={A.pipelineDec} run={runD} />
          <div className="actions"><button className="btn b-teal" disabled={!!busy} onClick={decrypt}>🔓 Déchiffrer</button></div>
          <Status s={st2} />
          {result !== null && <ByteView view={{ title: 'Clair obtenu', caption: `« ${result} »`, segs: [seg('Clair', utf8(result), 'pt')] }} encoding={enc} />}
          {outInside.map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}
        </Card>
      )}
    </>
  );
}
