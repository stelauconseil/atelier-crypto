import { Fad, IC } from '../lib/icons';
import { useEffect, useState } from 'react';
import { concat, i2osp, os2ip, quote, toHex, utf8 } from '../lib/bytes';
import { SIG, ecdsaWithK, recoverFromReusedK } from '../crypto/sig';
import { seg, type Seg, type View } from '../crypto/types';
import { p256 } from '@noble/curves/nist.js';
import { ByteView, EncodingToggle, type Encoding } from '../components/ByteView';
import { Card, FormatTabs, Pipeline, Status, useBusy } from '../components/ui';
import { errText, tamper } from './common';

type St = { kind: 'ok' | 'ko' | 'info'; text: string } | null;

export function SigLab({ id }: { id: string }) {
  const A = SIG[id];
  const [variant, setVariant] = useState(A.variants?.[0].id);
  const [keys, setKeys] = useState<any>(null);
  const [pub, setPub] = useState<View[]>([]);
  const [priv, setPriv] = useState<View[]>([]);
  const [msg, setMsg] = useState('Je soussigné, Benoit, autorise le virement de 100 € à Alice.');
  const [sig, setSig] = useState<Seg[] | null>(null);
  const [prev, setPrev] = useState<string | null>(null);
  const [inside, setInside] = useState<View[]>([]);
  const [vInside, setVInside] = useState<View[]>([]);
  const [st, setSt] = useState<St>(null);
  const [st2, setSt2] = useState<St>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const [runS, setRunS] = useState(0);
  const [runV, setRunV] = useState(0);
  const { busy, wrap } = useBusy();

  const keygen = wrap('keygen', async () => {
    const t = performance.now();
    const r = await A.keygen(variant);
    setKeys(r.keys); setPub(r.pub); setPriv(r.priv); setSig(null); setSt2(null); setPrev(null);
    setSt({ kind: 'info', text: `Biclé générée en ${(performance.now() - t).toFixed(0)} ms.` });
  });
  useEffect(() => { void keygen(); }, [id, variant]); // eslint-disable-line react-hooks/exhaustive-deps

  const sign = wrap('sign', async () => {
    setSt2(null); setVInside([]);
    try {
      const r = await A.sign(keys, utf8(msg));
      const hex = toHex(concat(...r.sig.map((s) => s.bytes)));
      setSig(r.sig); setInside(r.inside); setRunS((x) => x + 1);
      const same = prev !== null && prev.split('|')[0] === msg;
      setSt(same
        ? prev!.split('|')[1] === hex ? { kind: 'info', text: 'Même message, même signature : schéma déterministe.' } : { kind: 'info', text: 'Même message, signature différente : schéma probabiliste (aléa dans la signature).' }
        : { kind: 'ok', text: `Signature de ${hex.length / 2} octets. Signez à nouveau le même message pour tester le déterminisme.` });
      setPrev(msg + '|' + hex);
    } catch (e) {
      setSt({ kind: 'ko', text: errText(e) });
    }
  });

  const verify = wrap('verify', async () => {
    if (!sig) return;
    setRunV((x) => x + 1);
    try {
      const r = await A.verify(keys, utf8(msg), concat(...sig.map((s) => s.bytes)));
      setVInside(r.inside);
      setSt2(r.ok ? { kind: 'ok', text: 'Signature valide : le message est intègre et vient du détenteur de la clé privée.' } : { kind: 'ko', text: 'Signature invalide : message modifié, signature altérée ou mauvaise clé publique.' });
    } catch (e) {
      setSt2({ kind: 'ko', text: errText(e) });
    }
  });

  return (
    <>
      <Card n={2} title="Signataire : sa biclé" right={<span className="ctrls">
        {A.variants && <select className="t" value={variant} onChange={(e) => setVariant(e.target.value)}>{A.variants.map((v) => <option key={v.id} value={v.id}>{v.label}</option>)}</select>}
        <EncodingToggle value={enc} onChange={setEnc} />
        <button className="btn b-ghost b-sm" disabled={!!busy} onClick={keygen}><Fad icon={IC.keypair} />{busy === 'keygen' ? 'Génération…' : 'Nouvelle biclé'}</button></span>}>
        <div className="grid2">
          <div><div className="who" style={{ color: 'var(--c-secret)' }}><Fad icon={IC.private} />Clé privée : signe</div><FormatTabs views={priv} encoding={enc} /></div>
          <div><div className="who" style={{ color: 'var(--c-pub)' }}><Fad icon={IC.public} />Clé publique : vérifie</div><FormatTabs views={pub} encoding={enc} /></div>
        </div>
      </Card>

      <Card n={3} title="Signer avec la clé privée">
        <Pipeline label="Signer" steps={A.pipelineSign} run={runS} />
        <label className="f">
          <span className="lab"><span>Message (modifiable après signature, pour tester la vérification)</span><span>{utf8(msg).length} octets</span></span>
          <textarea className="t" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </label>
        <div className="actions">
          <button className="btn b-pri" disabled={!keys || !!busy} onClick={sign}><Fad icon={IC.sign} />{busy === 'sign' ? 'Signature…' : 'Signer'}</button>
        </div>
        <Status s={st} />
        {inside.map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}
      </Card>

      {sig && (
        <Card n={4} title="Transmis : le message et sa signature" right={<button className="btn b-red b-sm" onClick={() => { const t = tamper(sig, ['sig', 'hash', 'salt']); setSig(t.segs); setSt2({ kind: 'info', text: `Un bit inversé dans la signature : ${t.where}.` }); }}><Fad icon={IC.bolt} />Altérer la signature</button>}>
          <ByteView view={{ title: 'Message', caption: quote(msg), segs: [seg('M', utf8(msg), 'pt')] }} encoding={enc} />
          <ByteView view={{ title: 'Signature σ', segs: sig }} encoding={enc} />
        </Card>
      )}

      {sig && (
        <Card n={5} title="Vérifier avec la clé publique">
          <Pipeline label="Vérifier" steps={A.pipelineVerify} run={runV} />
          <div className="actions"><button className="btn b-teal" disabled={!!busy} onClick={verify}><Fad icon={IC.verify} />Vérifier</button></div>
          <Status s={st2} />
          {vInside.map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}
        </Card>
      )}

      {id === 'ecdsa' && <NonceReuse />}
    </>
  );
}

function NonceReuse() {
  const [m1, setM1] = useState('Virement de 10 € à Alice');
  const [m2, setM2] = useState('Virement de 20 € à Bob');
  const [out, setOut] = useState<null | { d: bigint; k: bigint; a: any; b: any; rec: { d: bigint; k: bigint } }>(null);
  const run = () => {
    const d = os2ip(p256.utils.randomSecretKey());
    const k = os2ip(p256.utils.randomSecretKey());
    const a = ecdsaWithK(d, k, utf8(m1));
    const b = ecdsaWithK(d, k, utf8(m2));
    setOut({ d, k, a, b, rec: recoverFromReusedK(a, b) });
  };
  const B = (x: bigint) => i2osp(x, 32);
  return (
    <Card n={6} title="Attaque « PS3 » : deux signatures avec le même nonce k">
      <p style={{ margin: '0 0 8px' }}>
        Ici l'ECDSA est calculé à la main avec un <b>k fixé</b>, comme dans le firmware de la PlayStation 3 (2010). Les deux signatures partagent le même r.
        Avec s₁ = k⁻¹(h₁ + d·r) et s₂ = k⁻¹(h₂ + d·r), l'attaquant calcule <code>k = (h₁ − h₂) / (s₁ − s₂)</code> puis <code>d = (s₁·k − h₁) / r</code>, sans connaître la clé.
      </p>
      <div className="row">
        <label className="f"><span className="lab">Message 1</span><input className="t" value={m1} onChange={(e) => setM1(e.target.value)} /></label>
        <label className="f"><span className="lab">Message 2</span><input className="t" value={m2} onChange={(e) => setM2(e.target.value)} /></label>
        <button className="btn b-org" onClick={run}><Fad icon={IC.attack} />Signer deux fois avec le même k, puis attaquer</button>
      </div>
      {out && (
        <>
          <ByteView view={{ title: 'Ce que l\'attaquant observe', caption: 'r₁ = r₂ trahit immédiatement la réutilisation de k.', segs: [seg('r₁', B(out.a.r), 'sig'), seg('s₁', B(out.a.s), 'sig'), seg('r₂', B(out.b.r), 'sig'), seg('s₂', B(out.b.s), 'sig')] }} />
          <ByteView view={{ title: 'Ce qu\'il en déduit', segs: [seg('k retrouvé', B(out.rec.k), 'secret'), seg('d retrouvé', B(out.rec.d), 'priv')] }} />
          <Status s={out.rec.d === out.d ? { kind: 'ko', text: 'La clé privée retrouvée est exactement la vraie clé d : toutes les signatures futures peuvent être forgées.' } : { kind: 'info', text: 'Échec inattendu.' }} />
        </>
      )}
    </Card>
  );
}
