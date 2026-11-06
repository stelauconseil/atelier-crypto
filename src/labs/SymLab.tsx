import { Fad, IC } from '../lib/icons';
import { useMemo, useState } from 'react';
import { concat, fromHex, fromUtf8, quote, rand, toHex, utf8 } from '../lib/bytes';
import { SYM } from '../crypto/sym';
import { seg, type Seg, type View } from '../crypto/types';
import { ByteView, EncodingToggle, type Encoding } from '../components/ByteView';
import { Card, Pipeline, Status } from '../components/ui';
import { errText, tamper } from './common';

type St = { kind: 'ok' | 'ko' | 'info'; text: string } | null;

export function SymLab({ id, defaultText }: { id: string; defaultText?: string }) {
  const A = SYM[id];
  const [keyLen, setKeyLen] = useState(A.keyLens.includes(16) ? 16 : A.keyLens[0]);
  const [keyHex, setKeyHex] = useState(() => toHex(rand(keyLen)));
  const [nonceHex, setNonceHex] = useState(() => (A.nonceLen ? toHex(rand(A.nonceLen)) : ''));
  const [aad, setAad] = useState('en-tête : version=1, destinataire=bob');
  const [pt, setPt] = useState(A.hexPlaintext ? toHex(rand(32)) : (defaultText ?? 'Rendez-vous à 14 h, salle 42. Apportez la clé.'));
  const [wire, setWire] = useState<Seg[] | null>(null);
  const [inside, setInside] = useState<View[]>([]);
  const [outInside, setOutInside] = useState<View[]>([]);
  const [result, setResult] = useState<string | null>(null);
  const [st, setSt] = useState<St>(null);
  const [st2, setSt2] = useState<St>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const [runE, setRunE] = useState(0);
  const [runD, setRunD] = useState(0);
  const [used, setUsed] = useState<Map<string, string>>(new Map());

  const keyBytes = useMemo(() => { try { return fromHex(keyHex); } catch { return null; } }, [keyHex]);

  const newKey = (len = keyLen) => { setKeyHex(toHex(rand(len))); setWire(null); setResult(null); setSt(null); setSt2(null); setUsed(new Map()); };
  const newNonce = () => setNonceHex(toHex(rand(A.nonceLen)));

  async function encrypt() {
    setSt2(null); setResult(null); setOutInside([]);
    try {
      if (!keyBytes) fromHex(keyHex); // relance l'erreur de saisie précise
      if (!keyBytes || !A.keyLens.includes(keyBytes.length)) throw new Error(`clé de ${A.keyLens.map((n) => n * 8).join(', ')} bits attendue`);
      const nonce = A.nonceLen ? fromHex(nonceHex) : new Uint8Array(0);
      if (A.nonceLen && nonce.length !== A.nonceLen) throw new Error(`${A.nonceName} : ${A.nonceLen} octets attendus`);
      const p = A.hexPlaintext ? fromHex(pt) : utf8(pt);
      const r = await A.encrypt(keyBytes, nonce, p, utf8(aad));
      setWire(r.wire); setInside(r.inside); setRunE((x) => x + 1);
      const k = keyHex + '|' + nonceHex;
      const prev = used.get(k);
      if (A.nonceLen && prev !== undefined && prev !== pt) {
        setSt({ kind: 'ko', text: id === 'gcmsiv' ? 'Nonce réutilisé avec un autre message : GCM-SIV le tolère, seule l\'égalité de messages identiques fuirait.' : `${A.nonceName} réutilisé avec un autre message sous la même clé : C₁ ⊕ C₂ = P₁ ⊕ P₂ ${A.aead ? 'et le MAC devient falsifiable' : ''}. Changez de nonce !` });
      } else if (A.nonceLen && prev === pt) {
        setSt({ kind: 'info', text: 'Même clé, même nonce, même message : même chiffré. Rien de nouveau ne fuit, mais l\'observateur sait que le message est identique.' });
      } else setSt({ kind: 'ok', text: `Chiffré : ${concat(...r.wire.map((s) => s.bytes)).length} octets transmis pour ${p.length} octets de clair.` });
      setUsed(new Map(used).set(k, pt));
    } catch (e) {
      setSt({ kind: 'ko', text: errText(e) }); setWire(null);
    }
  }

  async function decrypt() {
    if (!wire || !keyBytes) return;
    setRunD((x) => x + 1);
    try {
      const r = await A.decrypt(keyBytes, concat(...wire.map((s) => s.bytes)), utf8(aad));
      const txt = A.hexPlaintext ? toHex(r.pt) : fromUtf8(r.pt);
      setResult(txt); setOutInside(r.inside);
      const changed = txt !== pt;
      setSt2(changed ? { kind: 'ko', text: 'Déchiffrement accepté… mais le clair a changé sans que rien ne le signale : aucune intégrité.' } : { kind: 'ok', text: A.aead ? 'Tag vérifié : clair authentique.' : 'Déchiffré.' });
    } catch (e) {
      setResult(null); setOutInside([]); setSt2({ kind: 'ko', text: errText(e) });
    }
  }

  function alter() {
    if (!wire) return;
    const t = tamper(wire);
    setWire(t.segs); setSt2({ kind: 'info', text: `Un bit inversé : ${t.where}. Déchiffrez pour voir la réaction du mode.` });
  }

  return (
    <>
      <Card n={2} title="Émetteur : clé, paramètres et clair" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <Pipeline label="Chiffrer" steps={A.pipelineEnc} run={runE} />
        <div className="row">
          {A.keyLens.length > 1 && (
            <label className="f fit">
              <span className="lab"><span>Taille (bits)</span></span>
              <span className="segctl">
                {A.keyLens.map((n) => (
                  <button key={n} className={n === keyLen ? 'on' : ''} onClick={() => { setKeyLen(n); newKey(n); }}>{n * 8}</button>
                ))}
              </span>
            </label>
          )}
          <label className="f" style={{ flex: 2 }}>
            <span className="lab"><span>{A.hexPlaintext ? 'KEK' : 'Clé K'} ({(keyBytes?.length ?? 0) * 8} bits, hex, secrète)</span></span>
            <input className="t mono" value={keyHex} onChange={(e) => setKeyHex(e.target.value)} />
          </label>
          <button className="btn b-ghost" onClick={() => newKey()}><Fad icon={IC.key} />Nouvelle clé</button>
        </div>
        {A.nonceLen > 0 && (
          <div className="row" style={{ marginTop: 8 }}>
            <label className="f" style={{ flex: 2 }}>
              <span className="lab"><span>{A.nonceName} · {A.nonceLen} octets, hex, public</span></span>
              <input className="t mono" value={nonceHex} onChange={(e) => setNonceHex(e.target.value)} />
            </label>
            <button className="btn b-ghost" onClick={newNonce}><Fad icon={IC.dice} />Nouveau nonce</button>
          </div>
        )}
        {A.aead && (
          <label className="f" style={{ marginTop: 8 }}>
            <span className="lab"><span>Données associées (AAD) : authentifiées, non chiffrées</span></span>
            <input className="t" value={aad} onChange={(e) => setAad(e.target.value)} />
          </label>
        )}
        <label className="f" style={{ marginTop: 8 }}>
          <span className="lab"><span>{A.hexPlaintext ? 'Clé à envelopper (hex, 16 à 32 octets)' : 'Clair (UTF-8)'}</span><span>{A.hexPlaintext ? '' : `${utf8(pt).length} octets`}</span></span>
          <textarea className={`t ${A.hexPlaintext ? 'mono' : ''}`} value={pt} onChange={(e) => setPt(e.target.value)} />
        </label>
        <div className="actions">
          <button className="btn b-pri" onClick={encrypt}><Fad icon={IC.lock} />Chiffrer</button>
          {A.hexPlaintext && <button className="btn b-ghost" onClick={() => setPt(toHex(rand(32)))}><Fad icon={IC.dice} />Nouvelle clé à envelopper</button>}
        </div>
        <Status s={st} />
        {keyBytes && <ByteView view={{ title: 'La clé, telle qu\'elle est en mémoire', segs: [seg(A.hexPlaintext ? 'KEK' : 'K', keyBytes, 'key')] }} encoding={enc} />}
        {inside.map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}
      </Card>

      {wire && (
        <Card n={3} title="Message transmis : un seul envoi" right={<button className="btn b-red b-sm" onClick={alter}><Fad icon={IC.bolt} />Altérer un bit</button>}>
          <ByteView view={{ title: 'Ce qui circule sur le réseau', caption: A.aead ? 'Les AAD voyagent à part, en clair ; elles sont couvertes par le tag.' : 'Sans tag : rien ne permet de détecter une modification.', segs: wire }} encoding={enc} />
        </Card>
      )}

      {wire && (
        <Card n={4} title="Destinataire : même clé K">
          <Pipeline label="Déchiffrer" steps={A.pipelineDec} run={runD} />
          <div className="actions"><button className="btn b-teal" onClick={decrypt}><Fad icon={IC.unlock} />Déchiffrer</button></div>
          <Status s={st2} />
          {result !== null && <ByteView view={{ title: 'Clair obtenu', segs: [seg('Clair', A.hexPlaintext ? fromHex(result) : utf8(result), 'pt')], caption: A.hexPlaintext ? undefined : quote(result) }} encoding={enc} />}
          {outInside.map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}
        </Card>
      )}
    </>
  );
}
