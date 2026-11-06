import { useEffect, useState } from 'react';
import { joseSign, type Jws } from '../crypto/jose';
import type { SigAlgo } from '../crypto/sig';
import { fromUtf8, toB64, toHex, utf8 } from '../lib/bytes';
import { Fad, IC } from '../lib/icons';
import { Status } from './ui';

type Tab = 'raw' | 'compact' | 'flat' | 'general';

const MAXC = 600;
const cut = (s: string, open: boolean) => (open || s.length <= MAXC ? s : `${s.slice(0, 400)} … ${s.slice(-120)}`);

/** La même signature exprimée dans les formats JSON de JOSE (JWS, RFC 7515). */
export function JoseView({ A, keys, msg, raw, run }: { A: SigAlgo; keys: unknown; msg: string; raw: Uint8Array; run: number }) {
  const [tab, setTab] = useState<Tab>('compact');
  const [jws, setJws] = useState<Jws | null>(null);
  const rawSig = raw;
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!run || !keys) return;
    let live = true;
    setBusy(true);
    (async () => {
      const j = await joseSign(A, keys, utf8(msg));
      if (!live) return;
      setJws(j);
      setBusy(false);
    })();
    return () => { live = false; };
  }, [run]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!A.jose || !run) return null;
  const text = !jws ? '' : tab === 'compact' ? jws.compact : tab === 'flat' ? JSON.stringify(jws.flattened, null, 2) : tab === 'general' ? JSON.stringify(jws.general, null, 2) : '';
  const copy = async () => {
    try { await navigator.clipboard.writeText(tab === 'raw' && rawSig ? toHex(rawSig) : text); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* indisponible */ }
  };

  return (
    <div className="jose">
      <div className="bv-h" style={{ marginTop: 16 }}><h3>La même signature en JSON : JWS (JOSE, RFC 7515)</h3></div>
      <div className="split" style={{ marginTop: 4 }}>
        <div className="tabs" style={{ marginBottom: 0, borderBottom: 'none' }}>
          <button className={tab === 'raw' ? 'on' : ''} onClick={() => setTab('raw')}><Fad icon={IC.layers} /> Octets</button>
          <button className={tab === 'compact' ? 'on' : ''} onClick={() => setTab('compact')}><Fad icon={IC.code} /> JWS compact</button>
          <button className={tab === 'flat' ? 'on' : ''} onClick={() => setTab('flat')}><Fad icon={IC.file} /> JWS JSON aplati</button>
          <button className={tab === 'general' ? 'on' : ''} onClick={() => setTab('general')}><Fad icon={IC.file} /> JWS JSON général</button>
        </div>
        <span className="ctrls">
          {text.length > MAXC && tab !== 'raw' && <button className="btn b-ghost b-sm" onClick={() => setOpen(!open)}><Fad icon={open ? IC.less : IC.more} />{open ? 'Replier' : 'Tout afficher'}</button>}
          <button className="btn b-ghost b-sm" onClick={copy}><Fad icon={IC.layers} />{copied ? 'Copié' : 'Copier'}</button>
        </span>
      </div>
      {busy && <div className="meta">Signature JWS en cours…</div>}
      {jws && (
        <>
          {tab === 'raw' && rawSig && (
            <>
              <pre className="txt">{`hex    : ${cut(toHex(rawSig), open)}\nbase64 : ${cut(toB64(rawSig), open)}`}</pre>
              <div className="meta">La signature telle que l'API la produit, sur le message brut ({utf8(msg).length} octets).</div>
            </>
          )}
          {tab === 'compact' && (
            <>
              <div className="bytes jws">
                <span className="sg t-hdr">{jws.h}</span>.<span className="sg t-pt">{cut(jws.p, open)}</span>.<span className="sg t-sig">{cut(jws.s, open)}</span>
              </div>
              <div className="legend">
                <span className="lg t-hdr">en-tête protégé <i>base64url</i></span>
                <span className="lg t-pt">charge utile <i>base64url</i></span>
                <span className="lg t-sig">signature <i>base64url, {jws.sig.length} o</i></span>
              </div>
            </>
          )}
          {(tab === 'flat' || tab === 'general') && <pre className="txt">{cut(text, open)}</pre>}
          {tab !== 'raw' && (
            <div className="grid2" style={{ marginTop: 8 }}>
              <div><div className="who">En-tête décodé</div><pre className="txt">{JSON.stringify(jws.header, null, 2)}</pre></div>
              <div><div className="who">Ce qui est réellement signé</div><pre className="txt">{cut(jws.signingInput, open)}</pre></div>
            </div>
          )}
          <div className="meta"><b>alg = {jws.header.alg}</b> — {jws.note}. La signature JWS porte sur l'entrée ASCII <code>base64url(en-tête) "." base64url(charge utile)</code>, pas sur le message brut : elle diffère donc de la signature ci-dessus.</div>
          <Status s={jws.ok ? { kind: 'ok', text: `JWS vérifié avec la clé publique (charge utile : ${fromUtf8(utf8(msg)).length} caractères).` } : { kind: 'ko', text: 'JWS invalide.' }} />
        </>
      )}
    </div>
  );
}
