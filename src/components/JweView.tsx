import { useEffect, useState } from 'react';
import { JWE, type Jwe } from '../crypto/jwe';
import { fromUtf8, utf8 } from '../lib/bytes';
import { Fad, IC } from '../lib/icons';
import { errText } from '../labs/common';
import { Status } from './ui';

type Tab = 'compact' | 'flat' | 'general';

const MAXC = 600;
const cut = (s: string, open: boolean) => (open || s.length <= MAXC ? s : `${s.slice(0, 400)} … ${s.slice(-120)}`);

/** Le même chiffrement exprimé au format JOSE : JWE (RFC 7516), compact et JSON. */
export function JweView({ id, keys, msg, run }: { id: string; keys: unknown; msg: string; run: number }) {
  const J = JWE[id];
  const [tab, setTab] = useState<Tab>('compact');
  const [jwe, setJwe] = useState<Jwe | null>(null);
  const [back, setBack] = useState<{ ok: boolean; text: string } | null>(null);
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!J || !run || !keys) return;
    let live = true;
    (async () => {
      try {
        const j = await J.encrypt(keys, utf8(msg));
        const pt = fromUtf8(await J.decrypt(keys, j.compact));
        if (!live) return;
        setJwe(j);
        setBack({ ok: pt === msg, text: pt === msg ? 'JWE déchiffré avec la clé privée : clair identique.' : 'JWE déchiffré, mais le clair diffère.' });
      } catch (e) {
        if (live) { setJwe(null); setBack({ ok: false, text: errText(e) }); }
      }
    })();
    return () => { live = false; };
  }, [run]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!J || !run) return null;
  const text = !jwe ? '' : tab === 'compact' ? jwe.compact : JSON.stringify(tab === 'flat' ? jwe.flattened : jwe.general, null, 2);
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* indisponible */ }
  };
  const P = (cls: string, v: string) => <span className={`sg ${cls}`}>{v === '' ? '∅' : cut(v, open)}</span>;

  return (
    <div className="jose">
      <div className="bv-h" style={{ marginTop: 16 }}><h3>Le même chiffrement en JOSE : JWE (RFC 7516)</h3></div>
      <div className="split" style={{ marginTop: 4 }}>
        <div className="tabs" style={{ marginBottom: 0, borderBottom: 'none' }}>
          <button className={tab === 'compact' ? 'on' : ''} onClick={() => setTab('compact')}><Fad icon={IC.code} /> JWE compact</button>
          <button className={tab === 'flat' ? 'on' : ''} onClick={() => setTab('flat')}><Fad icon={IC.file} /> JWE JSON aplati</button>
          <button className={tab === 'general' ? 'on' : ''} onClick={() => setTab('general')}><Fad icon={IC.file} /> JWE JSON général</button>
        </div>
        <span className="ctrls">
          {text.length > MAXC && <button className="btn b-ghost b-sm" onClick={() => setOpen(!open)}><Fad icon={open ? IC.less : IC.more} />{open ? 'Replier' : 'Tout afficher'}</button>}
          <button className="btn b-ghost b-sm" onClick={copy}><Fad icon={IC.layers} />{copied ? 'Copié' : 'Copier'}</button>
        </span>
      </div>
      {jwe && (
        <>
          {tab === 'compact' ? (
            <>
              <div className="bytes jws">
                {P('t-hdr', jwe.s.h)}.{P('t-enc', jwe.s.ek)}.{P('t-nonce', jwe.s.iv)}.{P('t-ct', jwe.s.ct)}.{P('t-tag', jwe.s.tag)}
              </div>
              <div className="legend">
                <span className="lg t-hdr">en-tête protégé</span>
                <span className="lg t-enc">{J.alg.startsWith('HPKE') ? 'encapsulation HPKE' : 'clé chiffrée'} <i>{jwe.b.ek.length} o</i></span>
                <span className="lg t-nonce">IV <i>{jwe.b.iv.length} o</i></span>
                <span className="lg t-ct">{jwe.b.tag.length ? 'chiffré' : 'chiffré ‖ tag AEAD'} <i>{jwe.b.ct.length} o</i></span>
                <span className="lg t-tag">tag <i>{jwe.b.tag.length} o</i></span>
              </div>
            </>
          ) : (
            <pre className="txt">{cut(text, open)}</pre>
          )}
          <div className="grid2" style={{ marginTop: 8 }}>
            <div><div className="who">En-tête décodé</div><pre className="txt">{JSON.stringify(jwe.header, null, 2)}</pre></div>
            <div><div className="who">Données associées (AAD) de l'AEAD</div><pre className="txt">{jwe.s.h}</pre></div>
          </div>
          <div className="meta"><b>alg = {J.alg} · enc = {J.enc}</b> — {J.note}. Un « ∅ » signale une partie vide (comme la clé chiffrée de ECDH-ES ou l'IV et le tag de HPKE intégré).</div>
        </>
      )}
      {back && <Status s={{ kind: back.ok ? 'ok' : 'ko', text: back.text }} />}
    </div>
  );
}
