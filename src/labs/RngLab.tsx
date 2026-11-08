import { useEffect, useMemo, useRef, useState } from 'react';
import { Fad, IC } from '../lib/icons';
import { fromHex, i2osp, rand, toHex, utf8, type Bytes } from '../lib/bytes';
import { seg } from '../crypto/types';
import {
  JavaRandom, SOURCES, crackJavaRandom, crackWeakKey, drbgGenerate, drbgInstantiate, drbgReseed, dualEcAttack, dualEcSetup,
  dualEcStep, rfc6979, sourceBytes, stats, verdict, weakKey, type DrbgState, type DualEc, type SourceId,
} from '../crypto/rng';
import { ByteView, EncodingToggle, type Encoding } from '../components/ByteView';
import { Card, Pipeline, Status, useBusy } from '../components/ui';
import { usePersisted, z } from '../lib/persist';

type St = { kind: 'ok' | 'ko' | 'info'; text: string } | null;
const hexOr = (h: string): Bytes | null => { try { return fromHex(h); } catch { return null; } };

export function RngLab({ id }: { id: string }) {
  if (id === 'csprng') return <CsprngLab />;
  if (id === 'javarandom') return <JavaLab />;
  if (id === 'hmacdrbg') return <DrbgLab />;
  if (id === 'dualec') return <DualEcLab />;
  if (id === 'debian') return <DebianLab />;
  return null;
}

// ================================================================ le générateur du système
/** 16 384 octets = 131 072 bits dessinés en 256 × 512 pixels noirs et blancs. */
function Bitmap({ bytes }: { bytes: Bytes }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    const ctx = c?.getContext('2d');
    if (!c || !ctx) return;
    const img = ctx.createImageData(c.width, c.height);
    const n = c.width * c.height;
    for (let i = 0; i < n; i++) {
      const bit = (bytes[i >> 3] >> (7 - (i & 7))) & 1;
      const v = bit ? 20 : 245;
      img.data.set([v, v, v, 255], i * 4);
    }
    ctx.putImageData(img, 0, 0);
  }, [bytes]);
  return <canvas ref={ref} width={512} height={256} className="rg-bitmap" aria-label="les bits en noir et blanc" />;
}

function Histogram({ h }: { h: number[] }) {
  const max = Math.max(...h, 1);
  return (
    <svg viewBox="0 0 512 120" className="rg-hist" preserveAspectRatio="none" aria-label="répartition des 256 valeurs d'octet">
      {h.map((v, i) => <rect key={i} x={i * 2} y={110 - (100 * v) / max} width={1.6} height={(100 * v) / max} />)}
      <line x1={0} x2={512} y1={110} y2={110} />
    </svg>
  );
}

function CsprngLab() {
  const [src, setSrc] = usePersisted<SourceId>('csprng', 'source', 'crypto', z.enum(['crypto', 'math', 'randu', 'counter']));
  const [nonce, setNonce] = useState(0);
  const [enc, setEnc] = useState<Encoding>('hex');
  const bytes = useMemo(() => sourceBytes(src, 16384, 1 + nonce * 7919), [src, nonce]);
  const big = useMemo(() => sourceBytes(src, 65536, 1 + nonce * 7919), [src, nonce]);
  const s = useMemo(() => stats(big), [big]);
  const v = verdict(s);
  const pass = (ok: boolean) => <span className={`pill ${ok ? 'p-ok' : 'p-ko'}`}>{ok ? 'réussi' : 'échoue'}</span>;
  return (
    <>
      <Card n={2} title="Quatre sources d'octets, une même question : est-ce aléatoire ?" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <span className="segctl">
            {(Object.keys(SOURCES) as SourceId[]).map((k) => <button key={k} className={src === k ? 'on' : ''} onClick={() => setSrc(k)}>{SOURCES[k].label}</button>)}
          </span>
          <button className="btn b-ghost" onClick={() => setNonce(nonce + 1)}><Fad icon={IC.dice} />Nouveau tirage</button>
        </div>
        <div className="meta">{SOURCES[src].note}.</div>
        <ByteView view={{ title: 'Les 64 premiers octets', segs: [seg(SOURCES[src].label, bytes.slice(0, 64), 'nonce')] }} encoding={enc} />
        <div className="rg-grid">
          <div><div className="who">131 072 bits en image</div><Bitmap bytes={bytes} /></div>
          <div><div className="who">Répartition des 256 valeurs (65 536 octets)</div><Histogram h={s.histogram} /></div>
        </div>
      </Card>
      <Card n={3} title="Trois tests statistiques (SP 800-22, simplifiés)">
        <div className="kx-scroll">
          <table className="kx-table">
            <thead><tr><th>Test</th><th>Mesure</th><th>Attendu</th><th>Verdict</th></tr></thead>
            <tbody>
              <tr><td><b>Fréquence</b> : autant de 1 que de 0</td><td>{s.ones.toLocaleString('fr-FR')} uns sur {s.bits.toLocaleString('fr-FR')} (z = {s.monobitZ.toFixed(2)})</td><td>|z| &lt; 3</td><td>{pass(v.monobit)}</td></tr>
              <tr><td><b>Séries</b> : nombre de changements 0 ↔ 1</td><td>{s.runs.toLocaleString('fr-FR')}</td><td>≈ {Math.round(s.runsExpected).toLocaleString('fr-FR')}</td><td>{pass(v.runs)}</td></tr>
              <tr><td><b>χ² des octets</b> : 256 valeurs également fréquentes</td><td>χ² = {s.chi2.toFixed(0)}</td><td>≈ 255 (entre 190 et 330)</td><td>{pass(v.chi2)}</td></tr>
            </tbody>
          </table>
        </div>
        <Status s={src === 'math'
          ? { kind: 'ko', text: 'Math.random réussit tout… et reste inutilisable pour une clé : son état interne (128 bits) se reconstruit à partir de quelques sorties, puis il prédit toutes les suivantes.' }
          : src === 'crypto' ? { kind: 'ok', text: 'Le générateur du système réussit les tests, mais surtout il est imprévisible : c\'est la seule propriété qui compte, et aucun test statistique ne la mesure.' }
            : { kind: 'info', text: src === 'counter' ? 'Un compteur est parfaitement équilibré : la fréquence et les séries passent, seul le χ² le trouve « trop parfait ». Les tests détectent des défauts, ils ne prouvent jamais l\'aléa.' : 'RANDU : l\'octet de poids faible ne prend que 64 valeurs et se répète toutes les 64 sorties ; l\'image montre des motifs. Ses triplets tombent en outre sur 15 plans (Marsaglia, 1968).' }} />
      </Card>
    </>
  );
}

// ================================================================ java.util.Random
function JavaLab() {
  const [seed, setSeed] = useState(() => BigInt(Date.now()));
  const [server, setServer] = useState(() => new JavaRandom(seed));
  const [seen, setSeen] = useState<number[]>([]);
  const [pred, setPred] = useState<{ state: bigint; tries: number; ms: number; next: number[] } | null>(null);
  const [revealed, setRevealed] = useState<number[]>([]);
  const reset = () => { const s = BigInt(Date.now()); setSeed(s); setServer(new JavaRandom(s)); setSeen([]); setPred(null); setRevealed([]); };
  const code = (n: number) => (n >>> 0).toString().padStart(10, '0');
  const ask = () => setSeen([...seen, server.nextInt()]);
  const crack = () => {
    const t = performance.now();
    const c = crackJavaRandom(seen[seen.length - 2], seen[seen.length - 1]);
    if (!c) return;
    const clone = JavaRandom.fromState(c.state);
    setPred({ state: c.state, tries: c.tries, ms: performance.now() - t, next: Array.from({ length: 5 }, () => clone.nextInt()) });
  };
  const reveal = () => setRevealed(Array.from({ length: 5 }, () => server.nextInt()));
  return (
    <>
      <Card n={2} title="Le serveur émet des codes de réinitialisation" right={<button className="btn b-ghost b-sm" onClick={reset}><Fad icon={IC.again} />Redémarrer le serveur</button>}>
        <Pipeline label="Serveur" steps={['new Random(System.currentTimeMillis())', 'code = nextInt()', 'envoyé par courriel']} run={seen.length} />
        <div className="meta">Graine : l'heure de démarrage en millisecondes ({seed.toString()}), tenue secrète par le serveur.</div>
        <div className="actions"><button className="btn b-pri" onClick={ask}><Fad icon={IC.send} />Demander un code (pour mon propre compte)</button></div>
        {seen.length > 0 && <div className="rg-codes">{seen.map((v, i) => <code key={i} className="sg t-nonce">{code(v)}</code>)}</div>}
        {seen.length < 2 && <div className="meta">Il en faut deux, consécutifs.</div>}
      </Card>
      {seen.length >= 2 && (
        <Card n={3} title="L'attaquant reconstruit l'état et prédit les codes des autres">
          <Pipeline label="Attaque" steps={['32 bits hauts = 1er code', 'essayer les 2¹⁶ bits bas', 'garder celui qui donne le 2e code', 'faire tourner le générateur']} run={pred ? 1 : 0} />
          <div className="actions"><button className="btn b-red" onClick={crack}><Fad icon={IC.attacker} />Retrouver l'état interne</button></div>
          {pred && (
            <>
              <ByteView view={{ title: `État interne de 48 bits, trouvé en ${pred.tries.toLocaleString('fr-FR')} essais (${pred.ms.toFixed(0)} ms)`, segs: [seg('état', i2osp(pred.state, 6), 'secret')] }} encoding="hex" />
              <div className="who">Prochains codes, prédits</div>
              <div className="rg-codes">{pred.next.map((v, i) => <code key={i} className="sg t-ct">{code(v)}</code>)}</div>
              <div className="actions"><button className="btn b-ghost" onClick={reveal}><Fad icon={IC.eye} />Voir les codes que le serveur envoie ensuite aux autres comptes</button></div>
              {revealed.length > 0 && (
                <>
                  <div className="rg-codes">{revealed.map((v, i) => <code key={i} className={`sg ${v === pred.next[i] ? 't-tag' : 't-nonce'}`}>{code(v)}</code>)}</div>
                  <Status s={revealed.every((v, i) => v === pred.next[i]) ? { kind: 'ko', text: 'Tous prédits : l\'attaquant réinitialise le mot de passe de n\'importe quel compte. Il fallait java.security.SecureRandom.' } : { kind: 'info', text: 'Des codes ont été demandés entre-temps : la prédiction reste juste, décalée.' }} />
                </>
              )}
            </>
          )}
        </Card>
      )}
    </>
  );
}

// ================================================================ HMAC-DRBG
function DrbgLab() {
  const [entropy, setEntropy] = usePersisted('hmacdrbg', 'entropy', () => toHex(rand(32)), z.string());
  const [nonceHex, setNonceHex] = usePersisted('hmacdrbg', 'nonce', () => toHex(rand(16)), z.string());
  const [perso, setPerso] = usePersisted('hmacdrbg', 'perso', 'atelier crypto', z.string());
  const [n, setN] = usePersisted('hmacdrbg', 'n', 48, z.number().int().min(1).max(1024));
  const [addl, setAddl] = useState('');
  const [st, setSt] = useState<DrbgState | null>(null);
  const [outs, setOuts] = useState<{ out: Bytes; counter: number; addl: string; seq: number }[]>([]);
  const [seq, setSeq] = useState(0);
  const [msg, setMsg] = usePersisted('hmacdrbg', 'msg', 'sample', z.string());
  const [priv, setPriv] = usePersisted('hmacdrbg', 'priv', 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721', z.string());
  const [err, setErr] = useState<St>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const inst = () => {
    const e = hexOr(entropy), no = hexOr(nonceHex);
    if (!e || !no) return setErr({ kind: 'ko', text: 'Entropie ou nonce : hexadécimal invalide.' });
    if (e.length < 32) return setErr({ kind: 'ko', text: 'SP 800-90A exige au moins 256 bits d\'entropie pour une sécurité de 256 bits : 32 octets.' });
    setErr(null); setSt(drbgInstantiate(e, no, utf8(perso))); setOuts([]); setSeq(0); setReseeds(0);
  };
  const gen = () => { if (!st) return; const r = drbgGenerate(st, n, addl ? utf8(addl) : undefined); setSt(r.state); setOuts([{ out: r.out, counter: st.counter, addl, seq: seq + 1 }, ...outs].slice(0, 6)); setSeq(seq + 1); };
  const reseed = () => { if (!st) return; setSt(drbgReseed(st, rand(32))); setReseeds(reseeds + 1); };
  const [reseeds, setReseeds] = useState(0);
  const k = useMemo(() => { try { const p = fromHex(priv); return p.length === 32 ? rfc6979(p, utf8(msg)) : null; } catch { return null; } }, [priv, msg]);
  const isVector = msg === 'sample' && priv.toUpperCase() === 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
  return (
    <>
      <Card n={2} title="Instancier, générer, réalimenter" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <Pipeline label="HMAC-DRBG" steps={['Instantiate(entropie, nonce, perso)', 'Generate : V = HMAC(K, V)…', 'Update(K, V)', 'Reseed(entropie)']} run={outs.length} />
        <div className="row">
          <label className="f" style={{ flex: 3 }}><span className="lab"><span>Entropie (hex, ≥ 32 octets, secrète)</span><span>{hexOr(entropy)?.length ?? 0} octets</span></span><input className="t mono" value={entropy} onChange={(e) => setEntropy(e.target.value)} /></label>
          <button className="btn b-ghost" onClick={() => setEntropy(toHex(rand(32)))}><Fad icon={IC.dice} />Tirer</button>
        </div>
        <div className="row">
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Nonce (hex)</span></span><input className="t mono" value={nonceHex} onChange={(e) => setNonceHex(e.target.value)} /></label>
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Chaîne de personnalisation</span></span><input className="t" value={perso} onChange={(e) => setPerso(e.target.value)} /></label>
        </div>
        <div className="actions"><button className="btn b-pri" onClick={inst}><Fad icon={IC.rng} />Instancier</button></div>
        <Status s={err} />
        {st && (
          <>
            <ByteView view={{ title: `État interne (secret) · compteur de requêtes : ${st.counter}${reseeds ? ` · ${reseeds} réensemencement${reseeds > 1 ? 's' : ''}` : ''}`, segs: [seg('K', st.K, 'key'), seg('V', st.V, 'secret')] }} encoding={enc} />
            <div className="actions" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
              <label className="f fit" style={{ margin: 0 }}><span className="lab"><span>Octets demandés</span></span><input className="t mono" type="number" min={1} max={1024} value={n} style={{ width: 100 }} onChange={(e) => setN(Math.max(1, Math.min(1024, Number(e.target.value) || 1)))} /></label>
              <label className="f" style={{ margin: 0, flex: 1 }}><span className="lab"><span>Entrée additionnelle (facultative)</span></span><input className="t" value={addl} onChange={(e) => setAddl(e.target.value)} /></label>
              <button className="btn b-pri" onClick={gen}><Fad icon={IC.bolt} />Generate</button>
              <button className="btn b-ghost" onClick={reseed}><Fad icon={IC.again} />Reseed</button>
            </div>
            {outs.map((o) => <ByteView key={o.seq} view={{ title: `Sortie n° ${o.seq} · requête ${o.counter} depuis le dernier ensemencement${o.addl ? ` · entrée additionnelle « ${o.addl} »` : ''}`, segs: [seg('sortie', o.out, 'nonce')] }} encoding={enc} />)}
            {outs.length > 0 && <div className="meta">Après chaque Generate, K et V sont remplacés : qui volerait l'état maintenant ne pourrait pas recalculer les sorties précédentes (retour en arrière impossible).</div>}
          </>
        )}
      </Card>
      <Card n={3} title="RFC 6979 : le nonce d'ECDSA tiré de la clé et du message">
        <div className="row">
          <label className="f" style={{ flex: 3 }}><span className="lab"><span>Clé privée x (P-256, 32 octets hex)</span></span><input className="t mono" value={priv} onChange={(e) => setPriv(e.target.value.trim())} /></label>
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Message</span></span><input className="t" value={msg} onChange={(e) => setMsg(e.target.value)} /></label>
        </div>
        <div className="actions"><button className="btn b-ghost" onClick={() => { setPriv('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'); setMsg('sample'); }}><Fad icon={IC.file} />Vecteur RFC 6979 A.2.5</button></div>
        {k ? (
          <>
            <ByteView view={{ title: 'Graine du DRBG : x ‖ (SHA-256(M) mod n)', segs: [seg('x', fromHex(priv), 'priv'), seg('h₁ mod n', k.h1mod, 'hash')] }} encoding={enc} />
            <ByteView view={{ title: 'K et V après instanciation', segs: [seg('K', k.seed.K, 'key'), seg('V', k.seed.V, 'secret')] }} encoding={enc} />
            <ByteView view={{ title: `k = V = HMAC(K, V)${k.tries > 1 ? `, ${k.tries} essais` : ''}`, segs: [seg('k', i2osp(k.k, 32), 'nonce')] }} encoding={enc} />
            <Status s={isVector ? (k.k.toString(16).toUpperCase() === 'A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60' ? { kind: 'ok', text: 'k = A6E3C57D…8AAD60 : exactement la valeur de l\'annexe A.2.5 de RFC 6979.' } : { kind: 'ko', text: 'Différent du vecteur attendu !' }) : { kind: 'info', text: 'Même clé et même message donnent toujours le même k ; un message différent, un k sans rapport. Plus de nonce répété (PS3), plus de dépendance à un générateur défaillant.' }} />
          </>
        ) : <Status s={{ kind: 'ko', text: 'Clé privée : 32 octets en hexadécimal.' }} />}
      </Card>
    </>
  );
}

// ================================================================ Dual_EC_DRBG
function DualEcLab() {
  const [D, setD] = useState<DualEc>(dualEcSetup);
  const [seedHex, setSeedHex] = usePersisted('dualec', 'seed', () => toHex(rand(32)), z.string());
  const [outs, setOuts] = useState<Bytes[]>([]);
  const [state, setState] = useState<bigint | null>(null);
  const [atk, setAtk] = useState<{ state: bigint; tried: number; onCurve: number; ms: number; pred: Bytes[] } | null>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const { busy, wrap } = useBusy();
  const DROP = 1;
  const produce = () => {
    const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    let s = state ?? (() => { const b = hexOr(seedHex); const v = b && b.length ? BigInt('0x' + toHex(b)) % N : 0n; return v === 0n ? 1n : v; })();
    const r = dualEcStep(D, s, DROP);
    s = r.s;
    setState(s);
    setOuts([...outs, r.out]);
  };
  const attack = wrap('atk', async () => {
    const t = performance.now();
    const r = dualEcAttack(D, outs[0], outs[1], DROP);
    if (!r) return;
    let s = r.state;
    const pred: Bytes[] = [];
    for (let i = 2; i < outs.length + 3; i++) { const x = dualEcStep(D, s, DROP); s = x.s; pred.push(x.out); }
    setAtk({ ...r, ms: performance.now() - t, pred });
  });
  const restart = () => { setD(dualEcSetup()); setSeedHex(toHex(rand(32))); setOuts([]); setState(null); setAtk(null); };
  return (
    <>
      <Card n={2} title="Le générateur et ses deux points publics" right={<span className="ctrls"><EncodingToggle value={enc} onChange={setEnc} /><button className="btn b-ghost b-sm" onClick={restart}><Fad icon={IC.again} />Nouveaux P, Q, graine</button></span>}>
        <Pipeline label="Dual_EC" steps={['s ← x(s·P)', 'r = x(s·Q)', 'sortie = r sans ses premiers octets']} run={outs.length} />
        <div className="grid2">
          <ByteView view={{ title: 'Q (point public de la norme)', segs: [seg('Q', D.Q, 'pub')] }} encoding={enc} />
          <ByteView view={{ title: 'P = d·Q (public aussi ; d ne l\'est pas)', segs: [seg('P', D.P, 'pub')] }} encoding={enc} />
        </div>
        <label className="f"><span className="lab"><span>Graine s₀ (secrète, hex)</span></span><input className="t mono" value={seedHex} onChange={(e) => { setSeedHex(e.target.value); setState(null); setOuts([]); setAtk(null); }} /></label>
        <div className="actions"><button className="btn b-pri" onClick={produce}><Fad icon={IC.bolt} />Produire 31 octets</button></div>
        <div className="meta">Simplification : on retire 1 octet de chaque abscisse (256 candidats) au lieu de 2 dans la norme (65 536 candidats, quelques minutes ici). Le principe est identique.</div>
        {outs.map((o, i) => <ByteView key={i} view={{ title: `Sortie n° ${i + 1}`, segs: [seg(`r${i + 1}`, o, 'nonce')] }} encoding={enc} />)}
      </Card>
      {outs.length >= 2 && (
        <Card n={3} title="Celui qui connaît d">
          <ByteView view={{ title: 'd, tel que P = d·Q (choisi par le concepteur, jamais publié)', segs: [seg('d', i2osp(D.d, 32), 'priv')] }} encoding={enc} />
          <Pipeline label="Attaque" steps={['préfixe ‖ sortie 1 = x(R)', 'relever R sur la courbe', 'x(d·R) = x(s·P) = état suivant', 'vérifier avec la sortie 2']} run={atk ? 1 : 0} />
          <div className="actions"><button className="btn b-red" disabled={!!busy} onClick={attack}><Fad icon={IC.attacker} />{busy ? 'Recherche…' : 'Retrouver l\'état à partir des sorties 1 et 2'}</button></div>
          {atk && (
            <>
              <ByteView view={{ title: `État interne retrouvé : ${atk.tried} préfixes essayés, ${atk.onCurve} sur la courbe (${atk.ms.toFixed(0)} ms)`, segs: [seg('s', i2osp(atk.state, 32), 'secret')] }} encoding={enc} />
              {atk.pred.map((p, i) => {
                const real = outs[i + 2];
                return <ByteView key={i} view={{ title: `Sortie n° ${i + 3}, prédite${real ? (toHex(real) === toHex(p) ? ' : identique à la vraie' : ' : différente !') : ' (pas encore produite)'}`, segs: [seg(`r${i + 3}`, p, real ? 'tag' : 'ct')] }} encoding={enc} />;
              })}
              <Status s={{ kind: 'ko', text: 'Toutes les sorties futures sont connues : nonces, clés de session TLS dérivées de ce générateur… C\'est ce qui rendait Dual_EC si précieux pour qui détenait d, et c\'est pourquoi il a été retiré.' }} />
            </>
          )}
        </Card>
      )}
    </>
  );
}

// ================================================================ Debian 2008
function DebianLab() {
  const [pid, setPid] = useState(() => 1 + Math.floor(Math.random() * 32768));
  const [progress, setProgress] = useState(0);
  const [found, setFound] = useState<{ pid: number; ms: number } | null>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const { busy, wrap } = useBusy();
  const key = useMemo(() => weakKey(pid), [pid]);
  const crack = wrap('crack', async () => {
    setFound(null);
    const t = performance.now();
    const r = await crackWeakKey(key.pub, setProgress);
    if (r) setFound({ pid: r, ms: performance.now() - t });
  });
  return (
    <>
      <Card n={2} title="Un serveur Debian de 2007 génère sa clé" right={<span className="ctrls"><EncodingToggle value={enc} onChange={setEnc} /><button className="btn b-ghost b-sm" onClick={() => { setPid(1 + Math.floor(Math.random() * 32768)); setFound(null); setProgress(0); }}><Fad icon={IC.again} />Autre serveur</button></span>}>
        <Pipeline label="ssh-keygen" steps={['graine = PID seul', 'clé privée = f(graine)', 'clé publique diffusée']} run={1} />
        <ByteView view={{ title: 'Clé publique (diffusée : known_hosts, certificat…)', segs: [seg('pub', key.pub, 'pub')] }} encoding={enc} />
        <div className="meta">La clé privée ne dépend que du numéro de processus, inconnu de l'attaquant mais compris entre 1 et 32 768. (Clé X25519 ici ; en 2008, des clés RSA et DSA, mais le principe est le même.)</div>
      </Card>
      <Card n={3} title="L'attaquant énumère les 32 768 graines">
        <div className="actions"><button className="btn b-red" disabled={!!busy} onClick={crack}><Fad icon={IC.attacker} />{busy ? `Recherche… ${progress.toLocaleString('fr-FR')} / 32 768` : 'Lancer la recherche exhaustive'}</button></div>
        {busy && <div className="rg-prog"><i style={{ width: `${(100 * progress) / 32768}%` }} /></div>}
        {found && (
          <>
            <ByteView view={{ title: `Clé privée retrouvée : PID ${found.pid}, en ${(found.ms / 1000).toFixed(1)} s`, segs: [seg('priv', weakKey(found.pid).priv, 'priv')] }} encoding={enc} />
            <Status s={{ kind: 'ko', text: `15 bits d'entropie au lieu de 128 : ${found.pid.toLocaleString('fr-FR')} essais ont suffi. En 2008, des listes de toutes les clés possibles circulaient ; on les comparait aux clés publiques des serveurs.` }} />
          </>
        )}
      </Card>
    </>
  );
}

