import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Fad, IC } from '../lib/icons';
import { fromUtf8, quote, toB64url, toHex, utf8 } from '../lib/bytes';
import { seg, type View } from '../crypto/types';
import {
  DH_GROUPS, bigBytes, chipAuthenticate, clamp, cloneChip, compressP256, dhCheck, dhPublic, dhSecret, dhShared,
  ecdhP256, edPair, eveSteal, eveTry, gridSession, issuerNew, LOW_ORDER, p256Pair, personalize, ratchetDecrypt,
  ratchetEncrypt, ratchetInit, recoverable, sigmaRun, xdh, xPair, type CaRun, type Chip, type Eve, type GridSession,
  type Issuer, type Mode, type RatchetMsg, type RatchetState, type SigmaRun,
} from '../crypto/kex';
import { hkdf } from '../crypto/kdf';
import { ByteView, EncodingToggle, type Encoding } from '../components/ByteView';
import { Card, Pipeline, Status } from '../components/ui';
import { errText } from './common';
import { CELL_LABEL, DH_USES, type Cell } from '../data/dhUses';

type St = { kind: 'ok' | 'ko' | 'info'; text: string } | null;
const short = (b: Uint8Array, n = 6) => toHex(b.slice(0, n)) + '…';

export function KexLab({ id }: { id: string }) {
  if (id === 'dh') return <DhLab />;
  if (id === 'ecdh' || id === 'x25519') return <EcLab curve={id} />;
  if (id === 'kex-grid') return <GridLab />;
  if (id === 'sigma') return <SigmaLab />;
  if (id === 'chip-auth') return <ChipLab />;
  if (id === 'ratchet') return <RatchetLab />;
  return null;
}

/** Les deux colonnes Alice / Bob d'un échange. */
function Duo({ left, right }: { left: ReactNode; right: ReactNode }) {
  return (
    <div className="grid2">
      <div><div className="who" style={{ color: 'var(--c-pt)' }}><Fad icon={IC.private} />Alice</div>{left}</div>
      <div><div className="who" style={{ color: 'var(--c-pub)' }}><Fad icon={IC.private} />Bob</div>{right}</div>
    </div>
  );
}

// ================================================================ DH en corps fini
type Attack = 'none' | 'pm1' | 'one' | 'out';

function DhLab() {
  const [gid, setGid] = useState<'toy' | 'ffdhe2048'>('toy');
  const G = DH_GROUPS[gid];
  const [k, setK] = useState(() => ({ a: dhSecret(G), b: dhSecret(G) }));
  const [attack, setAttack] = useState<Attack>('none');
  const [validate, setValidate] = useState(true);
  const [run, setRun] = useState(0);
  const [enc, setEnc] = useState<Encoding>('hex');
  useEffect(() => { setK({ a: dhSecret(G), b: dhSecret(G) }); setAttack('none'); }, [gid]); // eslint-disable-line react-hooks/exhaustive-deps

  const A = dhPublic(G, k.a);
  const B = dhPublic(G, k.b);
  const forged = attack === 'pm1' ? G.p - 1n : attack === 'one' ? 1n : attack === 'out' ? (gid === 'toy' ? 5n : G.p - 2n) : B;
  const num = (x: bigint) => (gid === 'toy' ? x.toString() : `${x.toString(16).slice(0, 24)}… (${x.toString(2).length} bits)`);
  const bv = (title: string, x: bigint, tone: 'priv' | 'pub' | 'secret', caption?: string): View => ({ title, caption, segs: [seg(title, bigBytes(x, G.bytes), tone)] });

  const result = useMemo((): { st: St; zA?: bigint; zB?: bigint } => {
    if (!run) return { st: null };
    const zB = dhShared(G, k.b, A);
    try {
      const zA = dhShared(G, k.a, forged, validate);
      if (attack === 'none') return { st: { kind: 'ok', text: 'Z identique des deux côtés, sans qu\'il ait jamais circulé.' }, zA, zB };
      const small = zA === 1n || zA === G.p - 1n;
      return {
        st: small
          ? { kind: 'ko', text: `Validation désactivée : Z = ${zA === 1n ? '1' : 'p − 1'}. Mallory le devine en deux essais, quel que soit le secret a.` }
          : { kind: 'ko', text: 'Validation désactivée : Z sort du sous-groupe et trahit des informations sur a (sa parité ici).' },
        zA, zB,
      };
    } catch (e) {
      return { st: { kind: 'ok', text: `Valeur refusée par Alice : ${errText(e)}` }, zB };
    }
  }, [run, k, attack, validate, gid]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      <Card n={2} title="Le groupe et les deux biclés" right={<span className="ctrls">
        <select className="t" value={gid} onChange={(e) => setGid(e.target.value as 'toy' | 'ffdhe2048')}>
          {Object.values(DH_GROUPS).map((g) => <option key={g.id} value={g.id}>{g.label}</option>)}
        </select>
        <EncodingToggle value={enc} onChange={setEnc} />
        <button className="btn b-ghost b-sm" onClick={() => setK({ a: dhSecret(G), b: dhSecret(G) })}><Fad icon={IC.dice} />Nouveaux secrets</button>
      </span>}>
        <div className="formula">p = {num(G.p)} · g = {G.g.toString()} · q = (p − 1) / 2 = {num(G.q)}</div>
        <Duo
          left={<><div className="meta">a = {num(k.a)}</div><ByteView view={bv('a (secret)', k.a, 'priv')} encoding={enc} /><ByteView view={bv('A = gᵃ mod p', A, 'pub', gid === 'toy' ? `A = ${G.g}^${k.a} mod ${G.p} = ${A}` : `A = ${num(A)}`)} encoding={enc} /></>}
          right={<><div className="meta">b = {num(k.b)}</div><ByteView view={bv('b (secret)', k.b, 'priv')} encoding={enc} /><ByteView view={bv('B = gᵇ mod p', B, 'pub', gid === 'toy' ? `B = ${G.g}^${k.b} mod ${G.p} = ${B}` : `B = ${num(B)}`)} encoding={enc} /></>}
        />
      </Card>
      <Card n={3} title="Échanger A et B, calculer Z">
        <Pipeline label="Accord" steps={['Alice publie A', 'Bob publie B', 'Alice : Z = Bᵃ', 'Bob : Z = Aᵇ', 'KDF(Z)']} run={run} />
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <label className="f" style={{ margin: 0 }}><span className="lab"><span>Ce qu'Alice reçoit à la place de B</span></span>
            <select className="t" value={attack} onChange={(e) => setAttack(e.target.value as Attack)}>
              <option value="none">B, la vraie valeur de Bob</option>
              <option value="pm1">p − 1 (ordre 2), injecté par Mallory</option>
              <option value="one">1 (ordre 1), injecté par Mallory</option>
              <option value="out">{gid === 'toy' ? '5, hors du sous-groupe d\'ordre q' : 'p − 2, hors du sous-groupe'}</option>
            </select>
          </label>
          <label className="chk"><input type="checkbox" checked={validate} onChange={(e) => setValidate(e.target.checked)} /> Alice valide la valeur reçue</label>
          <button className="btn b-pri" onClick={() => setRun((x) => x + 1)}><Fad icon={IC.kex} />Calculer Z</button>
        </div>
        {attack !== 'none' && <div className="meta">Contrôle SP 800-56A : {dhCheck(G, forged) ?? 'valeur acceptable'}</div>}
        <Status s={result.st} />
        {run > 0 && (
          <Duo
            left={result.zA !== undefined ? <><ByteView view={bv('Z calculé par Alice', result.zA, 'secret', gid === 'toy' ? `Z = ${forged}^${k.a} mod ${G.p} = ${result.zA}` : `Z = ${num(result.zA)}`)} encoding={enc} /><ByteView view={{ title: 'Clé dérivée : HKDF-SHA256(Z)', segs: [seg('K', hkdf(bigBytes(result.zA, G.bytes), new Uint8Array(0), utf8('atelier dh'), 16), 'key')] }} encoding={enc} /></> : <div className="meta">Pas de Z : la valeur a été rejetée.</div>}
            right={result.zB !== undefined ? <ByteView view={bv('Z calculé par Bob', result.zB, 'secret', gid === 'toy' ? `Z = ${A}^${k.b} mod ${G.p} = ${result.zB}` : `Z = ${num(result.zB)}`)} encoding={enc} /> : null}
          />
        )}
      </Card>
    </>
  );
}

// ================================================================ ECDH P-256 et X25519
type EcAttack = 'none' | 'flip' | 'zero' | 'one';

function EcLab({ curve }: { curve: 'ecdh' | 'x25519' }) {
  const isX = curve === 'x25519';
  const gen = () => (isX ? xPair() : p256Pair());
  const [a, setA] = useState(gen);
  const [b, setB] = useState(gen);
  const [attack, setAttack] = useState<EcAttack>('none');
  const [run, setRun] = useState(0);
  const [enc, setEnc] = useState<Encoding>('hex');

  const pubViews = (pub: Uint8Array): View[] => isX
    ? [{ title: 'Clé publique u (32 octets, petit-boutiste)', segs: [seg('u', pub, 'pub')] }]
    : [
      { title: 'Point non compressé (SEC 1)', segs: [seg('04', pub.slice(0, 1), 'hdr', 'non compressé'), seg('X', pub.slice(1, 33), 'pub'), seg('Y', pub.slice(33), 'pub')] },
      { title: 'Point compressé', caption: '02 si Y est pair, 03 sinon : Y se recalcule à partir de X.', segs: (() => { const c = compressP256(pub); return [seg(toHex(c.slice(0, 1)), c.slice(0, 1), 'hdr', 'parité de Y'), seg('X', c.slice(1), 'pub')]; })() },
      { title: 'JWK', text: JSON.stringify({ kty: 'EC', crv: 'P-256', x: toB64url(pub.slice(1, 33)), y: toB64url(pub.slice(33)) }, null, 2) },
    ];
  const privViews = (priv: Uint8Array): View[] => isX
    ? [
      { title: 'Clé privée tirée (32 octets)', segs: [seg('k', priv, 'priv')] },
      { title: 'Après « clamping » (RFC 7748)', caption: 'Octet 0 : 3 bits bas à 0 (multiple de 8, le cofacteur). Octet 31 : bit 255 à 0, bit 254 à 1.', segs: (() => { const c = clamp(priv); return [seg('k[0] & 248', c.slice(0, 1), 'hdr'), seg('k[1..30]', c.slice(1, 31), 'priv'), seg('k[31] & 127 | 64', c.slice(31), 'hdr')]; })() },
    ]
    : [{ title: 'Scalaire d (32 octets)', segs: [seg('d', priv, 'priv')] }];

  const sent = (() => {
    if (attack === 'flip') { const x = b.pub.slice(); x[x.length - 2] ^= 1; return x; }
    if (attack === 'zero') return LOW_ORDER.zero;
    if (attack === 'one') return LOW_ORDER.one;
    return b.pub;
  })();
  const dh = (priv: Uint8Array, pub: Uint8Array) => (isX ? xdh(priv, pub) : ecdhP256(priv, pub));
  const res = useMemo(() => {
    if (!run) return null;
    const zB = dh(b.priv, a.pub);
    try {
      const zA = dh(a.priv, sent);
      return { zA, zB, st: { kind: 'ok', text: 'Même Z des deux côtés.' } as St };
    } catch (e) {
      return { zB, st: { kind: 'ok', text: `Clé publique refusée par Alice. ${errText(e)}` } as St };
    }
  }, [run]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      <Card n={2} title={`Deux biclés ${isX ? 'X25519' : 'P-256'}`} right={<span className="ctrls">
        <EncodingToggle value={enc} onChange={setEnc} />
        <button className="btn b-ghost b-sm" onClick={() => { setA(gen()); setB(gen()); setRun(0); }}><Fad icon={IC.keypair} />Nouvelles biclés</button>
      </span>}>
        <Duo
          left={<>{privViews(a.priv).map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}{pubViews(a.pub).map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}</>}
          right={<>{privViews(b.priv).map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}{pubViews(b.pub).map((v, i) => <ByteView key={i} view={v} encoding={enc} />)}</>}
        />
      </Card>
      <Card n={3} title="Calculer le secret partagé">
        <Pipeline label="Accord" steps={isX ? ['u_A, u_B publiés', 'Z = X25519(a, u_B)', 'Z = X25519(b, u_A)', 'Z ≠ 0 ?', 'HKDF(Z)'] : ['Points publiés', 'Point sur la courbe ?', 'Z = x(a·B)', 'Z = x(b·A)', 'KDF(Z)']} run={run} />
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <label className="f" style={{ margin: 0 }}><span className="lab"><span>Ce qu'Alice reçoit comme clé publique de Bob</span></span>
            <select className="t" value={attack} onChange={(e) => setAttack(e.target.value as EcAttack)}>
              <option value="none">La vraie clé de Bob</option>
              {!isX && <option value="flip">Un octet de Y altéré (point invalide)</option>}
              {isX && <option value="zero">u = 0 (point d'ordre faible)</option>}
              {isX && <option value="one">u = 1 (point d'ordre faible)</option>}
            </select>
          </label>
          <button className="btn b-pri" onClick={() => setRun((x) => x + 1)}><Fad icon={IC.kex} />Calculer Z</button>
        </div>
        {res && <Status s={res.st} />}
        {res && (
          <Duo
            left={res.zA ? <><ByteView view={{ title: 'Z calculé par Alice', caption: isX ? undefined : 'Abscisse x du point a·B, 32 octets.', segs: [seg('Z', res.zA, 'secret')] }} encoding={enc} /><ByteView view={{ title: 'Clé dérivée : HKDF-SHA256(Z)', segs: [seg('K', hkdf(res.zA, new Uint8Array(0), utf8('atelier ecdh'), 16), 'key')] }} encoding={enc} /></> : <div className="meta">Aucun secret : Alice a refusé la clé reçue{isX ? ' (Z serait 00…00, connu de tous)' : ''}.</div>}
            right={<ByteView view={{ title: 'Z calculé par Bob', segs: [seg('Z', res.zB, 'secret')] }} encoding={enc} />}
          />
        )}
      </Card>
    </>
  );
}

// ================================================================ Grille statique / éphémère
const PROPS: Record<string, { fresh: string; fs: string; auth: string; ex: string }> = {
  ss: { fresh: 'Non : Z est toujours le même (seuls des nonces rendent la clé dérivée neuve).', fs: 'Aucune : la fuite d\'une des deux clés rouvre tout l\'historique.', auth: 'Mutuelle et implicite.', ex: 'TLS 1.2 ECDH statique, Noise KK (partie ss), ECDH-1PU' },
  es: { fresh: 'Oui : l\'éphémère d\'Alice change à chaque session.', fs: 'Partielle : la fuite de la clé statique de Bob rouvre toutes les sessions passées.', auth: 'Bob seul, implicitement ; Alice reste anonyme.', ex: 'ECIES, HPKE, JWE ECDH-ES, Chip Authentication' },
  se: { fresh: 'Oui : l\'éphémère de Bob change à chaque session.', fs: 'Partielle : la fuite de la clé statique d\'Alice rouvre les sessions passées.', auth: 'Alice seule, implicitement.', ex: 'Réponse d\'un serveur à un client connu (Noise, partie se)' },
  ee: { fresh: 'Oui.', fs: 'Totale : les éphémères effacées, aucune fuite ne rouvre le passé.', auth: 'Personne : il faut signer (SIGMA) ou utiliser un mot de passe (PACE).', ex: 'TLS 1.3, SSH, IKEv2, PACE, Double Ratchet' },
};

function GridLab() {
  const [parties] = useState(() => ({ A: { name: 'Alice', static: xPair() }, B: { name: 'Bob', static: xPair() } }));
  const [modeA, setModeA] = useState<Mode>('e');
  const [modeB, setModeB] = useState<Mode>('s');
  const [nonces, setNonces] = useState(false);
  const [sessions, setSessions] = useState<GridSession[]>([]);
  const [leak, setLeak] = useState<'none' | 'A' | 'B'>('none');
  const [filter, setFilter] = useState<Cell | 'all'>('all');
  const key = `${modeA}${modeB}`;
  const P = PROPS[key];
  const play = () => { setSessions((s) => [...s.slice(-5), gridSession((s.at(-1)?.n ?? 0) + 1, parties.A, parties.B, modeA, modeB, nonces)]); };
  const zCount = new Map<string, number>();
  sessions.forEach((s) => zCount.set(toHex(s.z), (zCount.get(toHex(s.z)) ?? 0) + 1));

  return (
    <>
      <Card n={2} title="Choisir, de chaque côté, une clé statique ou éphémère">
        <div className="kx-grid">
          <div />
          <div className="kx-h">Bob statique</div>
          <div className="kx-h">Bob éphémère</div>
          {(['s', 'e'] as Mode[]).map((ma) => (
            <div key={ma} style={{ display: 'contents' }}>
              <div className="kx-h">Alice {ma === 's' ? 'statique' : 'éphémère'}</div>
              {(['s', 'e'] as Mode[]).map((mb) => {
                const k = `${ma}${mb}`;
                return (
                  <button key={k} className={`kx-cell ${k === key ? 'on' : ''}`} onClick={() => { setModeA(ma); setModeB(mb); }}>
                    <b>{ma === 's' ? 'S' : 'E'} × {mb === 's' ? 'S' : 'E'}</b>
                    <span>{PROPS[k].ex}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        <div className="grid3" style={{ marginTop: 10 }}>
          <div className="tip"><b>Fraîcheur</b><br />{P.fresh}</div>
          <div className="tip"><b>Confidentialité persistante</b><br />{P.fs}</div>
          <div className="tip"><b>Authentification</b><br />{P.auth}</div>
        </div>
      </Card>
      <Card n={3} title="Jouer des sessions, puis faire fuir une clé statique" right={<span className="ctrls">
        <label className="chk"><input type="checkbox" checked={nonces} onChange={(e) => setNonces(e.target.checked)} /> nonces dans la KDF</label>
        <button className="btn b-ghost b-sm" onClick={() => { setSessions([]); setLeak('none'); }}>Effacer</button>
      </span>}>
        <div className="actions" style={{ flexWrap: 'wrap', gap: 8 }}>
          <button className="btn b-pri" onClick={play}><Fad icon={IC.again} />Nouvelle session ({modeA === 's' ? 'S' : 'E'} × {modeB === 's' ? 'S' : 'E'})</button>
          <button className={`btn ${leak === 'A' ? 'b-red' : 'b-ghost'}`} onClick={() => setLeak(leak === 'A' ? 'none' : 'A')}><Fad icon={IC.attack} />La clé statique d'Alice fuit</button>
          <button className={`btn ${leak === 'B' ? 'b-red' : 'b-ghost'}`} onClick={() => setLeak(leak === 'B' ? 'none' : 'B')}><Fad icon={IC.attack} />La clé statique de Bob fuit</button>
        </div>
        {sessions.length > 0 && (
          <div className="kx-scroll">
            <table className="kx-table">
              <thead><tr><th>#</th><th>Cas</th><th>Clé publique d'Alice</th><th>Clé publique de Bob</th><th>Z</th><th>Clé de session</th>{leak !== 'none' && <th>Après la fuite</th>}</tr></thead>
              <tbody>
                {sessions.map((s) => {
                  const dup = (zCount.get(toHex(s.z)) ?? 0) > 1;
                  const lost = recoverable(s, leak);
                  return (
                    <tr key={s.n} className={lost ? 'lost' : ''}>
                      <td>{s.n}</td>
                      <td>{s.modeA === 's' ? 'S' : 'E'} × {s.modeB === 's' ? 'S' : 'E'}</td>
                      <td><code className="sg t-pub">{short(s.pubA)}</code></td>
                      <td><code className="sg t-pub">{short(s.pubB)}</code></td>
                      <td><code className={`sg t-secret ${dup ? 'dup' : ''}`}>{short(s.z)}</code></td>
                      <td><code className="sg t-key">{short(s.key)}</code></td>
                      {leak !== 'none' && <td>{lost ? <span className="pill p-ko">Z recalculable</span> : <span className="pill p-ok">protégée</span>}</td>}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {[...zCount.values()].some((n) => n > 1) && <Status s={{ kind: 'info', text: `Z encadré : la même valeur revient d'une session à l'autre${nonces ? ', mais les nonces rendent la clé de session différente' : ''}.` }} />}
        {leak !== 'none' && <Status s={{ kind: sessions.some((s) => recoverable(s, leak)) ? 'ko' : 'ok', text: `L'attaquant a enregistré les clés publiques de chaque session ; avec la clé statique ${leak === 'A' ? 'd\'Alice' : 'de Bob'}, il recalcule Z partout où elle a servi. Les sessions où ce côté était éphémère restent protégées, si l'éphémère a bien été effacée.` }} />}
      </Card>
      <Card n={4} title="Où trouve-t-on Diffie-Hellman ?" right={<span className="ctrls">
        <select className="t" value={filter} onChange={(e) => setFilter(e.target.value as Cell | 'all')}>
          <option value="all">Tous ({DH_USES.length})</option>
          {(Object.keys(CELL_LABEL) as Cell[]).map((c) => <option key={c} value={c}>{CELL_LABEL[c]} ({DH_USES.filter((u) => u.cell === c).length})</option>)}
        </select>
      </span>}>
        <div className="kx-scroll">
          <table className="kx-table kx-uses">
            <thead><tr><th>Protocole</th><th>Case</th><th>Le ou les DH</th><th>Qui est authentifié, et comment</th></tr></thead>
            <tbody>
              {DH_USES.filter((u) => filter === 'all' || u.cell === filter).map((u) => (
                <tr key={u.name}>
                  <td><b>{u.name}</b><br /><span className="meta">{u.domain}</span></td>
                  <td><span className={`pill ${u.cell === 'ee' ? 'p-ok' : u.cell === 'es' ? 'p-nt' : u.cell === 'ss' ? 'p-mid' : 'p-pq'}`}>{CELL_LABEL[u.cell]}</span></td>
                  <td>{u.dh}</td>
                  <td>{u.auth}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

// ================================================================ SIGMA
function SigmaLab() {
  const [ids, setIds] = useState(() => ({ A: { name: 'Alice', sign: edPair() }, B: { name: 'Bob', sign: edPair() } }));
  const [auth, setAuth] = useState(false);
  const [mitm, setMitm] = useState(true);
  const [r, setR] = useState<SigmaRun | null>(null);
  const [run, setRun] = useState(0);
  const [enc, setEnc] = useState<Encoding>('hex');
  const go = () => { setR(sigmaRun(ids.A, ids.B, auth, mitm)); setRun((x) => x + 1); };
  const same = r && toHex(r.zA) === toHex(r.zB);
  const st: St = !r ? null
    : !r.aAccepts || !r.bAccepts ? { kind: 'ok', text: `Échange refusé : ${!r.aAccepts ? 'la signature de Bob ne porte pas sur l\'éphémère qu\'Alice a reçue' : ''}${!r.aAccepts && !r.bAccepts ? ' ; ' : ''}${!r.bAccepts ? 'la signature d\'Alice ne porte pas sur l\'éphémère que Bob a reçue' : ''}. Mallory, sans les clés d'identité, ne peut pas re-signer.` }
      : r.malloryKnows ? { kind: 'ko', text: 'Alice et Bob acceptent, mais ont deux secrets différents, tous deux connus de Mallory : elle déchiffre, relit, rechiffre.' }
        : { kind: 'ok', text: auth ? 'Même Z, et chacun sait avec qui il le partage.' : 'Même Z, mais rien ne prouve à Alice qu\'elle parle à Bob : un attaquant actif aurait pu s\'interposer.' };

  return (
    <>
      <Card n={2} title="Clés d'identité (signature Ed25519, certifiées)" right={<span className="ctrls">
        <EncodingToggle value={enc} onChange={setEnc} />
        <button className="btn b-ghost b-sm" onClick={() => setIds({ A: { name: 'Alice', sign: edPair() }, B: { name: 'Bob', sign: edPair() } })}><Fad icon={IC.keypair} />Nouvelles identités</button>
      </span>}>
        <Duo
          left={<ByteView view={{ title: 'Clé publique d\'identité d\'Alice', segs: [seg('IK_A', ids.A.sign.pub, 'pub')] }} encoding={enc} />}
          right={<ByteView view={{ title: 'Clé publique d\'identité de Bob', segs: [seg('IK_B', ids.B.sign.pub, 'pub')] }} encoding={enc} />}
        />
        <div className="meta">Ces clés ne servent qu'à signer ; le secret vient uniquement des éphémères X25519, tirées à chaque échange.</div>
      </Card>
      <Card n={3} title="L'échange, avec ou sans Mallory au milieu">
        <Pipeline label="SIGMA" steps={['A → gᵃ', 'B → gᵇ, Sign_B(gᵇ ‖ gᵃ)', 'A vérifie', 'A → Sign_A(gᵃ ‖ gᵇ)', 'B vérifie', 'Z = g^ab']} run={run} />
        <div className="actions" style={{ flexWrap: 'wrap', gap: 12 }}>
          <label className="chk"><input type="checkbox" checked={mitm} onChange={(e) => setMitm(e.target.checked)} /> <Fad icon={IC.attacker} /> Mallory s'interpose</label>
          <label className="chk"><input type="checkbox" checked={auth} onChange={(e) => setAuth(e.target.checked)} /> <Fad icon={IC.sign} /> Éphémères signées (SIGMA)</label>
          <button className="btn b-pri" onClick={go}><Fad icon={IC.kex} />Lancer l'échange</button>
        </div>
        <Status s={st} />
        {r && (
          <>
            <div className="grid3">
              <div>
                <div className="who" style={{ color: 'var(--c-pt)' }}>Alice</div>
                <ByteView view={{ title: 'Envoie gᵃ', segs: [seg('gᵃ', r.ea.pub, 'pub')] }} encoding={enc} />
                <ByteView view={{ title: 'Reçoit (croit : gᵇ)', segs: [seg(r.mallory ? 'g^m₂' : 'gᵇ', r.aSees, 'pub')] }} encoding={enc} />
                <ByteView view={{ title: 'Z selon Alice', segs: [seg('Z_A', r.zA, 'secret')] }} encoding={enc} />
              </div>
              <div>
                <div className="who" style={{ color: r.mallory ? 'var(--c-tag)' : 'var(--mute)' }}><Fad icon={r.mallory ? IC.attacker : IC.send} />{r.mallory ? 'Mallory' : 'Réseau'}</div>
                {r.mallory ? (
                  <>
                    <ByteView view={{ title: 'Remplace gᵃ par g^m₁', segs: [seg('g^m₁', r.mallory.ma.pub, 'pub')] }} encoding={enc} />
                    <ByteView view={{ title: 'Remplace gᵇ par g^m₂', segs: [seg('g^m₂', r.mallory.mb.pub, 'pub')] }} encoding={enc} />
                    <div className="meta">Mallory calcule Z_A = DH(m₂, gᵃ) et Z_B = DH(m₁, gᵇ) : elle connaît les deux secrets.</div>
                  </>
                ) : <div className="meta">Les valeurs passent sans modification.</div>}
                {r.sigB && <ByteView view={{ title: 'Signature de Bob (relayée telle quelle)', segs: [seg('σ_B', r.sigB, 'sig')] }} encoding={enc} />}
              </div>
              <div>
                <div className="who" style={{ color: 'var(--c-pub)' }}>Bob</div>
                <ByteView view={{ title: 'Envoie gᵇ', segs: [seg('gᵇ', r.eb.pub, 'pub')] }} encoding={enc} />
                <ByteView view={{ title: 'Reçoit (croit : gᵃ)', segs: [seg(r.mallory ? 'g^m₁' : 'gᵃ', r.bSees, 'pub')] }} encoding={enc} />
                <ByteView view={{ title: 'Z selon Bob', segs: [seg('Z_B', r.zB, 'secret')] }} encoding={enc} />
              </div>
            </div>
            <div className="meta">Z_A {same ? '=' : '≠'} Z_B · Alice {r.aAccepts ? 'accepte' : 'refuse'} · Bob {r.bAccepts ? 'accepte' : 'refuse'}</div>
          </>
        )}
      </Card>
    </>
  );
}

// ================================================================ Chip Authentication
const DG1 = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10';
type ChipKind = 'genuine' | 'clone' | 'swap';

function ChipLab() {
  const [iss, setIss] = useState<Issuer>(issuerNew);
  const [chip, setChip] = useState<Chip>(() => personalize(iss));
  const [kind, setKind] = useState<ChipKind>('genuine');
  const [r, setR] = useState<CaRun | null>(null);
  const [run, setRun] = useState(0);
  const [enc, setEnc] = useState<Encoding>('hex');
  const renew = () => { const i = issuerNew(); setIss(i); setChip(personalize(i)); setR(null); };
  const presented = (): Chip => {
    if (kind === 'clone') return cloneChip(chip);
    if (kind === 'swap') { const other = personalize(issuerNew()); return { ...chip, dg14: other.dg14, caPriv: other.caPriv }; }
    return chip;
  };
  const read = () => { setR(chipAuthenticate(presented(), iss.dsPub, utf8(DG1))); setRun((x) => x + 1); };
  const pub = chip.dg14.slice(chip.dg14.length - 65);

  return (
    <>
      <Card n={2} title="Personnalisation : ce que l'État émetteur met dans la puce" right={<span className="ctrls">
        <EncodingToggle value={enc} onChange={setEnc} />
        <button className="btn b-ghost b-sm" onClick={renew}><Fad icon={IC.chip} />Nouveau passeport</button>
      </span>}>
        <div className="grid2">
          <div>
            <div className="who" style={{ color: 'var(--c-secret)' }}><Fad icon={IC.private} />Dans la puce, jamais lisible</div>
            <ByteView view={{ title: 'Clé privée de Chip Authentication', caption: 'Tirée à la personnalisation, propre à ce document.', segs: [seg('sk_puce', chip.caPriv, 'priv')] }} encoding={enc} />
          </div>
          <div>
            <div className="who" style={{ color: 'var(--c-pub)' }}><Fad icon={IC.public} />Lisible par tout lecteur</div>
            <ByteView view={{ title: 'DG14 (simplifié) : SecurityInfos', caption: 'OID id-CA-ECDH-AES-CBC-CMAC-256 suivi de la clé publique de la puce.', segs: [seg('6e', chip.dg14.slice(0, 1), 'hdr', 'tag DG14'), seg('OID', chip.dg14.slice(1, 13), 'hdr'), seg('04 41', chip.dg14.slice(13, 15), 'hdr'), seg('PK_puce', pub, 'pub')] }} encoding={enc} />
            <ByteView view={{ title: 'SOD : haché du DG14 signé par le Document Signer', segs: [seg('SHA-256(DG14)', chip.sod.dg14Hash, 'hash'), seg('σ_DS (ECDSA)', chip.sod.sig, 'sig')] }} encoding={enc} />
          </div>
        </div>
      </Card>
      <Card n={3} title="Lecture par le système d'inspection (IS)">
        <Pipeline label="IS" steps={['Lire DG14 + SOD', 'Authentification passive', 'Biclé éphémère IS', 'Envoyer PK_IS', 'Z = ECDH', 'K_Enc, K_MAC', 'Vérifier le MAC']} run={run} />
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div className="segctl">
            <button className={kind === 'genuine' ? 'on' : ''} onClick={() => setKind('genuine')}>puce authentique</button>
            <button className={kind === 'clone' ? 'on' : ''} onClick={() => setKind('clone')}>clone</button>
            <button className={kind === 'swap' ? 'on' : ''} onClick={() => setKind('swap')}>DG14 remplacé</button>
          </div>
          <button className="btn b-pri" onClick={read}><Fad icon={IC.idcard} />Lire le passeport</button>
        </div>
        <div className="meta">{kind === 'clone' ? 'Le clone a copié DG1, DG14 et SOD octet pour octet, mais pas la clé privée : il en utilise une autre.' : kind === 'swap' ? 'Le faussaire met sa propre clé publique dans le DG14 pour pouvoir répondre, sans pouvoir re-signer le SOD.' : 'Une vraie puce, avec sa vraie clé privée.'}</div>
        {r && (
          <>
            <Status s={r.error ? { kind: 'ko', text: r.error } : { kind: 'ok', text: `MAC vérifié : c'est bien la puce dont l'État a signé la clé. Données lues : ${quote(fromUtf8(r.read!), 60)}` }} />
            <div className="meta">Authentification passive : haché du DG14 {r.pa.hashOk ? 'conforme' : 'différent de celui signé'} · signature du SOD {r.pa.sigOk ? 'valide' : 'invalide'}</div>
            <div className="grid2">
              <div>
                <div className="who" style={{ color: 'var(--c-pt)' }}><Fad icon={IC.eye} />Système d'inspection</div>
                <ByteView view={{ title: 'Biclé éphémère (nouvelle à chaque lecture)', segs: [seg('sk_IS', r.eph.priv, 'priv'), seg('PK_IS', r.eph.pub, 'pub')] }} encoding={enc} />
                <ByteView view={{ title: 'Z = x(sk_IS · PK_puce du DG14)', segs: [seg('Z', r.zIS, 'secret')] }} encoding={enc} />
                <ByteView view={{ title: 'Clés de session (KDF ICAO, SHA-256)', segs: [seg('K_Enc = H(Z‖1)', r.isKeys.kEnc, 'key'), seg('K_MAC = H(Z‖2)', r.isKeys.kMac, 'key')] }} encoding={enc} />
              </div>
              <div>
                <div className="who" style={{ color: 'var(--c-pub)' }}><Fad icon={IC.chip} />Puce présentée</div>
                <ByteView view={{ title: 'Z = x(sk_puce · PK_IS)', caption: toHex(r.zChip) === toHex(r.zIS) ? 'Identique à celui de l\'IS.' : 'Différent : la puce n\'a pas la clé privée qui correspond au DG14 lu.', segs: [seg('Z', r.zChip, 'secret')] }} encoding={enc} />
                <ByteView view={{ title: 'Première réponse en Secure Messaging', caption: 'IV = E(K_Enc, SSC), AES-CBC, puis CMAC tronqué à 8 octets.', segs: [seg('SSC', r.resp.ssc, 'nonce'), seg('DO87 (chiffré)', r.resp.ct, 'ct'), seg('DO8E (MAC)', r.resp.mac, 'tag')] }} encoding={enc} />
              </div>
            </div>
          </>
        )}
      </Card>
    </>
  );
}

// ================================================================ Double Ratchet
interface LogLine { m: RatchetMsg; pt: string; eve: string | null | undefined; recvStep: boolean }

function RatchetLab() {
  const init = () => ratchetInit(hkdf(xdh(xPair().priv, xPair().pub), new Uint8Array(0), utf8('X3DH simulé'), 32));
  const [s, setS] = useState(init);
  const [log, setLog] = useState<LogLine[]>([]);
  const [eve, setEve] = useState<Eve | null>(null);
  const [txt, setTxt] = useState<Record<string, string>>({ Alice: 'Salut Bob !', Bob: 'Salut Alice !' });
  const [st, setSt] = useState<St>(null);
  const [tick, setTick] = useState(0);

  const send = (from: 'Alice' | 'Bob') => {
    const me = from === 'Alice' ? s.alice : s.bob;
    const peer = from === 'Alice' ? s.bob : s.alice;
    try {
      const m = ratchetEncrypt(me, utf8(txt[from]));
      const { pt, dhStep } = ratchetDecrypt(peer, m);
      const e = eve ? eveTry(eve, m) : undefined;
      setLog((l) => [...l, { m, pt: fromUtf8(pt), eve: e === undefined ? undefined : e ? fromUtf8(e) : null, recvStep: dhStep }]);
      setSt(null);
      setTick((x) => x + 1);
    } catch (err) {
      setSt({ kind: 'info', text: errText(err) });
    }
  };
  const reset = () => { setS(init()); setLog([]); setEve(null); setSt(null); };

  const State = ({ x }: { x: RatchetState }) => (
    <div className="kx-state">
      <div><span>DHs (sa clé de ratchet)</span><code className="sg t-pub">{short(x.dhs.pub, 8)}</code></div>
      <div><span>RK (clé racine)</span><code className="sg t-secret">{short(x.rk, 8)}</code></div>
      <div><span>CKs (chaîne d'envoi)</span><code className="sg t-key">{x.cks ? short(x.cks, 8) : '—'}</code> <i>n° {x.ns}</i></div>
      <div><span>CKr (chaîne de réception)</span><code className="sg t-key">{x.ckr ? short(x.ckr, 8) : '—'}</code> <i>n° {x.nr}</i></div>
    </div>
  );

  return (
    <>
      <Card n={2} title="Deux appareils, une conversation" right={<span className="ctrls">
        <button className={`btn b-sm ${eve ? 'b-red' : 'b-ghost'}`} disabled={!!eve || log.length === 0} onClick={() => { setEve(eveSteal(s.bob)); setSt({ kind: 'ko', text: 'Ève a copié tout l\'état de Bob : clé racine, chaînes et clé privée de ratchet.' }); }}><Fad icon={IC.attacker} />{eve ? 'État de Bob volé' : 'Ève vole l\'état de Bob'}</button>
        <button className="btn b-ghost b-sm" onClick={reset}><Fad icon={IC.again} />Recommencer</button>
      </span>}>
        <div className="meta">Le secret initial vient d'un X3DH simulé. Bob a publié sa clé de ratchet ; Alice parle la première. Le DH n'a lieu qu'au changement de sens, la KDF symétrique avance à chaque message.</div>
        <Duo
          left={<><State x={s.alice} key={`a${tick}`} /><div className="actions"><input className="t" value={txt.Alice} onChange={(e) => setTxt({ ...txt, Alice: e.target.value })} /><button className="btn b-pri" onClick={() => send('Alice')}><Fad icon={IC.send} />Envoyer</button></div></>}
          right={<><State x={s.bob} key={`b${tick}`} /><div className="actions"><input className="t" value={txt.Bob} onChange={(e) => setTxt({ ...txt, Bob: e.target.value })} /><button className="btn b-teal" onClick={() => send('Bob')}><Fad icon={IC.send} />Envoyer</button></div></>}
        />
        <Status s={st} />
      </Card>
      {log.length > 0 && (
        <Card n={3} title="Ce qui circule, message par message">
          <div className="kx-scroll">
            <table className="kx-table">
              <thead><tr><th>#</th><th>De</th><th>En-tête : clé DH · PN · N</th><th>Clé de message</th><th>Chiffré</th><th>Clair reçu</th>{eve && <th>Ève</th>}</tr></thead>
              <tbody>
                {log.map((l, i) => (
                  <tr key={i}>
                    <td>{i + 1}</td>
                    <td>{l.m.from}{l.m.dhStep && <span className="pill p-nt" title="Nouvelle clé publique de ratchet : le destinataire fait un pas DH">pas DH</span>}</td>
                    <td><code className="sg t-pub">{short(l.m.header.dh, 5)}</code> · {l.m.header.pn} · {l.m.header.n}</td>
                    <td><code className="sg t-key">{short(l.m.mk, 6)}</code></td>
                    <td><code className="sg t-ct">{short(l.m.ct, 6)}</code></td>
                    <td>{quote(l.pt, 40)}</td>
                    {eve && <td>{l.eve === undefined ? '—' : l.eve === null ? <span className="pill p-ok"><Fad icon={IC.heal} /> aveugle</span> : <span className="pill p-ko">lit {quote(l.eve, 20)}</span>}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {eve && log.some((l) => l.eve === null) && <Status s={{ kind: 'ok', text: 'Auto-guérison : un pas DH a eu lieu avec une clé privée tirée après le vol. Ève ne peut plus suivre, même avec tout l\'ancien état.' }} />}
          {eve && !log.some((l) => l.eve === null) && <Status s={{ kind: 'info', text: 'Ève lit tant que la conversation reste sur des clés qu\'elle a copiées. Faites répondre Bob, puis Alice : chaque changement de sens tire une nouvelle paire DH.' }} />}
          <div className="meta">KDF_RK(RK, DH) = HKDF-SHA256 → (RK′, CK) · KDF_CK(CK) : MK = HMAC(CK, 01), CK′ = HMAC(CK, 02) · chiffrement AES-256-GCM, l'en-tête en données associées.</div>
        </Card>
      )}
    </>
  );
}

