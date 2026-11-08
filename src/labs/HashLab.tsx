import { useMemo, useState } from 'react';
import { sha256 } from '@noble/hashes/sha2.js';
import { Fad, IC } from '../lib/icons';
import { concat, fromHex, quote, rand, toHex, utf8, type Bytes } from '../lib/bytes';
import { seg, type View } from '../crypto/types';
import {
  HASHES, TOO_MUCH, avalancheByRounds, roundsToAvalanche, bitDiff, flipBit, hkdfSteps, hmacParts, pwHash, pwMemory, sha256Padded,
  PW_DEFAULTS, type PwAlg, type PwParams,
} from '../crypto/hash';
import { lengthExtend, naiveMac, sha256Rounds } from '../crypto/mac';
import { xPair, xdh } from '../crypto/kex';
import { ByteView, EncodingToggle, type Encoding } from '../components/ByteView';
import { Card, Pipeline, Status, useBusy } from '../components/ui';
import { errText } from './common';
import { usePersisted, z } from '../lib/persist';

type St = { kind: 'ok' | 'ko' | 'info'; text: string } | null;
const hexOr = (h: string): Bytes | null => { try { return fromHex(h); } catch { return null; } };

export function HashLab({ id }: { id: string }) {
  if (id === 'sha256') return <ShaLab />;
  if (id === 'sha3') return <Sha3Lab />;
  if (id === 'blake') return <BlakeLab />;
  if (id === 'hmac') return <HmacLab />;
  if (id === 'hkdf') return <HkdfLab />;
  if (id === 'pwhash') return <PwLab />;
  return null;
}

/** 256 (ou 512) cases : les bits de sortie qui ont changé. */
function BitGrid({ a, b }: { a: Bytes; b: Bytes }) {
  const cells: boolean[] = [];
  for (let i = 0; i < a.length; i++) for (let j = 7; j >= 0; j--) cells.push((((a[i] ^ b[i]) >> j) & 1) === 1);
  return (
    <div className="hx-bits" style={{ gridTemplateColumns: `repeat(${Math.min(64, cells.length)}, 1fr)` }} aria-label="bits modifiés">
      {cells.map((c, i) => <span key={i} className={c ? 'on' : ''} />)}
    </div>
  );
}

// ================================================================ SHA-256
function ShaLab() {
  const [msg, setMsg] = usePersisted('sha256', 'msg', 'abc', z.string());
  const [algo, setAlgo] = usePersisted('sha256', 'algo', 'sha256', z.enum(['sha256', 'sha512']));
  const [bit, setBit] = usePersisted('sha256', 'bit', 0, z.number().int().min(0));
  const [rounds, setRounds] = usePersisted('sha256', 'rounds', 16, z.number().int().min(1).max(64));
  const [enc, setEnc] = useState<Encoding>('hex');
  const m = utf8(msg);
  const p = sha256Padded(m);
  const H = HASHES[algo];
  const nbits = Math.max(8, m.length * 8);
  const b = bit % nbits;
  const m2 = flipBit(m.length ? m : new Uint8Array([0]), b);
  const h1 = H.h(m.length ? m : new Uint8Array([0]));
  const h2 = H.h(m2);
  const d = bitDiff(h1, h2);
  const early = useMemo(() => avalancheByRounds(m, 0), [msg]); // eslint-disable-line react-hooks/exhaustive-deps
  const late = useMemo(() => avalancheByRounds(m, 54), [msg]); // eslint-disable-line react-hooks/exhaustive-deps
  const r1 = sha256Rounds(m.length ? m : new Uint8Array([0]), rounds);
  const r2 = sha256Rounds(m2, rounds);
  const padView: View = {
    title: `Ce que SHA-256 traite : ${p.blocks} bloc${p.blocks > 1 ? 's' : ''} de 64 octets`,
    caption: `${m.length} octets de message, puis 0x80, ${p.zeros.length} zéros et la longueur en bits (${m.length * 8}) sur 8 octets.`,
    block: 64,
    segs: [seg('message', m, 'pt'), seg('80', p.mark, 'hdr', 'premier bit de bourrage'), seg('zéros', p.zeros, 'pad'), seg('longueur', p.len, 'hdr', 'longueur en bits, 64 bits grand-boutiste')],
  };
  return (
    <>
      <Card n={2} title="Le message et son bourrage" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <Pipeline label="SHA-256" steps={['Bourrer', 'Découper en blocs', 'f(H, bloc) × n', 'Haché = état final']} run={1} />
        <label className="f"><span className="lab"><span>Message (UTF-8)</span><span>{m.length} octets{m.length === 55 ? ' : le maximum pour un seul bloc' : ''}</span></span>
          <textarea className="t" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </label>
        <ByteView view={padView} encoding={enc} />
        <ByteView view={{ title: 'SHA-256(message)', segs: [seg('haché', sha256(m), 'hash')] }} encoding={enc} />
      </Card>
      <Card n={3} title="L'effet avalanche : un bit change, la moitié de l'empreinte suit" right={<span className="segctl">
        {(['sha256', 'sha512'] as const).map((x) => <button key={x} className={algo === x ? 'on' : ''} onClick={() => setAlgo(x)}>{HASHES[x].label}</button>)}
      </span>}>
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <label className="f fit" style={{ margin: 0 }}><span className="lab"><span>Bit inversé dans le message</span></span>
            <input className="t mono" type="number" min={0} max={nbits - 1} value={b} onChange={(e) => setBit(Math.max(0, Number(e.target.value) || 0))} style={{ width: 110 }} />
          </label>
          <button className="btn b-ghost" onClick={() => setBit(Math.floor(Math.random() * nbits))}><Fad icon={IC.dice} />Un autre bit</button>
        </div>
        <ByteView view={{ title: `${H.label}(M)`, segs: [seg('h', h1, 'hash')] }} encoding={enc} />
        <ByteView view={{ title: `${H.label}(M avec le bit ${b} inversé)`, segs: [seg('h′', h2, 'hash')] }} encoding={enc} />
        <BitGrid a={h1} b={h2} />
        <Status s={{ kind: 'info', text: `${d} bits sur ${h1.length * 8} ont changé (${((100 * d) / (h1.length * 8)).toFixed(0)} %). Une fonction idéale en change la moitié en moyenne, sans motif visible.` }} />
      </Card>
      <Card n={4} title="Combien de tours faut-il ? SHA-256 réduit">
        <div className="actions" style={{ flexWrap: 'wrap', gap: 12 }}>
          <label className="f" style={{ margin: 0, flex: 1 }}><span className="lab"><span>Tours de la fonction de compression</span><span>{rounds} / 64</span></span>
            <input type="range" min={1} max={64} value={rounds} onChange={(e) => setRounds(Number(e.target.value))} />
          </label>
        </div>
        <AvalancheChart curves={[early, late]} at={rounds} />
        <div className="hx-legend"><span className="c0">bit basculé dans l'octet 0 (mot w₀, utilisé dès le tour 1)</span><span className="c1">dans l'octet 54 (mot w₁₃, utilisé à partir du tour 14)</span></div>
        <ByteView view={{ title: `SHA-256 à ${rounds} tours : M et M avec un bit inversé`, segs: [seg('h', r1, 'hash'), seg('h′', r2, 'hash')] }} encoding={enc} />
        <Status s={{ kind: bitDiff(r1, r2) > 100 ? 'ok' : 'info', text: `${bitDiff(r1, r2)} bits changés à ${rounds} tour${rounds > 1 ? 's' : ''} (bit ${b} du message). Selon l'endroit du bit, l'avalanche est complète après ${roundsToAvalanche(early)} tours (début du bloc) ou ${roundsToAvalanche(late)} tours (fin du bloc). SHA-256 en fait 64 : le reste est la marge face à la cryptanalyse, que « Too Much Crypto » discute (page BLAKE).` }} />
      </Card>
    </>
  );
}

function AvalancheChart({ curves, at }: { curves: number[][]; at: number }) {
  const W = 640, Hh = 150, x = (r: number) => 36 + ((r - 1) / 63) * (W - 50), y = (v: number) => Hh - 22 - (v / 256) * (Hh - 34);
  const path = (c: number[]) => c.map((v, i) => `${i ? 'L' : 'M'}${x(i + 1).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  return (
    <svg viewBox={`0 0 ${W} ${Hh}`} className="hx-chart" role="img" aria-label="Bits de sortie modifiés selon le nombre de tours">
      {[0, 64, 128, 192, 256].map((v) => <g key={v}><line x1={36} x2={W - 14} y1={y(v)} y2={y(v)} className="grid" /><text x={30} y={y(v) + 3} textAnchor="end">{v}</text></g>)}
      {[1, 8, 16, 24, 32, 40, 48, 56, 64].map((r) => <text key={r} x={x(r)} y={Hh - 6} textAnchor="middle">{r}</text>)}
      <line x1={36} x2={W - 14} y1={y(128)} y2={y(128)} className="ideal" />
      {curves.map((c, i) => <path key={i} d={path(c)} className={`curve c${i}`} />)}
      <line x1={x(at)} x2={x(at)} y1={10} y2={Hh - 22} className="at" />
      <text x={W - 16} y={y(128) - 5} textAnchor="end" className="lbl">idéal : 128 bits</text>
    </svg>
  );
}

// ================================================================ SHA-3
function Sha3Lab() {
  const [msg, setMsg] = usePersisted('sha3', 'msg', 'abc', z.string());
  const [algo, setAlgo] = usePersisted('sha3', 'algo', 'sha3_256', z.enum(['sha3_256', 'sha3_512', 'keccak256', 'shake128', 'shake256']));
  const [dk, setDk] = usePersisted('sha3', 'dkLen', 32, z.number().int().min(1).max(512));
  const [enc, setEnc] = useState<Encoding>('hex');
  const H = HASHES[algo];
  const m = utf8(msg);
  const out = H.h(m, { dkLen: dk });
  const r = H.block;
  const c = 200 - r;
  return (
    <>
      <Card n={2} title="Absorber puis essorer : l'éponge" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <Pipeline label="Éponge" steps={['Bourrer (domaine)', 'Absorber r octets', 'Keccak-f × 24', 'Essorer']} run={1} />
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <span className="segctl">
            {(['sha3_256', 'sha3_512', 'keccak256', 'shake128', 'shake256'] as const).map((x) => <button key={x} className={algo === x ? 'on' : ''} onClick={() => setAlgo(x)}>{HASHES[x].label}</button>)}
          </span>
          {H.xof && <label className="f" style={{ margin: 0, flex: 1, minWidth: 220 }}><span className="lab"><span>Longueur de sortie (XOF)</span><span>{dk} octets</span></span>
            <input type="range" min={1} max={256} value={dk} onChange={(e) => setDk(Number(e.target.value))} />
          </label>}
        </div>
        <label className="f"><span className="lab"><span>Message (UTF-8)</span><span>{m.length} octets</span></span>
          <textarea className="t" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </label>
        <div className="hx-sponge">
          <div className="r" style={{ flex: r }}>débit r = {r} octets : reçoit le message, rend la sortie</div>
          <div className="c" style={{ flex: c }}>capacité c = {c} o : jamais publiée</div>
        </div>
        <div className="meta">État de Keccak : 200 octets (5 × 5 mots de 64 bits). {H.build}.</div>
        <ByteView view={{ title: `${H.label}(message)`, segs: [seg(H.xof ? `${dk} octets` : 'haché', out, 'hash')] }} encoding={enc} />
      </Card>
      <Card n={3} title="SHA3-256 contre Keccak-256 : un seul octet de différence">
        <ByteView view={{ title: 'SHA3-256 (FIPS 202) : séparation de domaine 0x06', segs: [seg('SHA3-256', HASHES.sha3_256.h(m), 'hash')] }} encoding={enc} />
        <ByteView view={{ title: 'Keccak-256 (Ethereum, soumission de 2011) : bourrage 0x01', segs: [seg('Keccak-256', HASHES.keccak256.h(m), 'hash')] }} encoding={enc} />
        <Status s={{ kind: 'info', text: `${bitDiff(HASHES.sha3_256.h(m), HASHES.keccak256.h(m))} bits sur 256 diffèrent. Ethereum a figé Keccak avant la normalisation : « SHA-3 » dans un contrat Solidity (keccak256) n'est pas le SHA-3 du NIST.` }} />
        <div className="meta">Pas d'extension de longueur ici : le haché ne montre que r octets de l'état, la capacité reste cachée. SHA-3 peut donc servir de MAC directement (c'est KMAC).</div>
      </Card>
    </>
  );
}

// ================================================================ BLAKE2 / BLAKE3
const BLAKE_VECTORS: Record<string, string> = {
  blake2s: '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9',
  blake2b: '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
  blake3: 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
};

function BlakeLab() {
  const [msg, setMsg] = usePersisted('blake', 'msg', 'Jean-Philippe Aumasson', z.string());
  const [algo, setAlgo] = usePersisted('blake', 'algo', 'blake3', z.enum(['blake2s', 'blake2b', 'blake3']));
  const [keyHex, setKeyHex] = usePersisted('blake', 'key', '', z.string());
  const [enc, setEnc] = useState<Encoding>('hex');
  const [race, setRace] = useState<{ id: string; mbps: number }[] | null>(null);
  const { busy, wrap } = useBusy();
  const H = HASHES[algo];
  const m = utf8(msg);
  const key = hexOr(keyHex);
  const keyOk = !keyHex || (key && (algo === 'blake3' ? key.length === 32 : key.length >= 1 && key.length <= (algo === 'blake2s' ? 32 : 64)));
  const out = keyOk ? H.h(m, { key: key ?? undefined }) : null;
  const vecOk = toHex(H.h(new Uint8Array(0))) === BLAKE_VECTORS[algo];
  const runRace = wrap('race', async () => {
    const data = new Uint8Array(4 << 20).map((_, i) => (i * 167 + 13) & 255);
    const res: { id: string; mbps: number }[] = [];
    for (const hid of ['sha256', 'sha512', 'sha3_256', 'blake2s', 'blake2b', 'blake3']) {
      HASHES[hid].h(data.subarray(0, 1 << 16)); // échauffement
      const t = performance.now();
      HASHES[hid].h(data);
      res.push({ id: hid, mbps: 4 / ((performance.now() - t) / 1000) });
      setRace([...res]);
      await new Promise((r) => setTimeout(r, 10));
    }
  });
  const max = Math.max(...(race ?? []).map((r) => r.mbps), 1);
  return (
    <>
      <Card n={2} title="Hacher, avec ou sans clé" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <span className="segctl">
            {(['blake2s', 'blake2b', 'blake3'] as const).map((x) => <button key={x} className={algo === x ? 'on' : ''} onClick={() => setAlgo(x)}>{HASHES[x].label}</button>)}
          </span>
          <span className="meta">{H.build}</span>
        </div>
        <label className="f"><span className="lab"><span>Message (UTF-8)</span><span>{m.length} octets</span></span>
          <textarea className="t" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </label>
        <div className="row">
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Clé (hex, facultative{algo === 'blake3' ? ' : 32 octets exactement' : ` : 1 à ${algo === 'blake2s' ? 32 : 64} octets`}) : le haché devient un MAC</span></span>
            <input className="t mono" value={keyHex} onChange={(e) => setKeyHex(e.target.value.trim())} placeholder="vide : hachage simple" />
          </label>
          <button className="btn b-ghost" onClick={() => setKeyHex(toHex(rand(32)))}><Fad icon={IC.key} />Clé aléatoire</button>
          <button className="btn b-ghost" onClick={() => setKeyHex('')}>Sans clé</button>
        </div>
        {out ? <ByteView view={{ title: `${H.label}(message${key?.length ? ', clé' : ''})`, segs: [seg(key?.length ? 'MAC' : 'haché', out, key?.length ? 'tag' : 'hash')] }} encoding={enc} />
          : <Status s={{ kind: 'ko', text: 'Clé invalide pour cette variante.' }} />}
        <Status s={{ kind: vecOk ? 'ok' : 'ko', text: `Chaîne vide : ${H.label} donne ${BLAKE_VECTORS[algo].slice(0, 16)}…, ${vecOk ? 'conforme au vecteur officiel' : 'non conforme !'}` }} />
      </Card>
      <Card n={3} title="La course : débit de chaque fonction dans ce navigateur" right={<button className="btn b-pri b-sm" disabled={!!busy} onClick={runRace}><Fad icon={IC.bolt} />{busy ? 'Mesure…' : 'Hacher 4 Mio'}</button>}>
        {race ? (
          <div className="hx-race">
            {race.map((r) => (
              <div key={r.id} className={r.id.startsWith('blake') ? 'b' : ''}>
                <span>{HASHES[r.id].label}</span>
                <span className="bar"><i style={{ width: `${(100 * r.mbps) / max}%` }} /></span>
                <span className="v">{r.mbps.toFixed(0)} Mio/s</span>
              </div>
            ))}
          </div>
        ) : <div className="meta">Lancez la mesure. Implémentations JavaScript (@noble/hashes) : les rapports diffèrent des versions natives, où BLAKE3 profite en plus du SIMD et du parallélisme de son arbre.</div>}
      </Card>
      <Card n={4} title="« Too Much Crypto » : combien de tours suffisent ?">
        <div className="kx-scroll">
          <table className="kx-table hx-tmc">
            <thead><tr><th>Primitive</th><th>Tours normalisés</th><th>Proposés (2019)</th><th></th><th>Où en est l'analyse</th></tr></thead>
            <tbody>
              {TOO_MUCH.map((t) => (
                <tr key={t.algo}>
                  <td><b>{t.algo}</b></td><td>{t.std}</td><td>{t.proposed}</td>
                  <td style={{ minWidth: 120 }}><span className="tmc"><i style={{ width: `${(100 * t.proposed) / t.std}%` }} /></span></td>
                  <td>{t.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="meta">Aumasson, « Too Much Crypto » (2019, Real World Crypto 2020), puis son bilan de 2025 : aucune des réductions proposées n'a été cassée. BLAKE3 met l'idée en pratique avec 7 tours. Les normes (NIST, IETF) n'ont pas bougé. Voir « Pour aller plus loin ».</div>
      </Card>
    </>
  );
}

// ================================================================ HMAC
function HmacLab() {
  const [key, setKey] = usePersisted('hmac', 'key', 'clé secrète partagée', z.string());
  const [msg, setMsg] = usePersisted('hmac', 'msg', 'montant=100&dest=alice', z.string());
  const [suffix, setSuffix] = usePersisted('hmac', 'suffix', '&dest=mallory', z.string());
  const [recv, setRecv] = useState<string | null>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const K = utf8(key);
  const M = utf8(msg);
  const r = hmacParts(K, M);
  const forged = lengthExtend(naiveMac(K, M), K.length, M, utf8(suffix));
  const naiveOk = toHex(naiveMac(K, forged.forgedMsg)) === toHex(forged.forgedTag);
  const hmacForged = hmacParts(K, forged.forgedMsg).tag;
  const recvTag = recv === null ? null : hmacParts(K, utf8(recv)).tag;
  return (
    <>
      <Card n={2} title="Calculer HMAC-SHA-256, étape par étape" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <Pipeline label="HMAC" steps={['K₀ = K complétée à 64 o', 'K₀ ⊕ ipad ‖ M', 'haché intérieur', 'K₀ ⊕ opad ‖ intérieur', 'tag']} run={1} />
        <div className="row">
          <label className="f" style={{ flex: 1 }}><span className="lab"><span>Clé K (UTF-8, secrète)</span><span>{K.length} octets{r.hashedKey ? ' > 64 : hachée' : ''}</span></span>
            <input className="t" value={key} onChange={(e) => setKey(e.target.value)} />
          </label>
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Message M</span><span>{M.length} octets</span></span>
            <input className="t" value={msg} onChange={(e) => { setMsg(e.target.value); setRecv(null); }} />
          </label>
        </div>
        <ByteView view={{ title: 'K₀ : la clé complétée par des zéros jusqu\'à la taille de bloc (64 octets)', block: 16, segs: [seg('K', r.k0.slice(0, r.hashedKey ? 32 : K.length), 'key'), seg('zéros', r.k0.slice(r.hashedKey ? 32 : K.length), 'pad')] }} encoding={enc} />
        <ByteView view={{ title: 'Intérieur : SHA-256((K₀ ⊕ 0x36…) ‖ M)', segs: [seg('K₀ ⊕ ipad', r.ipadKey, 'mask'), seg('M', M, 'pt')] }} encoding={enc} />
        <ByteView view={{ title: 'Haché intérieur', segs: [seg('intérieur', r.inner, 'hash')] }} encoding={enc} />
        <ByteView view={{ title: 'Extérieur : SHA-256((K₀ ⊕ 0x5c…) ‖ intérieur)', segs: [seg('K₀ ⊕ opad', r.opadKey, 'mask'), seg('intérieur', r.inner, 'hash')] }} encoding={enc} />
        <ByteView view={{ title: 'Tag HMAC (32 octets)', segs: [seg('tag', r.tag, 'tag')] }} encoding={enc} />
        <Status s={{ kind: r.ok ? 'ok' : 'ko', text: r.ok ? 'Identique au HMAC de la bibliothèque @noble/hashes.' : 'Différent du HMAC de référence !' }} />
      </Card>
      <Card n={3} title="Le destinataire vérifie">
        <label className="f"><span className="lab"><span>Message reçu (modifiez-le pour simuler une altération)</span></span>
          <input className="t" value={recv ?? msg} onChange={(e) => setRecv(e.target.value)} />
        </label>
        {recvTag && <Status s={toHex(recvTag) === toHex(r.tag) ? { kind: 'ok', text: 'Tag recalculé identique : message authentique.' } : { kind: 'ko', text: `Tag recalculé ${toHex(recvTag).slice(0, 16)}… ≠ tag reçu ${toHex(r.tag).slice(0, 16)}… : message rejeté. (Comparer en temps constant !)` }} />}
        {!recvTag && <div className="meta">Le tag a voyagé avec le message ; seul un détenteur de K peut le recalculer.</div>}
      </Card>
      <Card n={4} title="Pourquoi pas SHA-256(K ‖ M) ? L'extension de longueur">
        <label className="f"><span className="lab"><span>Ce que Mallory veut ajouter, sans connaître K</span></span>
          <input className="t" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
        </label>
        <ByteView view={{ title: 'Message forgé : M ‖ bourrage de K ‖ M ‖ ajout', segs: [seg('M', M, 'pt'), seg('bourrage', forged.glue, 'pad'), seg('ajout', utf8(suffix), 'ct')] }} encoding={enc} />
        <div className="grid2">
          <div>
            <div className="who" style={{ color: 'var(--c-tag)' }}>MAC naïf SHA-256(K ‖ M)</div>
            <ByteView view={{ title: 'Tag fabriqué par Mallory, à partir du seul tag connu', segs: [seg('tag forgé', forged.forgedTag, 'tag')] }} encoding={enc} />
            <Status s={naiveOk ? { kind: 'ko', text: 'Le serveur recalcule SHA-256(K ‖ message forgé) : identique. Falsification acceptée.' } : { kind: 'ok', text: 'Rejet.' }} />
          </div>
          <div>
            <div className="who" style={{ color: 'var(--c-pub)' }}>HMAC</div>
            <ByteView view={{ title: 'Ce que le serveur attend pour ce message', segs: [seg('HMAC', hmacForged, 'tag')] }} encoding={enc} />
            <Status s={{ kind: 'ok', text: 'Le tag de Mallory ne correspond pas : le haché extérieur cache l\'état intérieur, il n\'y a rien à prolonger.' }} />
          </div>
        </div>
      </Card>
    </>
  );
}

// ================================================================ HKDF
type IkmSrc = 'dh' | 'random' | 'password';

function HkdfLab() {
  const [src, setSrc] = usePersisted<IkmSrc>('hkdf', 'src', 'dh', z.enum(['dh', 'random', 'password']));
  const [ikmHex, setIkmHex] = usePersisted('hkdf', 'ikm', () => toHex(xdh(xPair().priv, xPair().pub)), z.string());
  const [pw, setPw] = usePersisted('hkdf', 'password', 'motdepasse123', z.string());
  const [saltHex, setSaltHex] = usePersisted('hkdf', 'salt', () => toHex(rand(32)), z.string());
  const [info, setInfo] = usePersisted('hkdf', 'info', 'atelier v1 : clé de chiffrement client → serveur', z.string());
  const [info2, setInfo2] = usePersisted('hkdf', 'info2', 'atelier v1 : clé de chiffrement serveur → client', z.string());
  const [L, setL] = usePersisted('hkdf', 'L', 42, z.number().int().min(1).max(255 * 32));
  const [enc, setEnc] = useState<Encoding>('hex');
  const ikm = src === 'password' ? utf8(pw) : hexOr(ikmHex);
  const salt = hexOr(saltHex);
  let res: ReturnType<typeof hkdfSteps> | null = null;
  let res2: ReturnType<typeof hkdfSteps> | null = null;
  let err: string | null = null;
  try {
    if (!ikm) throw new Error('IKM : hexadécimal invalide.');
    if (!salt) throw new Error('Sel : hexadécimal invalide.');
    res = hkdfSteps(ikm, salt, utf8(info), L);
    res2 = hkdfSteps(ikm, salt, utf8(info2), L);
  } catch (e) { err = errText(e); }
  const newIkm = (s: IkmSrc) => { setSrc(s); if (s === 'dh') setIkmHex(toHex(xdh(xPair().priv, xPair().pub))); if (s === 'random') setIkmHex(toHex(rand(32))); };
  return (
    <>
      <Card n={2} title="Le secret d'entrée et le contexte" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <Pipeline label="HKDF" steps={['IKM + sel', 'Extract : PRK = HMAC(sel, IKM)', 'Expand : T(1), T(2)…', 'OKM = L premiers octets']} run={1} />
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10 }}>
          <span className="segctl">
            <button className={src === 'dh' ? 'on' : ''} onClick={() => newIkm('dh')}>Z d'un X25519</button>
            <button className={src === 'random' ? 'on' : ''} onClick={() => newIkm('random')}>32 octets aléatoires</button>
            <button className={src === 'password' ? 'on' : ''} onClick={() => newIkm('password')}>un mot de passe</button>
          </span>
        </div>
        {src === 'password'
          ? <label className="f"><span className="lab"><span>Mot de passe</span></span><input className="t" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          : <label className="f"><span className="lab"><span>IKM (hex)</span><span>{ikm?.length ?? 0} octets</span></span><input className="t mono" value={ikmHex} onChange={(e) => setIkmHex(e.target.value)} /></label>}
        {src === 'password' && <Status s={{ kind: 'ko', text: 'HKDF est rapide : appliqué à un mot de passe, il laisse un attaquant essayer des milliards de candidats par seconde. Pour un mot de passe, voir la page PBKDF2 / Argon2.' }} />}
        <div className="row">
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Sel (hex, public, facultatif)</span><span>{salt?.length ?? 0} octets</span></span>
            <input className="t mono" value={saltHex} onChange={(e) => setSaltHex(e.target.value)} placeholder="vide : 32 octets nuls" />
          </label>
          <button className="btn b-ghost" onClick={() => setSaltHex(toHex(rand(32)))}><Fad icon={IC.dice} />Sel aléatoire</button>
          <button className="btn b-ghost" onClick={() => setSaltHex('')}>Sans sel</button>
        </div>
        <div className="row">
          <label className="f" style={{ flex: 3 }}><span className="lab"><span>info (contexte, lié à la clé)</span></span><input className="t" value={info} onChange={(e) => setInfo(e.target.value)} /></label>
          <label className="f" style={{ flex: 1 }}><span className="lab"><span>L (octets)</span></span><input className="t mono" type="number" min={1} max={8160} value={L} onChange={(e) => setL(Math.max(1, Math.min(8160, Number(e.target.value) || 1)))} /></label>
        </div>
        {err && <Status s={{ kind: 'ko', text: err }} />}
      </Card>
      {res && (
        <Card n={3} title="Extract, puis Expand">
          <ByteView view={{ title: 'PRK = HMAC-SHA-256(sel, IKM) : 32 octets uniformes', segs: [seg('PRK', res.prk, 'secret')] }} encoding={enc} />
          <ByteView view={{ title: `Expand : ${res.T.length} bloc${res.T.length > 1 ? 's' : ''} T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i)`, segs: res.T.map((t, i) => seg(`T(${i + 1})`, t, i % 2 ? 'mask' : 'key')) }} encoding={enc} />
          <ByteView view={{ title: `OKM : les ${L} premiers octets`, segs: [seg('OKM', res.okm, 'key')] }} encoding={enc} />
        </Card>
      )}
      {res && res2 && (
        <Card n={4} title="Même secret, autre contexte : clés indépendantes">
          <label className="f"><span className="lab"><span>Second info</span></span><input className="t" value={info2} onChange={(e) => setInfo2(e.target.value)} /></label>
          <ByteView view={{ title: `OKM pour « ${quote(info, 50)} »`, segs: [seg('OKM₁', res.okm, 'key')] }} encoding={enc} />
          <ByteView view={{ title: `OKM pour « ${quote(info2, 50)} »`, segs: [seg('OKM₂', res2.okm, 'key')] }} encoding={enc} />
          <Status s={{ kind: 'info', text: `${bitDiff(res.okm, res2.okm)} bits sur ${L * 8} diffèrent : sans PRK, connaître l'une ne dit rien de l'autre. C'est ainsi que TLS 1.3 tire ses clés client et serveur, de handshake et d'application, d'un même secret.` }} />
        </Card>
      )}
    </>
  );
}

// ================================================================ mots de passe
const PW_LABEL: Record<PwAlg, string> = { pbkdf2: 'PBKDF2-HMAC-SHA256', scrypt: 'scrypt', argon2id: 'Argon2id' };
const fmtDur = (s: number) => {
  if (!isFinite(s)) return '∞';
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 120) return `${s.toFixed(0)} s`;
  if (s < 7200) return `${(s / 60).toFixed(0)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(0)} h`;
  if (s < 3.15e7 * 2) return `${(s / 86400).toFixed(0)} jours`;
  return `${(s / 3.15e7).toLocaleString('fr-FR', { maximumFractionDigits: 0 })} ans`;
};

function PwLab() {
  const [pw, setPw] = usePersisted('pwhash', 'password', 'correct horse battery staple', z.string());
  const [saltHex, setSaltHex] = usePersisted('pwhash', 'salt', () => toHex(rand(16)), z.string());
  const [alg, setAlg] = usePersisted<PwAlg>('pwhash', 'alg', 'argon2id', z.enum(['pbkdf2', 'scrypt', 'argon2id']));
  const [P, setP] = usePersisted<PwParams>('pwhash', 'params', PW_DEFAULTS, z.object({ iterations: z.number().int().min(1), logN: z.number().int().min(1).max(20), r: z.number().int().min(1).max(32), mKiB: z.number().int().min(8), t: z.number().int().min(1), p: z.number().int().min(1).max(4) }));
  const [res, setRes] = useState<{ out: Bytes; ms: number; alg: PwAlg } | null>(null);
  const [st, setSt] = useState<St>(null);
  const [enc, setEnc] = useState<Encoding>('hex');
  const { busy, wrap } = useBusy();
  const salt = hexOr(saltHex);
  const run = wrap('run', async () => {
    setSt(null);
    try {
      if (!salt || salt.length < 8) throw new Error('Le sel doit faire au moins 8 octets (hex).');
      const t = performance.now();
      const out = await pwHash(alg, utf8(pw), salt, P);
      setRes({ out, ms: performance.now() - t, alg });
    } catch (e) { setSt({ kind: 'ko', text: errText(e) }); }
  });
  const num = (k: keyof PwParams, label: string, min: number, max: number) => (
    <label className="f fit" style={{ margin: 0 }}><span className="lab"><span>{label}</span></span>
      <input className="t mono" type="number" min={min} max={max} value={P[k]} style={{ width: 120 }} onChange={(e) => setP({ ...P, [k]: Math.max(min, Math.min(max, Number(e.target.value) || min)) })} />
    </label>
  );
  const mem = pwMemory(alg, P);
  return (
    <>
      <Card n={2} title="Dériver une clé d'un mot de passe" right={<EncodingToggle value={enc} onChange={setEnc} />}>
        <Pipeline label="KDF lente" steps={['mot de passe + sel', alg === 'pbkdf2' ? 'HMAC itéré' : 'remplir la mémoire', alg === 'pbkdf2' ? `× ${P.iterations.toLocaleString('fr-FR')}` : 'accès dépendant des données', 'clé de 32 octets']} run={res ? 1 : 0} />
        <div className="row">
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Mot de passe</span><span>{utf8(pw).length} octets</span></span><input className="t" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          <label className="f" style={{ flex: 2 }}><span className="lab"><span>Sel (hex, public, unique par compte)</span><span>{salt?.length ?? 0} octets</span></span><input className="t mono" value={saltHex} onChange={(e) => setSaltHex(e.target.value)} /></label>
          <button className="btn b-ghost" onClick={() => setSaltHex(toHex(rand(16)))}><Fad icon={IC.dice} />Nouveau sel</button>
        </div>
        <div className="actions" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
          <span className="segctl">
            {(['pbkdf2', 'scrypt', 'argon2id'] as const).map((a) => <button key={a} className={alg === a ? 'on' : ''} onClick={() => { setAlg(a); setRes(null); }}>{PW_LABEL[a]}</button>)}
          </span>
          {alg === 'pbkdf2' && num('iterations', 'Itérations', 1, 5_000_000)}
          {alg === 'scrypt' && <>{num('logN', 'log₂ N', 1, 20)}{num('r', 'r', 1, 32)}{num('p', 'p', 1, 4)}</>}
          {alg === 'argon2id' && <>{num('mKiB', 'Mémoire (Kio)', 8, 262_144)}{num('t', 'Passes t', 1, 10)}{num('p', 'Fils p', 1, 4)}</>}
          <button className="btn b-ghost b-sm" onClick={() => setP(PW_DEFAULTS)}><Fad icon={IC.reset} />Valeurs recommandées</button>
        </div>
        <div className="meta">Mémoire par essai : {mem >= 1 << 20 ? `${(mem / (1 << 20)).toFixed(0)} Mio` : `${mem} octets`}. Recommandations OWASP : PBKDF2-SHA256 600 000 itérations ; scrypt N = 2¹⁷, r = 8 ; Argon2id 19 Mio, t = 2, p = 1.</div>
        <div className="actions"><button className="btn b-pri" disabled={!!busy} onClick={run}><Fad icon={IC.key} />{busy ? 'Dérivation…' : 'Dériver la clé'}</button></div>
        <Status s={st} />
        {res && <ByteView view={{ title: `${PW_LABEL[res.alg]}(mot de passe, sel) : 32 octets, en ${res.ms.toFixed(0)} ms`, segs: [seg('clé', res.out, 'key')] }} encoding={enc} />}
      </Card>
      {res && (
        <Card n={3} title="Ce que cela coûte à un attaquant">
          <div className="kx-scroll">
            <table className="kx-table">
              <thead><tr><th>Dictionnaire</th><th>Candidats</th><th>Ce navigateur (1 cœur)</th><th>1 000 cœurs</th></tr></thead>
              <tbody>
                {[['Mots de passe courants', 1e4], ['rockyou.txt', 1.43e7], ['Grand dictionnaire avec règles', 1e10]].map(([n, c]) => (
                  <tr key={n as string}><td>{n}</td><td>{(c as number).toLocaleString('fr-FR')}</td><td>{fmtDur(((c as number) * res.ms) / 1000)}</td><td>{fmtDur(((c as number) * res.ms) / 1e6)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="meta">Estimation simple : temps mesuré × nombre de candidats. Sur GPU, PBKDF2 va des milliers de fois plus vite qu'ici (il ne demande presque pas de mémoire) ; Argon2id et scrypt bornent ce gain par la mémoire exigée à chaque essai. Le sel, lui, oblige à recommencer pour chaque compte.</div>
        </Card>
      )}
    </>
  );
}
