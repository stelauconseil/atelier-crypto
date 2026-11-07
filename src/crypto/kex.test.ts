import { describe, expect, it } from 'vite-plus/test';
import { toHex, utf8, fromUtf8, fromHex } from '../lib/bytes';
import {
  DH_GROUPS, dhSecret, dhPublic, dhShared, dhCheck, p256Pair, ecdhP256, xPair, xdh, clamp, LOW_ORDER,
  gridSession, recoverable, isSquare, powerTable, edPair, sigmaRun, issuerNew, personalize, cloneChip, chipAuthenticate, iso9797,
  ratchetInit, ratchetEncrypt, ratchetDecrypt, eveSteal, eveTry,
} from './kex';
import { x25519 } from '@noble/curves/ed25519.js';

describe('Diffie-Hellman', () => {
  for (const G of Object.values(DH_GROUPS)) {
    it(`${G.id} : g^ab = g^ba`, () => {
      const a = dhSecret(G), b = dhSecret(G);
      const A = dhPublic(G, a), B = dhPublic(G, b);
      expect(dhShared(G, a, B)).toBe(dhShared(G, b, A));
      expect(dhCheck(G, A)).toBeNull();
    });
  }
  it('DH War (p = 47, g = 26) : racine primitive, la table couvre 1…46, la parité de a fuit', () => {
    const G = DH_GROUPS.dhwar;
    const t = powerTable(G);
    expect(new Set(t.map(String)).size).toBe(46);
    for (let a = 1n; a < 46n; a++) expect(isSquare(G, dhPublic(G, a))).toBe(a % 2n === 0n);
    const T = powerTable(DH_GROUPS.toy);
    expect(T).toHaveLength(11);
    expect(T.every((y) => isSquare(DH_GROUPS.toy, y))).toBe(true);
  });
  it('petit sous-groupe : Y = p − 1 ou 1 refusé, sinon Z ∈ {1, p − 1}', () => {
    const G = DH_GROUPS.ffdhe2048;
    const a = dhSecret(G);
    expect(() => dhShared(G, a, G.p - 1n)).toThrow();
    expect(() => dhShared(G, a, 1n)).toThrow();
    expect([1n, G.p - 1n]).toContain(dhShared(G, a, G.p - 1n, false));
  });
  it('ECDH P-256 : même Z des deux côtés ; point hors courbe refusé', () => {
    const a = p256Pair(), b = p256Pair();
    expect(toHex(ecdhP256(a.priv, b.pub))).toBe(toHex(ecdhP256(b.priv, a.pub)));
    const bad = b.pub.slice(); bad[40] ^= 1;
    expect(() => ecdhP256(a.priv, bad)).toThrow(/Point refusé/);
  });
  it('X25519 : vecteur RFC 7748 §6.1 et point d\'ordre faible refusé', () => {
    const a = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const B = fromHex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    expect(toHex(xdh(a, B))).toBe('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
    expect(toHex(x25519.getPublicKey(a))).toBe('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    expect(() => xdh(xPair().priv, LOW_ORDER.zero)).toThrow();
    const c = clamp(new Uint8Array(32).fill(0xff));
    expect(c[0] & 7).toBe(0); expect(c[31] >> 6).toBe(1);
  });
});

describe('grille statique / éphémère', () => {
  const A = { name: 'A', static: xPair() }, B = { name: 'B', static: xPair() };
  it('statique-statique : Z identique d\'une session à l\'autre', () => {
    const s1 = gridSession(1, A, B, 's', 's', false), s2 = gridSession(2, A, B, 's', 's', false);
    expect(toHex(s1.z)).toBe(toHex(s2.z));
    expect(toHex(s1.key)).toBe(toHex(s2.key));
    const n1 = gridSession(3, A, B, 's', 's', true);
    expect(toHex(n1.z)).toBe(toHex(s1.z));
    expect(toHex(n1.key)).not.toBe(toHex(s1.key));
  });
  it('éphémère-statique : Z neuf, mais la fuite de la clé statique de B rouvre les sessions', () => {
    const s1 = gridSession(1, A, B, 'e', 's', false), s2 = gridSession(2, A, B, 'e', 's', false);
    expect(toHex(s1.z)).not.toBe(toHex(s2.z));
    expect(toHex(xdh(B.static.priv, s1.pubA))).toBe(toHex(s1.z));
    expect(recoverable(s1, 'B')).toBe(true);
    expect(recoverable(s1, 'A')).toBe(false);
  });
  it('éphémère-éphémère : aucune fuite de clé statique ne rouvre la session', () => {
    const s = gridSession(1, A, B, 'e', 'e', false);
    expect(recoverable(s, 'A') || recoverable(s, 'B')).toBe(false);
  });
});

describe('SIGMA', () => {
  const A = { name: 'Alice', sign: edPair() }, B = { name: 'Bob', sign: edPair() };
  it('sans attaque : même Z, signatures acceptées', () => {
    const r = sigmaRun(A, B, true, false);
    expect(toHex(r.zA)).toBe(toHex(r.zB));
    expect(r.aAccepts && r.bAccepts).toBe(true);
  });
  it('homme du milieu sans signatures : accepté, mais deux Z différents connus de Mallory', () => {
    const r = sigmaRun(A, B, false, true);
    expect(r.aAccepts && r.bAccepts).toBe(true);
    expect(toHex(r.zA)).not.toBe(toHex(r.zB));
    expect(toHex(xdh(r.mallory!.mb.priv, r.ea.pub))).toBe(toHex(r.zA));
  });
  it('homme du milieu avec signatures : rejeté des deux côtés', () => {
    const r = sigmaRun(A, B, true, true);
    expect(r.aAccepts).toBe(false);
    expect(r.bAccepts).toBe(false);
  });
});

describe('Chip Authentication', () => {
  const I = issuerNew();
  const data = utf8('P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<');
  it('puce authentique : MAC valide, données lues', () => {
    const r = chipAuthenticate(personalize(I), I.dsPub, data);
    expect(r.error).toBeNull();
    expect(fromUtf8(r.read!)).toBe(fromUtf8(data));
    expect(toHex(r.zIS)).toBe(toHex(r.zChip));
  });
  it('clone (DG14 et SOD copiés, sans la clé privée) : détecté', () => {
    const r = chipAuthenticate(cloneChip(personalize(I)), I.dsPub, data);
    expect(r.pa.sigOk && r.pa.hashOk).toBe(true);
    expect(r.error).toMatch(/MAC/);
  });
  it('DG14 remplacé : l\'authentification passive échoue', () => {
    const c = personalize(I);
    const other = personalize(I);
    const r = chipAuthenticate({ ...c, dg14: other.dg14, caPriv: other.caPriv }, I.dsPub, data);
    expect(r.pa.hashOk).toBe(false);
    expect(r.error).toMatch(/passive/);
  });
  it('bourrage ISO 9797-1 méthode 2', () => {
    expect(iso9797(new Uint8Array(15)).length).toBe(16);
    expect(iso9797(new Uint8Array(16)).length).toBe(32);
    expect(iso9797(new Uint8Array(0))[0]).toBe(0x80);
  });
});

describe('Double Ratchet', () => {
  it('échange aller-retour, clés de message toutes distinctes', () => {
    const { alice, bob } = ratchetInit(new Uint8Array(32).fill(7));
    const seen = new Set<string>();
    const turns: [typeof alice, typeof bob, string][] = [[alice, bob, 'a1'], [alice, bob, 'a2'], [bob, alice, 'b1'], [alice, bob, 'a3'], [bob, alice, 'b2'], [bob, alice, 'b3']];
    for (const [from, to, t] of turns) {
      const m = ratchetEncrypt(from, utf8(t));
      seen.add(toHex(m.mk));
      expect(fromUtf8(ratchetDecrypt(to, m).pt)).toBe(t);
    }
    expect(seen.size).toBe(turns.length);
  });
  it('vol de l\'état de Bob : Ève lit un temps, puis la conversation guérit', () => {
    const { alice, bob } = ratchetInit(new Uint8Array(32).fill(9));
    const send = (f: typeof alice, t: typeof alice, s: string) => { const m = ratchetEncrypt(f, utf8(s)); ratchetDecrypt(t, m); return m; };
    send(alice, bob, 'a1');
    send(bob, alice, 'b1');
    const eve = eveSteal(bob);
    const r = (m: ReturnType<typeof send>) => { const p = eveTry(eve, m); return p ? fromUtf8(p) : null; };
    expect(r(send(bob, alice, 'b2'))).toBe('b2'); // même chaîne d'envoi que celle volée
    expect(r(send(alice, bob, 'a2'))).toBe('a2'); // pas DH calculable avec la clé privée volée de Bob
    expect(r(send(bob, alice, 'b3'))).toBeNull(); // Bob a tiré une nouvelle clé : Ève est aveugle
    expect(r(send(alice, bob, 'a3'))).toBeNull();
  });
});
