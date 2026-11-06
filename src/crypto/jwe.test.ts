import { describe, expect, it } from 'vite-plus/test';
import { compactDecrypt, CompactEncrypt, importJWK } from 'jose';
import { JWE } from './jwe';
import { PKE } from './pke';
import { fromUtf8, toB64url, utf8 } from '../lib/bytes';

const msg = 'Rendez-vous à 14 h, salle 42 — 🔐';
const subtle = globalThis.crypto.subtle;

describe('JWE (RFC 7516)', () => {
  for (const id of Object.keys(JWE)) {
    it(`${JWE[id].alg} : aller-retour, 5 parties, altération refusée`, async () => {
      const { keys } = await PKE[id].keygen();
      const j = await JWE[id].encrypt(keys, utf8(msg));
      expect(j.compact.split('.')).toHaveLength(5);
      expect(fromUtf8(await JWE[id].decrypt(keys, j.compact))).toBe(msg);
      const p = j.compact.split('.');
      const c = p[3];
      p[3] = (c[0] === 'A' ? 'B' : 'A') + c.slice(1);
      await expect(JWE[id].decrypt(keys, p.join('.'))).rejects.toThrow();
    });
  }


  it('RSA-OAEP-256 : notre JWE est déchiffré par la bibliothèque jose', async () => {
    const { keys } = await PKE['rsa-oaep'].keygen();
    const j = await JWE['rsa-oaep'].encrypt(keys, utf8(msg));
    const { plaintext, protectedHeader } = await compactDecrypt(j.compact, keys.oaepPriv);
    expect(protectedHeader.alg).toBe('RSA-OAEP-256');
    expect(fromUtf8(plaintext)).toBe(msg);
  });

  it('ECDH-ES : JWE croisés avec la bibliothèque jose (dans les deux sens)', async () => {
    const { keys } = await PKE.ecies.keygen();
    const j = await JWE.ecies.encrypt(keys, utf8(msg));
    expect(fromUtf8((await compactDecrypt(j.compact, keys.priv)).plaintext)).toBe(msg);
    const pub = await importJWK({ kty: 'EC', crv: 'P-256', x: toB64url(keys.pubRaw.slice(1, 33)), y: toB64url(keys.pubRaw.slice(33)) }, 'ECDH-ES');
    const theirs = await new CompactEncrypt(utf8(msg)).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' }).encrypt(pub);
    expect(fromUtf8(await JWE.ecies.decrypt(keys, theirs))).toBe(msg);
  });

  it('RSA-OAEP-256 : un JWE produit par jose est déchiffré ici', async () => {
    const { keys } = await PKE['rsa-oaep'].keygen();
    const pubJwk = { kty: 'RSA', n: toB64url(bi(keys.n)), e: 'AQAB' };
    const pub = await subtle.importKey('jwk', pubJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    const theirs = await new CompactEncrypt(utf8(msg)).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }).encrypt(pub);
    expect(fromUtf8(await JWE['rsa-oaep'].decrypt(keys, theirs))).toBe(msg);
  });
});

function bi(x: bigint) {
  let h = x.toString(16); if (h.length % 2) h = '0' + h;
  return Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
}
