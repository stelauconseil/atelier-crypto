import { describe, expect, it } from 'vite-plus/test';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes128Gcm } from '@hpke/core';
import { concat, flipByte, fromHex, fromUtf8, os2ip, rand, toHex, utf8 } from '../lib/bytes';
import { SYM, aesBlock } from './sym';
import { PKE, HPKE, hpkeSeal, HPKE_INFO } from './pke';
import { SIG, ecdsaWithK, recoverFromReusedK } from './sig';
import { hmacSha256, lengthExtend, mySha256, naiveMac } from './mac';
import { sha256 } from './kdf';
import { p256 } from '@noble/curves/nist.js';

const msg = utf8('Bonjour l\'atelier — message de test');
const aad = utf8('en-tête v1');
const wireOf = (segs: { bytes: Uint8Array }[]) => concat(...segs.map((s) => s.bytes));

describe('symétrique', () => {
  it('AES-128(0, 0) = vecteur de test FIPS', () => {
    expect(toHex(aesBlock(new Uint8Array(16), new Uint8Array(16)))).toBe('66e94bd4ef8a2c3b884cfa59ca342b2e');
  });
  for (const [id, A] of Object.entries(SYM)) {
    it(`${id} : aller-retour, et rejet après altération si AEAD`, async () => {
      const key = rand(A.keyLens.at(-1)!);
      const nonce = rand(A.nonceLen);
      const pt = A.hexPlaintext ? rand(32) : msg;
      const { wire } = await A.encrypt(key, nonce, pt, aad);
      const w = wireOf(wire);
      const { pt: back } = await A.decrypt(key, w, aad);
      expect(toHex(back)).toBe(toHex(pt));
      if (A.aead || id === 'kw') {
        await expect(A.decrypt(key, flipByte(w, w.length - 1).out, aad)).rejects.toThrow();
      }
    });
  }
  it('ECB révèle les blocs répétés', async () => {
    const key = rand(16);
    const { wire } = await SYM.ecb.encrypt(key, new Uint8Array(0), new Uint8Array(32).fill(0x41), aad);
    const c = wire[0].bytes;
    expect(toHex(c.slice(0, 16))).toBe(toHex(c.slice(16, 32)));
  });
  it('CTR est malléable : un bit du chiffré inverse le même bit du clair', async () => {
    const key = rand(16);
    const { wire } = await SYM.ctr.encrypt(key, rand(16), msg, aad);
    const w = wireOf(wire);
    const { pt } = await SYM.ctr.decrypt(key, flipByte(w, 16).out, aad);
    expect(pt[0] ^ msg[0]).toBe(1);
  });
});

describe('chiffrement asymétrique', () => {
  for (const [id, A] of Object.entries(PKE)) {
    it(`${id} : aller-retour et altération`, async () => {
      const { keys } = await A.keygen();
      const { wire } = await A.encrypt(keys, msg);
      const w = wireOf(wire);
      const { pt } = await A.decrypt(keys, w);
      expect(fromUtf8(pt)).toBe(fromUtf8(msg));
      if (id !== 'rsa-textbook') {
        const bad = flipByte(w, w.length - 1).out;
        let failedOrChanged = false;
        try {
          const r = await A.decrypt(keys, bad);
          failedOrChanged = fromUtf8(r.pt) !== fromUtf8(msg);
        } catch {
          failedOrChanged = true;
        }
        expect(failedOrChanged).toBe(true);
      }
    }, 60000);
  }

  it('RSA textbook est déterministe, OAEP non', async () => {
    const { keys } = await PKE['rsa-textbook'].keygen();
    const a = await PKE['rsa-textbook'].encrypt(keys, msg);
    const b = await PKE['rsa-textbook'].encrypt(keys, msg);
    expect(toHex(wireOf(a.wire))).toBe(toHex(wireOf(b.wire)));
    const c = await PKE['rsa-oaep'].encrypt(keys, msg);
    const d = await PKE['rsa-oaep'].encrypt(keys, msg);
    expect(toHex(wireOf(c.wire))).not.toBe(toHex(wireOf(d.wire)));
  });

  it('HPKE maison = HPKE de référence (@hpke/core, RFC 9180)', async () => {
    const { keys } = await HPKE.keygen();
    const { enc, ct } = hpkeSeal(keys.pk, msg);
    const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
    const recipientKey = await suite.kem.importKey('raw', keys.sk.slice().buffer, false);
    const pub = await suite.kem.importKey('raw', keys.pk.slice().buffer, true);
    const rc = await suite.createRecipientContext({ recipientKey: { privateKey: recipientKey, publicKey: pub }, enc: enc.slice().buffer, info: HPKE_INFO.slice().buffer });
    const pt = new Uint8Array(await rc.open(ct.slice().buffer));
    expect(fromUtf8(pt)).toBe(fromUtf8(msg));
  });
});

describe('signatures', () => {
  for (const [id, A] of Object.entries(SIG)) {
    it(`${id} : signe, vérifie, rejette un message modifié`, async () => {
      const { keys } = await A.keygen();
      const { sig } = await A.sign(keys, msg);
      const s = wireOf(sig);
      expect((await A.verify(keys, msg, s)).ok).toBe(true);
      expect((await A.verify(keys, utf8('Bonjour l\'atelier — message de tesT'), s)).ok).toBe(false);
      expect((await A.verify(keys, msg, flipByte(s, 5).out)).ok).toBe(false);
    }, 60000);
  }

  it('ECDSA : le même k pour deux messages révèle la clé privée (PS3)', () => {
    const d = os2ip(p256.utils.randomSecretKey());
    const k = os2ip(p256.utils.randomSecretKey());
    const a = ecdsaWithK(d, k, utf8('message 1'));
    const b = ecdsaWithK(d, k, utf8('message 2'));
    expect(a.r).toBe(b.r);
    expect(recoverFromReusedK(a, b).d).toBe(d);
  });
});

describe('MAC et extension de longueur', () => {
  it('SHA-256 maison = SHA-256 de référence', () => {
    for (const n of [0, 3, 55, 56, 64, 100]) expect(toHex(mySha256(rand(n).fill(7)))).toBe(toHex(sha256(new Uint8Array(n).fill(7))));
  });
  it('SHA-256(K ‖ M) est falsifiable, HMAC non', () => {
    const key = rand(16);
    const m = utf8('montant=10&dest=alice');
    const tag = naiveMac(key, m);
    const { forgedMsg, forgedTag } = lengthExtend(tag, 16, m, utf8('&dest=mallory'));
    expect(toHex(naiveMac(key, forgedMsg))).toBe(toHex(forgedTag));
    expect(toHex(hmacSha256(key, forgedMsg))).not.toBe(toHex(forgedTag));
  });
  it('fromHex', () => expect(toHex(fromHex('de ad be ef'))).toBe('deadbeef'));
  it('fromHex refuse les caractères non hexadécimaux', () => expect(() => fromHex('zz12')).toThrow());
  it('RSA textbook refuse m ≥ n', async () => {
    const { keys } = await PKE['rsa-textbook'].keygen();
    await expect(PKE['rsa-textbook'].encrypt(keys, new Uint8Array(300).fill(0x41))).rejects.toThrow();
  });
});
