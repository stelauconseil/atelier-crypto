import { describe, expect, it } from 'vite-plus/test';
import { decode, decodeSync, encode, encodeSync, isKeyPair } from './persist';
import { PKE } from '../crypto/pke';
import { SIG } from '../crypto/sig';
import { toHex, utf8 } from './bytes';

describe('persistance : codage JSON', () => {
  it('octets, bigint, objets imbriqués : aller-retour synchrone via JSON', () => {
    const v = { a: new Uint8Array([1, 2, 255]), n: 2n ** 200n + 1n, s: 'é', list: [{ b: new Uint8Array(0) }, 3, true] };
    const back = decodeSync(JSON.parse(JSON.stringify(encodeSync(v)))) as typeof v;
    expect(toHex(back.a)).toBe('0102ff');
    expect(back.n).toBe(v.n);
    expect(back.list[0]).toEqual({ b: new Uint8Array(0) });
    expect(back.s).toBe('é');
  });
  it('biclé RSA-OAEP (bigint + CryptoKey WebCrypto) : rechargée, elle déchiffre encore', async () => {
    const kp = await PKE['rsa-oaep'].keygen();
    const json = JSON.parse(JSON.stringify(await encode(kp)));
    const back = await decode(json);
    expect(isKeyPair(back)).toBe(true);
    const keys = (back as { keys: never }).keys;
    const ct = await PKE['rsa-oaep'].encrypt(keys, utf8('bonjour'));
    const pt = await PKE["rsa-oaep"].decrypt(keys, new Uint8Array(ct.wire.flatMap((s) => [...s.bytes])));
    expect(new TextDecoder().decode(pt.pt)).toBe('bonjour');
  });
  it('biclé ECDSA rechargée : signe et vérifie', async () => {
    const kp = await SIG.ecdsa.keygen();
    const back = (await decode(JSON.parse(JSON.stringify(await encode(kp))))) as { keys: never };
    const s = await SIG.ecdsa.sign(back.keys, utf8('m'));
    const v = await SIG.ecdsa.verify(back.keys, utf8('m'), new Uint8Array(s.sig.flatMap((x) => [...x.bytes])));
    expect(v.ok).toBe(true);
  });
});
