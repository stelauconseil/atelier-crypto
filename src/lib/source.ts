// Le code affiché dans l'onglet « Le code » est le code réellement exécuté :
// on importe les fichiers sources bruts (?raw) et on en extrait les déclarations voulues.
import symSrc from '../crypto/sym.ts?raw';
import pkeSrc from '../crypto/pke.ts?raw';
import sigSrc from '../crypto/sig.ts?raw';
import kexSrc from '../crypto/kex.ts?raw';
import kdfSrc from '../crypto/kdf.ts?raw';
import hashSrc from '../crypto/hash.ts?raw';
import macSrc from '../crypto/mac.ts?raw';
import rngSrc from '../crypto/rng.ts?raw';
import bytesSrc from '../lib/bytes.ts?raw';

export const SOURCES: Record<string, string> = {
  'src/crypto/sym.ts': symSrc,
  'src/crypto/pke.ts': pkeSrc,
  'src/crypto/sig.ts': sigSrc,
  'src/crypto/kex.ts': kexSrc,
  'src/crypto/kdf.ts': kdfSrc,
  'src/crypto/hash.ts': hashSrc,
  'src/crypto/mac.ts': macSrc,
  'src/crypto/rng.ts': rngSrc,
  'src/lib/bytes.ts': bytesSrc,
};

export interface Snippet {
  file: string;
  name: string;
  line: number;
  code: string;
}

/** Extrait une déclaration (fonction, constante, objet) et les commentaires qui la précèdent. */
export function extract(file: string, name: string): Snippet | null {
  const lines = SOURCES[file].split('\n');
  const re = new RegExp(`^(export )?(async )?(function|const|let) ${name}\\b`);
  const start = lines.findIndex((l) => re.test(l));
  if (start < 0) return null;
  let end = start;
  const first = lines[start].trimEnd();
  const oneLine = first.endsWith(';') && !/[{([]\s*$/.test(first);
  if (!oneLine) {
    while (end < lines.length - 1 && !/^[}\])]/.test(lines[end + 1])) end++;
    end++;
  }
  let top = start;
  while (top > 0 && /^\s*(\/\/|\/\*\*|\*)/.test(lines[top - 1])) top--;
  return { file, name, line: top + 1, code: lines.slice(top, end + 1).join('\n') };
}

const S = 'src/crypto/sym.ts';
const P = 'src/crypto/pke.ts';
const G = 'src/crypto/sig.ts';
const K = 'src/crypto/kdf.ts';
const B = 'src/lib/bytes.ts';
const X = 'src/crypto/kex.ts';
const HS = 'src/crypto/hash.ts';
const MC = 'src/crypto/mac.ts';
const R = 'src/crypto/rng.ts';

/** Pour chaque algorithme : les déclarations à montrer, dans l'ordre de lecture. */
export const CODE: Record<string, [string, string][]> = {
  ecb: [[S, 'pkcs7'], [S, 'unpkcs7'], [S, 'ECB']],
  cbc: [[S, 'CBC']],
  ctr: [[S, 'CTR']],
  gcm: [[S, 'aesBlock'], [S, 'GCM']],
  gcmsiv: [[S, 'GCMSIV']],
  chacha: [[S, 'CHACHA']],
  kw: [[S, 'KW']],
  'rsa-textbook': [[P, 'rsaKeygen'], [B, 'modPow'], [P, 'rsaPub'], [P, 'rsaPriv'], [P, 'RSA_TEXTBOOK']],
  'rsa-pkcs1': [[P, 'pkcs1v15Encode'], [P, 'RSA_PKCS1V15']],
  'rsa-oaep': [[K, 'mgf1'], [P, 'oaepEncode'], [P, 'RSA_OAEP']],
  'rsa-kem': [[K, 'x963kdf'], [P, 'RSA_KEM']],
  ecies: [[K, 'x963kdf'], [P, 'ECIES']],
  hpke: [[P, 'lExtract'], [P, 'lExpand'], [P, 'hpkeSchedule'], [P, 'hpkeSeal'], [P, 'HPKE']],
  mlkem: [[P, 'MLKEM']],
  hybrid: [[P, 'HYBRID']],
  'rsa-pkcs1-sig': [[G, 'DIGESTINFO_SHA256'], [G, 'openSig'], [G, 'RSA_PKCS1_SIG']],
  'rsa-pss': [[G, 'RSA_PSS'], [G, 'pssDecode']],
  ecdsa: [[G, 'ECDSA'], [G, 'derFromRaw'], [G, 'ecdsaWithK'], [G, 'recoverFromReusedK']],
  ed25519: [[G, 'ED25519']],
  mldsa: [[G, 'MLDSA']],
  slhdsa: [[G, 'SLH'], [G, 'SLHDSA']],
  sha256: [[MC, 'compress'], [MC, 'mdPadding'], [MC, 'sha256Rounds'], [HS, 'bitDiff'], [HS, 'avalancheByRounds']],
  sha3: [[HS, 'HASHES']],
  blake: [[HS, 'HASHES'], [HS, 'TOO_MUCH']],
  hmac: [[HS, 'hmacParts'], [MC, 'naiveMac'], [MC, 'lengthExtend']],
  hkdf: [[HS, 'hkdfSteps']],
  pwhash: [[HS, 'pwMemory'], [HS, 'pwHash'], [HS, 'PW_DEFAULTS']],
  csprng: [[R, 'sourceBytes'], [R, 'stats'], [R, 'verdict']],
  javarandom: [[R, 'JavaRandom'], [R, 'crackJavaRandom']],
  hmacdrbg: [[R, 'drbgUpdate'], [R, 'drbgInstantiate'], [R, 'drbgGenerate'], [R, 'drbgReseed'], [R, 'rfc6979']],
  dualec: [[R, 'dualEcSetup'], [R, 'dualEcStep'], [R, 'dualEcAttack']],
  debian: [[R, 'weakKey'], [R, 'crackWeakKey']],
  dh: [[X, 'DH_GROUPS'], [X, 'dhSecret'], [X, 'dhPublic'], [X, 'dhCheck'], [X, 'dhShared'], [B, 'modPow']],
  ecdh: [[X, 'p256Pair'], [X, 'ecdhP256'], [X, 'compressP256']],
  x25519: [[X, 'clamp'], [X, 'xPair'], [X, 'xdh'], [X, 'LOW_ORDER']],
  'kex-grid': [[X, 'gridSession'], [X, 'recoverable']],
  sigma: [[X, 'sigmaRun']],
  'chip-auth': [[X, 'dg14Of'], [X, 'personalize'], [X, 'cloneChip'], [X, 'passiveAuth'], [X, 'icaoKdf'], [X, 'iso9797'], [X, 'smWrap'], [X, 'smUnwrap'], [X, 'chipAuthenticate']],
  ratchet: [[X, 'kdfRk'], [X, 'kdfCk'], [X, 'ratchetInit'], [X, 'ratchetEncrypt'], [X, 'dhRatchet'], [X, 'ratchetDecrypt'], [X, 'eveSteal'], [X, 'eveTry']],
};
