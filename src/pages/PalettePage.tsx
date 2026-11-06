import { useMemo } from 'react';
import { concat, fromHex, rand, utf8 } from '../lib/bytes';
import { seg, type View } from '../crypto/types';
import { ByteView } from '../components/ByteView';
import { Card } from '../components/ui';
import { usePalette } from '../lib/prefs';

const FAMILIES: { tone: string; name: string; roles: string; style?: string }[] = [
  { tone: 'key', name: 'Secret', roles: 'clé symétrique, clé privée, secret partagé ou dérivé' },
  { tone: 'pub', name: 'Public', roles: 'clé publique, points, modules' },
  { tone: 'nonce', name: 'Aléa public', roles: 'IV, nonce, sel, graine' },
  { tone: 'pt', name: 'Clair', roles: 'message en clair' },
  { tone: 'ct', name: 'Chiffré', roles: 'sortie du chiffrement' },
  { tone: 'tag', name: 'Tag', roles: 'tag d\'authentification (AEAD, MAC)' },
  { tone: 'enc', name: 'Encapsulation', roles: 'enc, point éphémère, ct d\'un KEM' },
  { tone: 'sig', name: 'Signature', roles: 'σ, r, s, z…' },
  { tone: 'hash', name: 'Haché', roles: 'H(M), lHash, défi c̃' },
  { tone: 'pad', name: 'Bourrage et masques', roles: 'PS, PKCS#7, flux de clé, maskedDB', style: 'hachures' },
  { tone: 'hdr', name: 'Octets de format', roles: '00 02, 04, DigestInfo, BC, en-têtes DER', style: 'pointillés' },
  { tone: 'aad', name: 'Données associées', roles: 'AAD d\'un AEAD' },
];

export function PalettePage() {
  const [palette, setPalette] = usePalette();
  const samples: View[] = useMemo(() => {
    const ct = rand(40);
    return [
      { title: 'AEAD : nonce ‖ C ‖ tag', segs: [seg('Nonce', rand(12), 'nonce'), seg('Chiffré', ct, 'ct'), seg('Tag', rand(16), 'tag')] },
      { title: 'HPKE : enc ‖ C ‖ tag', segs: [seg('enc', rand(32), 'enc'), seg('C', ct, 'ct'), seg('tag', rand(16), 'tag')] },
      { title: 'PKCS#1 v1.5 : 00 02 PS 00 M', segs: [seg('00 02', fromHex('0002'), 'hdr'), seg('PS', rand(24), 'pad'), seg('00', fromHex('00'), 'hdr'), seg('M', utf8('clé de session'), 'pt')] },
      { title: 'OAEP : lHash ‖ PS ‖ 01 ‖ M', segs: [seg('lHash', rand(32), 'hash'), seg('PS', new Uint8Array(12), 'pad'), seg('01', fromHex('01'), 'hdr'), seg('M', utf8('bonjour'), 'pt')] },
      { title: 'Clé ML-KEM : ŝ ‖ ek ‖ H(ek) ‖ z', segs: [seg('ŝ', rand(24), 'priv'), seg('ek', rand(24), 'pub'), seg('H(ek)', rand(16), 'hash'), seg('z', rand(16), 'salt')] },
      { title: 'ML-DSA : c̃ ‖ z ‖ h', segs: [seg('c̃', rand(16), 'hash'), seg('z', rand(32), 'sig'), seg('h', rand(8), 'hdr')] },
      { title: 'GCM : H ‖ J₀ ‖ E_K(J₀)', segs: [seg('H', rand(16), 'secret'), seg('J₀', concat(rand(12), fromHex('00000001')), 'nonce'), seg('E_K(J₀)', rand(16), 'mask')] },
    ];
  }, []);
  return (
    <div className="page">
      <div className="head"><div><div className="fam">Lisibilité</div><h1>Palette des octets</h1></div>
        <span className="segctl">
          <button className={palette === 'atelier' ? 'on' : ''} onClick={() => setPalette('atelier')}>atelier</button>
          <button className={palette === 'planches' ? 'on' : ''} onClick={() => setPalette('planches')}>planches PDF</button>
        </span>
      </div>
      <Card n={1} title="Douze familles de rôles, une encre chacune">
        <p style={{ margin: '0 0 10px' }}>
          Chaque segment d'octets porte l'encre de son rôle, sur un fond teinté de la même couleur. La palette « atelier » a été choisie par calcul
          sur les juxtapositions réelles de l'app (nonce ‖ C ‖ tag, 00 02 ‖ PS, ŝ ‖ ek…) : écart minimal entre voisins ΔE 7,3 en clair et 6,3 en sombre
          sous simulation protanopie, deutéranopie et tritanopie, et ΔE ≥ 16,9 en vision normale. La couleur n'est jamais seule : chaque segment est nommé dans
          la légende, séparé par un espace, et le bourrage est hachuré, les octets de format en pointillés.
        </p>
        <div className="grid3">
          {FAMILIES.map((f) => (
            <div key={f.tone} className={`lg t-${f.tone}`} style={{ display: 'block', border: '1px solid', borderRadius: 8, padding: '8px 10px' }}>
              <b>{f.name}</b>{f.style && <i style={{ fontStyle: 'normal', opacity: 0.7 }}> · {f.style}</i>}
              <div style={{ fontSize: 12, opacity: 0.85 }}>{f.roles}</div>
              <div className="mono" style={{ marginTop: 4, fontSize: 12 }}>3f a0 9c 51 e2</div>
            </div>
          ))}
        </div>
      </Card>
      <Card n={2} title="En situation, sur des formats réels">
        {samples.map((v) => <ByteView key={v.title} view={v} animate={false} />)}
      </Card>
    </div>
  );
}
