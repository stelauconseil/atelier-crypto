import { ALGO_ICON, Fad, IC } from '../lib/icons';
import { Link, Outlet, useRouterState } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { ALGOS, FAMILIES } from '../data/algos';
import { usePalette } from '../lib/prefs';
import { resetState, savedPages } from '../lib/persist';

export function Layout() {
  const [theme, setTheme] = useState<string>(() => {
    try { return localStorage.getItem('atelier-theme') ?? 'light'; } catch { return 'light'; }
  });
  const [palette, setPalette] = usePalette();
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('atelier-theme', theme); } catch { /* stockage indisponible */ }
  }, [theme]);
  const path = useRouterState({ select: (s) => s.location.pathname });
  const main = useRef<HTMLElement>(null);
  useEffect(() => { main.current?.scrollTo({ top: 0 }); }, [path]);
  // nombre de pages ayant un état conservé : recalculé à chaque navigation, effacement ou retour sur l'onglet
  const [saved, setSaved] = useState(0);
  useEffect(() => {
    const upd = () => setSaved(savedPages().length);
    const t = setTimeout(upd, 300);
    window.addEventListener('atelier-reset', upd);
    window.addEventListener('focus', upd);
    return () => { clearTimeout(t); window.removeEventListener('atelier-reset', upd); window.removeEventListener('focus', upd); };
  }, [path]);
  const clearAll = () => {
    const n = savedPages().length;
    if (n === 0) return;
    if (window.confirm(`Effacer ce que ce navigateur a conservé pour ${n} page${n > 1 ? 's' : ''} (clés, textes, réglages) ?`)) resetState('*');
  };

  return (
    <div className="app">
      <aside className="side">
        <Link to="/" className="brand">
          <span className="logo"><Fad icon={IC.logo} /></span>
          <span><b>Atelier crypto</b><small>chiffrer · signer · voir les octets</small></span>
        </Link>
        <div className="side-scroll">
        <nav className="nav">
          <Link to="/" activeOptions={{ exact: true }} activeProps={{ className: 'active' }}><span><Fad icon={IC.home} />Accueil</span></Link>
          <Link to="/planches" activeProps={{ className: 'active' }}><span><Fad icon={IC.books} />Planches du cours (PDF)</span></Link>
          <Link to="/histoire" activeProps={{ className: 'active' }}><span><Fad icon={IC.history} />Histoire en frise</span></Link>
          <Link to="/notions" activeProps={{ className: 'active' }}><span><Fad icon={IC.notions} />Notions et glossaire</span></Link>
          <Link to="/palette" activeProps={{ className: 'active' }}><span><Fad icon={IC.palette} />Palette des octets</span></Link>
        </nav>
        {FAMILIES.map((f) => (
          <div className="nav-sec" key={f.id}>
            <h4>{f.label}</h4>
            <nav className="nav">
              {ALGOS.filter((a) => a.family === f.id).map((a) => (
                <Link key={a.id} to="/algo/$id" params={{ id: a.id }} activeProps={{ className: 'active' }}>
                  <span><Fad icon={ALGO_ICON[a.id]} />{a.short}</span>
                  <span className="yr">{a.year.slice(0, 4)}</span>
                </Link>
              ))}
            </nav>
          </div>
        ))}
        <div className="side-foot">
          Introduction à la cryptographie moderne
          <br />Benoit LEGER-DERVILLE · Stelau · iDAKTO
        </div>
        </div>
        <div className="side-bar" role="toolbar" aria-label="Réglages">
          <button onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title={theme === 'dark' ? 'Passer au thème clair' : 'Passer au thème sombre'}>
            <Fad icon={theme === 'dark' ? IC.sun : IC.moon} /><span>{theme === 'dark' ? 'Clair' : 'Sombre'}</span>
          </button>
          <button onClick={() => setPalette(palette === 'atelier' ? 'planches' : 'atelier')} title={`Couleurs des octets : ${palette === 'atelier' ? 'atelier' : 'planches PDF'} (cliquer pour changer)`}>
            <Fad icon={IC.palette} /><span>{palette === 'atelier' ? 'Atelier' : 'Planches'}</span>
          </button>
          <button onClick={clearAll} disabled={saved === 0} className="sb-clear"
            title={saved ? `Oublier les clés, textes et réglages conservés dans ce navigateur (${saved} page${saved > 1 ? 's' : ''})` : 'Rien n\'est conservé dans ce navigateur'}>
            <Fad icon={IC.broom} /><span>Oublier</span>{saved > 0 && <i className="sb-count">{saved}</i>}
          </button>
        </div>
      </aside>
      <main className="main" ref={main}>
        <Outlet />
      </main>
    </div>
  );
}
