import { ALGO_ICON, Fad, IC } from '../lib/icons';
import { Link, Outlet, useRouterState } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { ALGOS, FAMILIES } from '../data/algos';
import { usePalette } from '../lib/prefs';
import { resetState } from '../lib/persist';

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

  return (
    <div className="app">
      <aside className="side">
        <Link to="/" className="brand">
          <span className="logo"><Fad icon={IC.logo} /></span>
          <span><b>Atelier crypto</b><small>chiffrer · signer · voir les octets</small></span>
        </Link>
        <nav className="nav">
          <Link to="/" activeOptions={{ exact: true }} activeProps={{ className: 'active' }}><span><Fad icon={IC.home} />Accueil</span></Link>
          <Link to="/planches" activeProps={{ className: 'active' }}><span><Fad icon={IC.books} />Planches du cours (PDF)</span></Link>
          <Link to="/histoire" activeProps={{ className: 'active' }}><span><Fad icon={IC.history} />Histoire en frise</span></Link>
          <Link to="/notions" activeProps={{ className: 'active' }}><span><Fad icon={IC.notions} />Notions : MAC, anniversaires…</span></Link>
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
          <button className="theme-btn" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
            <Fad icon={theme === 'dark' ? IC.sun : IC.moon} />{theme === 'dark' ? 'Thème clair' : 'Thème sombre'}
          </button>
          <button className="theme-btn" onClick={() => setPalette(palette === 'atelier' ? 'planches' : 'atelier')}>
            <Fad icon={IC.palette} />Palette : {palette === 'atelier' ? 'atelier' : 'planches PDF'}
          </button>
          <button className="theme-btn" title="Efface les clés, textes et réglages conservés dans ce navigateur pour toutes les pages" onClick={() => { if (window.confirm('Effacer l\'état conservé de toutes les pages (clés, textes, réglages) ?')) resetState('*'); }}>
            <Fad icon={IC.trash} />Effacer l'état de toutes les pages
          </button>
        </div>
      </aside>
      <main className="main" ref={main}>
        <Outlet />
      </main>
    </div>
  );
}
