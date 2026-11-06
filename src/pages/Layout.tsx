import { Link, Outlet, useRouterState } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { ALGOS, FAMILIES } from '../data/algos';
import { usePalette } from '../lib/prefs';

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
          <span className="logo">K</span>
          <span><b>Atelier crypto</b><small>chiffrer · signer · voir les octets</small></span>
        </Link>
        <nav className="nav">
          <Link to="/" activeOptions={{ exact: true }} activeProps={{ className: 'active' }}>Accueil</Link>
          <Link to="/histoire" activeProps={{ className: 'active' }}>Histoire en frise</Link>
          <Link to="/notions" activeProps={{ className: 'active' }}>Notions : MAC, anniversaires…</Link>
          <Link to="/palette" activeProps={{ className: 'active' }}>Palette des octets</Link>
        </nav>
        {FAMILIES.map((f) => (
          <div className="nav-sec" key={f.id}>
            <h4>{f.label}</h4>
            <nav className="nav">
              {ALGOS.filter((a) => a.family === f.id).map((a) => (
                <Link key={a.id} to="/algo/$id" params={{ id: a.id }} activeProps={{ className: 'active' }}>
                  <span>{a.short}</span>
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
            {theme === 'dark' ? '☀ Thème clair' : '☾ Thème sombre'}
          </button>
          <button className="theme-btn" onClick={() => setPalette(palette === 'atelier' ? 'planches' : 'atelier')}>
            Palette : {palette === 'atelier' ? 'atelier' : 'planches PDF'}
          </button>
        </div>
      </aside>
      <main className="main" ref={main}>
        <Outlet />
      </main>
    </div>
  );
}
