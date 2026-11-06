import { useEffect, useState } from 'react';

export type Palette = 'atelier' | 'planches';
const listeners = new Set<(p: Palette) => void>();

function read(): Palette {
  try {
    return (localStorage.getItem('atelier-palette') as Palette) || 'atelier';
  } catch {
    return 'atelier';
  }
}

/** Palette des octets partagée entre le menu et la page /palette (préférence locale du lecteur). */
export function usePalette(): [Palette, (p: Palette) => void] {
  const [p, setP] = useState<Palette>(read);
  useEffect(() => {
    listeners.add(setP);
    return () => void listeners.delete(setP);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.palette = p;
  }, [p]);
  const set = (v: Palette) => {
    try { localStorage.setItem('atelier-palette', v); } catch { /* stockage indisponible */ }
    listeners.forEach((l) => l(v));
  };
  return [p, set];
}
