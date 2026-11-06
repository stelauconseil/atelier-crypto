import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider, createHashHistory, createMemoryHistory, createRootRoute, createRoute, createRouter } from '@tanstack/react-router';
import './styles.css';
import { Layout } from './pages/Layout';
import { HomePage } from './pages/HomePage';
import { AlgoPage } from './pages/AlgoPage';
import { HistoryPage } from './pages/HistoryPage';
import { NotionsPage } from './pages/NotionsPage';

const root = createRootRoute({ component: Layout });
const routes = [
  createRoute({ getParentRoute: () => root, path: '/', component: HomePage }),
  createRoute({ getParentRoute: () => root, path: '/algo/$id', component: AlgoPage }),
  createRoute({ getParentRoute: () => root, path: '/histoire', component: HistoryPage }),
  createRoute({ getParentRoute: () => root, path: '/notions', component: NotionsPage }),
];

// Historique par fragment (#/…) : l'app fonctionne hébergée n'importe où ou ouverte depuis le disque.
// VITE_HISTORY=memory : historique en mémoire, pour un hébergement en cadre isolé (artefact claude.ai).
const history = import.meta.env.VITE_HISTORY === 'memory' ? createMemoryHistory({ initialEntries: ['/'] }) : createHashHistory();
const router = createRouter({ routeTree: root.addChildren(routes), history });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
