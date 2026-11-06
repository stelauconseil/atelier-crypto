import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider, createHashHistory, createRootRoute, createRoute, createRouter } from '@tanstack/react-router';
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

// Historique par fragment (#/…) : l'app fonctionne aussi en fichier unique, hébergée n'importe où.
const router = createRouter({ routeTree: root.addChildren(routes), history: createHashHistory() });

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
