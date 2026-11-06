import { defineConfig, devices } from '@playwright/test';

// Tests de robustesse de l'interface (débordements, saisies extrêmes, erreurs JavaScript).
// Par défaut : build puis `vp preview`. Pour tester un build existant (fichier unique compris) :
//   ATELIER_URL=file:///chemin/dist-single/index.html npx playwright test
const url = process.env.ATELIER_URL;

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 120_000,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL: url ?? 'http://localhost:4173/',
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
  },
  projects: [
    { name: 'large-1440', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
    { name: 'etroit-1100', use: { ...devices['Desktop Chrome'], viewport: { width: 1100, height: 900 } } },
  ],
  webServer: url ? undefined : { command: 'vp build && vp preview --port 4173 --strictPort', url: 'http://localhost:4173/', timeout: 120_000, reuseExistingServer: true },
});
