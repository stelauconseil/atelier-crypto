import { test, expect, type Page } from '@playwright/test';

/** Rien ne doit dépasser horizontalement de la zone principale. */
async function noOverflow(page: Page) {
  const [sw, cw] = await page.evaluate(() => {
    const m = document.querySelector('.main')!;
    return [m.scrollWidth, m.clientWidth];
  });
  expect(sw, `débordement horizontal : ${sw}px pour ${cw}px`).toBeLessThanOrEqual(cw + 1);
}

async function go(page: Page, hash: string) {
  await page.click(`.side a[href$='#${hash}']`);
  await page.waitForTimeout(400);
}

const lastStatus = (page: Page) => page.locator('.status').last();

const LONG = 'A'.repeat(300);

const CASES: { algo: string; input: string; expect: RegExp; wait?: number }[] = [
  { algo: 'ecb', input: LONG, expect: /Déchiffré/ },
  { algo: 'gcm', input: LONG, expect: /Tag vérifié/ },
  { algo: 'kw', input: 'zz-pas-hexa', expect: /Caractère non hexadécimal/ },
  { algo: 'rsa-textbook', input: LONG, expect: /m doit être strictement inférieur à n/, wait: 2500 },
  { algo: 'rsa-pkcs1', input: LONG, expect: /Message trop long/, wait: 2500 },
  { algo: 'hpke', input: LONG, expect: /Déchiffré avec la clé privée/ },
  { algo: 'mlkem', input: LONG, expect: /Déchiffré avec la clé privée/ },
  { algo: 'ecdsa', input: '🔐 émoji ' + 'x'.repeat(250), expect: /Signature valide/ },
  { algo: 'slhdsa', input: LONG, expect: /Signature valide/, wait: 1500 },
];

let errors: string[] = [];

test.describe('robustesse des ateliers', () => {
  test.beforeEach(async ({ page }) => {
    errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    await page.goto('');
    await page.waitForSelector('.side');
  });

  test.afterEach(() => {
    expect(errors, 'erreurs JavaScript dans la page').toEqual([]);
  });

  for (const c of CASES) {
    test(`${c.algo} : saisie extrême, aucun débordement`, async ({ page }) => {
      await go(page, `/algo/${c.algo}`);
      await page.waitForTimeout(c.wait ?? 800); // génération de biclé
      await page.locator('textarea').first().fill(c.input);
      await page.locator("button:has-text('Chiffrer'), button:has-text('Signer')").first().click();
      await page.waitForTimeout(1200);
      for (const t of ['Déchiffrer', 'Vérifier']) {
        const b = page.locator(`button:has-text('${t}')`);
        if (await b.count()) { await b.first().click(); await page.waitForTimeout(600); }
      }
      await expect(lastStatus(page)).toContainText(c.expect);
      await noOverflow(page);
    });
  }

  test('GCM : clé invalide puis message vide', async ({ page }) => {
    await go(page, '/algo/gcm');
    const key = page.locator('input.t.mono').first();
    await key.fill('zz');
    await page.locator("button:has-text('Chiffrer')").first().click();
    await expect(lastStatus(page)).toContainText(/non hexadécimal/);
    await key.fill('00112233445566778899aabbccddeeff');
    await page.locator('textarea').first().fill('');
    await page.locator("button:has-text('Chiffrer')").first().click();
    await page.locator("button:has-text('Déchiffrer')").first().click();
    await expect(lastStatus(page)).toContainText(/Tag vérifié/);
  });

  test('GCM : un bit altéré donne ⊥', async ({ page }) => {
    await go(page, '/algo/gcm');
    await page.locator("button:has-text('Chiffrer')").first().click();
    await page.locator("button:has-text('Altérer un bit')").click();
    await page.locator("button:has-text('Déchiffrer')").first().click();
    await expect(lastStatus(page)).toContainText(/tag invalide/);
  });

  test('ECDSA : formats JWS et vérification', async ({ page }) => {
    await go(page, '/algo/ecdsa');
    await page.waitForTimeout(600);
    await page.locator("button:has-text('Signer')").first().click();
    await expect(page.locator('.jose .status')).toContainText(/JWS vérifié/);
    await page.click(".jose button:has-text('JWS JSON général')");
    await expect(page.locator('.jose pre.txt').first()).toContainText('"signatures"');
    await noOverflow(page);
  });

  for (const [algo, alg] of [['rsa-oaep', 'RSA-OAEP-256'], ['rsa-pkcs1', 'RSA1_5'], ['ecies', 'ECDH-ES'], ['hpke', 'HPKE-3']]) {
    test(`${algo} : format JWE ${alg} et déchiffrement`, async ({ page }) => {
      await go(page, `/algo/${algo}`);
      await page.waitForTimeout(algo.startsWith('rsa') ? 2500 : 600);
      await page.locator("button:has-text('Chiffrer pour le destinataire')").click();
      await expect(page.locator('.jose .status')).toContainText(/JWE déchiffré/);
      await expect(page.locator('.jose .meta')).toContainText(alg);
      await page.click(".jose button:has-text('JWE JSON général')");
      await expect(page.locator('.jose pre.txt').first()).toContainText('"recipients"');
      await noOverflow(page);
    });
  }

  test('onglets « Pour aller plus loin » et « Le code »', async ({ page }) => {
    await go(page, '/algo/rsa-oaep');
    await page.click(".main-tabs button:has-text('Pour aller plus loin')");
    await expect(page.locator('.adv h3').first()).toBeVisible();
    await page.click(".main-tabs button:has-text('Le code')");
    await expect(page.locator('.code-block').first()).toContainText('mgf1');
    await noOverflow(page);
  });

  test('Notions : extension de longueur avec une suite très longue', async ({ page }) => {
    await go(page, '/notions');
    await page.locator('input.t.mono').nth(1).fill('B'.repeat(400));
    await page.click('text=Forger sans la clé');
    await expect(page.locator('.status').first()).toContainText(/ACCEPTÉ/);
    await noOverflow(page);
  });

  for (const p of ['/histoire', '/palette', '/']) {
    test(`page ${p} : aucun débordement`, async ({ page }) => {
      if (p !== '/') await go(page, p);
      await page.waitForTimeout(600);
      await noOverflow(page);
    });
  }
});
