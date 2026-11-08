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

  test.afterEach(async ({ page }) => {
    expect(errors, 'erreurs JavaScript dans la page').toEqual([]);
    // Une erreur de rendu attrapée par le routeur n'émet pas de pageerror : on cherche son écran.
    await expect(page.getByText('Something went wrong'), 'écran d\'erreur du routeur').toHaveCount(0);
  });

  test('chaque sélecteur, dans les deux sens, après un premier calcul', async ({ page }) => {
    test.setTimeout(240_000);
    const links = await page.locator('.side a[href*="/algo/"]').evaluateAll((as) => as.map((a) => a.getAttribute('href') ?? ''));
    const fire = async () => {
      const b = page.locator('main button.b-pri');
      for (let i = 0; i < Math.min(await b.count(), 3); i++) if (await b.nth(i).isEnabled()) await b.nth(i).click({ timeout: 5000 }).catch(() => {});
    };
    for (const h of links) {
      await page.click(`.side a[href='${h}']`);
      await page.waitForTimeout(h.includes('rsa') ? 2500 : 400);
      await fire();
      const sels = page.locator('main select');
      for (let s = 0; s < (await sels.count()); s++) {
        const opts = await sels.nth(s).locator('option').evaluateAll((o) => o.map((x) => (x as HTMLOptionElement).value));
        for (const o of [...opts, ...opts.slice().reverse()]) {
          await sels.nth(s).selectOption(o);
          await page.waitForTimeout(100);
          await expect(page.getByText('Something went wrong'), `${h}, sélecteur ${s} = ${o}`).toHaveCount(0);
        }
      }
      const segs = page.locator('main .segctl button');
      for (const i of [...Array(await segs.count()).keys(), ...[...Array(await segs.count()).keys()].reverse()]) {
        await segs.nth(i).click();
        await page.waitForTimeout(80);
        await expect(page.getByText('Something went wrong'), `${h}, bouton segmenté ${i}`).toHaveCount(0);
      }
    }
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

  test('DH : petit sous-groupe, avec et sans validation', async ({ page }) => {
    await go(page, '/algo/dh');
    await page.locator('label.f', { hasText: 'à la place de B' }).locator('select').selectOption('pm1');
    await page.click("button:has-text('Calculer Z')");
    await expect(lastStatus(page)).toContainText(/Valeur refusée/);
    await page.uncheck('text=Alice valide la valeur reçue');
    await page.click("button:has-text('Calculer Z')");
    await expect(lastStatus(page)).toContainText(/Validation désactivée/);
    await page.selectOption('.card select.t >> nth=0', 'ffdhe2048');
    await page.click("button:has-text('Calculer Z')");
    await expect(page.locator('.status').first()).toContainText(/Z identique/);
    await noOverflow(page);
  });

  test('DH : changer de groupe dans tous les sens, après calcul', async ({ page }) => {
    await go(page, '/algo/dh');
    const grp = page.locator('.card select.t').first();
    for (const g of ['p47g26', 'ffdhe2048', 'toy', 'p47g18', 'ffdhe2048', 'p47g31', 'toy']) {
      await page.click("button:has-text('Calculer Z')");
      await grp.selectOption(g);
      await page.click("button:has-text('Calculer Z')");
      await expect(page.locator('.status').first()).toContainText(/Z identique/);
    }
    await grp.selectOption('p47g23');
    await expect(page.locator('.kx-pow td')).toHaveCount(92);
    await expect(page.getByText('tout le monde le voit').first()).toBeVisible();
    await grp.selectOption('p47g12');
    await expect(page.locator('.kx-pow td')).toHaveCount(46);
    await expect(page.getByText('rien à apprendre sur a')).toBeVisible();
  });

  test('X25519 : point d\'ordre faible refusé', async ({ page }) => {
    await go(page, '/algo/x25519');
    await page.click("button:has-text('Calculer Z')");
    await expect(lastStatus(page)).toContainText(/Même Z/);
    await page.locator('label.f', { hasText: 'comme clé publique de Bob' }).locator('select').selectOption('zero');
    await page.click("button:has-text('Calculer Z')");
    await expect(lastStatus(page)).toContainText(/refusée/);
    await noOverflow(page);
  });

  test('Grille : statique × statique répète Z, la fuite rouvre les sessions', async ({ page }) => {
    await go(page, '/algo/kex-grid');
    await page.click('.kx-cell >> nth=0');
    await page.click("button:has-text('Nouvelle session')");
    await page.click("button:has-text('Nouvelle session')");
    await expect(page.locator('code.dup').first()).toBeVisible();
    await page.click("button:has-text('La clé statique de Bob fuit')");
    await expect(page.locator('tr.lost')).toHaveCount(2);
    await page.click('.kx-cell >> nth=3');
    await page.click("button:has-text('Nouvelle session')");
    await expect(page.locator('tr.lost')).toHaveCount(2);
    await expect(page.locator('.kx-uses tbody tr').first()).toBeVisible();
    await noOverflow(page);
  });

  test('SIGMA : Mallory passe sans signatures, échoue avec', async ({ page }) => {
    await go(page, '/algo/sigma');
    await page.click("button:has-text('Lancer l\\'échange')");
    await expect(page.locator('.status').first()).toContainText(/deux secrets différents/);
    await page.check('text=Éphémères signées');
    await page.click("button:has-text('Lancer l\\'échange')");
    await expect(page.locator('.status').first()).toContainText(/Échange refusé/);
    await noOverflow(page);
  });

  test('Chip Authentication : puce authentique, clone, DG14 remplacé', async ({ page }) => {
    await go(page, '/algo/chip-auth');
    await page.click("button:has-text('Lire le passeport')");
    await expect(page.locator('.status').first()).toContainText(/MAC vérifié/);
    await page.click(".segctl button:has-text('clone')");
    await page.click("button:has-text('Lire le passeport')");
    await expect(page.locator('.status').first()).toContainText(/MAC de Secure Messaging invalide/);
    await page.click(".segctl button:has-text('DG14 remplacé')");
    await page.click("button:has-text('Lire le passeport')");
    await expect(page.locator('.status').first()).toContainText(/Authentification passive en échec/);
    await noOverflow(page);
  });

  test('Double Ratchet : vol de l\'état puis auto-guérison', async ({ page }) => {
    await go(page, '/algo/ratchet');
    const send = (who: number) => page.locator("button:has-text('Envoyer')").nth(who).click();
    await send(0); await send(1);
    await page.click("button:has-text('Ève vole')");
    await send(1); await send(0); await send(1); await send(0);
    await expect(page.locator('.kx-table .p-ko').first()).toBeVisible();
    await expect(page.locator('.kx-table .p-ok').first()).toBeVisible();
    await expect(lastStatus(page)).toContainText(/Auto-guérison/);
    await noOverflow(page);
  });

  test('Hachage : chaque page s\'exécute sans erreur ni débordement', async ({ page }) => {
    await go(page, '/algo/sha256');
    await page.locator('textarea').first().fill('x'.repeat(56));
    await expect(page.getByText('2 blocs de 64 octets')).toBeVisible();
    await page.locator('input[type=range]').first().fill('5');
    await noOverflow(page);
    await go(page, '/algo/sha3');
    await page.click(".segctl button:has-text('SHAKE128')");
    await noOverflow(page);
    await go(page, '/algo/blake');
    for (const v of ['BLAKE2s-256', 'BLAKE2b-512', 'BLAKE3']) {
      await page.click(`.segctl button:has-text('${v}')`);
      await expect(page.locator('.status').first()).toContainText(/conforme au vecteur officiel/);
    }
    await page.click("button:has-text('Clé aléatoire')");
    await expect(page.locator('.bv').filter({ hasText: 'MAC' }).first()).toBeVisible();
    await go(page, '/algo/hmac');
    await expect(page.getByText('Identique au HMAC de la bibliothèque')).toBeVisible();
    await expect(page.getByText('Falsification acceptée')).toBeVisible();
    await page.locator('.card').filter({ hasText: 'Le destinataire vérifie' }).locator('input').fill('montant=900&dest=alice');
    await expect(page.getByText('message rejeté')).toBeVisible();
    await go(page, '/algo/hkdf');
    await page.click(".segctl button:has-text('un mot de passe')");
    await expect(page.getByText('HKDF est rapide')).toBeVisible();
    await go(page, '/algo/pwhash');
    await page.click(".segctl button:has-text('PBKDF2')");
    await page.locator('label.f', { hasText: 'Itérations' }).locator('input').fill('2000');
    await page.click("button:has-text('Dériver la clé')");
    await expect(page.getByText('Ce que cela coûte à un attaquant')).toBeVisible({ timeout: 20000 });
    await noOverflow(page);
  });

  test('Aléa : sources, Java prédit, DRBG, Dual_EC et Debian cassés', async ({ page }) => {
    await go(page, '/algo/csprng');
    for (const v of ['compteur', 'RANDU', 'Math.random', 'crypto']) {
      await page.locator('.segctl button', { hasText: v }).first().click();
      await expect(page.locator('.kx-table tbody tr')).toHaveCount(3);
    }
    await expect(page.locator('.rg-bitmap')).toBeVisible();
    await noOverflow(page);
    await go(page, '/algo/javarandom');
    await page.click("button:has-text('Demander un code')");
    await page.click("button:has-text('Demander un code')");
    await page.click("button:has-text('Retrouver l\\'état interne')");
    await page.click("button:has-text('Voir les codes')");
    await expect(page.locator('.status').last()).toContainText(/Tous prédits/);
    await go(page, '/algo/hmacdrbg');
    await page.click("button:has-text('Instancier')");
    await page.click("button:has-text('Generate')");
    await page.click("button:has-text('Reseed')");
    await page.click("button:has-text('Generate')");
    await expect(page.locator('.bv').filter({ hasText: 'Sortie n° 2 · requête 1' })).toBeVisible();
    await page.click("button:has-text('Vecteur RFC 6979')");
    await expect(page.getByText(/exactement la valeur de l'annexe A\.2\.5/)).toBeVisible();
    await noOverflow(page);
    await go(page, '/algo/dualec');
    for (let i = 0; i < 3; i++) await page.click("button:has-text('Produire 31 octets')");
    await page.click("button:has-text('Retrouver l\\'état')");
    await expect(page.getByText('Sortie n° 3, prédite : identique à la vraie')).toBeVisible({ timeout: 20000 });
    await go(page, '/algo/debian');
    await page.click("button:has-text('Lancer la recherche exhaustive')");
    await expect(page.getByText(/Clé privée retrouvée : PID/)).toBeVisible({ timeout: 90000 });
    await noOverflow(page);
  });

  test('Menu : réglages toujours visibles, « Oublier » efface l\'état conservé', async ({ page }) => {
    await expect(page.locator('.side-bar button')).toHaveCount(3);
    await go(page, '/algo/sha256');
    await page.locator('textarea').first().fill('à oublier');
    await page.locator('.side-scroll').evaluate((e) => e.scrollTo(0, e.scrollHeight));
    await expect(page.locator('.side-bar')).toBeInViewport();
    await page.waitForTimeout(500);
    await go(page, '/notions');
    await expect(page.locator('.sb-count')).toBeVisible();
    page.once('dialog', (d) => d.accept());
    await page.click('.sb-clear');
    await expect(page.locator('.sb-clear')).toBeDisabled();
    await go(page, '/algo/sha256');
    await expect(page.locator('textarea').first()).toHaveValue('abc');
  });

  test('Planches : page dédiée, vignettes et liens PDF, rappel dans « Pour aller plus loin »', async ({ page }) => {
    await go(page, '/planches');
    await expect(page.locator('.planche')).toHaveCount(2);
    const hrefs = await page.locator('.planche a:has-text("Télécharger")').evaluateAll((as) => as.map((a) => a.getAttribute('href')));
    expect(hrefs.every((h) => !!h && h.endsWith('.pdf'))).toBe(true);
    const loaded = await page.locator('.pl-page img').evaluateAll(async (imgs) => {
      (imgs as HTMLImageElement[]).forEach((i) => { i.loading = 'eager'; });
      await Promise.all((imgs as HTMLImageElement[]).map((i) => (i.complete ? null : new Promise((r) => { i.onload = r; i.onerror = r; }))));
      return (imgs as HTMLImageElement[]).filter((i) => i.naturalWidth > 0).length;
    });
    expect(loaded).toBe(8);
    await go(page, '/algo/gcm');
    await page.click(".main-tabs button:has-text('Pour aller plus loin')");
    await expect(page.locator('.pl-link')).toHaveCount(3);
    await noOverflow(page);
  });

  test('État conservé : texte et biclé survivent au rechargement, « Réinitialiser » les efface', async ({ page }) => {
    await go(page, '/algo/sha256');
    await page.locator('textarea').first().fill('conservé ?');
    await page.reload();
    await page.waitForTimeout(600);
    await expect(page.locator('textarea').first()).toHaveValue('conservé ?');
    await page.click("button:has-text('Réinitialiser la page')");
    await expect(page.locator('textarea').first()).toHaveValue('abc');
    await go(page, '/algo/ecdsa');
    await expect(page.locator('.status').first()).toContainText(/Biclé générée/);
    const pub1 = await page.locator('.bv').first().innerText();
    await page.reload();
    await page.waitForTimeout(1500);
    await expect(page.locator('.status').first()).toContainText(/reprise de votre dernière visite/);
    expect(await page.locator('.bv').first().innerText()).toBe(pub1);
    await page.click("button.b-pri:has-text('Signer')");
    await expect(page.locator('.jose')).toBeVisible();
  });

  test('Accueil : carrousel, un exemple par famille', async ({ page }) => {
    await go(page, '/');
    const dots = page.locator('.car-dots button');
    await expect(dots).toHaveCount(6);
    for (let i = 0; i < 6; i++) {
      await dots.nth(i).click();
      await page.waitForTimeout(300);
      await expect(page.locator('.car-stage svg')).toBeVisible();
    }
    await page.locator('.carousel a.btn').click();
    await expect(page.locator('.head h1')).toBeVisible();
    await noOverflow(page);
  });

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
