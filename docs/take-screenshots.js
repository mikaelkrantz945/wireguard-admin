const { chromium } = require('playwright');

const BASE = process.env.WG_ADMIN_URL || 'http://localhost:8092';
const EMAIL = process.env.WG_ADMIN_EMAIL || 'admin@example.com';
const PASSWORD = process.env.WG_ADMIN_PASSWORD;
const OUT = __dirname + '/screenshots';

if (!PASSWORD) {
  console.error('Set WG_ADMIN_PASSWORD env var');
  process.exit(1);
}

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });

  // Login
  await page.goto(BASE + '/admin/ui', { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  await page.fill('#loginEmail', EMAIL);
  await page.fill('#loginPass', PASSWORD);
  await page.screenshot({ path: OUT + '/debug-pre-login.png' });
  await page.click('.box button');
  await page.waitForTimeout(2000);
  // Check if must_change_password page appeared
  const cpVisible = await page.$eval('#pgChangePass', el => el.classList.contains('active')).catch(() => false);
  if (cpVisible) {
    console.log('must_change_password detected, skipping');
    await page.fill('#cpPass1', PASSWORD);
    await page.fill('#cpPass2', PASSWORD);
    await page.click('#pgChangePass .box button');
    await page.waitForTimeout(1000);
  }
  await page.waitForSelector('#appView', { state: 'visible', timeout: 10000 });
  await page.waitForTimeout(1000);

  // Dashboard
  await page.screenshot({ path: OUT + '/dashboard.png' });
  console.log('dashboard');

  // Peers
  await page.click('nav button:has-text("Peers")');
  await page.waitForTimeout(800);
  await page.screenshot({ path: OUT + '/peers.png' });
  console.log('peers');

  // Groups
  await page.click('nav button:has-text("Groups")');
  await page.waitForTimeout(800);
  await page.screenshot({ path: OUT + '/groups.png' });
  console.log('groups');

  // ACL Profiles
  await page.click('nav button:has-text("ACL Profiles")');
  await page.waitForTimeout(800);
  await page.screenshot({ path: OUT + '/acl-profiles.png' });
  console.log('acl-profiles');

  // Interfaces
  await page.click('nav button:has-text("Interfaces")');
  await page.waitForTimeout(800);
  await page.screenshot({ path: OUT + '/interfaces.png' });
  console.log('interfaces');

  // API Keys
  await page.click('nav button:has-text("API Keys")');
  await page.waitForTimeout(800);
  await page.screenshot({ path: OUT + '/api-keys.png' });
  console.log('api-keys');

  // Request Logs
  await page.click('nav button:has-text("Request Logs")');
  await page.waitForTimeout(800);
  await page.screenshot({ path: OUT + '/request-logs.png' });
  console.log('request-logs');

  // Login page (fresh)
  await page.evaluate(() => { sessionStorage.clear(); });
  await page.goto(BASE + '/admin/ui');
  await page.waitForTimeout(500);
  await page.screenshot({ path: OUT + '/login.png' });
  console.log('login');

  await browser.close();
  console.log('Done — screenshots in docs/screenshots/');
})();
