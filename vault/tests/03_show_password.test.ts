import { test, expect } from '@playwright/test';
import { loginAsTestUser } from './helper/login.ts';

test.beforeEach(async ({ page }) => {
  await page.context().clearCookies();
  await loginAsTestUser(page);

});



test('show password', async ({ page }) => {
  
  page.once('dialog', dialog => {
    console.log(`Dialog message: ${dialog.message()}`);
    dialog.dismiss().catch(() => {});
  });
  await page.getByRole('button', { name: 'Show' }).nth(0).click();
  await page.getByRole('button', { name: '☰' }).click();
  await page.getByRole('link', { name: 'Logout' }).click();
});