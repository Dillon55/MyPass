import { test, expect } from '@playwright/test';
import { loginAsTestUser } from './helper/login.ts';

test.beforeEach(async ({ page }) => {
  await page.context().clearCookies();
  await loginAsTestUser(page);

});

test('add password to group', async ({ page }) => {
  
  await page.getByRole('button', { name: 'Edit Group' }).first().click();
  await page.locator('input[type="checkbox"][name="add_passwords"]').first().check();
  await page.getByRole('button', { name: 'Save Changes' }).click();
  await page.getByRole('button', { name: '☰' }).click();
  await page.getByRole('link', { name: 'Logout' }).click();
});