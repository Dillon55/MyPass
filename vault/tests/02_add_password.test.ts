import { test, expect } from '@playwright/test';
import { loginAsTestUser } from './helper/login.ts';

test.beforeEach(async ({ page }) => {
  await page.context().clearCookies();
  await loginAsTestUser(page);

});

test('add passwords', async ({ page }) => {

  
  await page.getByRole('button', { name: '☰' }).click();
  await page.getByRole('link', { name: 'Add New Password' }).click();
  await page.getByRole('textbox', { name: 'Service Name' }).click();
  await page.getByRole('textbox', { name: 'Service Name' }).fill('netfilx');
  await page.getByRole('textbox', { name: 'Username' }).click();
  await page.getByRole('textbox', { name: 'Username' }).fill('dillon');
  await page.getByRole('textbox', { name: 'Password', exact: true }).click();
  await page.getByRole('textbox', { name: 'Password', exact: true }).fill('pass');
  await page.getByRole('textbox', { name: 'Your Account Password' }).click();
  await page.getByRole('textbox', { name: 'Your Account Password' }).fill('pass');
  await page.getByRole('button', { name: 'Add Password' }).click();
  await page.getByRole('button', { name: '☰' }).click();
  await page.getByRole('link', { name: 'Logout' }).click();
});