import { test, expect } from '@playwright/test';

test('user can log in and log out cleanly', async ({ page }) => {
  // Go to homepage and start login flow
  await page.goto('http://localhost:8000/');
  await page.getByRole('link', { name: 'Login' }).click();

  // Fill credentials
  await page.getByRole('textbox', { name: 'Username:' }).fill('test_user');
  await page.getByRole('textbox', { name: 'Password:' }).fill('pass');
  await page.getByRole('button', { name: 'Login' }).click();

  // Complete 2FA
  await page.getByRole('textbox', { name: 'Verification Code' }).fill('123456');
  await page.getByRole('button', { name: 'Verify' }).click();

  // Open menu and click logout
  await page.getByRole('button', { name: '☰' }).click();
  await page.getByRole('link', { name: 'Logout' }).click();

  // ✅ Assertion to confirm logout
  await expect(page.getByRole('link', { name: 'Login' })).toBeVisible();
});
