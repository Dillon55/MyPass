import { test, expect } from '@playwright/test';

test('remove passwords from group', async ({ page }) => {
  await page.goto('http://localhost:8000/');
  await page.getByRole('link', { name: 'Login' }).click();
  await page.getByRole('textbox', { name: 'Username:' }).click();
  await page.getByRole('textbox', { name: 'Username:' }).fill('test_user');
  await page.getByRole('textbox', { name: 'Password:' }).click();
  await page.getByRole('textbox', { name: 'Password:' }).fill('pass');
  await page.getByRole('button', { name: 'Login' }).click();
  await page.getByRole('textbox', { name: 'Verification Code' }).click();
  await page.getByRole('textbox', { name: 'Verification Code' }).fill('123456');
  await page.getByRole('button', { name: 'Verify' }).click();
  await page.locator('.group-box > .button-row > a > button').first().click();
  await page.locator('input[name="remove_passwords"]').nth(1).check();
  await page.locator('div:nth-child(4) > span').first().click();
  await page.locator('input[name="remove_passwords"]').nth(2).check();
  await page.getByRole('button', { name: 'Save Changes' }).click();
});