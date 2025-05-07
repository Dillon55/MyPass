import { Page } from '@playwright/test';

export async function loginAsTestUser(page: Page) {
  await page.goto('http://localhost:8000/');
  await page.getByRole('link', { name: 'Login' }).click();
  await page.getByRole('textbox', { name: 'Username:' }).fill('test_user');
  await page.getByRole('textbox', { name: 'Password:' }).fill('pass');
  await page.getByRole('button', { name: 'Login' }).click();
  await page.getByRole('textbox', { name: 'Verification Code' }).fill('123456');
  await page.getByRole('button', { name: 'Verify' }).click();
}
