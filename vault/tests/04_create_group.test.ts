import { test, expect } from '@playwright/test';
import { loginAsTestUser } from './helper/login.ts';

test.beforeEach(async ({ page }) => {
  
  await page.context().clearCookies();
  await loginAsTestUser(page);
  

});
test('creating group', async ({ page }) => {
  
  
  await page.getByRole('button', { name: '☰' }).click();
  await page.getByRole('link', { name: 'Create New Group' }).click();
  await page.getByRole('textbox', { name: 'Group Name:' }).click();
  await page.getByRole('textbox', { name: 'Group Name:' }).fill('test');
  await page.getByRole('button', { name: 'Create Group' }).click();
});