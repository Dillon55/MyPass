import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './vault/tests', // or wherever your tests are located
  workers: 1,               // runs tests one at a time
  timeout: 30 * 1000,       // 30s timeout per test
  use: {
    baseURL: 'http://localhost:8000',
    headless: true,         // change to false if debugging
  },
});
