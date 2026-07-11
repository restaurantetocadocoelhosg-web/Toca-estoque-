const { defineConfig, devices } = require("@playwright/test");
const fs = require("fs");
const path = require("path");

// Carrega as credenciais do robô de .env.e2e (arquivo local, fora do git).
try {
  const env = fs.readFileSync(path.join(__dirname, ".env.e2e"), "utf8");
  for (const line of env.split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
} catch {}

module.exports = defineConfig({
  testDir: "./tests",
  timeout: 90_000,
  expect: { timeout: 15_000 },
  retries: 1,
  reporter: [["list"]],
  use: {
    // Aponta direto pra produção (Railway) — é onde a equipe realmente usa o app.
    baseURL: "https://toca-estoque-production.up.railway.app",
    ...devices["Pixel 7"],
    screenshot: "only-on-failure",
  },
});
