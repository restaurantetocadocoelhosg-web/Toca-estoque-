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

function urlE2E() {
  const url = process.env.E2E_BASE_URL;
  if (!url) throw new Error("Defina E2E_BASE_URL (ex.: http://127.0.0.1:3000). Os testes E2E não apontam mais para produção por padrão.");
  if (/railway.app|toca-estoque-production/i.test(url) && process.env.E2E_PERMITIR_PRODUCAO !== "1") {
    throw new Error("E2E_BASE_URL aponta para PRODUÇÃO. Esses testes alteram saldo real. Use E2E_PERMITIR_PRODUCAO=1 só com autorização.");
  }
  return url;
}

module.exports = defineConfig({
  testDir: "./tests",
  timeout: 90_000,
  expect: { timeout: 15_000 },
  retries: 1,
  reporter: [["list"]],
  use: {
    // Antes apontava direto para PRODUÇÃO e alterava saldo real. Agora exige E2E_BASE_URL explícito;
    // produção só com E2E_PERMITIR_PRODUCAO=1 (ver test/README.md).
    baseURL: urlE2E(),
    ...devices["Pixel 7"],
    screenshot: "only-on-failure",
  },
});
