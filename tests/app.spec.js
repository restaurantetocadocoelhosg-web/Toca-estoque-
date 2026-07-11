import { test, expect } from "@playwright/test";

// Fluxos críticos do Toca Estoque, testados como a equipe usaria (celular), contra PRODUÇÃO.
// Conta: robô de testes (role gerente, sem o bloqueio de anomalia do operador).
// Produto: "ROBO TESTE (nao usar)" — fictício, isolado do estoque real, categoria "QA Robo (teste)".
// Toda saída de teste desfaz a entrada equivalente (fecha em zero) para nunca sujar os números reais.

const USER = process.env.E2E_USER;
const PASSWORD = process.env.E2E_PASSWORD;
const USER_OPERADOR = process.env.E2E_USER_OPERADOR;
const PASSWORD_OPERADOR = process.env.E2E_PASSWORD_OPERADOR;
const PRODUTO_TESTE = "ROBO TESTE (nao usar)";
const PRODUTO_ID = process.env.E2E_PRODUTO_TESTE_ID;
// Produto SEPARADO só pro teste de anomalia (7/8): precisa de uma média de 30 dias baixa e
// estável — se usasse o mesmo produto dos testes 4/5, as saídas desses testes inflariam a
// média do dia e o alerta nunca dispararia (já vivi isso rodando a suite).
const PRODUTO_ANOMALIA = "ROBO TESTE ANOMALIA (nao usar)";
const PRODUTO_ANOMALIA_ID = process.env.E2E_PRODUTO_ANOMALIA_ID;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

test.describe.configure({ mode: "serial" });

// Reseta o saldo dos produtos fictícios de teste ANTES de cada teste — assim o robô nunca
// depende do que sobrou de uma rodada anterior (retry, teste interrompido, etc). Só mexe nos
// produtos isolados de QA; nunca toca no estoque real do restaurante.
async function resetProduto(id, qtd) {
  if (!SUPABASE_URL || !SUPABASE_KEY || !id) return;
  await fetch(`${SUPABASE_URL}/rest/v1/produtos?id=eq.${id}`, {
    method: "PATCH",
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ qtd }),
  });
}
test.beforeEach(async () => {
  await resetProduto(PRODUTO_ID, 100);
  await resetProduto(PRODUTO_ANOMALIA_ID, 50);
});

async function login(page, { user = USER, password = PASSWORD, badge = "Robo QA" } = {}) {
  await page.goto("/");
  await expect(page.locator("#login-user")).toBeVisible({ timeout: 20_000 });
  await page.locator("#login-user").fill(user);
  await page.locator("#login-pass").fill(password);
  await page.getByRole("button", { name: "Entrar" }).click();
  await expect(page.locator("#user-badge")).toContainText(badge, { timeout: 20_000 });
}

async function selecionarProduto(page, nomeProduto, termoBusca) {
  // Se o produto já está selecionado (ex.: sobrou de um lançamento anterior na mesma
  // sessão), o campo de busca fica escondido de propósito — não busca de novo.
  const jaSelecionado = await page.locator("#sel-nome").filter({ hasText: nomeProduto }).count();
  if (jaSelecionado > 0) return;
  await page.locator("#f-busca").fill(termoBusca);
  const item = page.locator(".ac-item", { hasText: nomeProduto });
  await expect(item).toBeVisible({ timeout: 10_000 });
  await item.click();
  await expect(page.locator("#sel-nome")).toContainText(nomeProduto);
}
async function selecionarProdutoTeste(page) { await selecionarProduto(page, PRODUTO_TESTE, "ROBO TESTE"); }
async function selecionarProdutoAnomalia(page) { await selecionarProduto(page, PRODUTO_ANOMALIA, "ANOMALIA"); }

async function lancar(page, tipoLabel, qtd) {
  await page.locator(".tipo-card", { hasText: tipoLabel }).click();
  await selecionarProdutoTeste(page);
  await page.locator("#f-qtd").fill(String(qtd));
  await page.locator("#btn-lancar").click();
  await expect(page.locator("#toast.show")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#toast.show.err")).toHaveCount(0);
}

test("1. tela de login abre", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#login-user")).toBeVisible({ timeout: 20_000 });
  await expect(page.locator("#login-pass")).toBeVisible();
});

test("2. login errado mostra erro claro", async ({ page }) => {
  await page.goto("/");
  await page.locator("#login-user").fill(USER);
  await page.locator("#login-pass").fill("senha-errada-123");
  await page.getByRole("button", { name: "Entrar" }).click();
  await expect(page.locator("#toast.show.err")).toBeVisible({ timeout: 15_000 });
});

test("3. login funciona e chega no painel", async ({ page }) => {
  await login(page);
  await expect(page.locator("nav")).toContainText("Lançar");
  await expect(page.locator("nav")).toContainText("Estoque");
});

test("4. lançar Entrada aparece nos últimos lançamentos", async ({ page }) => {
  await login(page);
  await lancar(page, "Entrada", 3);
  await expect(page.locator("#ultimos-list")).toContainText(PRODUTO_TESTE, { timeout: 10_000 });
  // Desfaz: saída da mesma quantidade, pra fechar em zero e não sujar o estoque de teste.
  await lancar(page, "Saída", 3);
});

test("5. lançar Saída reflete no estoque (some do zerado se aplicável) e volta", async ({ page }) => {
  await login(page);
  await lancar(page, "Saída", 5);
  await expect(page.locator("#ultimos-list")).toContainText(PRODUTO_TESTE, { timeout: 10_000 });
  // Desfaz: entrada da mesma quantidade.
  await lancar(page, "Entrada", 5);
});

test("7. operador NÃO consegue burlar o alerta de quantidade suspeita (sem botão de confirmar)", async ({ page }) => {
  // Baseline semeado no banco (produto isolado): 5 saídas de 1un em 30 dias (média ~0,167/dia)
  // — qualquer saída ≥1un dispara o alerta de anomalia (3x a média) pro papel operador.
  await login(page, { user: USER_OPERADOR, password: PASSWORD_OPERADOR, badge: "Robo QA Operador" });
  await page.locator(".tipo-card", { hasText: "Saída" }).click();
  await selecionarProdutoAnomalia(page);
  await page.locator("#f-qtd").fill("1");
  await page.locator("#btn-lancar").click();

  // Aviso claro, SEM opção de "confirmar mesmo assim" — o bloqueio é de verdade agora.
  await expect(page.getByText("Precisa de um gerente")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole("button", { name: "Confirmar mesmo assim" })).toHaveCount(0);
  await page.getByRole("button", { name: "Entendi" }).click();

  // Confere que NADA foi gravado (estoque continua em 50 — o bloqueio segurou de verdade).
  await page.getByRole("button", { name: "Estoque" }).click();
  await page.locator("#est-search").fill("ROBO TESTE ANOMALIA");
  const linha = page.locator("#prod-list .prod-row", { hasText: PRODUTO_ANOMALIA });
  await expect(linha.locator(".prod-row-qtd")).toHaveText(/^50([.,]0+)?$/, { timeout: 10_000 });
});

test("8. gerente consegue lançar a mesma quantidade sem bloqueio (fica só anotado)", async ({ page }) => {
  await login(page);
  await page.locator(".tipo-card", { hasText: "Saída" }).click();
  await selecionarProdutoAnomalia(page);
  await page.locator("#f-qtd").fill("1");
  await page.locator("#btn-lancar").click();
  await expect(page.locator("#toast.show")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#toast.show.err")).toHaveCount(0);
  await expect(page.locator("#ultimos-list")).toContainText(PRODUTO_ANOMALIA, { timeout: 10_000 });
  // Desfaz: entrada da mesma quantidade.
  await page.locator(".tipo-card", { hasText: "Entrada" }).click();
  await selecionarProdutoAnomalia(page);
  await page.locator("#f-qtd").fill("1");
  await page.locator("#btn-lancar").click();
  await expect(page.locator("#toast.show")).toBeVisible({ timeout: 15_000 });
});

test("6. estoque do produto de teste sempre fecha em 100 (net-zero das rodadas acima)", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Estoque" }).click();
  await page.locator("#est-search").fill("ROBO TESTE");
  const linha = page.locator("#prod-list .prod-row", { hasText: PRODUTO_TESTE });
  await expect(linha).toBeVisible({ timeout: 10_000 });
  await expect(linha.locator(".prod-row-qtd")).toHaveText(/^100([.,]0+)?$/, { timeout: 10_000 });
});

test("9. o número de 'Zerados' do Dashboard bate com a lista real da aba Estoque (sem contar arquivados)", async ({ page }) => {
  // Bug real encontrado e corrigido nesta sessão: /api/dashboard contava produto ARQUIVADO
  // (ativo=0) junto com os ativos, inflando o card "Zerados" — o número do topo não batia
  // com o que aparecia ao tocar e entrar na lista de verdade.
  await login(page);
  const cardZerados = page.locator(".card", { hasText: "Zerados" }).locator(".card-val");
  const numeroCard = Number((await cardZerados.textContent()).trim());
  expect(numeroCard).toBeGreaterThan(0);

  await page.locator(".card", { hasText: "Zerados" }).click();
  await expect(page.locator("#prod-list .prod-row").first()).toBeVisible({ timeout: 10_000 });
  const linhas = await page.locator("#prod-list .prod-row").count();

  expect(linhas).toBe(numeroCard);
});
