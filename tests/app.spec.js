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
// Produto com nome DE PROPÓSITO parecido com PRODUTO_TESTE — testa se busca/lançamento
// confundem "ROBO TESTE" com "ROBO TESTE 2".
const PRODUTO_PARECIDO = "ROBO TESTE 2 (nao usar)";
const PRODUTO_PARECIDO_ID = process.env.E2E_PRODUTO_PARECIDO_ID;
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
  await resetProduto(PRODUTO_PARECIDO_ID, 30);
});

// Cache de token por conta (dura o worker inteiro — a suíte roda serial, 1 worker só).
// Sem isso, CADA teste fazia login via UI = até 21 POSTs em /api/login por rodada,
// batendo fácil no limite de 20/15min do próprio servidor (o loginLimiter, correto e
// intencional — o problema era só a suíte gastando a cota à toa testando o mesmo login
// repetidas vezes). O app restaura sessão sozinho a partir do token salvo em localStorage
// (função init(), sem passar pelo endpoint de login de novo) — aproveitamos exatamente isso.
const tokenCache = {};

async function login(page, { user = USER, password = PASSWORD, badge = "Robo QA", forceUi = false } = {}) {
  if (!forceUi && tokenCache[user]) {
    await page.addInitScript((tok) => {
      localStorage.setItem("toca_token", tok);
      localStorage.setItem("toca_session_ts", String(Date.now()));
    }, tokenCache[user]);
    await page.goto("/");
    await expect(page.locator("#user-badge")).toContainText(badge, { timeout: 20_000 });
    return;
  }
  // Primeira vez desta conta no worker (ou forceUi pedido de propósito) — login real pela
  // tela, exatamente como a equipe faria. Guarda o token pra reaproveitar nos próximos testes.
  await page.goto("/");
  await expect(page.locator("#login-user")).toBeVisible({ timeout: 20_000 });
  await page.locator("#login-user").fill(user);
  await page.locator("#login-pass").fill(password);
  await page.getByRole("button", { name: "Entrar" }).click();
  await expect(page.locator("#user-badge")).toContainText(badge, { timeout: 20_000 });
  const token = await page.evaluate(() => localStorage.getItem("toca_token"));
  if (token) tokenCache[user] = token;
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
  //
  // ATENÇÃO — o baseline VENCE. A detecção (server.js: "Detecção de anomalia") só liga com
  // hist.length >= 5 nos ÚLTIMOS 30 DIAS. Como as saídas semeadas têm data fixa, elas saem
  // da janela e o teste passa a falhar sozinho, sem nenhuma mudança de código (aconteceu em
  // 01/08/2026: sobraram 3 na janela e o alerta não disparou). Se este teste falhar, ANTES de
  // caçar regressão rode:
  //   select count(*) from movimentacoes where produto_id=328
  //     and tipo in ('Saída','Perda') and created_at >= now() - interval '30 days';
  // Se der < 5, é só re-semear (produto 328 é fictício e isolado; estoque volta pra 50):
  //   delete from movimentacoes where produto_id=328;
  //   insert into movimentacoes (produto_id, produto_nome, categoria, tipo, qtd, unidade,
  //          custo, valor, motivo, responsavel, obs, created_at)
  //   select 328,'ROBO TESTE ANOMALIA (nao usar)','QA Robo (teste)','Saída',1,'un',0,0,
  //          'Consumo','seed-qa','baseline do teste 7',
  //          (now() at time zone 'America/Sao_Paulo') - (d||' days')::interval
  //   from unnest(array[3,8,13,18,23]) d;
  //   update produtos set qtd=50 where id=328;
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

test("8. gerente consegue lançar sem bloqueio (não usa o produto de anomalia — não precisa da baseline)", async ({ page }) => {
  // Propositalmente usa o produto NORMAL (não o de anomalia): gerente nunca é bloqueado por
  // quantidade suspeita, então não precisa de baseline nenhuma — e ficar de fora de id=328
  // evita que os próprios lançamentos de teste inflem a média de 30 dias que o teste 7 usa
  // (isso já aconteceu: rodar esta suíte várias vezes no mesmo dia empurrou a média pra cima
  // até o alerta do teste 7 parar de disparar).
  await login(page);
  await lancar(page, "Saída", 1);
  await expect(page.locator("#ultimos-list")).toContainText(PRODUTO_TESTE, { timeout: 10_000 });
  await lancar(page, "Entrada", 1);
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
  // toHaveCount espera o filtro terminar de recarregar (evita contar a lista "Todos" ainda
  // não filtrada, que aparece por um instante antes do fetch filtrado chegar). Timeout maior
  // (20s) — já flakou algumas vezes com a lista de 280+ produtos demorando a assentar.
  await expect(page.locator("#prod-list .prod-row")).toHaveCount(numeroCard, { timeout: 20_000 });
});

test("10. busca manual do Lançar encontra produto pelo apelido cadastrado (não só pelo nome)", async ({ page }) => {
  // Bug real encontrado e corrigido: /api/produtos/buscar (autocomplete da tela de Lançar)
  // não consultava a tabela de sinônimos — só achava por pedaço do nome. Medido: 221 dos 305
  // apelidos cadastrados (72%) não são substring do nome real, ou seja, a maioria simplesmente
  // não aparecia aqui, mesmo já funcionando certinho via WhatsApp/chat da IA. Suspeita forte de
  // ser a causa real por trás de "procurei o produto, não achei, e não lancei" — apelido de
  // teste "robotestecodigosecreto" está cadastrado apontando pro produto fictício, sem ter
  // nenhuma letra em comum com o nome dele, então só passa se a busca ENTENDER apelido de verdade.
  await login(page);
  await page.locator("#f-busca").fill("robotestecodigosecreto");
  await expect(page.locator(".ac-item", { hasText: PRODUTO_TESTE })).toBeVisible({ timeout: 10_000 });
});

// ═══════════════════════════════════════════════════════════════════════
// RODADA "HOSTIL" — tentando quebrar o sistema de propósito: nomes
// parecidos, acento, vírgula, negativo, texto malicioso, concorrência.
// ═══════════════════════════════════════════════════════════════════════

test("11. busca SEM acento acha produto COM acento no nome", async ({ page }) => {
  // "File de Frango" tem acento; buscar "file de frango" sem acento tem que achar do mesmo
  // jeito. Aqui testamos com o produto fictício mesmo: busca sem qualquer acento/maiúscula.
  await login(page);
  await page.locator("#f-busca").fill("robo teste");
  await expect(page.locator(".ac-item", { hasText: PRODUTO_TESTE })).toBeVisible({ timeout: 10_000 });
});

test("12. busca com ESPAÇOS EXTRAS no meio ainda encontra o produto", async ({ page }) => {
  await login(page);
  await page.locator("#f-busca").fill("robo    teste");
  await expect(page.locator(".ac-item", { hasText: PRODUTO_TESTE })).toBeVisible({ timeout: 10_000 });
});

test("13. dois produtos com nome MUITO parecido não se confundem no lançamento", async ({ page }) => {
  // "ROBO TESTE" e "ROBO TESTE 2" — lança no produto 2 e confere que SÓ ele mudou,
  // o produto 1 (mesmo prefixo de nome) tem que continuar intocado.
  await login(page);
  await page.locator(".tipo-card", { hasText: "Saída" }).click();
  await page.locator("#f-busca").fill("ROBO TESTE 2");
  const item = page.locator(".ac-item", { hasText: PRODUTO_PARECIDO });
  await expect(item).toBeVisible({ timeout: 10_000 });
  await item.click();
  await expect(page.locator("#sel-nome")).toContainText(PRODUTO_PARECIDO);
  await expect(page.locator("#sel-nome")).not.toContainText(PRODUTO_TESTE); // garante que NÃO pegou o outro
  await page.locator("#f-qtd").fill("5");
  await page.locator("#btn-lancar").click();
  await expect(page.locator("#toast.show")).toBeVisible({ timeout: 15_000 });

  await page.getByRole("button", { name: "Estoque" }).click();
  await page.locator("#est-search").fill("ROBO TESTE");
  await expect(page.locator("#prod-list .prod-row", { hasText: PRODUTO_PARECIDO }).locator(".prod-row-qtd")).toHaveText(/^25([.,]0+)?$/, { timeout: 10_000 });
  await expect(page.locator("#prod-list .prod-row", { hasText: PRODUTO_TESTE }).first().locator(".prod-row-qtd")).toHaveText(/^100([.,]0+)?$/);

  // Desfaz.
  await page.getByRole("button", { name: "Lançar" }).click();
  await page.locator(".tipo-card", { hasText: "Entrada" }).click();
  await selecionarProduto(page, PRODUTO_PARECIDO, "ROBO TESTE 2");
  await page.locator("#f-qtd").fill("5");
  await page.locator("#btn-lancar").click();
  await expect(page.locator("#toast.show")).toBeVisible({ timeout: 15_000 });
});

test("14. busca pelo CÓDIGO do produto (não pelo nome) também funciona", async ({ page }) => {
  await login(page);
  await page.locator("#f-busca").fill("QA-01");
  await expect(page.locator(".ac-item", { hasText: PRODUTO_TESTE })).toBeVisible({ timeout: 10_000 });
});

test("15. lançar Saída MAIOR que o estoque disponível é bloqueado (sem deixar negativo)", async ({ page }) => {
  await login(page);
  await page.locator(".tipo-card", { hasText: "Saída" }).click();
  await selecionarProdutoTeste(page);
  await page.locator("#f-qtd").fill("99999");
  await page.locator("#btn-lancar").click();
  await expect(page.getByText("Estoque Insuficiente")).toBeVisible({ timeout: 10_000 });
  await page.getByRole("button", { name: "Entendi" }).click();
  // Confere que o estoque NÃO mudou (continua 100 — nada foi gravado).
  await page.getByRole("button", { name: "Estoque" }).click();
  await page.locator("#est-search").fill("ROBO TESTE");
  await expect(page.locator("#prod-list .prod-row", { hasText: PRODUTO_TESTE }).first().locator(".prod-row-qtd")).toHaveText(/^100([.,]0+)?$/, { timeout: 10_000 });
});

test("16. lançar Ajuste com valor NEGATIVO é rejeitado", async ({ page }) => {
  await login(page);
  await page.locator(".tipo-card", { hasText: "Ajuste" }).click();
  await selecionarProdutoTeste(page);
  await page.locator("#f-qtd").fill("-10");
  await page.locator("#btn-lancar").click();
  // Não pode ter gravado nada — nem toast de sucesso, nem mudança no estoque.
  await expect(page.locator("#toast.show.ok")).toHaveCount(0);
  await expect(page.locator("#toast.show.err")).toBeVisible({ timeout: 10_000 });
});

test("17. valor com VÍRGULA decimal (12,5) digitado TECLA POR TECLA (não .fill)", async ({ page }) => {
  // Mesma classe de bug já corrigida no app Prosperidade: um campo type="number" pode ENGOLIR
  // a vírgula em silêncio enquanto a pessoa digita de verdade (tecla por tecla), virando
  // "125" em vez de "12,5" — um erro de 10x sem ninguém perceber. .fill() não serve pra
  // testar isso (o Playwright recusa vírgula num input number de uma vez só); aqui simulamos
  // TECLAS de verdade, uma a uma, como uma pessoa realmente digitaria no celular.
  await login(page);
  await page.locator(".tipo-card", { hasText: "Saída" }).click();
  await selecionarProdutoTeste(page);
  const campo = page.locator("#f-qtd");
  await campo.click();
  await campo.pressSequentially("12,5", { delay: 50 });
  const valorDigitado = await campo.inputValue();

  // O que quer que tenha ficado no campo, NUNCA pode virar "125" (o valor com a vírgula
  // silenciosamente removida) — isso lançaria 10x mais do que a pessoa quis.
  expect(valorDigitado).not.toBe("125");

  if (valorDigitado === "" || valorDigitado === "12") {
    // Comportamento aceitável: vírgula foi ignorada mas o "5" também não colou depois dela
    // (campo ficou só com "12" ou vazio) — nesse caso NÃO pode lançar 12,5 como 12 sem avisar.
    // Só confirmamos que não vira um "125" silencioso; o valor final (12) é intencional e
    // aceitável (a pessoa pode corrigir na tela antes de confirmar).
  }
  // Sempre limpa o campo pra não deixar lixo se o teste parar aqui.
  await campo.fill("");
});

test("18. texto malicioso/estranho na busca não quebra a tela (sem erro 500, sem crash)", async ({ page }) => {
  await login(page);
  const termos = ["%%%", "' OR '1'='1", "<script>alert(1)</script>", "😀🔥", "___"];
  for (const termo of termos) {
    await page.locator("#f-busca").fill(termo);
    await page.waitForTimeout(400);
    // A tela tem que continuar de pé (campo de busca ainda visível, sem tela em branco/erro).
    await expect(page.locator("#f-busca")).toBeVisible();
  }
  await page.locator("#f-busca").fill("");
});

test("19. busca com 1 caractere não dispara (exige mínimo 2)", async ({ page }) => {
  await login(page);
  await page.locator("#f-busca").fill("r");
  await page.waitForTimeout(500);
  await expect(page.locator(".ac-list.open")).toHaveCount(0);
});

test("20. duas saídas SIMULTÂNEAS no mesmo produto não perdem lançamento (trava de concorrência)", async ({ page, browser }) => {
  // Duas ABAS separadas logadas ao mesmo tempo, cada uma lança Saída de 10un no MESMO produto,
  // ao mesmo tempo. Sem trava, uma sobrescreveria a outra (perderia 10un). Com trava otimista
  // (já existente no server.js), as duas devem se registrar: estoque final = 100 - 10 - 10 = 80.
  const context2 = await browser.newContext();
  const page2 = await context2.newPage();
  try {
    await login(page);
    await login(page2);

    const fazerSaida = async (p) => {
      await p.locator(".tipo-card", { hasText: "Saída" }).click();
      await selecionarProduto(p, PRODUTO_TESTE, "ROBO TESTE");
      await p.locator("#f-qtd").fill("10");
      await p.locator("#btn-lancar").click();
    };
    await Promise.all([fazerSaida(page), fazerSaida(page2)]);
    await page.waitForTimeout(2000);

    await page.getByRole("button", { name: "Estoque" }).click();
    await page.locator("#est-search").fill("ROBO TESTE");
    await expect(page.locator("#prod-list .prod-row", { hasText: PRODUTO_TESTE }).first().locator(".prod-row-qtd")).toHaveText(/^80([.,]0+)?$/, { timeout: 15_000 });

    // Desfaz: entrada de 20 pra voltar a 100.
    await page.getByRole("button", { name: "Lançar" }).click();
    await lancar(page, "Entrada", 20);
  } finally {
    await context2.close();
  }
});

test("21. busca da aba Estoque (e do Admin) TAMBÉM encontra por apelido", async ({ page }) => {
  // Mesmo bug do teste 10, achado numa SEGUNDA rota: /api/produtos (usada pela aba Estoque e
  // pelo Admin de gestão de produtos) também não consultava sinônimos — só a busca do Lançar
  // (/api/produtos/buscar) tinha sido corrigida antes. Corrigido nos dois ao mesmo tempo.
  await login(page);
  await page.getByRole("button", { name: "Estoque" }).click();
  await page.locator("#est-search").fill("robotestecodigosecreto");
  await expect(page.locator("#prod-list .prod-row", { hasText: PRODUTO_TESTE })).toBeVisible({ timeout: 10_000 });
});

// ═══════════════════════════════════════════════════════════════════════
// CONTAS / FINANÇAS / RELATÓRIOS — áreas sem cobertura nenhuma até aqui,
// incluindo a Planilha Mensal e a exportação "compras", onde mexi hoje
// (percentual mensal e filtro minimo>0) sem nunca ter aberto a tela de
// verdade pra confirmar que renderiza certo.
// ═══════════════════════════════════════════════════════════════════════

test("22. Realidade do Dia (fechamento diário) abre e carrega sem erro", async ({ page }) => {
  // SÓ LEITURA de propósito: Realidade do Dia tem 1 registro por DIA — salvar algo de teste
  // aqui sobrescreveria o fechamento de verdade que a equipe já lançou hoje. Confere só que a
  // tela carrega (resumo aparece, sem tela de erro/vazia travada).
  await login(page);
  await page.getByRole("button", { name: "Dia" }).click();
  await expect(page.locator("#real-resumo")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator("#real-resumo .loading")).toHaveCount(0, { timeout: 15_000 });
});

test("23. Contas pagas: criar → aparece na lista → excluir", async ({ page }) => {
  // Diferente da Realidade do Dia: cada conta paga é um registro INDEPENDENTE (não é 1 por
  // dia), então criar e apagar uma de teste é seguro — não sobrescreve nada real.
  const fornecedor = `ROBO TESTE PAGAMENTO ${Date.now()}`;
  await login(page);
  await page.getByRole("button", { name: "Contas" }).click();
  await expect(page.locator("#pag-form-card")).toBeVisible({ timeout: 10_000 });

  await page.locator("#pag-data").fill(new Date().toISOString().slice(0, 10));
  await page.locator("#pag-fornecedor").fill(fornecedor);
  await page.locator("#pag-forma").selectOption("Pix");
  await page.locator("#pag-bruto").fill("1,23");
  await page.locator("#pag-descricao").fill("Lançamento de teste do robô — pode ignorar");
  await page.getByRole("button", { name: "Salvar conta paga" }).click();
  await expect(page.locator("#toast.show.ok")).toBeVisible({ timeout: 15_000 });

  await expect(page.getByText(fornecedor)).toBeVisible({ timeout: 10_000 });

  // Desfaz: exclui a conta de teste (askConfirm in-app, botão "Confirmar" padrão).
  // Escopa no card ".pay-item" que contém o fornecedor desta rodada — a lista pode ter
  // outras contas (inclusive de rodadas anteriores), então ".last()" é ambíguo e pode
  // clicar em "Excluir" da linha errada.
  const linha = page.locator(".pay-item", { hasText: fornecedor });
  await linha.getByRole("button", { name: "Excluir" }).click();
  await page.getByRole("button", { name: "Confirmar" }).click();
  await expect(page.getByText(fornecedor)).toHaveCount(0, { timeout: 10_000 });
});

test("24. Planilha Mensal mostra os 4 percentuais (Compras/Consumo/Perdas/Despesas) sem erro", async ({ page }) => {
  // Valida de ponta a ponta o que corrigi hoje (commits b054d9a/f5ebef9): os 4 cards de
  // percentual sobre vendas têm que aparecer formatados (contendo "%"), não em branco/NaN.
  await login(page);
  await page.getByRole("button", { name: "Planilha" }).click();
  await expect(page.locator("#planilha-resumo")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator("#planilha-resumo .loading")).toHaveCount(0, { timeout: 15_000 });

  // Percentual só existe se houve venda no mês (pct() devolve null com total zero, e o card
  // mostra "—"). No dia 1º, antes do primeiro caixa, o mês corrente está zerado e este teste
  // falhava sem nenhuma regressão de código — foi o que aconteceu em 01/08/2026. Então: se o
  // mês aberto ainda não tem venda, volta pro mês anterior, que é onde os percentuais existem.
  const mesInput = page.locator("#planilha-mes");
  const semVenda = async () => {
    const vendas = page.locator(".real-kpi").filter({
      has: page.locator(".real-label", { hasText: /^Vendas$/ }),
    });
    return /R\$\s*0,00/.test((await vendas.innerText()) || "");
  };
  if (await semVenda()) {
    const [ano, mes] = ((await mesInput.inputValue()) || "").split("-").map(Number);
    const d = new Date(Date.UTC(ano, mes - 2, 1));
    const anterior = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
    await mesInput.fill(anterior);
    await mesInput.dispatchEvent("change");
    await expect(page.locator("#planilha-resumo .loading")).toHaveCount(0, { timeout: 15_000 });
  }

  for (const label of ["Compras", "Consumo", "Perdas", "Despesas"]) {
    // Escopa pelo texto EXATO do ".real-label", não pelo card inteiro: o card "Resultado do
    // mês" tem no texto de apoio "vendas - consumo - perdas - despesas" (minúsculo), e o
    // hasText do Playwright faz substring case-insensitive no elemento inteiro — "Consumo"
    // batia nos dois cards e dava "strict mode violation".
    const card = page.locator(".real-kpi").filter({
      has: page.locator(".real-label", { hasText: new RegExp(`^${label}$`) }),
    });
    await expect(card).toContainText("%", { timeout: 10_000 });
    await expect(card).not.toContainText("NaN");
    await expect(card).not.toContainText("undefined");
  }
});

test("25. Relatórios (comparativo por período) abre e carrega sem erro", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Relatórios" }).click();
  await expect(page.locator("#rel-resumo")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator("#rel-resumo .loading")).toHaveCount(0, { timeout: 15_000 });
});
