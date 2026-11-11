// Contagem do inventário que não se perde (11/11/2026). Em 03/08/2026 o Rubens contou 292 itens,
// a sessão caiu (1h parado) e ele perdeu tudo: a contagem só existia na tela até clicar em Salvar.
// Aqui, num Chromium de verdade contra o app real + banco descartável:
//  1) digitar já grava no banco, sem clicar em Salvar;
//  2) sem conexão/sessão, o número fica guardado no aparelho e sobe sozinho quando a tela volta;
//  3) tela desatualizada não apaga a contagem que outro aparelho já gravou.
const test = require('node:test');
const assert = require('node:assert/strict');
const { chromium } = require('@playwright/test');
const { subirApp } = require('./ambiente/app-teste');

let ctx, navegador, pagina, invId, pA, pB, pC;
const q = (s, p) => ctx.db.query(s, p);
const prod = async (nome, qtd) => (await q(
  `insert into produtos (nome, categoria, unidade, qtd, minimo, custo, ativo, tenant_id) values ($1,'Inv Teste','un',$2,0,1,1,1) returning id`,
  [nome, qtd])).rows[0].id;
const contada = async (pid) => {
  const r = await q('select qtd_contada from inventario_itens where inventario_id=$1 and produto_id=$2', [invId, pid]);
  return r.rows[0].qtd_contada === null ? null : Number(r.rows[0].qtd_contada);
};
const ate = async (fn, ms = 8000) => {
  const fim = Date.now() + ms;
  for (;;) { if (await fn()) return true; if (Date.now() > fim) return false; await new Promise((r) => setTimeout(r, 150)); }
};
const campo = (pid) => `.inv-input[data-pid="${pid}"]`;

async function abrirTelaInventario() {
  await pagina.goto(ctx.base + '/');
  await pagina.waitForFunction(() => typeof goPage === 'function' && typeof currentUser !== 'undefined' && !!currentUser, null, { timeout: 30000 });
  await pagina.evaluate(() => goPage('inventario', document.getElementById('nav-admin')));
  await pagina.waitForSelector('.inv-input', { timeout: 15000 });
}

test.before(async () => {
  ctx = await subirApp();
  pA = await prod('Inv Arroz', 10);
  pB = await prod('Inv Feijao', 20);
  pC = await prod('Inv Oleo', 30);
  const r = await ctx.api('admin', 'POST', '/api/inventario/abrir', { categoria: 'Inv Teste' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  invId = (await q(`select id from inventarios where status='aberto' order by id desc limit 1`)).rows[0].id;
  navegador = await chromium.launch();
  pagina = await navegador.newPage();
  const { token } = await ctx.novaSessao('admin');
  await pagina.goto(ctx.base + '/');
  await pagina.evaluate((t) => localStorage.setItem('toca_token', t), token);
  await abrirTelaInventario();
});
test.after(async () => { if (navegador) await navegador.close(); if (ctx) await ctx.parar(); });

test('digitar a contagem grava no banco sem clicar em Salvar', async () => {
  await pagina.fill(campo(pA), '7,5');
  await pagina.locator(campo(pA)).blur();
  assert.ok(await ate(async () => (await contada(pA)) === 7.5), `não gravou sozinho: banco tem ${await contada(pA)}`);
  assert.equal(await contada(pB), null, 'item não digitado não pode ser tocado');
});

test('sem conexão: o número fica no aparelho e sobe sozinho quando a tela volta', async () => {
  await pagina.route('**/api/inventario/contar', (rota) => rota.abort());
  await pagina.fill(campo(pB), '12');
  await pagina.locator(campo(pB)).blur();
  await pagina.waitForTimeout(2500);
  assert.equal(await contada(pB), null, 'a rede estava cortada: ainda não pode estar no banco');
  const aviso = await pagina.textContent('#inv-estado');
  assert.match(aviso, /guardad|aparelho|pendente/i, `a tela tem que avisar que ficou guardado: "${aviso}"`);

  await pagina.unroute('**/api/inventario/contar');
  await abrirTelaInventario(); // recarrega a página: como quem relogou depois da sessão cair
  assert.equal(await pagina.inputValue(campo(pB)), '12', 'o número digitado sumiu da tela depois de recarregar');
  assert.ok(await ate(async () => (await contada(pB)) === 12), `não subiu sozinho: banco tem ${await contada(pB)}`);
  assert.equal(await contada(pA), 7.5, 'a contagem anterior tem que continuar');
});

test('tela desatualizada não apaga o que outro aparelho contou (Salvar e Fechar)', async () => {
  // Outro aparelho grava o Óleo depois que esta tela já carregou com o campo vazio.
  const r = await ctx.api('admin', 'POST', '/api/inventario/contar', { inventario_id: invId, itens: [{ produto_id: pC, qtd_contada: 28 }] });
  assert.equal(r.status, 200);
  assert.equal(await pagina.inputValue(campo(pC)), '', 'premissa: esta tela ainda mostra o Óleo vazio');
  await pagina.click('#inv-conteudo button:has-text("Salvar")');
  await pagina.waitForTimeout(1200);
  assert.equal(await contada(pC), 28, 'Salvar com a tela velha apagou a contagem do outro aparelho');

  await pagina.click('#inv-conteudo button:has-text("Fechar")');
  await pagina.click('#confirm-modal-yes');
  assert.ok(await ate(async () => (await q('select status from inventarios where id=$1', [invId])).rows[0].status === 'fechado'), 'o inventário não fechou');
  assert.equal(await contada(pC), 28, 'Fechar com a tela velha apagou a contagem do outro aparelho');
  assert.equal(await contada(pA), 7.5);
  assert.equal(await contada(pB), 12);
  const sobrou = await pagina.evaluate((id) => localStorage.getItem('toca_inv_rascunho_' + id), invId);
  assert.equal(sobrou, null, 'depois de fechar, o rascunho do aparelho tem que ser limpo');
});
