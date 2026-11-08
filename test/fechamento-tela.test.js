// Tela Dia com o texto real de 08/11/2026, num navegador de verdade (Chromium) contra o app REAL +
// banco descartável. Confere cada número na tela e o que chega no banco ao salvar.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');
const { subirApp } = require('./ambiente/app-teste');

const TEXTO = fs.readFileSync(path.join(__dirname, 'fixtures', 'movimento-08-11-2026.txt'), 'utf8')
  .replace('TOTAL VENDIDO: R$ 6.358,07', 'TOTAL VENDIDO: R$ 6.358,07\nBALANÇA: 70,402 KG');

let ctx, navegador, pagina;
test.before(async () => {
  ctx = await subirApp();
  navegador = await chromium.launch();
  pagina = await navegador.newPage();
  const { token } = await ctx.novaSessao('admin');
  await pagina.goto(ctx.base + '/');
  await pagina.evaluate((t) => localStorage.setItem('toca_token', t), token);
  await pagina.goto(ctx.base + '/');
  await pagina.waitForFunction(() => typeof goPage === 'function' && !!window.currentUser || !!document.getElementById('nav-realidade')?.offsetParent, null, { timeout: 30000 });
  await pagina.evaluate(() => goPage('realidade', document.getElementById('nav-realidade')));
  await pagina.fill('#real-data', '2026-11-08');
  await pagina.evaluate(() => loadRealidade());
  await pagina.waitForFunction(() => window.realidadeCache?.data === '2026-11-08' || (typeof realidadeCache !== 'undefined' && realidadeCache?.data === '2026-11-08'));
});
test.after(async () => { if (navegador) await navegador.close(); if (ctx) await ctx.parar(); });

const txt = async (sel) => (await pagina.textContent(sel)).replace(/\u00a0/g, ' ');

async function colar(texto) {
  await pagina.fill('#real-relatorio-texto', texto);
  await pagina.click('button:has-text("Ler texto")');
  await pagina.waitForTimeout(300);
}

test('colar o texto preenche balança, 5 perdas e a conta das bebidas', async () => {
  await colar(TEXTO);
  assert.equal(await pagina.inputValue('#real-balanca'), '70,402');
  assert.equal(await pagina.inputValue('#real-perda-lixo_buffet_g'), '2,890');
  assert.equal(await pagina.inputValue('#real-perda-lixo_salada_g'), '6,200');
  assert.equal(await pagina.inputValue('#real-perda-desperdicio_g'), '');
  assert.equal(await pagina.inputValue('#real-perda-fritura_g'), '1,750');
  assert.equal(await pagina.inputValue('#real-perda-doacao_corte_g'), '2,750');
  const conta = await txt('#real-conta-balanca');
  for (const v of ['R$ 6.335,48', 'R$ 698,39', 'R$ 5.637,09', 'R$ 6.468,07', 'R$ 830,98']) assert.ok(conta.includes(v), `faltou ${v} em: ${conta}`);
  const preco = await txt('#real-preco-kg');
  assert.ok(preco.includes('89,99') && /domingo/i.test(preco), preco);
  const despesas = await pagina.$$eval('#real-despesas-list .real-desc', (els) => els.map((e) => e.value));
  assert.ok(!despesas.some((d) => /fritura|doa/i.test(d)), `peso virou despesa: ${despesas}`);
  assert.ok((await txt('#real-caixa-alerta')).includes('110,00'));
});

test('Porcionamento e Observação não aparecem na tela', async () => {
  assert.equal(await pagina.isVisible('#real-porc-block'), false);
  assert.equal(await pagina.isVisible('#real-obs'), false);
  assert.equal(await pagina.isVisible('#real-porc-semana-card'), false);
});

test('marcar feriado num dia útil troca o preço para 89,99', async () => {
  await pagina.fill('#real-data', '2026-11-10');
  await pagina.evaluate(() => loadRealidade());
  await pagina.waitForFunction(() => realidadeCache?.data === '2026-11-10');
  await colar(TEXTO.replace('08/11/2026', '10/11/2026'));
  assert.ok((await txt('#real-preco-kg')).includes('64,99'));
  await pagina.check('#real-feriado');
  assert.ok((await txt('#real-preco-kg')).includes('89,99'));
  assert.ok((await txt('#real-conta-balanca')).includes('R$ 830,98'));
});

test('salvar grava balança, perdas e preço do dia no banco', async () => {
  await pagina.fill('#real-data', '2026-11-08');
  await pagina.evaluate(() => loadRealidade());
  await pagina.waitForFunction(() => realidadeCache?.data === '2026-11-08');
  await colar(TEXTO.replace('TOTAL VENDIDO: R$ 6.358,07', 'TOTAL VENDIDO: R$ 6.468,07'));
  await pagina.click('#real-btn-salvar');
  await pagina.waitForFunction(() => realidadeCache?.venda_lancada === true, null, { timeout: 15000 });
  const l = (await ctx.db.query(`select * from fechamentos_diarios where data = '2026-11-08'`)).rows[0];
  assert.equal(Number(l.balanca_kg), 70.402);
  assert.equal(Number(l.preco_kg), 89.99);
  assert.equal(l.perdas.fritura_g, 1750);
  assert.equal(Number(l.vendas), 6468.07);
  assert.ok((await txt('#real-conta-balanca')).includes('R$ 830,98'), 'conta continua na tela depois de salvar');
});

test('reabrir um dia salvo mostra balança, perdas e a conta de novo', async () => {
  await pagina.fill('#real-data', '2026-11-09');
  await pagina.evaluate(() => loadRealidade());
  await pagina.waitForFunction(() => realidadeCache?.data === '2026-11-09');
  await pagina.fill('#real-data', '2026-11-08');
  await pagina.evaluate(() => loadRealidade());
  await pagina.waitForFunction(() => realidadeCache?.data === '2026-11-08');
  assert.equal(await pagina.inputValue('#real-balanca'), '70,402');
  assert.equal(await pagina.inputValue('#real-perda-fritura_g'), '1,750');
  assert.equal(await pagina.inputValue('#real-perda-lixo_salada_g'), '6,200');
  assert.ok((await txt('#real-conta-balanca')).includes('R$ 830,98'));
});

test('impressão do dia mostra balança, bebidas e as perdas em kg (sem porcionamento)', async () => {
  await colar(TEXTO);
  const [popup] = await Promise.all([pagina.waitForEvent('popup'), pagina.evaluate(() => imprimirDia())]);
  await popup.waitForLoadState('domcontentloaded');
  const html = (await popup.evaluate(() => document.body.innerText)).replace(/\u00a0/g, ' ');
  for (const t of ['Balança', '70,402 kg', 'R$ 89,99', 'Bebidas e derivados', 'R$ 830,98', 'Fritura', '1,750 kg', 'Lixo salada', '6,200 kg']) {
    assert.ok(html.includes(t), `faltou "${t}" na impressão`);
  }
  assert.ok(!html.includes('Porcionamento'), 'porcionamento saiu da tela, sai da impressão');
  await popup.close();
});
