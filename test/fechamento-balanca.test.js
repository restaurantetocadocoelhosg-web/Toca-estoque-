// Fechamento do dia com BALANÇA (08/11/2026): app REAL + Postgres local descartável.
// O servidor congela o preço do quilo do dia, guarda as 5 perdas e devolve a conta das bebidas.
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirApp } = require('./ambiente/app-teste');

let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });

const PAGAMENTOS = [
  { descricao: 'CRED STONE:', valor: 123.83 }, { descricao: 'VOUCHER STONE:', valor: 729.21 },
  { descricao: 'CRED PAG BANK:', valor: 1580.72 }, { descricao: 'DEB PAG BANK:', valor: 2127.03 },
  { descricao: 'PIX PAG BANK:', valor: 988.49 }, { descricao: 'DINHEIRO:', valor: 918.79 },
];
const CORTES = [
  { qtd: 2, descricao: 'ERRO/TARA/CANC', valor: 90.17 }, { qtd: 5, descricao: 'PATRÕES', valor: 248.98 },
  { qtd: 6, descricao: 'FUNCIONARIO', valor: 359.24 },
];
const PERDAS = { lixo_buffet_g: 2890, lixo_salada_g: 6200, desperdicio_g: null, fritura_g: 1750, doacao_corte_g: 2750 };
const dia = (data, extra = {}) => ({
  data, pratos_vendidos: 150, pagamentos: PAGAMENTOS, cortes: CORTES,
  despesas: [{ descricao: 'PAO', valor: 8 }], balanca_kg: 70.402, perdas: PERDAS, feriado: false, ...extra,
});
const linha = async (data) => (await ctx.db.query('select * from fechamentos_diarios where tenant_id = 1 and data = $1', [data])).rows[0];

test('domingo 08/11: preço 89,99 congelado pelo servidor, perdas salvas, bebidas R$ 830,98', async () => {
  const r = await ctx.api('operador', 'POST', '/api/realidade-dia', dia('2026-11-08', { preco_kg: 1 }));
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const l = await linha('2026-11-08');
  assert.equal(Number(l.balanca_kg), 70.402);
  assert.equal(Number(l.preco_kg), 89.99, 'preço vem do servidor, não do aparelho');
  assert.equal(l.feriado, false);
  assert.deepEqual(l.perdas, PERDAS);
  assert.equal(l.lixo_buffet_g, 2890, 'campo antigo continua recebendo o lixo do buffet');
  const g = await ctx.api('operador', 'GET', '/api/realidade-dia?data=2026-11-08');
  assert.equal(g.json.conta_balanca.bebidas, 830.98);
  assert.equal(g.json.conta_balanca.comida_vendida, 5637.09);
  assert.equal(g.json.balanca_kg, 70.402);
  assert.equal(g.json.preco_kg, 89.99);
});

test('dia útil usa 64,99; feriado marcado usa 89,99', async () => {
  await ctx.api('operador', 'POST', '/api/realidade-dia', dia('2026-11-10'));
  assert.equal(Number((await linha('2026-11-10')).preco_kg), 64.99);
  await ctx.api('operador', 'POST', '/api/realidade-dia', dia('2026-11-11', { feriado: true }));
  const l = await linha('2026-11-11');
  assert.equal(Number(l.preco_kg), 89.99);
  assert.equal(l.feriado, true);
});

test('GET de dia ainda não lançado sugere o preço e o feriado automático', async () => {
  const g = await ctx.api('operador', 'GET', '/api/realidade-dia?data=2026-11-20');
  assert.equal(g.json.feriado_automatico, 'Consciência Negra');
  assert.equal(g.json.preco_kg_sugerido, 89.99);
  assert.equal(g.json.conta_balanca, null);
});

test('preço do quilo: só admin muda; vale da data em diante', async () => {
  const op = await ctx.api('operador', 'POST', '/api/precos-kg', { inicio: '2026-12-01', preco_util: 69.99, preco_fim_semana: 94.99 });
  assert.equal(op.status, 403);
  const ruim = await ctx.api('admin', 'POST', '/api/precos-kg', { inicio: '2026-12-01', preco_util: -1, preco_fim_semana: 94.99 });
  assert.equal(ruim.status, 400);
  const ad = await ctx.api('admin', 'POST', '/api/precos-kg', { inicio: '2026-12-01', preco_util: 69.99, preco_fim_semana: 94.99 });
  assert.equal(ad.status, 200, JSON.stringify(ad.json));
  const lista = await ctx.api('operador', 'GET', '/api/precos-kg');
  assert.equal(lista.json.precos[0].preco_util, 69.99);
  await ctx.api('operador', 'POST', '/api/realidade-dia', dia('2026-12-02'));
  assert.equal(Number((await linha('2026-12-02')).preco_kg), 69.99);
  await ctx.api('operador', 'POST', '/api/realidade-dia', dia('2026-11-12'));
  assert.equal(Number((await linha('2026-11-12')).preco_kg), 64.99, 'preço novo não muda dia antes do início');
});

test('dia antigo sem balança continua igual (sem conta, sem preço)', async () => {
  const antigo = dia('2026-10-05');
  delete antigo.balanca_kg; delete antigo.perdas; delete antigo.feriado;
  antigo.lixo_buffet_g = 2785;
  await ctx.api('operador', 'POST', '/api/realidade-dia', antigo);
  const l = await linha('2026-10-05');
  assert.equal(l.balanca_kg, null);
  assert.equal(l.preco_kg, null);
  assert.equal(l.lixo_buffet_g, 2785);
  const g = await ctx.api('operador', 'GET', '/api/realidade-dia?data=2026-10-05');
  assert.equal(g.json.conta_balanca, null);
  assert.equal(g.json.vendas, 6468.07);
});

test('peso inválido não salva lixo absurdo nem balança negativa', async () => {
  const r = await ctx.api('operador', 'POST', '/api/realidade-dia', dia('2026-11-13', { balanca_kg: -5, perdas: { fritura_g: 'abc', lixo_salada_g: 999999999 } }));
  assert.equal(r.status, 200);
  const l = await linha('2026-11-13');
  assert.equal(l.balanca_kg, null);
  assert.equal(l.perdas.fritura_g, null);
  assert.equal(l.perdas.lixo_salada_g, null, 'acima de 500 kg é erro de digitação');
});

test('ANTES da migração rodar (sem as colunas novas): salvar e abrir o dia continua funcionando', async () => {
  await ctx.db.query('alter table fechamentos_diarios drop column balanca_kg, drop column preco_kg, drop column perdas, drop column feriado');
  await ctx.db.query(`notify pgrst, 'reload schema'`);
  await new Promise((r) => setTimeout(r, 1500));
  const r = await ctx.api('operador', 'POST', '/api/realidade-dia', dia('2026-11-14'));
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const l = await linha('2026-11-14');
  assert.equal(Number(l.vendas), 6468.07);
  assert.equal(l.lixo_buffet_g, 2890);
  const g = await ctx.api('operador', 'GET', '/api/realidade-dia?data=2026-11-14');
  assert.equal(g.status, 200);
  assert.equal(g.json.configuracao_pendente, false);
  assert.equal(g.json.conta_balanca, null);
});
