// Onda 2 — centavos. O total de uma compra com nota é o TOTAL DA NOTA; o custo unitário é referência.
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirApp } = require('./ambiente/app-teste');

let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });

async function pendencia(produtoCupom, qtd, valorTotal) {
  const { rows: [p] } = await ctx.db.query(
    `insert into nota_pendencias (produto_cupom, qtd, valor_total, candidatos, status, tenant_id) values ($1, $2, $3, '[]', 'pendente', 1) returning id`,
    [produtoCupom, qtd, valorTotal]);
  return p.id;
}
async function contasDaMov(produtoId) {
  const [mov] = await ctx.movimentos(produtoId);
  const { rows } = await ctx.db.query('select valor_bruto::float8 as v from pagamentos_comprovantes where mov_id = $1', [mov.id]);
  return { movValor: Number(mov.valor), contas: rows.map((r) => r.v) };
}

for (const [nome, qtd, total] of [
  ['3 caixas × 139,25 (300 un a 1,3925)', 300, 417.75],
  ['PERDA: R$ 1,00 em 900 un (0,0011 × 900 = 0,99)', 900, 1.0],
  ['ACRÉSCIMO: R$ 1,00 em 600 un (0,0017 × 600 = 1,02)', 600, 1.0],
  ['dízima: R$ 100,00 em 3 un', 3, 100.0],
]) {
  test(`centavos — ${nome}: estoque e Contas = total da nota`, async () => {
    const id = await ctx.criarProduto({ nome: `C ${nome}`, unidade: 'un', qtd: 0, custo: Number((total / qtd).toFixed(4)) });
    const pid = await pendencia(`C ${nome}`, qtd, total);
    const r = await ctx.api('admin', 'POST', `/api/pendencias/${pid}/resolver`, { produto_id: id, qtd, memorizar: false });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const { movValor, contas } = await contasDaMov(id);
    assert.equal(movValor, total, 'valor da movimentação');
    assert.deepEqual(contas, [total], 'valor em Contas');
  });
}

test('centavos — preço sugerido reenviado com 2 casas (botão "pacote") ainda usa o total da nota', async () => {
  const id = await ctx.criarProduto({ nome: 'C sugerido', unidade: 'un', qtd: 0, custo: 1.39 });
  const pid = await pendencia('C sugerido', 300, 417.75);
  const r = await ctx.api('admin', 'POST', `/api/pendencias/${pid}/resolver`, { produto_id: id, qtd: 300, custo: 1.39, memorizar: false });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual((await contasDaMov(id)).contas, [417.75]);
});

test('centavos — CONTROLE: preço digitado diferente da nota vale custo × quantidade', async () => {
  const id = await ctx.criarProduto({ nome: 'C digitado', unidade: 'un', qtd: 0, custo: 2 });
  const pid = await pendencia('C digitado', 10, 15);
  const r = await ctx.api('admin', 'POST', `/api/pendencias/${pid}/resolver`, { produto_id: id, qtd: 10, custo: 2.5, memorizar: false });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual((await contasDaMov(id)).contas, [25]);
});
