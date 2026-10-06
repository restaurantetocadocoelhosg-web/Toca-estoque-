// F7 pelo app REAL: foto da nota → /api/ler-cupom com a IA FALSA (custo zero) contra o banco descartável.
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirApp } = require('./ambiente/app-teste');

let ctx;
const fetchOriginal = globalThis.fetch;
let respostaIa = null;
test.before(async () => {
  ctx = await subirApp();
  globalThis.fetch = async (url, opts) => {
    if (String(url).startsWith('https://api.anthropic.com/')) {
      return new Response(JSON.stringify({ content: [{ type: 'text', text: JSON.stringify(respostaIa) }] }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return fetchOriginal(url, opts);
  };
});
test.after(async () => { globalThis.fetch = fetchOriginal; if (ctx) await ctx.parar(); });

test('F7 — nota em g, caixa sem conteúdo, kg para unidade e linha sem valor: converte ou manda conferir; o normal segue automático', async () => {
  await ctx.criarProduto({ nome: 'F7 Queijo Ralado', unidade: 'kg', qtd: 0, custo: 50 });
  await ctx.criarProduto({ nome: 'F7 Coca Lata', unidade: 'un', qtd: 0, custo: 3 });
  await ctx.criarProduto({ nome: 'F7 Abacaxi', unidade: 'un', qtd: 0, custo: 8 });
  await ctx.criarProduto({ nome: 'F7 Guardanapo', unidade: 'un', qtd: 0, custo: 2 });
  await ctx.criarProduto({ nome: 'F7 Agua Mineral', unidade: 'un', qtd: 0, custo: 1.2 });
  process.env.ANTHROPIC_API_KEY = 'chave-falsa-de-teste';
  try {
    respostaIa = { itens: [
      { nome: 'F7 Queijo Ralado', qtd: 500, unidade: 'G', valor_total: 25, embalagem: 1, gramatura_kg: 0 },
      { nome: 'F7 Coca Lata', qtd: 2, unidade: 'CX', valor_total: 95.76, embalagem: 1, gramatura_kg: 0 },
      { nome: 'F7 Abacaxi', qtd: 3, unidade: 'KG', valor_total: 24, embalagem: 1, gramatura_kg: 0 },
      { nome: 'F7 Guardanapo', qtd: 10, unidade: 'UN', valor_total: null, embalagem: 1, gramatura_kg: 0 },
      { nome: 'F7 Agua Mineral', qtd: 24, unidade: 'UN', valor_total: 28.8, embalagem: 1, gramatura_kg: 0 },
    ] };
    const sess = await ctx.novaSessao('gerente');
    const r = await ctx.apiToken(sess.token, 'POST', '/api/ler-cupom', { imagem: 'eA==' });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const por = Object.fromEntries(r.json.itens.map((i) => [i.nome_cupom, i]));

    assert.equal(por['F7 Queijo Ralado'].qtd, 0.5, '500 g = 0,5 kg (antes: 500 kg)');
    assert.ok(por['F7 Queijo Ralado'].produto, 'queijo segue automático');
    assert.equal(por['F7 Queijo Ralado'].custo_unit, 50, 'R$ 25 por 0,5 kg = R$ 50/kg');

    for (const [nome, motivo] of [['F7 Coca Lata', /quantas unidades/], ['F7 Abacaxi', /quilo/], ['F7 Guardanapo', /sem valor/]]) {
      assert.equal(por[nome].produto, null, `${nome} vai para conferência`);
      assert.match(por[nome].problema_qtd, motivo);
      assert.equal(por[nome].incerto, true);
    }
    assert.ok(por['F7 Agua Mineral'].produto, 'controle: 24 unidades com valor seguem automático');
    assert.equal(por['F7 Agua Mineral'].problema_qtd, undefined);
  } finally {
    process.env.ANTHROPIC_API_KEY = '';
  }
});
