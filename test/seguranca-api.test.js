// Onda S — permissões, sessões e leitor de notas, pelo app REAL contra o banco descartável.
// A IA é FALSA: a chamada para api.anthropic.com é interceptada aqui (custo zero, resposta fixa).
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

// ---------- papéis ----------
test('operador NÃO faz Ajuste; gerente faz', async () => {
  const id = await ctx.criarProduto({ nome: 'S ajuste', qtd: 10 });
  const op = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Ajuste', qtd: 3, motivo: 'Contagem' });
  assert.equal(op.status, 403, JSON.stringify(op.json));
  assert.equal(await ctx.saldo(id), 10);
  const ge = await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Ajuste', qtd: 3, motivo: 'Contagem' });
  assert.equal(ge.status, 200, JSON.stringify(ge.json));
  assert.equal(await ctx.saldo(id), 3);
});

test('operador não confirma o próprio alerta de preço com forcar; gerente confirma', async () => {
  const id = await ctx.criarProduto({ nome: 'S preço', qtd: 0, custo: 3 });
  const corpo = { produto_id: id, tipo: 'Entrada', qtd: 2, motivo: 'Compra', custo: 48, forcar: true };
  const op = await ctx.api('operador', 'POST', '/api/movimentacoes', corpo);
  assert.equal(op.status, 409, JSON.stringify(op.json));
  assert.equal(op.json.codigo, 'PRECO_SUSPEITO');
  assert.equal(await ctx.saldo(id), 0);
  const ge = await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  assert.equal(ge.status, 200, JSON.stringify(ge.json));
  assert.equal(await ctx.saldo(id), 2);
});

test('CONTROLE — operador continua lançando Saída normal', async () => {
  const id = await ctx.criarProduto({ nome: 'S saída', qtd: 10 });
  const r = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Saída', qtd: 2, motivo: 'Produção' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(await ctx.saldo(id), 8);
});

// ---------- permissões falham fechado ----------
test('erro ao ler as liberações = nada liberado (não cai no padrão do papel)', async () => {
  const antes = await ctx.api('gerente', 'GET', '/api/me');
  assert.equal(antes.status, 200);
  const liberadasAntes = Object.values(antes.json.permissoes || antes.json.permissions?.permissoes || {}).filter(Boolean).length;
  await ctx.db.query('alter table users rename column permissoes to permissoes_x');
  try {
    const r = await ctx.api('gerente', 'GET', '/api/me');
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const perms = r.json.permissoes || r.json.permissions?.permissoes || {};
    assert.ok(Object.keys(perms).length > 0, `resposta sem liberações: ${JSON.stringify(r.json).slice(0, 300)}`);
    assert.deepEqual(Object.values(perms).filter(Boolean), [], `liberado mesmo com erro: ${JSON.stringify(perms)}`);
    assert.ok(liberadasAntes > 0, 'controle: antes do erro o gerente tinha liberações');
  } finally {
    await ctx.db.query('alter table users rename column permissoes_x to permissoes');
  }
});

// ---------- sessões ----------
test('admin redefine a senha do operador: sessões abertas do operador caem', async () => {
  const outra = await ctx.novaSessao('operador');
  assert.equal((await ctx.apiToken(outra.token, 'GET', '/api/me')).status, 200);
  const r = await ctx.api('admin', 'PUT', `/api/users/${outra.userId}`, { nova_senha: 'senha-nova-123' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal((await ctx.apiToken(outra.token, 'GET', '/api/me')).status, 401);
});

test('troca da própria senha: os OUTROS aparelhos caem, o atual continua', async () => {
  const login = await ctx.apiToken(null, 'POST', '/api/login', { username: 'teste_operador', password: 'senha-nova-123' });
  assert.equal(login.status, 200, JSON.stringify(login.json));
  const atual = login.json.token;
  const outro = await ctx.novaSessao('operador');
  const r = await ctx.apiToken(atual, 'POST', '/api/change-password', { current_password: 'senha-nova-123', new_password: 'outra-senha-456' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal((await ctx.apiToken(outro.token, 'GET', '/api/me')).status, 401, 'o outro aparelho deveria cair');
  assert.equal((await ctx.apiToken(atual, 'GET', '/api/me')).status, 200, 'quem trocou continua logado');
});

test('desativar o usuário derruba a sessão', async () => {
  const outra = await ctx.novaSessao('gerente');
  const r = await ctx.api('admin', 'PUT', `/api/users/${outra.userId}`, { active: false });
  assert.equal(r.status, 200);
  assert.equal((await ctx.apiToken(outra.token, 'GET', '/api/me')).status, 401);
  await ctx.db.query('update users set active = 1 where id = $1', [outra.userId]);
});

// ---------- leitor de notas (IA falsa) ----------
test('nota: "1,5" vale 1,5; negativa e exagerada NÃO entram no automático', async () => {
  await ctx.criarProduto({ nome: 'Tomate Nota', unidade: 'kg', qtd: 0, custo: 6 });
  await ctx.criarProduto({ nome: 'Cebola Nota', unidade: 'kg', qtd: 0, custo: 5 });
  await ctx.criarProduto({ nome: 'Batata Nota', unidade: 'kg', qtd: 0, custo: 4 });
  process.env.ANTHROPIC_API_KEY = 'chave-falsa-de-teste';
  try {
    respostaIa = { itens: [
      { nome: 'Tomate Nota', qtd: '1,5', unidade: 'KG', valor_total: 9, embalagem: 1, gramatura_kg: 0 },
      { nome: 'Cebola Nota', qtd: -2, unidade: 'KG', valor_total: 10, embalagem: 1, gramatura_kg: 0 },
      { nome: 'Batata Nota', qtd: 50000, unidade: 'KG', valor_total: 10, embalagem: 1, gramatura_kg: 0 },
    ] };
    const sess = await ctx.novaSessao('gerente'); // o teste anterior derrubou as sessões do gerente
    const r = await ctx.apiToken(sess.token, 'POST', '/api/ler-cupom', { imagem: 'eA==' });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const porNome = Object.fromEntries(r.json.itens.map((i) => [i.nome_cupom, i]));
    assert.equal(porNome['Tomate Nota'].qtd, 1.5);
    assert.ok(porNome['Tomate Nota'].produto, 'tomate reconhecido');
    assert.equal(porNome['Cebola Nota'].produto, null, 'negativa vai para conferência');
    assert.match(porNome['Cebola Nota'].problema_qtd, /inválida/);
    assert.equal(porNome['Batata Nota'].produto, null, 'exagerada vai para conferência');
    assert.match(porNome['Batata Nota'].problema_qtd, /limite/);
  } finally {
    process.env.ANTHROPIC_API_KEY = '';
  }
});

test('IA do chat: operador não faz Ajuste pela IA (mesma trava do REST)', async () => {
  // Executa a ferramenta da IA direto pelo chat com a IA falsa pedindo um Ajuste.
  const id = await ctx.criarProduto({ nome: 'S ia ajuste', qtd: 10 });
  process.env.ANTHROPIC_API_KEY = 'chave-falsa-de-teste';
  let chamadas = 0;
  const anterior = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    if (String(url).startsWith('https://api.anthropic.com/')) {
      chamadas++;
      const corpo = chamadas === 1
        ? { stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 't1', name: 'registrar_movimentacao', input: { produto_nome: 'S ia ajuste', tipo: 'Ajuste', qtd: 1 } }] }
        : { stop_reason: 'end_turn', content: [{ type: 'text', text: 'ok' }] };
      return new Response(JSON.stringify(corpo), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return anterior(url, opts);
  };
  try {
    await ctx.db.query(`update users set permissoes = '{"ia": true}'::jsonb where username = 'teste_operador'`);
    const sess = await ctx.novaSessao('operador');
    const r = await ctx.apiToken(sess.token, 'POST', '/api/chat', { pergunta: 'ajusta para 1', historico: [] });
    assert.equal(r.status, 200, JSON.stringify(r.json).slice(0, 300));
    assert.ok(chamadas >= 2, 'a IA falsa deveria ter pedido a ferramenta');
    assert.equal(await ctx.saldo(id), 10, 'saldo não pode mudar');
  } finally {
    globalThis.fetch = anterior;
    process.env.ANTHROPIC_API_KEY = '';
  }
});
