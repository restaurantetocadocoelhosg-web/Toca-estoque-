// Integridade do estoque: o app REAL contra Postgres 17 + PostgREST locais (descartáveis).
// Estes testes exigem o resultado CORRETO. Na v121 os de F1/F2/F3 falham de propósito (são a prova do defeito).
// Rodar: npm test   (ver test/README.md)
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirApp } = require('./ambiente/app-teste');

let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });

const saida = (id, extra = {}) => ({ produto_id: id, tipo: 'Saída', qtd: 10, motivo: 'Produção', ...extra });

test('F1 — dois cancelamentos simultâneos do mesmo movimento devolvem a quantidade UMA vez (saldo 90)', async () => {
  // A corrida depende do encaixe dos pedidos; repete para não depender de sorte.
  const finais = [];
  for (let i = 0; i < 8; i++) {
    const id = await ctx.criarProduto({ nome: `F1 produto ${i}`, qtd: 90 });
    const r = await ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id));
    assert.equal(r.status, 200, `lançamento base falhou: ${JSON.stringify(r.json)}`);
    assert.equal(await ctx.saldo(id), 80);
    const [mov] = await ctx.movimentos(id);
    await Promise.all([
      ctx.api('gerente', 'DELETE', `/api/movimentacoes/${mov.id}`),
      ctx.api('admin', 'DELETE', `/api/movimentacoes/${mov.id}`),
    ]);
    finais.push(await ctx.saldo(id));
  }
  assert.deepEqual(finais, finais.map(() => 90), `saldos finais por tentativa: ${finais.join(', ')}`);
});

test('F2 — falha ao gravar o histórico de A com B concorrente: só B tem efeito (saldo 90, 1 movimento)', async () => {
  // Gatilho SÓ do banco de teste: o insert do movimento marcado demora e depois falha.
  await ctx.db.query(`
    create or replace function teste_falha_mov() returns trigger language plpgsql as $$
    begin
      if new.obs = 'FORCAR_FALHA_TESTE' then perform pg_sleep(1.5); raise exception 'falha simulada'; end if;
      return new;
    end $$;
    drop trigger if exists teste_falha_mov on movimentacoes;
    create trigger teste_falha_mov before insert on movimentacoes for each row execute function teste_falha_mov();`);
  try {
    const id = await ctx.criarProduto({ nome: 'F2 produto', qtd: 100 });
    const pA = ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id, { obs: 'FORCAR_FALHA_TESTE' }));
    await new Promise((r) => setTimeout(r, 500)); // A já mexeu no saldo e está preso no insert
    const rB = await ctx.api('admin', 'POST', '/api/movimentacoes', saida(id));
    const rA = await pA;
    assert.equal(rB.status, 200);
    assert.notEqual(rA.status, 200, 'A deveria falhar');
    const movs = await ctx.movimentos(id);
    assert.equal(movs.length, 1, 'só o movimento de B');
    assert.equal(await ctx.saldo(id), 90, 'saldo deve refletir só B');
  } finally {
    await ctx.db.query('drop trigger if exists teste_falha_mov on movimentacoes');
  }
});

test('F3 — o mesmo evento reenviado (mesmo evento_id) tem UM efeito (saldo 90, 1 movimento)', async () => {
  const id = await ctx.criarProduto({ nome: 'F3 produto', qtd: 100 });
  const corpo = saida(id, { evento_id: 'teste-evento-123' });
  const r1 = await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  const r2 = await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200, 'reenvio deve devolver o resultado anterior, não erro');
  assert.equal((await ctx.movimentos(id)).length, 1);
  assert.equal(await ctx.saldo(id), 90);
});

test('F3 — reenvio CONCORRENTE do mesmo evento também tem UM efeito', async () => {
  const id = await ctx.criarProduto({ nome: 'F3 concorrente', qtd: 100 });
  const corpo = saida(id, { evento_id: 'teste-evento-concorrente' });
  await Promise.all([ctx.api('gerente', 'POST', '/api/movimentacoes', corpo), ctx.api('gerente', 'POST', '/api/movimentacoes', corpo)]);
  assert.equal((await ctx.movimentos(id)).length, 1);
  assert.equal(await ctx.saldo(id), 90);
});

test('CONTROLE — duas saídas reais iguais (eventos diferentes) continuam valendo as duas (saldo 80)', async () => {
  const id = await ctx.criarProduto({ nome: 'Controle iguais', qtd: 100 });
  const r1 = await ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id, { evento_id: 'evento-A' }));
  const r2 = await ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id, { evento_id: 'evento-B' }));
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200);
  assert.equal((await ctx.movimentos(id)).length, 2);
  assert.equal(await ctx.saldo(id), 80);
});

test('CONTROLE — dois operadores baixam 10 ao mesmo tempo: nenhum se perde (saldo 80)', async () => {
  const id = await ctx.criarProduto({ nome: 'Controle concorrência', qtd: 100 });
  const rs = await Promise.all([ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id)), ctx.api('admin', 'POST', '/api/movimentacoes', saida(id))]);
  assert.deepEqual(rs.map((r) => r.status), [200, 200]);
  assert.equal((await ctx.movimentos(id)).length, 2);
  assert.equal(await ctx.saldo(id), 80);
});

test('F3 — mesma chave de evento com conteúdo DIFERENTE é recusada (nunca adivinha qual vale)', async () => {
  const id = await ctx.criarProduto({ nome: 'F3 conflito', qtd: 100 });
  const r1 = await ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id, { evento_id: 'evento-conflito' }));
  const r2 = await ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id, { evento_id: 'evento-conflito', qtd: 20 }));
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 409, JSON.stringify(r2.json));
  assert.equal(await ctx.saldo(id), 90);
});

test('F3 — compra reenviada com o mesmo evento entra UMA vez também nas Contas', async () => {
  const id = await ctx.criarProduto({ nome: 'F3 compra', qtd: 0, custo: 5 });
  const corpo = { produto_id: id, tipo: 'Entrada', qtd: 4, motivo: 'Compra', custo: 5, evento_id: 'evento-compra' };
  await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  const r2 = await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  assert.equal(r2.status, 200);
  assert.equal(r2.json.repetido, true);
  const [mov] = await ctx.movimentos(id);
  const { rows } = await ctx.db.query('select count(*)::int as n from pagamentos_comprovantes where mov_id = $1', [mov.id]);
  assert.equal(rows[0].n, 1);
  assert.equal(await ctx.saldo(id), 4);
});

test('COMPATIBILIDADE — banco SEM a migração (função ausente): lançar e cancelar seguem funcionando no modo antigo', async () => {
  await ctx.db.query('alter function estoque_movimentar(bigint, bigint, text, numeric, numeric, boolean, numeric, text, text, text, timestamptz, text) rename to estoque_movimentar_x');
  await ctx.db.query('alter function estoque_cancelar(bigint, bigint) rename to estoque_cancelar_x');
  await ctx.recarregarEsquemaRest?.();
  try {
    const id = await ctx.criarProduto({ nome: 'Compat antigo', qtd: 50 });
    const r = await ctx.api('gerente', 'POST', '/api/movimentacoes', saida(id));
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.equal(await ctx.saldo(id), 40);
    const [mov] = await ctx.movimentos(id);
    const c = await ctx.api('gerente', 'DELETE', `/api/movimentacoes/${mov.id}`);
    assert.equal(c.status, 200, JSON.stringify(c.json));
    assert.equal(await ctx.saldo(id), 50);
  } finally {
    await ctx.db.query('alter function estoque_movimentar_x(bigint, bigint, text, numeric, numeric, boolean, numeric, text, text, text, timestamptz, text) rename to estoque_movimentar');
    await ctx.db.query('alter function estoque_cancelar_x(bigint, bigint) rename to estoque_cancelar');
    await ctx.recarregarEsquemaRest?.();
  }
});

test('F3 (caso 28/09) — a MESMA nota reprocessada pelo WhatsApp não lança de novo nem chama a IA', async () => {
  const id = await ctx.criarProduto({ nome: 'Cerveja Nota', unidade: 'un', qtd: 0, custo: 4 });
  const fetchOriginal = globalThis.fetch;
  let chamadasIa = 0;
  globalThis.fetch = async (url, opts) => {
    if (String(url).startsWith('https://api.anthropic.com/')) {
      chamadasIa++;
      const itens = [{ nome: 'Cerveja Nota', qtd: 12, unidade: 'UN', valor_total: 48, embalagem: 1, gramatura_kg: 0 }];
      return new Response(JSON.stringify({ content: [{ type: 'text', text: JSON.stringify({ itens }) }] }), { status: 200 });
    }
    return fetchOriginal(url, opts);
  };
  process.env.ANTHROPIC_API_KEY = 'chave-falsa-de-teste';
  try {
    const corpo = { imagem: 'Zm90by1kYS1ub3Rh', remetente: 'teste', secret: 'segredo-de-teste-local' };
    const r1 = await ctx.apiToken(null, 'POST', '/api/webhook/ler-nota', corpo);
    assert.equal(r1.status, 200, JSON.stringify(r1.json));
    assert.equal(await ctx.saldo(id), 12, 'primeira vez lança');
    const r2 = await ctx.apiToken(null, 'POST', '/api/webhook/ler-nota', corpo);
    assert.equal(r2.status, 200);
    assert.equal(r2.json.repetida, true, JSON.stringify(r2.json));
    assert.equal(await ctx.saldo(id), 12, 'reprocessar não lança de novo');
    assert.equal(chamadasIa, 1, 'nem gasta IA de novo');
    const { rows } = await ctx.db.query(`select count(*)::int as n from pagamentos_comprovantes p join movimentacoes m on m.id = p.mov_id where m.produto_id = $1`, [id]);
    assert.equal(rows[0].n, 1, 'Contas: uma compra só');
  } finally {
    globalThis.fetch = fetchOriginal;
    process.env.ANTHROPIC_API_KEY = '';
  }
});

test('F3 — pendência resolvida duas vezes AO MESMO TEMPO entra uma vez só', async () => {
  const id = await ctx.criarProduto({ nome: 'Pend duplo', unidade: 'un', qtd: 0, custo: 2 });
  const { rows: [p] } = await ctx.db.query(`insert into nota_pendencias (produto_cupom, qtd, valor_total, candidatos, status, tenant_id) values ('Pend duplo', 5, 10, '[]', 'pendente', 1) returning id`);
  const corpo = { produto_id: id, qtd: 5, memorizar: false };
  const outra = await ctx.novaSessao('admin'); // 2º aparelho do admin (gerente não tem a liberação 'pendencias')
  const rs = await Promise.all([ctx.api('admin', 'POST', `/api/pendencias/${p.id}/resolver`, corpo), ctx.apiToken(outra.token, 'POST', `/api/pendencias/${p.id}/resolver`, corpo)]);
  assert.ok(rs.every((r) => [200, 404].includes(r.status)), JSON.stringify(rs.map((r) => r.json)));
  assert.equal(await ctx.saldo(id), 5);
  assert.equal((await ctx.movimentos(id)).length, 1);
});

test('WhatsApp — entrada com total informado: saldo, histórico e Contas pelo caminho atômico (centavos do total)', async () => {
  const id = await ctx.criarProduto({ nome: 'Zap Arroz', unidade: 'un', qtd: 0, custo: 0.0017 });
  const r = await ctx.apiToken(null, 'POST', '/api/webhook/whatsapp', { secret: 'segredo-de-teste-local', acao: 'entrada', produto: 'Zap Arroz', qtd: 600, valor: 1, remetente: 'teste' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(await ctx.saldo(id), 600);
  const movs = await ctx.movimentos(id);
  assert.equal(movs.length, 1);
  assert.equal(Number(movs[0].valor), 1, 'R$ 1,00 da mensagem, não 0,0017 × 600 = 1,02');
  const s = await ctx.apiToken(null, 'POST', '/api/webhook/whatsapp', { secret: 'segredo-de-teste-local', acao: 'saida', produto: 'Zap Arroz', qtd: 1000, remetente: 'teste' });
  assert.match(s.json.resposta, /insuficiente/i);
  assert.equal(await ctx.saldo(id), 600);
});

test('Lote — a mesma lista reenviada com o mesmo lote_id não baixa duas vezes; lote novo baixa', async () => {
  const id = await ctx.criarProduto({ nome: 'Lote feijão', qtd: 20 });
  const corpo = { itens: [{ produto_id: id, qtd: 5, nome: 'Lote feijão' }], tipo: 'Saída', motivo: 'Produção', lote_id: 'lote-teste-1' };
  const r1 = await ctx.api('gerente', 'POST', '/api/movimentacoes/lote', corpo);
  const r2 = await ctx.api('gerente', 'POST', '/api/movimentacoes/lote', corpo);
  assert.equal(r1.status, 200, JSON.stringify(r1.json));
  assert.equal(r2.status, 200);
  assert.equal(await ctx.saldo(id), 15, 'reenvio do mesmo lote não baixa de novo');
  const r3 = await ctx.api('gerente', 'POST', '/api/movimentacoes/lote', { ...corpo, lote_id: 'lote-teste-2' });
  assert.equal(r3.status, 200);
  assert.equal(await ctx.saldo(id), 10, 'outro lote (outra baixa real) vale');
});
