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
