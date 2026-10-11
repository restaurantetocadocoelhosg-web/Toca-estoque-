// Recibo dos lançamentos (11/10/2026): diário do aparelho (public/recibo-lancamentos.js) e o
// endpoint /api/conferir-lancamentos contra o app REAL + Postgres local descartável.
const test = require('node:test');
const assert = require('node:assert/strict');
const { criarDiario, diaBrasilia } = require('../public/recibo-lancamentos.js');
const { subirApp } = require('./ambiente/app-teste');

function armazemFalso() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k),
    key: (i) => [...m.keys()][i] ?? null, get length() { return m.size; }, _m: m,
  };
}
const relogio = (iso) => { let t = new Date(iso).getTime(); return { agora: () => new Date(t), anda: (ms) => { t += ms; } }; };

test('diário: registra, atualiza pelo código e mostra o último', () => {
  const r = relogio('2026-10-06T19:10:00Z');
  const d = criarDiario(armazemFalso(), r.agora);
  d.registrar({ evento: 'tela-a', produto_id: 62, produto: 'Batata Frita', tipo: 'Entrada', qtd: 7, status: 'enviando' });
  d.registrar({ evento: 'tela-a', status: 'salvo', mov_id: 14609 });
  assert.equal(d.ler().length, 1);
  assert.equal(d.ultimo().status, 'salvo');
  assert.equal(d.ultimo().mov_id, 14609);
  assert.equal(d.ultimo().hora, '16:10', 'hora de Brasília');
});

test('diário: a mesma entrada salva há menos de 3 min é repetida; depois disso, ou outra qtd, não', () => {
  const r = relogio('2026-10-06T19:10:00Z');
  const d = criarDiario(armazemFalso(), r.agora);
  d.registrar({ evento: 'tela-a', produto_id: 62, tipo: 'Entrada', qtd: 7, status: 'salvo' });
  r.anda(16_000);
  assert.ok(d.repetidoRecente({ produto_id: 62, tipo: 'Entrada', qtd: 7, evento: 'tela-b' }), 'frita 7 + 7 em 16 s');
  assert.equal(d.repetidoRecente({ produto_id: 62, tipo: 'Entrada', qtd: 7, evento: 'tela-a' }), null, 'o mesmo código é reenvio, não repetição');
  assert.equal(d.repetidoRecente({ produto_id: 62, tipo: 'Entrada', qtd: 6, evento: 'tela-b' }), null);
  r.anda(4 * 60_000);
  assert.equal(d.repetidoRecente({ produto_id: 62, tipo: 'Entrada', qtd: 7, evento: 'tela-b' }), null);
});

test('diário: só o que ficou SALVO conta como repetido; sem confirmação aparece na lista de pendentes', () => {
  const d = criarDiario(armazemFalso(), relogio('2026-10-06T19:10:00Z').agora);
  d.registrar({ evento: 'tela-a', produto_id: 62, tipo: 'Entrada', qtd: 7, status: 'sem_confirmacao' });
  assert.equal(d.repetidoRecente({ produto_id: 62, tipo: 'Entrada', qtd: 7, evento: 'tela-b' }), null);
  assert.deepEqual(d.semConfirmacao().map((x) => x.evento), ['tela-a']);
});

test('diário: aplica a conferência do servidor (salvo, cancelado, não chegou)', () => {
  const d = criarDiario(armazemFalso(), relogio('2026-10-06T19:10:00Z').agora);
  for (const e of ['tela-a', 'tela-b', 'tela-c']) d.registrar({ evento: e, status: 'salvo' });
  const l = d.aplicarConferencia([
    { evento: 'tela-a', status: 'salvo', mov_id: 1 }, { evento: 'tela-b', status: 'cancelado', mov_id: 2 }, { evento: 'tela-c', status: 'nao_encontrado' }]);
  assert.deepEqual(l.map((x) => x.conferido), ['salvo', 'cancelado', 'nao_chegou']);
});

test('diário: um dia por chave (Brasília), apaga listas com mais de 3 dias, e armazém quebrado não derruba', () => {
  const r = relogio('2026-10-11T02:00:00Z'); // 23h do dia 10 em Brasília
  const arm = armazemFalso();
  const d = criarDiario(arm, r.agora);
  assert.equal(diaBrasilia(r.agora()), '2026-10-10');
  arm.setItem('toca-recibo:2026-10-01', '[]');
  arm.setItem('outra-coisa', 'x');
  d.registrar({ evento: 'tela-a', status: 'salvo' });
  d.limparAntigos();
  assert.deepEqual([...arm._m.keys()].sort(), ['outra-coisa', 'toca-recibo:2026-10-10']);
  const quebrado = { getItem() { throw new Error('bloqueado'); }, setItem() { throw new Error('cheio'); }, removeItem() {}, key: () => null, length: 0 };
  const d2 = criarDiario(quebrado, r.agora);
  assert.doesNotThrow(() => d2.registrar({ evento: 'x', status: 'salvo' }));
  assert.deepEqual(d2.ler(), []);
});

// ── servidor ──
let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });

test('servidor: lançamento devolve mov_id; conferir diz salvo, cancelado e não encontrado', async () => {
  const id = await ctx.criarProduto({ nome: 'Recibo frita', qtd: 10 });
  const ent = (ev) => ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 7, motivo: 'Ajuste de teste', evento_id: ev });
  const r1 = await ent('tela-11111111-aaaa');
  assert.equal(r1.status, 200, JSON.stringify(r1.json));
  assert.ok(Number(r1.json.mov_id) > 0, 'mov_id no recibo');
  const r2 = await ent('tela-22222222-bbbb');
  assert.equal(r2.status, 200);
  const del = await ctx.api('gerente', 'DELETE', `/api/movimentacoes/${r2.json.mov_id}`);
  assert.equal(del.status, 200, JSON.stringify(del.json));

  const c = await ctx.api('operador', 'POST', '/api/conferir-lancamentos', { eventos: ['tela-11111111-aaaa', 'tela-22222222-bbbb', 'tela-33333333-cccc'] });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  const porEv = Object.fromEntries(c.json.resultado.map((x) => [x.evento, x]));
  assert.equal(porEv['tela-11111111-aaaa'].status, 'salvo');
  assert.equal(porEv['tela-11111111-aaaa'].mov_id, Number(r1.json.mov_id));
  assert.equal(porEv['tela-22222222-bbbb'].status, 'cancelado');
  assert.equal(porEv['tela-33333333-cccc'].status, 'nao_encontrado');
});

test('servidor: reenvio com o mesmo código também devolve o mov_id (recibo do "toque de novo")', async () => {
  const id = await ctx.criarProduto({ nome: 'Recibo reenvio', qtd: 10 });
  const corpo = { produto_id: id, tipo: 'Saída', qtd: 1, motivo: 'Produção', evento_id: 'tela-44444444-dddd' };
  const a = await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  const b = await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  assert.equal(b.status, 200);
  assert.equal(b.json.repetido, true);
  assert.equal(Number(b.json.mov_id), Number(a.json.mov_id));
  assert.equal(await ctx.saldo(id), 9, 'não duplicou');
});

test('servidor: entrada inválida é recusada ou ignorada; sem login não entra', async () => {
  const muitos = await ctx.api('operador', 'POST', '/api/conferir-lancamentos', { eventos: Array.from({ length: 301 }, (_, i) => `tela-${String(i).padStart(8, '0')}`) });
  assert.equal(muitos.status, 400);
  const semLista = await ctx.api('operador', 'POST', '/api/conferir-lancamentos', { eventos: 'tela-x' });
  assert.equal(semLista.status, 400);
  // códigos de outras origens (nota, lote, inventário) e lixo não são consultados
  const lixo = await ctx.api('operador', 'POST', '/api/conferir-lancamentos', { eventos: ['pendencia:1053', 'cli:tela-1', "tela-' or 1=1", 'tela-12'] });
  assert.equal(lixo.status, 200);
  assert.deepEqual(lixo.json.resultado, []);
  const anon = await fetch(`${ctx.base}/api/conferir-lancamentos`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"eventos":["tela-11111111-aaaa"]}' });
  assert.equal(anon.status, 401);
});

// ── revisão (11/10): casos de borda ──
test('diário: lista estragada ("null", objeto) não trava o próximo lançamento', () => {
  const arm = armazemFalso();
  const d = criarDiario(arm, relogio('2026-10-06T19:10:00Z').agora);
  arm.setItem('toca-recibo:2026-10-06', 'null');
  assert.doesNotThrow(() => d.registrar({ evento: 'tela-a', produto: 'X', status: 'enviando' }));
  arm.setItem('toca-recibo:2026-10-06', '{"a":1}');
  assert.deepEqual(d.ler(), []);
});

test('diário: resposta que chega depois da meia-noite atualiza o item de ONTEM (sem item fantasma hoje)', () => {
  const r = relogio('2026-10-07T02:59:30Z'); // 23:59:30 em Brasília
  const arm = armazemFalso();
  const d = criarDiario(arm, r.agora);
  d.registrar({ evento: 'tela-a', produto: 'Frita', tipo: 'Entrada', qtd: 7, status: 'enviando' });
  r.anda(60_000); // 00:00:30 do dia seguinte
  d.registrar({ evento: 'tela-a', status: 'salvo', mov_id: 9 });
  assert.deepEqual(d.ler(), [], 'nada criado no dia novo');
  assert.equal(JSON.parse(arm.getItem('toca-recibo:2026-10-06'))[0].status, 'salvo');
});

test('diário: mesma qtd lançada com OUTRA data (retroativo) não é repetição', () => {
  const d = criarDiario(armazemFalso(), relogio('2026-10-06T19:10:00Z').agora);
  d.registrar({ evento: 'tela-a', produto_id: 62, tipo: 'Entrada', qtd: 7, data: '2026-10-05', status: 'salvo' });
  assert.equal(d.repetidoRecente({ produto_id: 62, tipo: 'Entrada', qtd: 7, evento: 'tela-b', data: '' }), null);
  assert.ok(d.repetidoRecente({ produto_id: 62, tipo: 'Entrada', qtd: 7, evento: 'tela-b', data: '2026-10-05' }));
});
