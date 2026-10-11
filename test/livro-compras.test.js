// Livro de compras — Fase 1 dos 3 livros (11/10/2026). Funções puras + app REAL contra Postgres local.
const test = require('node:test');
const assert = require('node:assert/strict');
const { cabecalhoDaNota, situacaoDaCompra, todasAsLinhas } = require('../compras');
const { subirApp } = require('./ambiente/app-teste');

test('cabeçalho da nota: aceita o que faz sentido, nunca inventa', () => {
  assert.deepEqual(cabecalhoDaNota({ fornecedor: '  Atacadão   Coelho ', data_emissao: '2026-10-06', total_nota: '115.43' }, '2026-10-11'),
    { fornecedor: 'Atacadão Coelho', data_nota: '2026-10-06', total_nota: 115.43 });
  const ruim = cabecalhoDaNota({ fornecedor: '', data_emissao: '2026-12-25', total_nota: -3 }, '2026-10-11');
  assert.deepEqual(ruim, { fornecedor: null, data_nota: null, total_nota: null }, 'data no futuro e total negativo viram null');
  assert.equal(cabecalhoDaNota({ data_emissao: '2025-01-01' }, '2026-10-11').data_nota, null, 'nota de 1 ano atrás = leitura errada');
  assert.equal(cabecalhoDaNota({ data_emissao: '06/10/2026' }, '2026-10-11').data_nota, null);
  assert.deepEqual(cabecalhoDaNota(undefined, '2026-10-11'), { fornecedor: null, data_nota: null, total_nota: null });
});

test('situação da compra: bate (tolerância R$ 1 ou 1%), diferença, pendente, sem total, sem nota', () => {
  assert.equal(situacaoDaCompra({ total_nota: 115.43, soma_lancada: 115.0, pendencias_abertas: 0 }), 'bate');
  assert.equal(situacaoDaCompra({ total_nota: 115.43, soma_lancada: 99, pendencias_abertas: 0 }), 'diferenca');
  assert.equal(situacaoDaCompra({ total_nota: 1000, soma_lancada: 991, pendencias_abertas: 0 }), 'bate', '1% de 1000 = 10');
  assert.equal(situacaoDaCompra({ total_nota: 115.43, soma_lancada: 0, pendencias_abertas: 1 }), 'pendente');
  assert.equal(situacaoDaCompra({ total_nota: null, soma_lancada: 50, pendencias_abertas: 0 }), 'sem_total');
  assert.equal(situacaoDaCompra({ sem_nota: true, aprovado_por: null }), 'aguardando_aprovacao');
  assert.equal(situacaoDaCompra({ sem_nota: true, aprovado_por: 'Rubens' }), 'sem_nota_aprovada');
});

test('paginação: soma passa de 1.000 linhas sem cortar', async () => {
  const paginas = [Array(1000).fill({ v: 1 }), Array(1000).fill({ v: 1 }), Array(5).fill({ v: 1 })];
  const pedidos = [];
  const linhas = await todasAsLinhas(async (de, ate) => { pedidos.push([de, ate]); return { data: paginas[de / 1000] || [] }; });
  assert.equal(linhas.length, 2005);
  assert.deepEqual(pedidos, [[0, 999], [1000, 1999], [2000, 2999]]);
});

let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });

const compraDaMov = async (movId) => (await ctx.db.query('select compra_id from movimentacoes where id = $1', [movId])).rows[0].compra_id;
const compra = async (id) => (await ctx.db.query('select * from compras where id = $1', [id])).rows[0];
const novaNota = async (extra = {}) => (await ctx.db.query(
  `insert into compras (tenant_id, origem, nota_hash, fornecedor, total_nota, remetente) values ($1, 'grupo', $2, 'Mercado Teste', $3, 'Rubens') returning id`,
  [extra.tenant ?? 1, extra.hash ?? `h-${Math.random()}`, extra.total ?? 100])).rows[0].id;

test('compra na mão SEM nota: operador fica aguardando aprovação; gerente já sai aprovado', async () => {
  const id = await ctx.criarProduto({ nome: 'Compra sem nota', qtd: 0, custo: 8.5 });
  const op = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 7, custo: 8.5, motivo: 'Compra', motivo_sem_nota: 'feira, nota perdida' });
  assert.equal(op.status, 200, JSON.stringify(op.json));
  const c1 = await compra(await compraDaMov(op.json.mov_id));
  assert.equal(c1.sem_nota, true);
  assert.equal(c1.origem, 'mao');
  assert.equal(c1.motivo_sem_nota, 'feira, nota perdida');
  assert.equal(c1.aprovado_por, null);
  const ge = await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 1, custo: 8.5, motivo: 'Compra' });
  const c2 = await compra(await compraDaMov(ge.json.mov_id));
  assert.equal(c2.aprovado_por, 'Teste gerente');
});

test('compra na mão ligada a uma NOTA: liga; nota inexistente ou de outro restaurante é recusada', async () => {
  const id = await ctx.criarProduto({ nome: 'Compra com nota', qtd: 0, custo: 5 });
  const nota = await novaNota();
  const r = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 2, custo: 5, motivo: 'Compra', compra_id: nota });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(Number(await compraDaMov(r.json.mov_id)), Number(nota));
  const nada = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 2, motivo: 'Compra', compra_id: 999999 });
  assert.equal(nada.status, 400);
  await ctx.db.query(`insert into tenants (id, nome, slug, plano, ativo) values (2, 'Outro', 'outro', 'completo', true) on conflict do nothing`);
  const alheia = await novaNota({ tenant: 2 });
  const outro = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 2, motivo: 'Compra', compra_id: alheia });
  assert.equal(outro.status, 400, 'nota de outro restaurante não serve');
  const op1 = await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 1, custo: 5, motivo: 'Compra' });
  const semNotaAprovada = await compraDaMov(op1.json.mov_id);
  const pulo = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 2, motivo: 'Compra', compra_id: semNotaAprovada });
  assert.equal(pulo.status, 400, 'ligar a uma compra SEM NOTA já aprovada pularia a aprovação do gerente');
  assert.equal(await ctx.saldo(id), 3, 'os recusados não mexeram no estoque (2 da nota + 1 do gerente)');
});

test('saída e reenvio (mesmo código) não criam compra nova', async () => {
  const id = await ctx.criarProduto({ nome: 'Sem compra', qtd: 10, custo: 2 });
  const antes = Number((await ctx.db.query('select count(*) from compras')).rows[0].count);
  await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Saída', qtd: 1, motivo: 'Produção' });
  const corpo = { produto_id: id, tipo: 'Entrada', qtd: 3, custo: 2, motivo: 'Compra', evento_id: 'tela-55555555-eeee', motivo_sem_nota: 'motivo unico do reenvio' };
  const a = await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  await ctx.api('gerente', 'POST', '/api/movimentacoes', corpo);
  const depois = Number((await ctx.db.query('select count(*) from compras')).rows[0].count);
  assert.equal(depois - antes, 1, 'só a 1ª entrada criou compra');
  assert.ok(await compraDaMov(a.json.mov_id));
});

test('pendência resolvida: a entrada herda a nota da pendência', async () => {
  const id = await ctx.criarProduto({ nome: 'Frita teste pend', unidade: 'kg', qtd: 0, custo: 8.5 });
  const nota = await novaNota({ total: 115.43 });
  const { rows: [p] } = await ctx.db.query(`insert into nota_pendencias (produto_cupom, qtd, unidade_cupom, valor_total, candidatos, remetente, status, tenant_id, compra_id)
    values ('Batata Uri 2KG', 14, 'KG', 115.43, '[]', 'Nayara', 'pendente', 1, $1) returning id`, [nota]);
  const r = await ctx.api('admin', 'POST', `/api/pendencias/${p.id}/resolver`, { produto_id: id });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const { rows: [m] } = await ctx.db.query('select compra_id from movimentacoes where produto_id = $1 order by id desc limit 1', [id]);
  assert.equal(Number(m.compra_id), Number(nota));
});

test('lista de compras: soma × total da nota, pendência aberta e aprovação', async () => {
  const id = await ctx.criarProduto({ nome: 'Lista compras', qtd: 0, custo: 10 });
  const bate = await novaNota({ total: 100 });
  for (const q of [6, 4]) assert.equal((await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: q, custo: 10, motivo: 'Compra', compra_id: bate })).status, 200);
  const falta = await novaNota({ total: 200 });
  await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 5, custo: 10, motivo: 'Compra', compra_id: falta });
  const comPend = await novaNota({ total: 50 });
  await ctx.db.query(`insert into nota_pendencias (produto_cupom, qtd, valor_total, candidatos, remetente, status, tenant_id, compra_id) values ('Coisa', 1, 50, '[]', 'x', 'pendente', 1, $1)`, [comPend]);

  const r = await ctx.api('operador', 'GET', '/api/compras?dias=3');
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const por = Object.fromEntries(r.json.compras.map((c) => [c.id, c]));
  assert.equal(por[bate].situacao, 'bate');
  assert.equal(por[bate].soma_lancada, 100);
  assert.equal(por[bate].itens, 2);
  assert.equal(por[falta].situacao, 'diferenca');
  assert.equal(por[falta].diferenca, -150);
  assert.equal(por[comPend].situacao, 'pendente');
  assert.equal(por[comPend].valor_pendente, 50);
  assert.ok(!r.json.compras.some((c) => c.fornecedor === 'Mercado Teste' && c.id === undefined));
});

test('vários itens sem nota da mesma pessoa e motivo viram UMA compra (gerente aprova 1x)', async () => {
  const id = await ctx.criarProduto({ nome: 'Feira junta', qtd: 0, custo: 2 });
  const ids = [];
  for (const q of [1, 2, 3]) {
    const r = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: q, custo: 2, motivo: 'Compra', motivo_sem_nota: 'feira de sábado' });
    ids.push(await compraDaMov(r.json.mov_id));
  }
  assert.equal(new Set(ids.map(String)).size, 1, 'os 3 itens na mesma compra');
  const outra = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 1, custo: 2, motivo: 'Compra', motivo_sem_nota: 'outro motivo' });
  assert.notEqual(String(await compraDaMov(outra.json.mov_id)), String(ids[0]), 'motivo diferente = outra compra');
});

test('aprovar compra sem nota: só gerente/admin, uma vez só', async () => {
  const id = await ctx.criarProduto({ nome: 'Aprovar', qtd: 0, custo: 3 });
  const op = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 1, custo: 3, motivo: 'Compra' });
  const cid = await compraDaMov(op.json.mov_id);
  assert.equal((await ctx.api('operador', 'POST', `/api/compras/${cid}/aprovar`)).status, 403);
  assert.equal((await ctx.api('gerente', 'POST', `/api/compras/${cid}/aprovar`)).status, 200);
  assert.equal((await compra(cid)).aprovado_por, 'Teste gerente');
  assert.equal((await ctx.api('admin', 'POST', `/api/compras/${cid}/aprovar`)).status, 404, 'já aprovada');
  const nota = await novaNota();
  assert.equal((await ctx.api('gerente', 'POST', `/api/compras/${nota}/aprovar`)).status, 404, 'nota de verdade não tem o que aprovar');
});

// Ordem da subida: o código pode chegar ANTES da migração. Sem a tabela, nada pode quebrar.
// (fica por último: tira a tabela do banco de teste)
test('banco SEM a migração: compra lança normal, lista avisa indisponível', async () => {
  await ctx.db.query('alter table movimentacoes drop column compra_id; alter table nota_pendencias drop column compra_id; drop table compras;');
  await ctx.recarregarEsquemaRest();
  const id = await ctx.criarProduto({ nome: 'Sem migracao', qtd: 0, custo: 4 });
  const r = await ctx.api('operador', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 2, custo: 4, motivo: 'Compra', motivo_sem_nota: 'x' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(await ctx.saldo(id), 2);
  const l = await ctx.api('operador', 'GET', '/api/compras');
  assert.equal(l.status, 200);
  assert.equal(l.json.indisponivel, true);
});
