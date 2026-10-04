// Relatórios, inventário, auditoria e entrada de dinheiro: app REAL contra o banco local descartável.
// Exigem o resultado CORRETO; na v121 os de F4/F8/F9/R2/"1.500" falham de propósito.
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirApp } = require('./ambiente/app-teste');
const { extrairFuncao } = require('./helpers/extrair-funcao');

let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });

const diaSP = (deslocDias = 0) => new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo' }).format(new Date(Date.now() + deslocDias * 86400000));

test('F4 — salão 100 + delivery 50 no mês: total 150 e NENHUM aviso falso de divergência interna', async () => {
  await ctx.db.query(`insert into fechamentos_diarios (data, vendas, tenant_id) values ('2026-09-10', 100, 1)`);
  await ctx.db.query(`insert into delivery_receitas (tenant_id, plataforma, periodo_inicio, periodo_fim, vendas_bruto, valor_liquido, parcial, origem)
                      values (1, 'ifood', '2026-09-01', '2026-09-30', 50, 40, false, 'teste')`);
  const r = await ctx.api('admin', 'GET', '/api/planilha-mensal?mes=2026-09');
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.ok(r.json.totais && Array.isArray(r.json.totais.divergencias_internas), 'a planilha precisa trazer totais.divergencias_internas (senão o teste não testa nada)');
  assert.deepEqual(r.json.totais.divergencias_internas, [], `avisos: ${JSON.stringify(r.json.totais.divergencias_internas)}`);
});

test('F8 — inventário abre com 10, saída normal de 3 durante a contagem, contagem 7: sem "sumiço"', async () => {
  const id = await ctx.criarProduto({ nome: 'F8 produto', qtd: 10, custo: 10, categoria: 'F8' });
  const ab = await ctx.api('gerente', 'POST', '/api/inventario/abrir', { categoria: 'F8' });
  assert.equal(ab.status, 200, JSON.stringify(ab.json));
  const { rows: [inv] } = await ctx.db.query(`select id from inventarios where status = 'aberto' order by id desc limit 1`);
  const s = await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Saída', qtd: 3, motivo: 'Produção', forcar: true });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  const c = await ctx.api('gerente', 'POST', '/api/inventario/contar', { inventario_id: inv.id, itens: [{ produto_id: id, qtd_contada: 7 }] });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  const f = await ctx.api('gerente', 'POST', '/api/inventario/fechar', { inventario_id: inv.id });
  assert.equal(f.status, 200, JSON.stringify(f.json));
  const { rows: [item] } = await ctx.db.query('select divergencia, valor_divergencia, causa from inventario_itens where inventario_id = $1 and produto_id = $2', [inv.id, id]);
  const { rows: [fech] } = await ctx.db.query('select valor_sumico from inventarios where id = $1', [inv.id]);
  assert.equal(Number(item.divergencia), 0, `divergência registrada: ${item.divergencia} (${item.causa})`);
  assert.equal(Number(fech.valor_sumico || 0), 0, `valor de sumiço: ${fech.valor_sumico}`);
  assert.equal(await ctx.saldo(id), 7, 'estoque final = contagem');
});

test('F8 — saída feita DEPOIS da contagem do item não é apagada pelo fechamento', async () => {
  const id = await ctx.criarProduto({ nome: 'F8b produto', qtd: 10, custo: 10, categoria: 'F8b' });
  const ab = await ctx.api('gerente', 'POST', '/api/inventario/abrir', { categoria: 'F8b' });
  assert.equal(ab.status, 200, JSON.stringify(ab.json));
  const { rows: [inv] } = await ctx.db.query(`select id from inventarios where status = 'aberto' order by id desc limit 1`);
  const c = await ctx.api('gerente', 'POST', '/api/inventario/contar', { inventario_id: inv.id, itens: [{ produto_id: id, qtd_contada: 10 }] });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  const s = await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Saída', qtd: 2, motivo: 'Produção', forcar: true });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  const f = await ctx.api('gerente', 'POST', '/api/inventario/fechar', { inventario_id: inv.id });
  assert.equal(f.status, 200, JSON.stringify(f.json));
  assert.equal(await ctx.saldo(id), 8, 'contou 10, saiu 2 depois: fica 8 (antes voltava para 10)');
  const { rows: [item] } = await ctx.db.query('select divergencia from inventario_itens where inventario_id = $1 and produto_id = $2', [inv.id, id]);
  assert.equal(Number(item.divergencia), 0);
});

test('F8 — CONTROLE: sumiço real continua sendo apontado', async () => {
  const id = await ctx.criarProduto({ nome: 'F8c produto', qtd: 10, custo: 10, categoria: 'F8c' });
  await ctx.api('gerente', 'POST', '/api/inventario/abrir', { categoria: 'F8c' });
  const { rows: [inv] } = await ctx.db.query(`select id from inventarios where status = 'aberto' order by id desc limit 1`);
  await ctx.api('gerente', 'POST', '/api/inventario/contar', { inventario_id: inv.id, itens: [{ produto_id: id, qtd_contada: 6 }] });
  const f = await ctx.api('gerente', 'POST', '/api/inventario/fechar', { inventario_id: inv.id });
  assert.equal(f.status, 200, JSON.stringify(f.json));
  const { rows: [item] } = await ctx.db.query('select divergencia from inventario_itens where inventario_id = $1 and produto_id = $2', [inv.id, id]);
  assert.equal(Number(item.divergencia), -4);
  assert.equal(await ctx.saldo(id), 6);
});

test('F9 — histórico maior que 1.000 linhas: a reconstrução considera tudo e acusa a falta de 1', async () => {
  const id = await ctx.criarProduto({ nome: 'F9 produto', qtd: 0, categoria: 'F9' });
  // 1.000 entradas antigas de 1 (há 10 dias) e uma saída de 1.001 hoje: o histórico fica 1 negativo.
  await ctx.db.query(`insert into movimentacoes (produto_id, produto_nome, categoria, tipo, qtd, unidade, custo, valor, motivo, responsavel, created_at, tenant_id)
    select $1, 'F9 produto', 'F9', 'Entrada', 1, 'un', 1, 1, 'Compra', 'teste', now() - interval '10 days' + g * interval '1 second', 1 from generate_series(1, 1000) g`, [id]);
  await ctx.db.query(`insert into movimentacoes (produto_id, produto_nome, categoria, tipo, qtd, unidade, custo, valor, motivo, responsavel, created_at, tenant_id)
    values ($1, 'F9 produto', 'F9', 'Saída', 1001, 'un', 1, 1001, 'Produção', 'teste', now(), 1)`, [id]);
  const r = await ctx.api('admin', 'GET', `/api/auditoria/divergencias?data_inicio=${diaSP(-20)}&data_fim=${diaSP(0)}&categoria=F9`);
  assert.equal(r.status, 200, JSON.stringify(r.json).slice(0, 300));
  const linha = (r.json.resultado || []).find((x) => String(x.produto_id) === String(id));
  assert.ok(linha, 'produto deveria aparecer na auditoria');
  assert.equal(linha.alerta, true, 'deveria acusar alerta');
  assert.equal(linha.faltou, 1, `faltou calculado: ${linha.faltou}`);
  assert.equal(linha.conferencia, 'inconclusivo', 'sem fotografia inicial, falta é inconclusiva (não prova de sumiço)');
});

test('F9 — CONTROLE: produto que já tinha saldo no 1º lançamento (fotografia) não vira alerta falso', async () => {
  const id = await ctx.criarProduto({ nome: 'F9 foto', qtd: 4, categoria: 'F9b' });
  await ctx.db.query(`insert into movimentacoes (produto_id, produto_nome, categoria, tipo, qtd, unidade, motivo, qtd_antes, qtd_depois, tenant_id)
    values ($1, 'F9 foto', 'F9b', 'Saída', 6, 'un', 'Produção', 10, 4, 1)`, [id]);
  const r = await ctx.api('admin', 'GET', `/api/auditoria/divergencias?data_inicio=${diaSP(-2)}&data_fim=${diaSP(0)}&categoria=F9b`);
  assert.equal(r.status, 200);
  const linha = r.json.resultado.find((x) => String(x.produto_id) === String(id));
  assert.equal(linha.alerta, false, 'partiu de 10 (fotografia), saiu 6: não faltou nada');
  assert.equal(linha.conferencia, 'conferido');
  assert.equal(linha.ancora, 'fotografia');
});

test('R2 — compra lançada com data retroativa vai para as Contas na MESMA data (não hoje)', async () => {
  const id = await ctx.criarProduto({ nome: 'R2 produto', qtd: 0, custo: 5, categoria: 'R2' });
  const ontem = diaSP(-1);
  const r = await ctx.api('gerente', 'POST', '/api/movimentacoes', { produto_id: id, tipo: 'Entrada', qtd: 2, motivo: 'Compra', custo: 5, data: ontem });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const [mov] = await ctx.movimentos(id);
  const { rows } = await ctx.db.query(`select data::text from pagamentos_comprovantes where mov_id = $1`, [mov.id]);
  assert.equal(rows.length, 1, 'a compra deveria gerar uma linha em Contas');
  assert.equal(rows[0].data, ontem, `data em Contas: ${rows[0].data}`);
});

test('Dinheiro — "1.500" digitado (milhar brasileiro) vale 1.500, não 1,50 (servidor)', () => {
  const parse = extrairFuncao('server.js', 'parseMoneyNumber');
  assert.equal(parse('1.500'), 1500);
  // controles que já funcionam e não podem quebrar:
  assert.equal(parse('1.500,00'), 1500);
  assert.equal(parse('1500,00'), 1500);
  assert.equal(parse('12,5'), 12.5);
  assert.equal(parse('1500.00'), 1500, 'formato da tela (toFixed(2)) segue decimal');
  assert.equal(parse('12.50'), 12.5);
  assert.equal(parse('1.50'), 1.5);
  assert.equal(parse('1.500.000'), 1500000);
  assert.equal(parse('R$ 2.350'), 2350);
  assert.equal(parse(1.5), 1.5, 'número canônico não é reinterpretado');
});

test('Dinheiro — "1.500" digitado vale 1.500 também na tela (moneyFromText)', () => {
  const parse = extrairFuncao('public/index.html', 'moneyFromText');
  assert.equal(parse('1.500'), 1500);
  assert.equal(parse('1.500,00'), 1500);
  assert.equal(parse('12.50'), 12.5, 'formato do moneyInputValue segue decimal');
  assert.equal(parse(Number(1500).toFixed(2)), 1500);
});

test('F6 — consumo da média usa os MESMOS meses do divisor (só meses com contas)', async () => {
  // Julho/2026: só consumo (sem contas). Agosto/2026: venda 1000, conta 100, consumo 300.
  const id = await ctx.criarProduto({ nome: 'F6 produto', qtd: 0, categoria: 'F6' });
  await ctx.db.query(`insert into movimentacoes (produto_id, produto_nome, categoria, tipo, qtd, unidade, valor, motivo, created_at, tenant_id) values
    ($1, 'F6 produto', 'F6', 'Saída', 1, 'un', 900, 'Produção', '2026-07-15T12:00:00-03:00', 1),
    ($1, 'F6 produto', 'F6', 'Saída', 1, 'un', 300, 'Produção', '2026-08-15T12:00:00-03:00', 1)`, [id]);
  await ctx.db.query(`insert into fechamentos_diarios (data, vendas, tenant_id) values ('2026-07-15', 1000, 1), ('2026-08-15', 1000, 1)`);
  await ctx.db.query(`insert into pagamentos_comprovantes (data, valor_bruto, grupo, categoria, origem, tenant_id) values ('2026-08-10', 100, 'Outras Despesas', 'Teste', 'manual', 1)`);
  const r = await ctx.api('admin', 'GET', '/api/indices?mes=2026-08');
  assert.equal(r.status, 200, JSON.stringify(r.json).slice(0, 300));
  assert.deepEqual(r.json.janela.meses_com_custo, ['2026-08']);
  assert.equal(r.json.janela.situacao, 'parcial');
  assert.equal(r.json.consumo_estoque.valor_janela, 300, 'julho (sem contas) não pode entrar no consumo da média');
});
