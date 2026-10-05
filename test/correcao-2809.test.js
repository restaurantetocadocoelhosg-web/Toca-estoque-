// Ensaio da correção de 28/09 (Downloads/corrigir-nota-2809.mjs) no banco descartável: mesmo bloco SQL.
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirAmbiente } = require('./ambiente/ambiente');

let amb;
test.before(async () => { amb = await subirAmbiente(); await amb.db.query(`insert into tenants (id, nome, slug, plano, ativo) values (1, 'T', 't', 'completo', true)`); });
test.after(async () => { if (amb) await amb.parar(); });

test('cancela os inflados, tira só de Contas os já acertados, registra auditoria — e falha inteira se um der errado', async () => {
  const q = (s, p) => amb.db.query(s, p);
  const prod = async (nome, qtd) => (await q(`insert into produtos (nome, categoria, unidade, qtd, custo, ativo, tenant_id) values ($1,'B','un',$2,1,1,1) returning id`, [nome, qtd])).rows[0].id;
  const mov = async (pid, nome, qtd) => (await q(`insert into movimentacoes (produto_id, produto_nome, tipo, qtd, valor, motivo, tenant_id) values ($1,$2,'Entrada',$3,$3,'Compra',1) returning id`, [pid, nome, qtd])).rows[0].id;
  const conta = async (mid, v) => (await q(`insert into pagamentos_comprovantes (data, valor_bruto, origem, mov_id, tenant_id) values ('2026-09-28',$2,'estoque-auto',$1,1) returning id`, [mid, v])).rows[0].id;
  const s = await prod('Schweppes', 24); const ms = await mov(s, 'Schweppes', 12); await conta(ms, 43.08);
  const c = await prod('Coca', 0); const mc = await mov(c, 'Coca', 12); const cc = await conta(mc, 36.96);
  await q(`do $$ begin
    perform estoque_cancelar(1, ${ms});
    insert into audit_logs (usuario_nome, role, acao, detalhes, tenant_id) values ('Rubens (correção aprovada)', 'admin', 'cancelar_movimentacao', '{"mov_id":${ms}}', 1);
    delete from pagamentos_comprovantes where id in (${cc}) and origem in ('estoque-auto','estoque-backfill');
    insert into audit_logs (usuario_nome, role, acao, detalhes, tenant_id) values ('Rubens (correção aprovada)', 'admin', 'pagamento_excluir', '{"contas_ids":[${cc}]}', 1);
  end $$`);
  assert.equal(Number((await q('select qtd from produtos where id=$1', [s])).rows[0].qtd), 12);
  assert.equal((await q('select count(*)::int n from movimentacoes where id=$1', [ms])).rows[0].n, 0);
  assert.equal((await q('select count(*)::int n from pagamentos_comprovantes where mov_id in ($1,$2)', [ms, mc])).rows[0].n, 0);
  assert.equal((await q('select count(*)::int n from movimentacoes where id=$1', [mc])).rows[0].n, 1, 'o já acertado mantém o lançamento');
  assert.equal(Number((await q('select qtd from produtos where id=$1', [c])).rows[0].qtd), 0, 'e o estoque');
  assert.equal((await q(`select count(*)::int n from audit_logs where usuario_nome like 'Rubens (correção%'`)).rows[0].n, 2);

  // Tudo ou nada: se um cancelamento falhar (ficaria negativo), nada do bloco fica gravado.
  const d = await prod('DelValle', 2); const md = await mov(d, 'DelValle', 6); const cd = await conta(md, 18.9);
  await assert.rejects(q(`do $$ begin delete from pagamentos_comprovantes where id = ${cd}; perform estoque_cancelar(1, ${md}); end $$`), /FICARIA_NEGATIVO/);
  assert.equal((await q('select count(*)::int n from pagamentos_comprovantes where id=$1', [cd])).rows[0].n, 1, 'Contas intacta após a falha');
});
