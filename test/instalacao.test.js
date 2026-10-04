// Teste do "teste sem rastro" usado na subida (Downloads/toca-estoque-subida-v122): o bloco DO lança duas
// vezes com o mesmo evento e termina em exceção — tudo deve ser desfeito e a mensagem trazer os resultados.
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirAmbiente } = require('./ambiente/ambiente');

let amb;
test.before(async () => {
  amb = await subirAmbiente();
  await amb.db.query(`insert into tenants (id, nome, slug, plano, ativo) values (1, 'Teste', 'teste', 'completo', true)`);
});
test.after(async () => { if (amb) await amb.parar(); });

test('teste sem rastro da instalação: devolve "repetido" na mensagem e não deixa nada gravado', async () => {
  const { rows: [p] } = await amb.db.query(`insert into produtos (nome, categoria, unidade, qtd, custo, ativo, tenant_id) values ('Instalação', 'T', 'un', 5, 2, 1, 1) returning id`);
  let msg = '';
  try {
    await amb.db.query(`do $$ declare a jsonb; b jsonb; begin
      a := estoque_movimentar(1, ${p.id}, 'Entrada', 1, null, false, null, 'teste de instalação', 'instalação', 'teste', null, 'teste-instalacao-v122');
      b := estoque_movimentar(1, ${p.id}, 'Entrada', 1, null, false, null, 'teste de instalação', 'instalação', 'teste', null, 'teste-instalacao-v122');
      raise exception 'RESULTADO_TESTE %', jsonb_build_object('a', a, 'b', b);
    end $$`);
  } catch (e) { msg = e.message; }
  const comoApi = JSON.stringify({ message: `Failed to run sql query: ERROR:  P0001: ${msg}` }); // formato da Management API
  assert.match(comoApi, /RESULTADO_TESTE/);
  assert.match(comoApi, /repetido\W{1,8}true/);
  assert.match(comoApi, /qtd_depois/);
  const { rows: [d] } = await amb.db.query(`select qtd::float8 as qtd, (select count(*)::int from movimentacao_eventos where evento_id = 'teste-instalacao-v122') as ev,
    (select count(*)::int from movimentacoes where produto_id = $1) as movs from produtos where id = $1`, [p.id]);
  assert.deepEqual(d, { qtd: 5, ev: 0, movs: 0 });
});
