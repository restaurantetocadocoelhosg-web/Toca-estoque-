// "PARADOS SEM GIRO" do bom-dia (09/11/2026): o Rubens viu dois erros no aviso real.
//  1) Detergente com 26 saídas aparecia "sem histórico" (a busca só via as últimas 1.000 saídas).
//  2) H2O comprada ontem aparecia "17d parado" (compra nova não contava).
const test = require('node:test');
const assert = require('node:assert/strict');
const { subirApp } = require('./ambiente/app-teste');

let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });

const q = (s, p) => ctx.db.query(s, p);
const prod = async (nome, categoria, qtd) => (await q(
  `insert into produtos (nome, categoria, unidade, qtd, minimo, custo, ativo, tenant_id) values ($1,$2,'un',$3,0,1,1,1) returning id`,
  [nome, categoria, qtd])).rows[0].id;
const diasAtras = (d) => new Date(Date.now() - d * 86400000).toISOString();

async function preparar() {
  const det = await prod('Giro Detergente', 'Limpeza', 4);
  const h2o = await prod('Giro H2O', 'Bebidas', 36);
  const novo = await prod('Giro Suco Novo', 'Bebidas', 12);
  const nunca = await prod('Giro Nunca Mexeu', 'Bebidas', 3);
  const cheio = await prod('Giro Arroz Rodando', 'Secos', 50);
  const mov = (pid, tipo, quando) => q(
    `insert into movimentacoes (produto_id, produto_nome, tipo, qtd, valor, motivo, created_at, tenant_id) values ($1,'x',$2,1,1,'teste',$3,1)`,
    [pid, tipo, quando]);
  await mov(det, 'Saída', diasAtras(23));
  await mov(h2o, 'Saída', diasAtras(18));
  await mov(h2o, 'Entrada', diasAtras(1));
  await mov(novo, 'Entrada', diasAtras(1));
  // 1.100 saídas recentes de outro produto: empurram o detergente pra fora das "últimas 1.000".
  await q(`insert into movimentacoes (produto_id, produto_nome, tipo, qtd, valor, motivo, created_at, tenant_id)
           select $1,'x','Saída',0.001,0,'teste', now() - (g || ' minutes')::interval, 1 from generate_series(1,1100) g`, [cheio]);
  // gatilhos podem mexer no saldo: deixa o saldo como no teste
  await q(`update produtos set qtd = v.q from (values ($1::bigint,4),($2::bigint,36),($3::bigint,12),($4::bigint,3),($5::bigint,50)) v(id,q) where produtos.id = v.id`,
    [det, h2o, novo, nunca, cheio]);
}

test('parados: saída antiga mostra os dias certos e compra recente não conta como parado', async () => {
  await preparar();
  const r = await ctx.apiToken(null, 'POST', '/api/webhook/whatsapp', { secret: 'segredo-de-teste-local', acao: 'criticos' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const txt = r.json.resposta;
  const linhaDe = (nome) => txt.split('\n').find((l) => l.includes(nome)) || '';

  assert.match(linhaDe('Giro Detergente'), /23d parado/, 'detergente tem saída: não é "sem histórico"');
  assert.equal(linhaDe('Giro H2O'), '', 'H2O comprada ontem não é parado');
  assert.equal(linhaDe('Giro Suco Novo'), '', 'produto que acabou de chegar não é parado');
  assert.match(linhaDe('Giro Nunca Mexeu'), /sem histórico/, 'nunca teve movimento continua sem histórico');
  assert.equal(linhaDe('Giro Arroz Rodando'), '', 'quem sai todo dia não é parado');
});
